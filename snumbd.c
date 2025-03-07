/* snumbd26.c
   Copyright (C) Acronis, 2004
   Copyright (c) CyberProtect
*/

#include "snconfig.h"
#include "snumbd.h"
#include "debug.h"


#define MAX_MINOR	255

#define SN_MMPAGES BIO_MAX_PAGES
#define SN_MMAP_SIZE (SN_MMPAGES << PAGE_SHIFT)
#define SN_MAX_SECTORS (BIO_MAX_PAGES << (PAGE_SHIFT - SECTOR_SHIFT))

extern const int * const snumbd_major_p;

static LIST_HEAD(sessions_list);
static LIST_HEAD(notinited_list);
static int sessions_count;

#ifdef HAVE_SPIN_LOCK_UNLOCKED
/* sessions_list  & noninit_sessions_list protection */
static spinlock_t sessions_lock = SPIN_LOCK_UNLOCKED;
/* protects 'session->s_disk->private_data' */
static spinlock_t disk_lock = SPIN_LOCK_UNLOCKED;
#else
static DEFINE_SPINLOCK(sessions_lock);
static DEFINE_SPINLOCK(disk_lock);
#endif

#define TIMER_INTERVAL (900*HZ)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#	define HAVE_BIO_BVEC_ITER 1
#endif

#ifdef HAVE_BIO_BVEC_ITER

#define	bio_for_each_segment4(bv, bvp, b, i)	\
	bio_for_each_segment((bv), (b), (i))
typedef struct bvec_iter bvec_iterator_t;
#else
#define	bio_for_each_segment4(bv, bvp, b, i)	\
	bio_for_each_segment((bvp), (b), (i))
typedef int bvec_iterator_t;
#endif

#ifndef HAVE_VM_FAULT_2ARGS
#	define snumbdctl_vm_fault(a, b) snumbdctl_vm_fault(b)
#endif

SA_STATIC dev_t sn_bio_dev(struct bio *bio)
{
#ifndef HAVE_BIO_SET_DEV
	return bio->bi_bdev->bd_dev;
#else
	return bio_dev(bio);
#endif
}

struct session_struct {
	struct list_head	s_list;		/* under sessions_lock */
	dev_t			s_kdev;
	unsigned long long 	s_bcount;	/* blocks count */
	unsigned int s_block_size;    	/* block size */

	volatile unsigned int	s_state;
	atomic_t		s_users;
	int 			s_ro;		/* read-only mode */
	unsigned int		s_hpid;

	struct gendisk *	s_disk;

	struct bio *		s_bio;

	spinlock_t		s_misc_lock;		/* protects from here to */
							/* s_vma */
	unsigned int		s_ioctlcnt;		/* state data */
	unsigned int		s_ioctlcnt_prev;

	struct vm_area_struct *	s_vma;
	char *					s_mpages;	/* continuous mmapped pages */

	struct semaphore        s_sem;		/* session_struct access serialization */

	pid_t				s_apgrp[2]; /* allowed pgrps */

	wait_queue_head_t	req_put_wq;	/* kernel waits for space to put request */
	wait_queue_head_t	req_get_wq;	/* userspace waits for request to handle */

#define MT_REQ_MAX 4
	struct bio *		bio[MT_REQ_MAX];
	pid_t			tag[MT_REQ_MAX];
	unsigned		bio_count;
	unsigned		tag_count;
};

SA_STATIC void unregister_device(struct session_struct *session);

static SA_INLINE int is_session_usable(struct session_struct *session)
{
	return SNUM_INITED == session->s_state;
}

SA_STATIC void shutdown_session(struct session_struct *session)
{
	unsigned i;

	down(&session->s_sem);

	sn_set_mb(session->s_state, SNUM_SESSION_ERR);

	/* fail all requests*/
	for (i = 0; i < MT_REQ_MAX; ++i) {
		struct bio *bio = session->bio[i];
		if (bio) {
			session->bio[i] = NULL;
			session->tag[i] = 0;
			bio_io_error(bio);
		}
	}
	session->bio_count = 0;
	session->tag_count = 0;

	wake_up_all(&session->req_put_wq);
	wake_up_all(&session->req_get_wq);

	up(&session->s_sem);
}

SA_STATIC void get_session(struct session_struct *session)
{
	atomic_inc(&session->s_users);
}

SA_STATIC void put_session(struct session_struct *session)
{
	if (atomic_dec_and_test(&session->s_users)) {
		unregister_device(session);

		spin_lock(&sessions_lock);
		list_del_init(&session->s_list);
		session->s_kdev = 0;
		sessions_count--;
		spin_unlock(&sessions_lock);

		kfree(session);
	}
}

#include <linux/nsproxy.h>
SA_STATIC pid_t sn_current_pgrp(void)
{
	if (!current->nsproxy)
		return 1;

#ifdef HAVE_PID_NS_CHILDREN
	return task_pgrp_nr_ns(current, current->nsproxy->pid_ns_for_children);
#else
	return task_pgrp_nr_ns(current, current->nsproxy->pid_ns);
#endif
}

SA_STATIC void sn_set_queue_block_size(struct request_queue *q, unsigned short size)
{
	blk_queue_logical_block_size(q, size);
	blk_queue_physical_block_size(q, size);
	blk_queue_io_min(q, size);
}

static SA_INLINE int get_free_minor(void)
{
	dev_t dev;
	int minor;
	struct list_head *tmp = NULL;

	minor = 0;
repeate:
	minor++;
	dev = MKDEV(*snumbd_major_p, minor);
	list_for_each(tmp, &sessions_list) {
		struct session_struct *session = list_entry(tmp, struct session_struct, s_list);
		if (session->s_kdev == dev)
			goto repeate;
	}
	return minor;
}

SA_STATIC int snumbd_ioctl_blk(struct block_device *bdev, fmode_t mode, unsigned cmd,
			    unsigned long arg)
{
#ifdef DEBUG
	struct session_struct *session = bdev->bd_disk->private_data;
	if (session)
	{
		sa_debug(DEBUG_API, "s=%p dev=%d:%d\n", session, MAJOR(session->s_kdev), MINOR(session->s_kdev));
	}
#endif
	return -ENOTTY;
}

SA_STATIC int snumbd_is_parent_task(unsigned int pid)
{
#ifdef CONFIG_PREEMPT_RCU
	return 0;
#else
	int ret = 0;
	struct task_struct *task = NULL;
	rcu_read_lock();
	task = current;
	while (task && (task != &init_task)) {
		if (task->pid == pid) {
			ret = 1;
			break;
		}
		task = rcu_dereference(task->parent);
	}
	rcu_read_unlock();
	return ret;
#endif
}

SA_STATIC int snumbd_open_blk(struct block_device *bdev, fmode_t mode)
{
	int users;
	pid_t pgrp;
	struct session_struct *session = NULL;
	loff_t old_size;
	loff_t new_size;

	spin_lock(&disk_lock);
	session = bdev->bd_disk->private_data;
	if (!session) {
		spin_unlock(&disk_lock);
		return -ENODEV;
	}
	users = atomic_read(&session->s_users);
	spin_unlock(&disk_lock);

	if (users == 0)
	{
		sa_info("dying session detected...(%p, %x)\n", session, session->s_kdev);
		return -ENODEV;
	}
	pgrp = sn_current_pgrp();
	/*
	Allow to open device only programs in device creator's group.
	This eliminates problems with device access(reference) from
	udev, multipathd, automount and others.
	*/
	if ((pgrp != session->s_apgrp[0]) && (pgrp != session->s_apgrp[1]) && (!snumbd_is_parent_task(session->s_hpid))) {
		sa_debug(DEBUG_API, "Disable access (%d,%d,%d) dev=%d:%d ...\n", pgrp, session->s_apgrp[0], session->s_apgrp[1],
				MAJOR(session->s_kdev), MINOR(session->s_kdev));
		return -EACCES;
	}

	get_session(session);
	sa_debug(DEBUG_API, "s=%p dev=%d:%d users=%d\n", session, MAJOR(session->s_kdev), MINOR(session->s_kdev), users);

	/* Note: On first open bdev has zero size */
	old_size = i_size_read(bdev->bd_inode);
	new_size = session->s_bcount * session->s_block_size;
	if (old_size != new_size) {
#ifdef HAVE_BD_SET_NR_SECTORS
		bd_set_nr_sectors(bdev, new_size >> SECTOR_SHIFT);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)
		bd_set_size(bdev, new_size);
#else
		set_capacity(bdev->bd_disk, new_size >> SECTOR_SHIFT);
#endif
		set_blocksize(bdev, session->s_block_size);
#ifdef HAVE_SET_DEVICE_RO
		set_device_ro(bdev, (session->s_ro != 0));
#else
		bdev->bd_read_only = (session->s_ro != 0);
#endif
	}

	/* Note: 'put_session()' will be done in 'snumbd_release_blk()' */
	return 0;
}

SA_STATIC BLK_OPS_RELEASE_RETURN_VALUE snumbd_release_blk(struct gendisk *disk, fmode_t mode)
{
	struct session_struct *session = NULL;

	spin_lock(&disk_lock);
	session = disk->private_data;
	if (!session) {
		spin_unlock(&disk_lock);
		return BLK_OPS_RELEASE_RETURN_STATUS;
	}
	spin_unlock(&disk_lock);

	sa_debug(DEBUG_API, "s=%p dev=%d:%d\n", session, MAJOR(session->s_kdev), MINOR(session->s_kdev));

	/* Note: respective 'get_session()' has been done in 'snumbd_open_blk()' */
	put_session(session);
	return BLK_OPS_RELEASE_RETURN_STATUS;
}

#if defined (HAVE_BDOPS_OPEN_ARG_GENDISK)
SA_STATIC int snumbd_open(struct gendisk *disk, blk_mode_t mode)
{
	struct block_device *bdev = disk->part0;
	return snumbd_open_blk(bdev, mode);
}

SA_STATIC void snumbd_release(struct gendisk *disk)
{
	snumbd_release_blk(disk, 1);
}

#define snumbd_ioctl snumbd_ioctl_blk
#else
#define snumbd_open snumbd_open_blk
#define snumbd_ioctl snumbd_ioctl_blk
#define snumbd_release snumbd_release_blk
#endif

#ifdef HAVE_BDOPS_SUBMIT_BIO
SA_STATIC MAKE_REQUEST_RETURN_VALUE snumbd_make_request(struct bio *bio);
#else
SA_STATIC MAKE_REQUEST_RETURN_VALUE snumbd_make_request(struct request_queue *q, struct bio *bio);
#endif

static const struct block_device_operations snumbd_bdops = {
	.owner =	THIS_MODULE,
	.open =		snumbd_open,
	.ioctl =	snumbd_ioctl,
	.release = 	snumbd_release,
#ifdef HAVE_BDOPS_SUBMIT_BIO
	.submit_bio =	snumbd_make_request,
#endif
};

SA_STATIC int register_device(struct session_struct *session)
{
	struct request_queue *queue = NULL;
	int ret;
	ret = -ENOMEM;
	sa_debug(DEBUG_API, "s=%p\n", session);

#ifndef HAVE_BLK_ALLOC_DISK

#ifdef HAVE_BLK_ALLOC_QUEUE_ONE_ARG_GFP
	queue = blk_alloc_queue(GFP_KERNEL);
#elif defined (HAVE_BLK_ALLOC_QUEUE_RH)
	queue = blk_alloc_queue_rh(snumbd_make_request, NUMA_NO_NODE);
#elif defined (HAVE_BLK_ALLOC_QUEUE_ONE_ARG_NODE_ID)
	queue = blk_alloc_queue(NUMA_NO_NODE);
#else
	queue = blk_alloc_queue(snumbd_make_request, NUMA_NO_NODE);
#endif /* HAVE_BLK_ALLOC_QUEUE_ONE_ARG */

	if (!queue) {
		sa_info("%s\n", "Alloc queue failed");
		return ret;
	}
	session->s_disk = alloc_disk(1);
	if (!session->s_disk) {
		sa_info("%s\n", "Alloc disk failed");
		blk_cleanup_queue(queue);
		goto out;
	}
	session->s_disk->queue = queue;
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
	session->s_disk = blk_alloc_disk(NULL, NUMA_NO_NODE);
#else
	session->s_disk = blk_alloc_disk(NUMA_NO_NODE);
#endif
	if (!session->s_disk) {
		sa_info("%s\n", "Alloc disk failed");
		goto out;
	}
	session->s_disk->minors = 1;
	queue = session->s_disk->queue;

#endif /* HAVE_BLK_ALLOC_DISK */ 

	session->s_disk->major = MAJOR(session->s_kdev);
	session->s_disk->first_minor = MINOR(session->s_kdev);
	sprintf(session->s_disk->disk_name, SNUMBD_NAME"%dd", MINOR(session->s_kdev));
	session->s_disk->private_data = session;
	session->s_disk->fops = &snumbd_bdops;
#ifdef GD_SUPPRESS_PART_SCAN
	set_bit(GD_SUPPRESS_PART_SCAN, &session->s_disk->state);
#endif

	sa_debug(DEBUG_INTERNALS, "s=%p(%d) users=%d\n", session, session->s_state,
						atomic_read(&session->s_users));

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0) || defined(HAVE_BD_SET_NR_SECTORS)
	set_capacity(session->s_disk, session->s_bcount * (session->s_block_size / SECTOR_SIZE));
#endif

#ifdef HAVE_BLK_QUEUE_MAKE_REQUEST
	/* Note: 'blk_queue_make_request()' resets queue's settings */
	blk_queue_make_request(queue, snumbd_make_request);
#endif

	sn_set_queue_block_size(queue, session->s_block_size);

#ifdef HAVE_QUEUE_MAX_HW_SECTORS
	blk_queue_max_hw_sectors(queue, SN_MAX_SECTORS);
#else
	blk_queue_max_sectors(queue, SN_MAX_SECTORS);
#endif

#ifdef VOID_ADD_DISK
	add_disk(session->s_disk);
	return 0;
#else
 /* signature was changed in https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/linux/genhd.h?h=linux-5.15.y#n210
	and uses _must_check from https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/linux/genhd.h?h=linux-5.16.y#n210
*/
	ret = add_disk(session->s_disk);
	return ret;
#endif /* VOID_ADD_DISK */

out:
	return ret;
}

SA_STATIC void unregister_device(struct session_struct *session)
{
	sa_debug(DEBUG_API, "s=%p\n", session);
	if (session->s_disk) {

		sa_debug(DEBUG_INTERNALS, "s=%p(%d) users=%d\n", session, session->s_state,
						atomic_read(&session->s_users));
		spin_lock(&disk_lock);
		session->s_disk->private_data = 0;
		spin_unlock(&disk_lock);

		del_gendisk(session->s_disk);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0) && LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)) || defined (HAVE_BLK_CLEANUP_DISK)
/* genhd.h was removed by commit
	  https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/include/linux/blkdev.h?h=linux-5.18.y&id=322cbb50de711814c42fb088f6d31901502c711a

   and blk_cleanup_disk was added to include/linux/blkdev.h in 5.18.y .. 5.19.y, removed from 6.0.y
*/
		blk_cleanup_disk(session->s_disk);
#else
#ifdef HAVE_BLK_CLEANUP_QUEUE
	{
		struct request_queue *queue = session->s_disk->queue;
		if (queue)
			blk_cleanup_queue(queue);
	}
#endif
		/* available from 6.0.y and in earlier version with backported changes */
		put_disk(session->s_disk);
#endif
		session->s_disk = NULL;
	}
}

#if 0
SA_STATIC void session_stat(struct sn_state *sn)
{
	sa_info("dev=%d:%d, state=%d, blksize=%d, mmapsize=%d\n",
				sn->major, sn->minor, sn->state,
				sn->blksize, sn->mmapsize);

	sa_info("psize=%u, pstrt=%u, mshft=%d, ioctls=%u\n",
				sn->partsize, sn->partstrt, sn->minorshft,
				sn->ioctlcnt);

	sa_info("bhpgs=%d, bhcnt=%d, abhs=%u, fbhs=%u, dbhs=%u\n",
				sn->bhpages, sn->bhcount,
				sn->abhs, sn->fbhs, sn->dbhs);

	sa_info("gpgs=%u, ppgs=%u, emmax=%d, emmin=%d, emcur=%d, cached=%d\n",
				sn->gpages, sn->ppages, sn->emmax, sn->emmin,
				sn->emcur, sn->cachepages);

	sa_info("rblocks=%u, cblocks=%u, rcblocks=%u, rwcolls=%u\n",
				sn->rblocks, sn->cblocks, sn->rcblocks,
				sn->rwcolls);
}
#endif

SA_STATIC void fill_state(struct session_struct *session, struct snumbd_state *out)
{
	out->version =  (COMMON_VMAJOR << 16) + (COMMON_VMINOR << 8) +
							COMMON_VSUBMINOR;
	out->major = MAJOR(session->s_kdev);
	out->minor = MINOR(session->s_kdev);
	out->state = session->s_state;
	out->hpid = session->s_hpid;

	out->scount = session->s_bcount;
	out->mmapsize = SN_MMAP_SIZE;

	out->ioctlcnt = session->s_ioctlcnt;
	out->users = atomic_read(&session->s_users);
}

SA_STATIC void close_session(struct session_struct *session)
{
	shutdown_session(session);
	down(&session->s_sem);
	sa_debug(DEBUG_API, "s=%p, state=%d, users=%d\n", session,
				session->s_state, atomic_read(&session->s_users));

	if (session->s_mpages) {
		vfree(session->s_mpages);
		session->s_mpages = NULL;
	}
	up(&session->s_sem);
	put_session(session);
}

#ifndef HAVE_BDOPS_SUBMIT_BIO
SA_STATIC MAKE_REQUEST_RETURN_VALUE snumbd_make_request(struct request_queue *q, struct bio *bio)
#else
SA_STATIC MAKE_REQUEST_RETURN_VALUE snumbd_make_request(struct bio *bio)
#endif
{
	struct session_struct *session = NULL;
	dev_t dev;
	bool write;
	unsigned i;

	dev = sn_bio_dev(bio);

	if (bio->bi_vcnt > 1)
	{
		dump_bio(bio, "snumbd_make_request:");
	}

#ifdef HAVE_BLK_QUEUE_SPLIT
	if (sn_bio_bi_size(bio) > SN_MMAP_SIZE)
#ifdef HAVE_BDOPS_SUBMIT_BIO
		blk_queue_split(&bio);
#elif defined(HAVE_BLK_QUEUE_SPLIT_3ARGS)
		blk_queue_split(q, &bio, q->bio_split);
#else
		blk_queue_split(q, &bio);
#endif /* HAVE_BDOPS_SUBMIT_BIO */
#elif defined(HAVE_BIO_SPLIT_TO_LIMITS)
	if (sn_bio_bi_size(bio) > SN_MMAP_SIZE) {
		struct bio *split = bio_split_to_limits(bio);
		if (split)
			bio = split;
	}
#endif
	if (sn_bio_bi_size(bio) > SN_MMAP_SIZE) {
		sa_warn("Request size=0x%X exceeds limit=0x%X, bio=%p dev=%d:%d\n", sn_bio_bi_size(bio), SN_MMAP_SIZE, bio,
				MAJOR(dev), MINOR(dev));
		bio_io_error(bio);
		return MAKE_REQUEST_EXIT_STATUS;
	}

	spin_lock(&disk_lock);
#ifdef HAVE_BIO_BI_BDEV
	session = (struct session_struct *)(bio->bi_bdev->bd_disk->private_data);
#else
	session = (struct session_struct *)(bio->bi_disk->private_data);
#endif
	if (!session) {
		spin_unlock(&disk_lock);
		sa_warn("Can't find session, bio=%p dev=%d:%d.\n", bio,
				MAJOR(dev), MINOR(dev));
		bio_io_error(bio);
		return MAKE_REQUEST_EXIT_STATUS;
	}
	get_session(session);
	spin_unlock(&disk_lock);

	sa_debug(DEBUG_INTERNALS, "s=%p state=%d %s(%u) sector=%llu"
			" bi_size=%d \n", session, session->s_state,
			(sn_op_is_write(bio)) ? "WRITE" : "READ",
			get_bio_req_flags(bio),
			(unsigned long long)
			sn_bio_bi_sector(bio), sn_bio_bi_size(bio));

	write = sn_op_is_write(bio);
retry:
	if (!is_session_usable(session)) {
		sa_warn("Session is in unusable state=%u, s=%p dev=%d:%d.\n", session->s_state, session,
				MAJOR(dev), MINOR(dev));
		put_session(session);
		bio_io_error(bio);
		return MAKE_REQUEST_EXIT_STATUS;
	}
	down(&session->s_sem);
	if (!is_session_usable(session)) {
		up(&session->s_sem);
		goto retry;
	}
	if (session->bio_count >= MT_REQ_MAX) {
		up(&session->s_sem);
		wait_event(session->req_put_wq, !is_session_usable(session)|| session->bio_count < MT_REQ_MAX);
		goto retry;
	}
	for (i = 0; i < MT_REQ_MAX; ++i) {
		if (!session->bio[i])
			break;
	}
	session->bio[i] = bio;
	++session->bio_count;
	wake_up(&session->req_get_wq);
	up(&session->s_sem);
	put_session(session);
	return MAKE_REQUEST_EXIT_STATUS;
}

SA_STATIC int session_init(struct session_struct *session, unsigned long long size,
								int ro, unsigned int block_size)
{
	int ret;
	int minor;

	sa_debug(DEBUG_API, "len=%llu.\n", size);
	ret = -EINVAL;
	down(&session->s_sem);
	if (session->s_state != SNUM_NOTINITED)
		goto out;

	if (!sn_is_power_of_2(block_size) || block_size < 512 || block_size > PAGE_SIZE) {
		sa_warn("Block size is invalid: size=%d", block_size);
		goto out;
	}

	session->s_bcount = size;
	session->s_block_size = block_size;
	session->s_ro = ro;
	session->s_hpid = current->pid;

	session->s_apgrp[0] = sn_current_pgrp();
	session->s_apgrp[1] = sn_current_pgrp();

	ret = -ENOMEM;
	session->s_mpages = sn_vmalloc_pages(SN_MMPAGES, GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO);
	if (!session->s_mpages) {
		goto out;
	}

	spin_lock(&sessions_lock);
	minor = get_free_minor();
	ret = -ENODEV;
	if (minor > MAX_MINOR) {
		spin_unlock(&sessions_lock);
		goto out;
	}
	list_del_init(&session->s_list);
	session->s_kdev = MKDEV(*snumbd_major_p, minor);
	list_add_tail(&session->s_list, &sessions_list);
	spin_unlock(&sessions_lock);

	ret = register_device(session);
	if (ret) {
		spin_lock(&sessions_lock);
		list_del_init(&session->s_list);
		session->s_kdev = 0;
		list_add(&session->s_list, &notinited_list);
		spin_unlock(&sessions_lock);
		goto out;
	}

	sa_kdebug("OK. dev=%d:%d, len=%llu bs=%u s=%p pgrp=(%d).\n", MAJOR(session->s_kdev),
			  MINOR(session->s_kdev), session->s_bcount, session->s_block_size, session, session->s_apgrp[0]);
	sn_set_mb(session->s_state, SNUM_INITED);

out:
	up(&session->s_sem);
	return ret;
}

static noinline void sn_data_to_user(struct session_struct *session, struct bio *bio)
{
	unsigned len;
	struct bio_vec bv, *bvp = &bv;
	bvec_iterator_t iter;

	len = 0;
	bio_for_each_segment4(bv, bvp, bio, iter) {
		char *kaddr = NULL;
		int i, count, rest, m_off;

		i = len >> PAGE_SHIFT;
		m_off = len % PAGE_SIZE;
		rest = PAGE_SIZE - m_off;
		count = (rest < bvp->bv_len) ? rest : bvp->bv_len;

		kaddr = sn_kmap_atomic(bvp->bv_page);
		memcpy(session->s_mpages + (i << PAGE_SHIFT) + m_off,
			kaddr + bvp->bv_offset,	count);
		if (count < bvp->bv_len) {
			/* place rest on the next page */
			rest = bvp->bv_len - count;
			memcpy(session->s_mpages + ((i + 1) << PAGE_SHIFT),
				   kaddr + bvp->bv_offset + count, rest);
		}
		len += bvp->bv_len;
		sn_kunmap_atomic(kaddr);
	}
	if (len != sn_bio_bi_size(bio))
		sa_warn("Strange bio: s=%p dev=%d:%d, total(%u)!=size(%u)\n",
				session, MAJOR(session->s_kdev), MINOR(session->s_kdev), len, sn_bio_bi_size(bio));
}

static noinline void sn_data_from_user(struct session_struct *session, struct bio *bio)
{
	unsigned len;
	struct bio_vec bv, *bvp = &bv;
	bvec_iterator_t iter;

	len = 0;
	bio_for_each_segment4(bv, bvp, bio, iter) {
		char *kaddr = NULL;
		int i, count, rest, m_off;

		i = len >> PAGE_SHIFT;
		m_off = len % PAGE_SIZE;
		rest = PAGE_SIZE - m_off;
		count = (rest < bvp->bv_len) ? rest : bvp->bv_len;

		kaddr = sn_kmap_atomic(bvp->bv_page);
		memcpy(kaddr + bvp->bv_offset,
			session->s_mpages + (i << PAGE_SHIFT) + m_off, count);
		if (count < bvp->bv_len) {
			/* get rest from the next page */
			rest = bvp->bv_len - count;
			memcpy(kaddr + bvp->bv_offset + count,
				   session->s_mpages + ((i + 1) << PAGE_SHIFT), rest);
		}
		len += bvp->bv_len;
		sn_kunmap_atomic(kaddr);
	}
	if (len != sn_bio_bi_size(bio))
		sa_warn("Strange bio: s=%p dev=%d:%d, total(%u)!=size(%u)\n",
				session, MAJOR(session->s_kdev), MINOR(session->s_kdev), len, sn_bio_bi_size(bio));
}

SA_STATIC int session_req(struct session_struct *session, unsigned int size,
								void *req)
{
	int ret;
	struct snumbd_req kreq;
	struct bio *bio = NULL;
	int i;
	bool write;

retry:
	down(&session->s_sem);
	if (!is_session_usable(session)) {
		up(&session->s_sem);
		return -EIO;
	}
	if (session->tag_count >= session->bio_count) {
		up(&session->s_sem);
		ret = wait_event_interruptible(session->req_get_wq, !is_session_usable(session) || session->tag_count < session->bio_count);
		if (ret) {
			goto out;
		}
		goto retry;
	}
	for (i = 0; i < MT_REQ_MAX; ++i) {
		if (!session->tag[i] && session->bio[i])
			break;
	}
	BUG_ON(i >= MT_REQ_MAX);
	session->tag[i] = current->pid;
	++session->tag_count;
	bio = session->bio[i];

	write = sn_op_is_write(bio);

	kreq.cmd = (write) ? WRITE_DATA : READ_DATA;
	kreq.sno = sn_bio_bi_sector(bio);
	kreq.offset = 0;
	kreq.len = sn_bio_bi_size(bio);

	sa_debug(DEBUG_INTERNALS, "s=%p, dev=%d:%d, size=%u, cmd=%d, state=%d, "
				"users=%d.\n", session, MAJOR(session->s_kdev), MINOR(session->s_kdev), size, kreq.cmd,
				session->s_state, atomic_read(&session->s_users));
	if (write) {
		sn_data_to_user(session, bio);
	}
	if (size > sizeof(kreq))
		size = sizeof(kreq);
	ret = copy_to_user(req, &kreq, size);
	if (ret)
		ret = -EACCES;

	up(&session->s_sem);
out:
	return ret;
}

SA_STATIC int session_dataready(struct session_struct *session, unsigned int size,
							const void *req)
{
	int ret;
	struct snumbd_req kreq;
	struct bio *bio = NULL;
	pid_t tag;
	int i;
	bool write;
	if (size > sizeof(kreq))
		size = sizeof(kreq);
	ret = copy_from_user(&kreq, req, size);
	if (ret) {
		ret = -EACCES;
		shutdown_session(session);
		goto out;
	}
	sa_debug(DEBUG_INTERNALS, "s=%p dev=%d:%d, size=%u, cmd=%d, state=%d, "
				"users=%d.\n", session, MAJOR(session->s_kdev), MINOR(session->s_kdev), size, kreq.cmd,
				session->s_state, atomic_read(&session->s_users));
	if (kreq.cmd & ERROR_FLAG) {
		ret = -ENOSPC;
		shutdown_session(session);
		goto out;
	}
	ret = -EIO;
	down(&session->s_sem);
	if (!is_session_usable(session)) {
		goto unlock;
	}
	tag = current->pid;
	for (i = 0; i < MT_REQ_MAX; ++i) {
		if (session->tag[i] == tag) {
			break;
		}
	}
	if (i >= MT_REQ_MAX) {
		sa_warn("Can't find tag=%d, dev=%d:%d.\n", tag,
				MAJOR(session->s_kdev), MINOR(session->s_kdev));
		goto unlock;
	}
	bio = session->bio[i];
	session->bio[i] = NULL;
	session->tag[i] = 0;
	--session->tag_count;
	--session->bio_count;
	write = sn_op_is_write(bio);
	if (!write) {
		sn_data_from_user(session, bio);
	}
	sn_bio_endio(bio);
	wake_up(&session->req_get_wq);
	wake_up(&session->req_put_wq);
	ret = 0;
unlock:
	up(&session->s_sem);
out:
	return ret;
}

SA_STATIC int session_state(struct session_struct *session, int size, void *state)
{
	struct snumbd_state st = {0};
	int ret;

	fill_state(session, &st);
	spin_lock(&sessions_lock);
	st.sessions = sessions_count;
	spin_unlock(&sessions_lock);

	if (size > sizeof(st))
		size = sizeof(st);
	ret = copy_to_user(state, &st, size);
	if (ret)
		ret = -EACCES;

	return ret;
}

SA_STATIC int session_states(struct session_struct *session, int size, void *state)
{
	struct snumbd_state st;
	struct snumbd_state *out = state;
	struct list_head *tmp = NULL;
	int len = 0;
	int ret = -ENOSPC;

	sa_debug(DEBUG_API, "s=%p, size=%d, state=%p\n", session, size, state);
	spin_lock(&sessions_lock);
	list_for_each(tmp, &sessions_list) {
		struct session_struct *session;
		session = list_entry(tmp, struct session_struct, s_list);
		memset(&st, 0, sizeof(st));
		fill_state(session, &st);
		st.sessions = sessions_count;
		if (size - len < sizeof(st))
			goto err_unlock;
		sa_debug(DEBUG_INTERNALS, "out=%p, len=%d\n", out, len);
		ret = copy_to_user(out, &st, sizeof(st));
		if (ret) {
			ret = -EACCES;
			goto err_unlock;
		}
		len += sizeof(st);
		out++;
	}
	list_for_each(tmp, &notinited_list) {
		struct session_struct *session = NULL;
		session = list_entry(tmp, struct session_struct, s_list);
		memset(&st, 0, sizeof(st));
		fill_state(session, &st);
		st.sessions = sessions_count;
		if (size - len < sizeof(st))
			goto err_unlock;
		sa_debug(DEBUG_INTERNALS, "out=%p, len=%d\n", out, len);
		ret = copy_to_user(out, &st, sizeof(st));
		if (ret) {
			ret = -EACCES;
			goto err_unlock;
		}
		len += sizeof(st);
		out++;
	}
	ret = 0;

err_unlock:
	spin_unlock(&sessions_lock);
	return ret;
}

SA_STATIC int session_allowed_pgrp(struct session_struct *session, pid_t pgrp)
{
	if (pgrp <= 0)
		return -EINVAL;
	session->s_apgrp[1] = session->s_apgrp[0];
    session->s_apgrp[0] = pgrp;
	return 0;
}

long snumbdctl3_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;
	struct session_struct *session = file->private_data;

	if (!session)
		return -EINVAL;
	err = -EFAULT;

	spin_lock(&session->s_misc_lock);
	session->s_ioctlcnt++;
	spin_unlock(&session->s_misc_lock);

	switch(cmd) {
	    case SNUMBDCTL_INIT: {
			struct snumbdctl_init s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_init(session, s.scount, s.dev_ro, SECTOR_SIZE);
		}
		break;
		case SNUMBDCTL_INIT_V2: {
			struct snumbdctl_init_v2 s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_init(session, s.scount, s.dev_ro, s.sector_size);
		}
		break;
	    case SNUMBDCTL_REQ: {
			struct snumbdctl_req s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_req(session, s.size, s.req);
		}
		break;
	    case SNUMBDCTL_DATAREADY: {
			struct snumbdctl_dataready s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_dataready(session, s.size, s.req);
		}
		break;
	    case SNUMBDCTL_STATE: {
			struct snumbdctl_state s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_state(session, s.size, s.state);
		}
		break;
	    case SNUMBDCTL_STATES: {
			struct snumbdctl_states s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_states(session, s.size, s.state);
		}
		break;
		case SNUMBDCTL_PGRP: {
			struct snumbdctl_pgrp s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_allowed_pgrp(session, s.allowed_pgrp);
		}
		break;
	    default:
		err = -ENOTTY;
		break;
	}
	sa_debug(DEBUG_API, "err=%d\n", -err);
	return err;
}

#ifndef HAVE_UNLOCKED_IOCTL
int snumbdctl4_ioctl(struct inode *ino, struct file *file, unsigned int cmd,
		unsigned long arg)
{
	return snumbdctl3_ioctl(file, cmd, arg);
}
#endif

#ifdef HAVE_IOCTL32_CONVERSION
SA_STATIC int snumbdctl_compat_ioctl(unsigned int fd, unsigned int cmd,
			unsigned long arg, struct file *filep)
{
	return snumbdctl3_ioctl(filep, cmd, arg);
}
#endif

#ifdef HAVE_COMPAT_IOCTL
long snumbdctl_compat_ioctl(struct file *filep, unsigned int cmd,
			unsigned long arg)
{
	return snumbdctl3_ioctl(filep, cmd, arg);
}
#endif

int snumbdctl_open(struct inode *ino, struct file *file)
{
	struct session_struct *session = NULL;

	sa_debug(DEBUG_API,"%s\n","enter");
	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session)
		return -ENOMEM;
	INIT_LIST_HEAD(&session->s_list);
	sema_init(&session->s_sem, 1);
	spin_lock_init(&session->s_misc_lock);
	atomic_set(&session->s_users, 1);
	init_waitqueue_head(&session->req_put_wq);
	init_waitqueue_head(&session->req_get_wq);

	spin_lock(&sessions_lock);
	list_add(&session->s_list, &notinited_list);
	sessions_count++;
	spin_unlock(&sessions_lock);

	file->private_data = session;
	sa_kdebug("%s s=%p\n", "OK", session);
	return 0;
}

int snumbdctl_release(struct inode *ino, struct file *file)
{
	struct session_struct *session = file->private_data;

	if (!session)
		return -EINVAL;
	file->private_data = NULL;
	sa_debug(DEBUG_API,"%s\n","enter");

	close_session(session);
	sa_kdebug("%s s=%p\n", "OK", session);
	return 0;
}

SA_STATIC struct page * snumbdctl_vm_nopage(struct vm_area_struct * vma,
					unsigned long address, int *unused)
{
	unsigned int i;
	struct session_struct *session = NULL;
	struct page *page = NULL;

	if (!vma->vm_file) {
		sa_warn("vma does not have a file attached.%s", "\n");
		return (struct page *)VM_FAULT_ERROR;
	}
	session = vma->vm_file->private_data;
	if (address - vma->vm_start >= SN_MMAP_SIZE) {
		sa_warn("Incorrect address.%s", "\n");
		return (struct page *)VM_FAULT_ERROR;
	}
	i = (address - vma->vm_start) >> PAGE_SHIFT;
	page = vmalloc_to_page(session->s_mpages + (i << PAGE_SHIFT));
	get_page(page);

	sa_debug(DEBUG_ALLOC, "s=%p, nopage=%p(%d)\n", session, page,
					page_count(page));

	return page;
}

SA_STATIC VMFAULT_RETURN_VALUE snumbdctl_vm_fault(struct vm_area_struct * vma,
					struct vm_fault *vmf)
{
#ifdef HAVE_VMFAULT_VIRTUAL_ADDRESS
	unsigned long address = (unsigned long) vmf->virtual_address;
#else
	unsigned long address = (unsigned long) vmf->address;
#endif
#ifdef HAVE_VM_FAULT_2ARGS
	vmf->page = snumbdctl_vm_nopage(vma, address, 0);
#else
	vmf->page = snumbdctl_vm_nopage(vmf->vma, address, 0);
#endif
	if (vmf->page == (struct page *)VM_FAULT_ERROR)
		return VM_FAULT_ERROR;
	return 0;
}

SA_STATIC void snumbdctl_vm_close(struct vm_area_struct * vma)
{
	struct session_struct *session = NULL;

	if (!vma->vm_file) {
		sa_warn("vma does not have a file attached.%s", "\n");
		return;
	}
	session = vma->vm_file->private_data;
	session->s_vma = NULL;
}

static const struct vm_operations_struct snumbdctl_vm_ops = {
	fault:	snumbdctl_vm_fault,
	close:	snumbdctl_vm_close,
};

int snumbdctl_mmap(struct file * file, struct vm_area_struct * vma)
{
	struct session_struct *session = file->private_data;
	int ret;
	unsigned long pg_off;

	sa_debug(DEBUG_API,"s=%p, vma=%p,%lx-%lx %lx %lx\n", session, vma,
						vma->vm_start, vma->vm_end,
						vma->vm_flags, vma->vm_pgoff);
	if (!session)
		return -EBADF;
	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	ret = -EINVAL;
	down(&session->s_sem);
	pg_off = SN_MMPAGES * (MINOR(session->s_kdev) - 1);
	if (session->s_vma || session->s_state < SNUM_INITED || vma->vm_pgoff != pg_off)
		goto out_up;

	ret = -ENOMEM;
	if (vma->vm_end - vma->vm_start != SN_MMAP_SIZE)
		goto out_up;

	ret = 0;
	session->s_vma = vma;
	vma->vm_ops = &snumbdctl_vm_ops;

out_up:
	up(&session->s_sem);
	return ret;
}

ssize_t
snumbdctl_read(struct file * filp, char * buf, size_t count, loff_t *ppos)
{
	struct session_struct *session = filp->private_data;
	ssize_t ret;

	if (count != sizeof(struct snumbd_req))
		return -EINVAL;
	if (!session)
		return -EBADF;
	sa_debug(DEBUG_INTERNALS,"s=%p, buf=%p, count=%zu, ppos=%lld, state=%d\n",
			session, buf, count, *ppos, session->s_state);
	ret = session_req(session, count, buf);
	if (!ret)
		ret = count;
	return ret;
}

ssize_t
snumbdctl_write(struct file *filp, const char *buf, size_t count, loff_t *ppos)
{
	struct session_struct *session = filp->private_data;
	ssize_t ret;

	if (!session)
		return -EBADF;
	sa_debug(DEBUG_INTERNALS,"s=%p, buf=%p, count=%zu, ppos=%lld, state=%d\n",
		session, buf, count, *ppos, session->s_state);
	ret = session_dataready(session, count, buf);
	if (!ret)
		ret = count;
	return ret;
}

unsigned int snumbdctl_poll(struct file *filp, poll_table *wait)
{
	struct session_struct *session = filp->private_data;
	unsigned int mask;

	sa_debug(DEBUG_INTERNALS, "s=%p\n", session);
	if (!session || IS_ERROR_STATE(session->s_state))
		return POLLERR;
	poll_wait(filp, &session->req_get_wq, wait);
	down(&session->s_sem);
	mask = 0;
	if (!is_session_usable(session)) {
		mask |= POLLERR;
	}
	if (session->tag_count < session->bio_count) {
		mask |= POLLIN | POLLRDNORM;
	}
	up(&session->s_sem);
	return mask;
}

void register_ioctl32(void)
{
#ifdef HAVE_IOCTL32_CONVERSION
	register_ioctl32_conversion(SNUMBDCTL_INIT, snumbdctl_compat_ioctl);
	register_ioctl32_conversion(SNUMBDCTL_INIT_V2, snumbdctl_compat_ioctl);
	register_ioctl32_conversion(SNUMBDCTL_STOP, snumbdctl_compat_ioctl);
	register_ioctl32_conversion(SNUMBDCTL_REQ, snumbdctl_compat_ioctl);
	register_ioctl32_conversion(SNUMBDCTL_DATAREADY, snumbdctl_compat_ioctl);
	register_ioctl32_conversion(SNUMBDCTL_STATE, snumbdctl_compat_ioctl);
	register_ioctl32_conversion(SNUMBDCTL_STATES, snumbdctl_compat_ioctl);
#endif
}

void unregister_ioctl32(void)
{
#ifdef HAVE_IOCTL32_CONVERSION
	unregister_ioctl32_conversion(SNUMBDCTL_INIT);
	unregister_ioctl32_conversion(SNUMBDCTL_INIT_V2);
	unregister_ioctl32_conversion(SNUMBDCTL_STOP);
	unregister_ioctl32_conversion(SNUMBDCTL_REQ);
	unregister_ioctl32_conversion(SNUMBDCTL_DATAREADY);
	unregister_ioctl32_conversion(SNUMBDCTL_STATE);
	unregister_ioctl32_conversion(SNUMBDCTL_STATES);
#endif
}

