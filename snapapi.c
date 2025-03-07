/* snapapi.c
   Copyright (C) Acronis, 2004
   Copyright (c) CyberProtect
*/

#include "snconfig.h"
#include "snapapi.h"
#include "debug.h"

#ifdef HAVE_BDOPS_SUBMIT_BIO
#include "kernel_config.h"
#endif

int snap_prealloc_force;
int snap_emergency_size;

static wait_queue_head_t select_wait;
static int messages_pos;

#define MESSAGE_SIZE (sizeof(struct snap_message))
#define MAX_MESSAGES (PAGE_SIZE / MESSAGE_SIZE)

static struct snap_message *messages_buf;
static struct semaphore messages_sem = __SEMAPHORE_INITIALIZER(messages_sem, 1);

static struct task_struct *resolver_thread;
static int resolver_thread_continue = 1;
static atomic_t slab_uid = ATOMIC_INIT(0);
static DECLARE_COMPLETION(resolver_thread_exited);

static LIST_HEAD(sessions_list);
static LIST_HEAD(notinited_list);

#ifdef HAVE_SPIN_LOCK_UNLOCKED
/* sessions_list, noninit_sessions_list and pid_info_p protection */
static spinlock_t sessions_lock = SPIN_LOCK_UNLOCKED;
#else
static DEFINE_SPINLOCK(sessions_lock);
#endif

#define REFS_PER_PAGE	(PAGE_SIZE / (sizeof(void *)))
#define REFS_PER_PAGE_MASK (~(REFS_PER_PAGE - 1))
#if BITS_PER_LONG == 32
#	define REFS_PER_PAGE_SHIFT (PAGE_SHIFT - 2)
#elif BITS_PER_LONG == 64
#	define REFS_PER_PAGE_SHIFT (PAGE_SHIFT - 3)
#else
#	error Unsupported architecture detected
#endif

#define MAX_BHPAGES	REFS_PER_PAGE
#define MAX_BH_DELAYED	(REFS_PER_PAGE * MAX_BHPAGES)

#ifndef HAVE_VM_FAULT_2ARGS
#	define snapapi_vm_fault(a, b) snapapi_vm_fault(b)
#endif

struct block_map {
	unsigned long long	size; /* size in bits of allocated memory */
	unsigned long long	rsize; /* size in bits of real data */
	struct page **		blkmap;
};

#ifdef __GFP_HIGHIO
#	define GFP_SNAPHIGH	(__GFP_IO | __GFP_HIGHIO | __GFP_FS | __GFP_HIGHMEM)
#else
#	define GFP_SNAPHIGH	(__GFP_IO | __GFP_FS | __GFP_HIGHMEM)
#endif
struct sa_page {
	struct sa_page *	next;
	char *				page;
	unsigned long long	bno;
};

struct sa_chain {
	struct sa_page *	busy;
	struct sa_page *	free;
	spinlock_t		lock;
#define FAKE_READ	1
#define READ_KERNEL1	2
#define READ_KERNEL2	3
};

#define MAX_MMPAGES BIO_MAX_PAGES
#define MAX_RDPAGES BIO_MAX_PAGES /* reading by 1MiB */
#define MEM_ALLOC_TM 5	/* memory allocation timeout ms */
#define TIMER_INTERVAL (5*HZ)
#define IOCTL_SIM_INTERVAL (1*HZ) /* ioctl simulate interval */

struct bio_req {
	struct bio *bio;
	struct completion event;
};

struct pending_request;
struct pending_queue {
	spinlock_t		pq_lock;
	struct pending_request	*pq_req;	/* pending request list head */
	struct pending_request	*pq_reqtail;	/* pending request list tail */
	int			pq_state;
	struct completion	pq_done;
	struct completion	pq_bio_done;	/* end_io signal */
	atomic_t		pq_ready_req;	/* number of ready requests */
	atomic_t		pq_notready_req;
};

enum  pending_queue_states {
	PQ_STOPPED,	/* Where is no any unhandled pending requests */
	PQ_RUNNING,	/* New requests may be pushed to queue */
	PQ_CLOSED,	/* New requests can't be pushed to queue, but old
			 * requests may stil unfinished */
};
struct pending_read_request {
	/*
	 * While rbio handling it may be remapped, this result in loosing
	 * information about initial request so we have to explicytly
	 * save rbio block number.
	 */
	unsigned long long	rblkno;	/* first rbio block */
	struct bio		*rbio;	/* bio to read */
};

struct pending_request {
	struct pending_request 	*pr_next;	/* pendnig requests list */
	struct bio		*pr_wbio;	/* original delayed bio */
	struct pending_queue	*pr_queue;	/* session delayed queue */
	int			pr_count;	/* read bios requests count */
	int			pr_ready;	/* ready count */
	struct pending_read_request	pr_bios[1]; /* bios to read */
};

struct level_entry {
	unsigned long long max_key;
	struct page* page;
};

struct stack_entry {
	struct page* page;
	struct level_entry* entry;
	unsigned long long max_key;
};

struct group_map {
	unsigned level;
	struct page* root;
	unsigned long long max_key;
	struct stack_entry stack[8];
};

struct sn_pid_info {
	pid_t sn_pid; 		/* pid */
	atomic_t sn_refs; 	/* reference count */
	atomic_t sn_ioctls;	/* ioctls counter */
};

#define MAX_PID_INFO (PAGE_SIZE / sizeof(struct sn_pid_info))
/* pid_info_p entries are protected by sessions_lock */
static struct sn_pid_info* pid_info_p;

/* 64 pages - ~11000 chains, memory size 256 Kb */
#define BLK_CHAINS_PAGES 64

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
#define HAVE_FREEZE_BDEV_INT
#define freeze_bdev bdev_freeze
#define thaw_bdev bdev_thaw
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
#define SN_BDEV(a) file_bdev(a)
typedef struct file sn_bdev_open_t;
#else
#define SN_BDEV(a) ((a)->bdev)
typedef struct bdev_handle sn_bdev_open_t;
#endif
#else
#define SN_BDEV(a) (a)
typedef struct block_device sn_bdev_open_t;
#endif

struct session_struct {
	struct list_head	s_list;
	dev_t				s_kdev;
	sn_bdev_open_t	 	*	s_bdev;
	volatile unsigned int	s_state;
	unsigned int		s_bppage;	/* blocks per page */
	unsigned int		s_bsize;	/* block size */
	unsigned int		s_spb;		/* secs per block */
	unsigned int		s_spbshift;	/* secs per block shift */
	unsigned long long	s_plen;
	unsigned long long	s_pstart;
	struct super_block *	s_sb;

	unsigned long long	s_fblock;	/* EXTxx: first data block */
	unsigned long		s_gcount;	/* group count */
	unsigned int		s_bpgroup;	/* blocks per group */

	atomic_t		s_users;
	struct block_map	s_blkmap;
#ifdef CATCH_ILLEGAL_ACCESS
	struct block_map	s_blkmap_backup;
#endif
	struct group_map	s_groupmap;
	int			s_usemap;
	unsigned long long 	s_bmsize;

#ifdef USE_VZ_VZSNAP
	struct vzsnap_struct *	s_vzs;
#endif

	int 			s_mess_pos;	/* last read message */
	spinlock_t		s_misc_lock;	/* protects from here to */
						/* s_make_request_fn */
	int			s_ioctlcnt;	/* state data */
	int			s_ioctlcnt_prev;
	struct sn_pid_info *	s_pid_info;	/* pid owning the session */
	unsigned long		s_simulate_tm;	/* next time to simulate ioctl */
	int			s_heartbeat_active;
	struct timer_list 	s_timer;	/* heartbeat in frozen*/

#ifndef HAVE_BDOPS_SUBMIT_BIO
	make_request_fn *	s_make_request_fn; /* original fn from queue */
#else
	const struct block_device_operations *	old_fops;	/* original fops */
#endif
	int			s_queue_mq_based; /* 1 if queue is mq-based (requests should be dispatched via blk_mq_make_request)*/
	struct request_queue *	s_request_queue;

	spinlock_t		s_biolist_lock;
	struct bio ***		s_bioarr;
	int			s_biopages;
	int			s_biocount;

	struct vm_area_struct *	s_vma;
	atomic_t		s_vma_users;
	int			s_msize;	/* vm area pages */
	int			s_maxmsize;	/* max vm area pages */
	char *		s_mpages;	/* continuous mmapped pages */
	struct bio_req *	s_local_bios;	/* space exchange */
	unsigned long long	s_ahead_bno;	/* start ahead buffer */
	unsigned int		s_asize;

	struct semaphore        s_sem;		/* user space requests
						   serialization */
	struct pending_queue	s_pending_queue;/* pending request queue used
						   by async handler */

	struct kmem_cache *		s_blkcachep;
	char			s_blkcachename[64];
	int 			s_blkcache_pages;
	spinlock_t		s_blkcache_emlock;
	int	 		s_blkcache_empages;
	int	 		s_blkcache_emmax;
	int	 		s_blkcache_emmin;
	struct sa_page *	s_blk_emlist;
	int			s_veid;
	int			s_simulate_freeze;	/* disable freeze */
	int			s_ok_freeze;		/* ok freeze without active sb */
	int			s_anyblk_chain;		/* first chain to be searched by next any_block_in_cache() */

	spinlock_t		s_stat_lock;	/* protects from here to s_abios */
	const char*		pref_gpages;
	const char*		pref_ppages;
	unsigned long long	s_gpages;	/* got pages */
	unsigned long long	s_ppages;	/* put pages */
	unsigned long long	s_abios;	/* allocated bios */
	unsigned long long	s_fbios;	/* freed bhs */
	unsigned long long	s_dbios;	/* delayed bhs */
	unsigned long long	s_rblocks;	/* read blocks */
	unsigned long long	s_cblocks;	/* cached blocks */
	unsigned long long	s_rcblocks;	/* read from cache */
	unsigned long long	s_fcblocks;	/* freed cache  blocks */
	unsigned long long	s_mcblocks;	/* max blocks in cache */
	unsigned long long	s_rwcolls;	/* read/write collisions */
	unsigned long long	s_rc2blocks;	/* read to cache2 blocks */
	unsigned int s_sync_req;		/* sync requests  */
	unsigned int s_mipr;		/* max increase pending requests */
	unsigned int s_async_req;	/* async requests  */
	unsigned int s_iprcnt;		/* increase pending requests count */
	unsigned int s_async_retr;	/* async retries */
	unsigned int s_mbio;  		/* min bio size */
	unsigned long long s_rccalls;	/* total number of searches in blkcache (sa_cache_chain_read calls) */
	unsigned long long s_maxrcdepth;	/* length of the deepest search in single blkcache chain */
	unsigned long long s_rcdepthcnt[4];	/* total counts of blkcache searches with depth > SNAP_RCDEPTHi */

	struct page*		s_blkchains_pages[BLK_CHAINS_PAGES];
};

const int session_struct_size = sizeof(struct session_struct);

static SA_INLINE void sa_complete_and_exit(struct completion *comp, long exit_code)
{
#if defined(HAVE_KTHREAD_COMPLETE_AND_EXIT) && !defined(HAVE_COMPLETE_AND_EXIT)
	return kthread_complete_and_exit(comp, exit_code);
#else
	return complete_and_exit(comp, exit_code);
#endif
}

static SA_INLINE void inc_get_pages(struct session_struct *session)
{
	spin_lock(&session->s_stat_lock);
	session->s_gpages++;
	spin_unlock(&session->s_stat_lock);
}

static SA_INLINE unsigned long long read_get_pages(struct session_struct *session)
{
	unsigned long long ret;
	spin_lock(&session->s_stat_lock);
	ret = session->s_gpages;
	spin_unlock(&session->s_stat_lock);
	return ret;
}

static SA_INLINE void inc_put_pages(struct session_struct *session)
{
	spin_lock(&session->s_stat_lock);
	session->s_ppages++;
	spin_unlock(&session->s_stat_lock);
}

static SA_INLINE unsigned long long read_put_pages(struct session_struct *session)
{
	unsigned long long ret;
	spin_lock(&session->s_stat_lock);
	ret = session->s_ppages;
	spin_unlock(&session->s_stat_lock);
	return ret;
}

#define BLK_CHAINS_PER_PAGE (PAGE_SIZE / sizeof(struct sa_chain))
const int blk_chains = BLK_CHAINS_PAGES * BLK_CHAINS_PER_PAGE;

static SA_INLINE int sa_get_blk_chain_index(unsigned long long num)
{
	return do_div(num, (unsigned)blk_chains);
}

static SA_INLINE struct sa_chain* sa_get_blk_chain(struct session_struct *session, unsigned long long num)
{
	unsigned index;
	unsigned page_no;
	unsigned no_on_page;
	struct sa_chain *chain = NULL;

	index = sa_get_blk_chain_index(num);
	no_on_page = index % (unsigned)BLK_CHAINS_PER_PAGE;
	page_no = index / (unsigned)BLK_CHAINS_PER_PAGE;
	chain = (struct sa_chain*) page_address(session->s_blkchains_pages[page_no]);

	return &chain[no_on_page];
}

static noinline void sa_blkchains_destroy(struct session_struct *session)
{
	int i;

	for (i = 0; i < BLK_CHAINS_PAGES; i++) {
		struct page *page = NULL;
		page = session->s_blkchains_pages[i];
		if (page) {
			put_page(page);
			inc_put_pages(session);
			session->s_blkchains_pages[i] = NULL;
		}
	}
}

static noinline int sa_blkchains_init(struct session_struct *session)
{
	struct page *pg = NULL;
	int ret, i;

	ret = -ENOMEM;
	for (i = 0; i < BLK_CHAINS_PAGES; i++) {
		int j;
		struct sa_chain *chain = NULL;

		pg = alloc_page(GFP_KERNEL|__GFP_ZERO);
		if (unlikely(!pg)) {
			goto out;
		}

		inc_get_pages(session);
		chain = (struct sa_chain*) page_address(pg);

		for (j = 0; j < BLK_CHAINS_PER_PAGE; j++, chain++)
			spin_lock_init(&chain->lock);

		session->s_blkchains_pages[i] = pg;
	}

	ret = 0;

out:
	return ret;
}

#ifdef HAVE_QUEUE_LOCK_NPTR
#define snapapi_lock_dev_queue(q) spin_lock_irq(&q->queue_lock)
#define snapapi_unlock_dev_queue(q) spin_unlock_irq(&q->queue_lock)
#else
#define snapapi_lock_dev_queue(q) do { \
		if (q->queue_lock) \
			spin_lock_irq(q->queue_lock); \
	} while (0)
#define snapapi_unlock_dev_queue(q) do { \
		if (q->queue_lock) \
			spin_unlock_irq(q->queue_lock); \
		} while (0)
#endif

struct locked_dev {
	sn_bdev_open_t *d_bdev;
	dev_t dev;
	unsigned lock_type;
	struct session_struct *sess;
};

#define MAX_LOCKEDDEVS (PAGE_SIZE / sizeof(struct locked_dev))

static int lockedcnt; /* global lock/unlock devs */
static struct locked_dev * devlocked;

/* devlocked & lockedcnt protection */
static struct semaphore devlocked_sem = __SEMAPHORE_INITIALIZER(devlocked_sem, 1);

SA_STATIC void unregister_make_request(struct session_struct *session);
SA_STATIC void mpages_destroy(struct session_struct *session);
SA_STATIC void close_session(struct session_struct *session, int do_free);

#if 0
static void dump_sessions(void);
#endif

#ifdef HAVE_TRY_TO_FREEZE_NO_ARGS
#  define snapapi_try_to_freeze() try_to_freeze()
#elif defined(HAVE_TRY_TO_FREEZE_ONE_ARG)
#  define snapapi_try_to_freeze() try_to_freeze(PF_FREEZE)
#else
#  define snapapi_try_to_freeze()
#endif

SA_STATIC void sn_freeze_bdev(struct session_struct *session)
{
	if (!session->s_simulate_freeze) {
#ifdef HAVE_FREEZE_BDEV_INT
		int ret = 0;
		ret = freeze_bdev(SN_BDEV(session->s_bdev));
		if (ret) {
			sa_warn("freeze_super error");
			session->s_ok_freeze = 0;
		} else
			session->s_ok_freeze = 1;
#     if LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)
		session->s_sb = SN_BDEV(session->s_bdev)->bd_fsfreeze_sb;
#     else /* >= 6.8.0 */
        if (0 == ret && NULL != SN_BDEV(session->s_bdev)->bd_holder)
        {
            session->s_sb = (struct super_block*)SN_BDEV(session->s_bdev)->bd_holder;
		}
#     endif /* < 6.8.0 */

#else 
		session->s_sb = freeze_bdev(SN_BDEV(session->s_bdev));
#endif	/* HAVE_FREEZE_BDEV_INT */
	} else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0)
		fsync_bdev(SN_BDEV(session->s_bdev));
#else
		mutex_lock(&SN_BDEV(session->s_bdev)->bd_holder_lock);
		if (SN_BDEV(session->s_bdev)->bd_holder_ops && SN_BDEV(session->s_bdev)->bd_holder_ops->sync)
			SN_BDEV(session->s_bdev)->bd_holder_ops->sync(SN_BDEV(session->s_bdev));
		else
			sync_blockdev(SN_BDEV(session->s_bdev));
		mutex_unlock(&SN_BDEV(session->s_bdev)->bd_holder_lock);
#endif /* < 6.6.0 */
		session->s_sb = sn_get_super(SN_BDEV(session->s_bdev));
	}
}

SA_STATIC void sn_thaw_bdev(struct session_struct *session)
{
	if (!session->s_simulate_freeze) {
#ifdef HAVE_THAW_BDEV_2ARGS
		thaw_bdev(SN_BDEV(session->s_bdev), session->s_sb);
#else
		thaw_bdev(SN_BDEV(session->s_bdev));
#endif
	} else {
		if (session->s_sb)
			sn_drop_super(session->s_sb);
	}
	session->s_sb = NULL;
}

SA_STATIC MAKE_BLKDEV_RETURN_VALUE sn_blkdev_put(sn_bdev_open_t *_bdev, fmode_t mode, void *holder)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
	return bdev_fput(_bdev);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
	return bdev_release(_bdev);
#elif defined(HAVE_BLKDEV_PUT_2ARG_FLAG)
	return blkdev_put(_bdev, holder);
#elif defined(HAVE_BLKDEV_PUT_2ARGS)
	return blkdev_put(_bdev, mode);
#else
	return blkdev_put(_bdev);
#endif
}

SA_STATIC int sn_is_error_bio(struct bio *bio)
{
#ifdef HAVE_BIO_UPTODATE
	return !test_bit(BIO_UPTODATE, &bio->bi_flags);
#elif defined(HAVE_BIO_BI_ERROR)
	return bio->bi_error;
#else
	return bio->bi_status;
#endif
}

SA_STATIC void sn_submit_bio(int rw, struct bio *bio)
{
#ifdef HAVE_SUBMIT_BIO_ONEARG

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)
#  ifdef HAVE_BIO_SET_OP_ATTRS
	bio_set_op_attrs(bio, rw, 0);
#  else
	bio->bi_opf = rw; //  & REQ_OP_MASK;  // (8 bits)
#  endif
#else
    bio->bi_opf = rw; //  & REQ_OP_MASK;  // (8 bits)
#endif

	submit_bio(bio);
#else
	submit_bio(rw, bio);
#endif
}

#ifdef HAVE_BDOPS_SUBMIT_BIO
SA_STATIC struct request_queue* sn_bio_queue(struct bio *bio)
{
#ifndef HAVE_BIO_BI_BDEV
	return bio->bi_disk->queue;
#else
	return bio->bi_bdev->bd_disk->queue;
#endif
}
#endif

/*
 * Add request to back of pending list
 */
SA_STATIC void pqueue_add_request(struct pending_queue *pq, struct pending_request *preq)
{
	if (pq->pq_reqtail) {
		pq->pq_reqtail->pr_next = preq;
		pq->pq_reqtail = preq;
	} else {
		pq->pq_req = pq->pq_reqtail = preq;
	}
}

/*
 * Grab first pending request
 */
SA_STATIC struct pending_request *pqueue_get_request(struct pending_queue *pq)
{
	struct pending_request *preq = pq->pq_req;
	if (preq) {
		if (preq == pq->pq_reqtail)
			pq->pq_reqtail = NULL;
		pq->pq_req = preq->pr_next;
		preq->pr_next = NULL;
	}
	return preq;
}

static SA_INLINE int blkmap_release_pages(struct session_struct *session,
		struct page **page_ptr)
{
	unsigned int count;
	unsigned int i;

	for (i = 0, count = 0; i < REFS_PER_PAGE; i++, page_ptr++) {
		struct page *page = *page_ptr;

		if (unlikely(!page))
			continue;
		put_page(page);
		inc_put_pages(session);
		count++;
	}
	return count;
}

SA_STATIC void do_block_map_destroy(struct session_struct *session,
				struct block_map *bmap)
{
	unsigned long long bsize;
	unsigned int pages, mpages;
	struct page *page = NULL;
	unsigned int i;

	if (!bmap->blkmap)
		return;
	bsize = sn_div_round(bmap->size, 8);
	pages = sn_div_round(bsize, PAGE_SIZE);
	/* pages with pointers to pages */
	mpages = sn_div_round(pages, REFS_PER_PAGE);

	for (i = 0; i < mpages; i++) {
		page = bmap->blkmap[i];
		if (unlikely(!page))
			break;
		sa_debug(DEBUG_BMAP, "s=%p, mpage(%u,%p,%p)\n",
				session, i, page, page_address(page));
		blkmap_release_pages(session, page_address(page));
		put_page(page);
		inc_put_pages(session);
	}
	kfree(bmap->blkmap);
	bmap->blkmap = NULL;
	bmap->size = 0;
	bmap->rsize = 0;
}

static noinline void block_map_destroy(struct session_struct *session)
{
	do_block_map_destroy(session, &session->s_blkmap);
#ifdef CATCH_ILLEGAL_ACCESS
	do_block_map_destroy(session, &session->s_blkmap_backup);
#endif
}

static SA_INLINE unsigned int blkmap_high_pages(struct session_struct *session,
		struct page **page_ptr, unsigned n)
{
	struct page *p = NULL;
	unsigned int count;

	for (count = 0; count < n; page_ptr++, count++) {
		p = alloc_page(GFP_HIGHUSER);
		if (unlikely(!p))
			return count;

		inc_get_pages(session);
		*page_ptr = p;
	}
	return count;
}

SA_STATIC int blkmap_alloc_pages(struct session_struct *session, struct page **blkmap,
					unsigned pages)
{
	struct page *p = NULL;
	unsigned int i, count, hpages;

	for (i = 0; i < pages; i += REFS_PER_PAGE, blkmap++) {
		p = alloc_page(GFP_KERNEL|__GFP_ZERO);
		if (unlikely(!p))
			goto out_free;
		*blkmap = p;
		sa_debug(DEBUG_BMAP, "s=%p, mpage(%u,%p,%p)\n",
		session, i, p, page_address(p));
		inc_get_pages(session);
		hpages = (i + REFS_PER_PAGE < pages) ? REFS_PER_PAGE :
							pages - i;
		count = blkmap_high_pages(session, page_address(p), hpages);
		if (count != hpages)
			goto out_free;
	}
	return 0;

out_free:
	block_map_destroy(session);
	return -ENOMEM;
}

static SA_INLINE struct page * blkmap_page(struct page **blkmap,
				unsigned int pageno)
{
	struct page **mpage = NULL;

	mpage = page_address(blkmap[pageno >> REFS_PER_PAGE_SHIFT]);
	return mpage[pageno & (~REFS_PER_PAGE_MASK)];
}

SA_STATIC void blkmap_page_release(struct page **blkmap, unsigned int pageno)
{
	struct page **mpage = NULL;
	struct page *page = NULL;
	unsigned int idx;

	mpage = page_address(blkmap[pageno >> REFS_PER_PAGE_SHIFT]);
	idx = pageno & (~REFS_PER_PAGE_MASK);
	page = mpage[idx];
	mpage[idx] = 0;
	put_page(page);
}

static noinline int block_map_init(struct session_struct *session,
			unsigned long long size, char *data, int optimize)
{
	struct block_map *bmap = NULL;
	unsigned long long bsize;
	unsigned int count, pages, mpages, i;
	int ret = -ENOMEM, bexists = 0;
	struct page *tpage = NULL;
	void *tpageaddr = NULL;

	sa_debug(DEBUG_API, "s=%p, size=%llu, data=%p mode=%d\n", session, size,
						data, optimize);
	bsize = sn_div_round(size, 8);
	if (!bsize)
		return -EINVAL;

	pages = sn_div_round(bsize, PAGE_SIZE);
	mpages = sn_div_round(pages, REFS_PER_PAGE);

	bmap = &session->s_blkmap;
	if (bmap->size) {
		if (unlikely(bmap->size < size))
			return -EINVAL;
		bexists = 1;
		/* it may be we load data into larger bitmap,
		   rsize keeps real data size */
		bmap->rsize = size;
	}
	if (!bmap->blkmap) {
		size_t memsize;

		memsize = mpages * sizeof(struct page *);
		bmap->blkmap = kzalloc(memsize, GFP_KERNEL);
		if (unlikely(!bmap->blkmap))
			return ret;
		bmap->size = size;
		bmap->rsize = size;
	}
	if (data) {
		tpage = alloc_page(GFP_KERNEL);
		if (unlikely(!tpage)) {
			kfree(bmap->blkmap);
			bmap->blkmap = NULL;
			bmap->size = 0;
			bmap->rsize = 0;
			return ret;
		}
		tpageaddr = page_address(tpage);
		inc_get_pages(session);
	}
	sa_debug(DEBUG_BMAP, "size=%llu, blkmap=%p, pages=%u, mpages=%u\n",
			size, bmap->blkmap, pages, mpages);
	if (!bexists) {
		if (unlikely(blkmap_alloc_pages(session, bmap->blkmap, pages)))
			goto out_free;
	}
	count = PAGE_SIZE;
	for (i = 0; i < pages; i++, data += PAGE_SIZE) {
		char *kaddr = NULL;
		struct page *p = NULL;

		if (unlikely((i == pages - 1) && (bsize & (PAGE_SIZE - 1))))
			/* Don't touch count if bsize%PAGE_SIZE == 0 */
			count = bsize & (PAGE_SIZE - 1);

		if (tpageaddr) {
			ret = copy_from_user(tpageaddr, data, count);
			if (unlikely(ret)) {
				sa_warn("copy_from_user failed. data=%p, "
					"count=%d, bsize=%llu.\n", data, count,
					bsize);
				ret = -EACCES;
				goto out_free;
			}
			if (optimize) {
				int fbit;
				fbit = find_first_bit(tpageaddr, PAGE_SIZE << 3);
				if (unlikely(fbit == PAGE_SIZE << 3)) {
					blkmap_page_release(bmap->blkmap, i);
					inc_put_pages(session);
					sa_debug(DEBUG_BMAP, "empty %u\n", i);
				}
			}
		}
		p = blkmap_page(bmap->blkmap, i);
		if (p) {
			kaddr = sn_kmap_atomic(p);
			if (!tpageaddr)
				memset(kaddr, 0xff, count);
			else
				memcpy(kaddr, tpageaddr, count);
			sn_kunmap_atomic(kaddr);
		}
	}

	if (tpage) {
		put_page(tpage);
		inc_put_pages(session);
	}
	return 0;

out_free:
	block_map_destroy(session);
	if (tpage) {
		put_page(tpage);
		inc_put_pages(session);
	}
	return ret;
}

#ifdef USE_VZ_VZSNAP
static noinline int block_map_init_vzsnap(struct session_struct *session,
					  struct vzsnap_struct *vzs)
{
	struct block_map *bmap = &session->s_blkmap;
	unsigned long long size = vzs->block_max;
	unsigned long long bsize;
	unsigned int pages;
	int i, ret = -ENOMEM;

	bsize = (size + 7) / 8;

	memset(bmap, 0, sizeof(*bmap));
	pages = (bsize + PAGE_SIZE - 1) >> PAGE_SHIFT;
	bmap->blkmap = kzalloc(pages * sizeof(struct page *), GFP_KERNEL);
	if (!bmap->blkmap)
		return ret;
	bmap->size = size;
	bmap->rsize = size;
#ifdef CATCH_ILLEGAL_ACCESS
	session->s_blkmap_backup.blkmap = kzalloc(pages * sizeof(struct page *), GFP_KERNEL);
	if (!session->s_blkmap_backup.blkmap)
		return ret;
	session->s_blkmap_backup.size = size;
	session->s_blkmap_backup.rsize = size;
#endif
	for (i = 0; i < pages; i++) {
		if (!vzs->block_map[i])
			continue;
		struct page **mpage = NULL;
		struct page **pg = bmap->blkmap + (i >> REFS_PER_PAGE_SHIFT);
		if (!*pg) {
			*pg = alloc_page(GFP_KERNEL|__GFP_ZERO);
			if (!*pg)
				return -ENOMEM;
			}

		get_page(vzs->block_map[i]);
		mpage = page_address(*pg);
		mpage[i & (~REFS_PER_PAGE_MASK)] = vzs->block_map[i];
#ifdef CATCH_ILLEGAL_ACCESS
		pg = bmap->blkmap_backup.blkmap + (i >> REFS_PER_PAGE_SHIFT);
		if (!*pg) {
			*pg = alloc_page(GFP_KERNEL|GFP_ZERO);
			if (!*pg)
				return -ENOMEM;
		}
		mpage = page_address(*pg);
		mpage[i & (~REFS_PER_PAGE_MASK)] = alloc_page(GFP_KERNEL);
		memcpy(page_address(mpage[i & (~REFS_PER_PAGE_MASK)]),
		       page_address(bmap->blkmap[i]), PAGE_SIZE);
#endif
	}
	return 0;
}
#endif

static SA_INLINE int is_block_in_map(struct block_map *bmap,
					unsigned long long bno)
{
	unsigned int pageno;
	struct page *page = NULL;
	long *kaddr = NULL;
	int ret;

	if (bno >= bmap->rsize)
		return 0;

	pageno = bno >> (PAGE_SHIFT + 3);
	page = blkmap_page(bmap->blkmap, pageno);
	if (!page)
		return 0;
	kaddr = sn_kmap_atomic(page);
	ret = test_bit(bno % (PAGE_SIZE * 8), kaddr);
	sn_kunmap_atomic(kaddr);

	return ret;
}

static SA_INLINE int clear_block_in_map(struct block_map *bmap,
					unsigned long long bno)
{
	unsigned int pageno;
	struct page *page = NULL;
	long *kaddr = NULL;
	int ret;

	if (bno >= bmap->rsize)
		return 1;

	pageno = bno >> (PAGE_SHIFT + 3);
	page = blkmap_page(bmap->blkmap, pageno);
	if (!page)
		return 1;
	kaddr = sn_kmap_atomic(page);
	ret = test_and_clear_bit(bno % (PAGE_SIZE * 8), kaddr);
	sn_kunmap_atomic(kaddr);
	return ret;
}

/*
static SA_INLINE void set_block_in_map(struct block_map *bmap,
					unsigned long long bno)
{
	unsigned int pageno;
	struct page *page = NULL;
	long *kaddr = NULL;

	if (bno >= bmap->rsize)
		return;

	pageno = bno >> (PAGE_SHIFT + 3);
	page = blkmap_page(bmap->blkmap, pageno);
	if (!page)
		return;
	kaddr = sn_kmap_atomic(page);
	set_bit(bno % (PAGE_SIZE * 8), kaddr);
	sn_kunmap_atomic(kaddr);
}
*/

#define BITS_ON_PAGE (1 << (PAGE_SHIFT+3))

SA_STATIC unsigned long long find_next_block(struct block_map *bmap, unsigned long long bno)
{
	unsigned int lpage; /* last pageno */
	unsigned int pageno;
	unsigned int psize; /* processing page size */

	if (bno >= bmap->rsize)
		return ~0ULL; /* goto out_end; */

	psize = BITS_ON_PAGE;
	lpage = (bmap->size - 1) >> (PAGE_SHIFT + 3);
	pageno = bno >> (PAGE_SHIFT + 3);
	bno &= BITS_ON_PAGE - 1;

	for (; pageno <= lpage; pageno++) {
		void *kaddr = NULL;
		struct page *page = NULL;

		if (pageno == lpage) {
			psize = bmap->size & ((PAGE_SIZE << 3) - 1);
			if (!psize)
				psize = BITS_ON_PAGE;
		}
		page = blkmap_page(bmap->blkmap, pageno);
		if (!page)
			continue;

		kaddr = sn_kmap_atomic(page);
		bno = find_next_bit(kaddr, psize, bno);
		sn_kunmap_atomic(kaddr);
		if (bno < psize) {
			bno += (unsigned long long)pageno << (PAGE_SHIFT + 3);
			goto out;
		}
		bno = 0;
	}

	bno = ~0ULL;
out:
	return bno;
}

#define snapapi_is_not_our_bio(session, bio) \
		(sn_bio_bi_sector(bio) + (sn_bio_bi_size(bio) >> SECTOR_SHIFT) < session->s_pstart || \
		sn_bio_bi_sector(bio) >= session->s_pstart + session->s_plen)
#if 0
SA_STATIC struct session_struct *find_by_part(struct bio *bio)
{
	struct session_struct *session = NULL;
	list_for_each_entry(session, &sessions_list, s_list) {
		if (session->s_state == SNAP_NOTINITED)
			continue;
		if ((SN_BDEV(session->s_bdev)->bd_contains == bio->bi_bdev ||
				SN_BDEV(session->s_bdev) == bio->bi_bdev)
				&& !snapapi_is_not_our_bio(session, bio))
			return session;
	}
	return NULL;
}

static SA_INLINE struct session_struct *find_by_dev(struct block_device *bd)
{
	struct session_struct *session = NULL;
	list_for_each_entry(session, &sessions_list, s_list)
		if (SN_BDEV(session->s_bdev) && (SN_BDEV(session->s_bdev)->bd_contains == bd
						|| SN_BDEV(session->s_bdev) == bd))
			return session;
	return NULL;
}
#endif

#ifdef HAVE_BDOPS_SUBMIT_BIO
static SA_INLINE struct session_struct *find_by_fops(const struct block_device_operations *fops)
{
	struct session_struct *session = NULL;
	list_for_each_entry(session, &sessions_list, s_list)
		if (session->s_request_queue && SN_BDEV(session->s_bdev) && (SN_BDEV(session->s_bdev)->bd_disk->fops == fops))
			return session;
	return NULL;
}

static SA_INLINE struct session_struct *find_by_fops_next(const struct block_device_operations *fops, struct session_struct *session)
{
	list_for_each_entry_continue(session, &sessions_list, s_list)
		if (session->s_request_queue && SN_BDEV(session->s_bdev) && (SN_BDEV(session->s_bdev)->bd_disk->fops == fops)) {
			return session;
		}
	return NULL;
}
#else
static SA_INLINE struct session_struct *find_by_queue(struct bio *bio, void *q)
{
	struct session_struct *session = NULL;
	list_for_each_entry(session, &sessions_list, s_list)
		if (session->s_request_queue == q)
			return session;
	return NULL;
}

static SA_INLINE struct session_struct *find_by_queue_next(struct bio *bio,
			void *q, struct session_struct *session)
{
	list_for_each_entry_continue(session, &sessions_list, s_list)
		if (session->s_request_queue == q)
			return session;
	return NULL;
}
#endif /* HAVE_BDOPS_SUBMIT_BIO */

static SA_INLINE struct session_struct *find_deadlocked(void)
{
	struct list_head *tmp = NULL;
	list_for_each(tmp, &sessions_list) {
		struct session_struct *session = NULL;
		session = list_entry(tmp, struct session_struct, s_list);
		sa_info("dev=%x state=%d\n", session->s_kdev, session->s_state);
		if (session->s_state == SNAP_DEADLOCK_ERR)
			return session;
	}
	return NULL;
}

#if 0
SA_STATIC int make_original_request(struct bio *bio)
{
	struct request_queue *q = NULL;
	do {
		q = bdev_get_queue(bio->bi_bdev);
		if (!q) {
			/*
			 * This is very sad situation. Bio can't be
			 * handled properly, but we have call end_io
			 * because nobody will do it for us.
			 */
			sa_error("Device %x does not have a queue.\n",
				bio->bi_bdev->bd_dev);
			bio_io_error(bio, sn_bio_bi_size(bio));
			return 1;
		}
	} while (q->make_request_fn(q, bio));
	return 0;
}
#endif

/* must be called with s_biolist_lock held*/
static noinline void flush_biolist_locked(struct session_struct *session)
{
	int pno, offset;
	struct bio *bio = NULL;

	if (!session->s_bioarr)
		return;

	while (session->s_biocount) {
		session->s_biocount--;
		pno = session->s_biocount / REFS_PER_PAGE;
		offset = session->s_biocount % REFS_PER_PAGE;
		bio = *(session->s_bioarr[pno] + offset);
		spin_unlock(&session->s_biolist_lock);
		sn_make_request(bio);
		spin_lock(&session->s_biolist_lock);
		sa_debug(DEBUG_BIO, "request sent, bh=%p\n", bio);
	}
	while (session->s_biopages) {
		pno = session->s_biopages - 1;
		free_page((unsigned long)session->s_bioarr[pno]);
		inc_put_pages(session);
		session->s_bioarr[pno] = NULL;
		session->s_biopages--;
	}
}

static noinline void flush_biolist(struct session_struct *session)
{
	spin_lock(&session->s_biolist_lock);
	flush_biolist_locked(session);
	spin_unlock(&session->s_biolist_lock);
}

static noinline void cleanup_biolist(struct session_struct *session)
{
	spin_lock(&session->s_biolist_lock);
	if (session->s_bioarr) {
		flush_biolist_locked(session);
		sa_debug(DEBUG_BIOQUE, "Free bioarr page=%p\n", session->s_bioarr);
		free_page((unsigned long)session->s_bioarr);
		inc_put_pages(session);
		session->s_bioarr = NULL;
	}
	spin_unlock(&session->s_biolist_lock);
}

static noinline int delay_bio(struct session_struct *session, struct bio *bio)
{
	int pno, idx;
	struct bio **bioptr = NULL;

	sa_debug(DEBUG_BIO, "delayed bio=%p\n", bio);

	spin_lock(&session->s_biolist_lock);
	if (session->s_biocount > MAX_BH_DELAYED - 1) {
		spin_unlock(&session->s_biolist_lock);
		sa_warn("No space for bio, count=%d.\n", session->s_biocount);
		return 1;
	}
	pno = session->s_biocount / REFS_PER_PAGE;
	idx = session->s_biocount % REFS_PER_PAGE;
	if (!session->s_bioarr[pno]) {
		session->s_bioarr[pno] = (struct bio **) get_zeroed_page(GFP_ATOMIC);
		if (!session->s_bioarr[pno]) {
			spin_unlock(&session->s_biolist_lock);
			sa_warn("No memory for bio queue, count=%d.\n",
							session->s_biocount);
			return 1;
		}
		inc_get_pages(session);
		session->s_biopages++;
	}
	bioptr = session->s_bioarr[pno];
	*(bioptr + idx) = bio;
	session->s_biocount++;
	session->s_dbios++;
	spin_unlock(&session->s_biolist_lock);

	return 0;
}
SA_STATIC void cleanup_chain(struct session_struct *session,
		struct sa_chain *chain, struct sa_page *sab)
{
	struct sa_page *next = NULL;

	while (sab) {
		next = sab->next;
		session->s_blkcache_pages--;
		vfree(sab->page);
		inc_put_pages(session);
		kmem_cache_free(session->s_blkcachep, sab);
		sab = next;
	}
}

static noinline void cleanup_snapshot(struct session_struct *session)
{
	struct sa_chain *chain = NULL;
	int i;

	if (!session->s_blkcachep)
		return;

	for (i = 0; i < blk_chains; i++) {
		chain = sa_get_blk_chain(session, i);
		cleanup_chain(session, chain, chain->busy);
		cleanup_chain(session, chain, chain->free);
	}

	kmem_cache_destroy(session->s_blkcachep);
	session->s_blkcachep = NULL;
}

static SA_INLINE void insert_into_free_list(struct sa_chain *chain,
			struct sa_page *sab)
{
	sab->next = chain->free;
	chain->free = sab;
}

static SA_INLINE void insert_into_busy_list(struct sa_chain *chain,
			struct sa_page *sab)
{
	sab->next = chain->busy;
	chain->busy = sab;
}

static SA_INLINE void remove_from_free_list(struct sa_chain *chain,
			struct sa_page *sab)
{
	chain->free = sab->next;
}

/*
static SA_INLINE void remove_from_busy_list(struct sa_chain *chain,
			struct sa_page *sab)
{
	chain->busy = sab->next;
}
*/

static SA_INLINE int find_free_on_page(struct sa_page *sab, int bppage,
							unsigned long long bno)
{
	int i;
	unsigned long long *bno_p = &sab->bno;

	for (i = 0; i < bppage; i++, bno_p++)
		if (*bno_p == ~0ULL) {
			/* mark as busy */
			*bno_p = bno;
			return i;
		}
	sa_BUG("Busy page in free list(%p).\n", sab);
	return 0;
}

static SA_INLINE int blocks_on_page(struct sa_page *sab, int bppage)
{
	int i, count;
	unsigned long long *bno_p = &sab->bno;

	for (i = 0, count = 0; i < bppage; i++, bno_p++)
		if (*bno_p != ~0ULL)
			count++;
	return count;
}

static SA_INLINE int find_block_on_page(struct sa_page *sab, int bppage,
							unsigned long long bno)
{
	int i;
	unsigned long long *bno_p = &sab->bno;

	for (i = 0; i < bppage; i++, bno_p++)
		if (*bno_p == bno)
			return i;
	return i;
}

static SA_INLINE void free_block_on_page(struct sa_page *sab, int idx)
{
	unsigned long long *bno_p = &sab->bno;

	/* mark as free */
	*(bno_p + idx) = ~0ULL;
}

SA_STATIC struct sa_page * find_block_in_chain(struct sa_page *sab, int bppage,
			unsigned long long bno, int *idx, struct sa_page **prev, unsigned long long* sdepth)
{
	struct sa_page *p = NULL;

	while (sab) {
		*idx = find_block_on_page(sab, bppage, bno);
		*sdepth += *idx;
		if (*idx != bppage) {
			if (p)
				*prev = p;
			break;
		}
		p = sab;
		sab = sab->next;
	}
	return sab;
}

static SA_INLINE void init_sa_page(struct sa_page *sab, int bppage)
{
	int i;
	unsigned long long *bno_p = &sab->bno;

	bno_p++;
	for (i = 1; i < bppage; i++, bno_p++)
		*bno_p = ~0ULL;
}

SA_STATIC unsigned long long any_block_on_page(struct sa_page *sab, int bppage)
{
	int i;
	unsigned long long *bno_p = &sab->bno;

	for (i = 0; i < bppage; i++, bno_p++)
		if (*bno_p != ~0ULL)
			return *bno_p;
	return ~0ULL;
}

SA_STATIC unsigned long long any_block_in_cache(struct session_struct *session)
{
	struct sa_chain *chain = NULL;
	int i, idx = 0;
	unsigned long long ret = ~0ULL;

	if (session->s_blkcache_pages == 0)
		return ret;
	for (i = 0; i < blk_chains; i++) {
		idx = sa_get_blk_chain_index(session->s_anyblk_chain + i);
		chain = sa_get_blk_chain(session, idx);
		spin_lock(&chain->lock);
		if (chain->busy) {
			ret = chain->busy->bno;
			spin_unlock(&chain->lock);
			break;
		}
		if (chain->free) {
			ret = any_block_on_page(chain->free, session->s_bppage);
			spin_unlock(&chain->lock);
			break;
		}
		spin_unlock(&chain->lock);
	}
	session->s_anyblk_chain = sa_get_blk_chain_index(idx + 1);
	return ret;
}

SA_STATIC int sa_cache_emlist_init(struct session_struct *session, int prealloc)
{
	struct sa_page *sab = NULL;
	int ret, i;

	session->s_blkcache_emmax = snap_emergency_size;
	session->s_blkcache_emmin = session->s_blkcache_emmax - (session->s_blkcache_emmax >> 4);

	prealloc = (prealloc && snap_prealloc_force != SNAP_PREALLOC_FORCE_OFF) ||
			   snap_prealloc_force == SNAP_PREALLOC_FORCE_ON;
	if (!prealloc)
		return 0;

	ret = -ENOMEM;
	for (i = 0; i < session->s_blkcache_emmax; i++) {
		unsigned long tm = jiffies + msecs_to_jiffies(MEM_ALLOC_TM) + 1;
		sab = (struct sa_page *)kmem_cache_alloc(session->s_blkcachep,
						GFP_KERNEL);
		if (!sab)
			goto out;
		session->s_blkcache_empages++;
		sab->page = sn_vmalloc_page(GFP_HIGHUSER);
		if (!sab->page) {
			kmem_cache_free(session->s_blkcachep, sab);
			goto out;
		}
		inc_get_pages(session);
		sab->next = session->s_blk_emlist;
		session->s_blk_emlist = sab;
		if (time_after(jiffies, tm)) {
	 		sa_warn("Note, continue with %d pages.\n",
						session->s_blkcache_empages);
			break;
		}
	}
	ret = 0;

out:
	return ret;
}

SA_STATIC struct sa_page * sa_cache_emget(struct session_struct *session)
{
	struct sa_page *sab = NULL;

	spin_lock(&session->s_blkcache_emlock);
	if (session->s_blkcache_empages > session->s_blkcache_emmin) {
		sab = session->s_blk_emlist;
		session->s_blk_emlist = sab->next;
		session->s_blkcache_empages--;
		session->s_blkcache_pages++;
		goto out_unlock;
	}
	spin_unlock(&session->s_blkcache_emlock);

	sab = (struct sa_page *)kmem_cache_alloc(session->s_blkcachep, GFP_ATOMIC);
	if (!sab)
		goto get_from_list;
	sab->page = sn_vmalloc_page(GFP_SNAPHIGH);
	if (!sab->page) {
		kmem_cache_free(session->s_blkcachep, sab);
		goto get_from_list;
	}
	inc_get_pages(session);
	session->s_blkcache_pages++;
	goto out;

get_from_list:
	spin_lock(&session->s_blkcache_emlock);
	sab = session->s_blk_emlist;
	if (sab) {
		session->s_blk_emlist = sab->next;
		session->s_blkcache_empages--;
		session->s_blkcache_pages++;
	}

out_unlock:
	spin_unlock(&session->s_blkcache_emlock);
out:
	if (unlikely(!sab)) {
		sa_error("s=%p sa_cache_emget failed\n", session);
	}
	return sab;
}

SA_STATIC void sa_cache_emput(struct session_struct *session, struct sa_page *sab)
{
	spin_lock(&session->s_blkcache_emlock);
	session->s_blkcache_pages--;
	if (session->s_blkcache_empages < session->s_blkcache_emmax) {
		sab->next = session->s_blk_emlist;
		session->s_blk_emlist = sab;
		session->s_blkcache_empages++;
		spin_unlock(&session->s_blkcache_emlock);
		return;
	}
	spin_unlock(&session->s_blkcache_emlock);
	vfree(sab->page);
	inc_put_pages(session);
	kmem_cache_free(session->s_blkcachep, sab);
}

SA_STATIC void sa_cache_emlist_destroy(struct session_struct *session)
{
	struct sa_page *sab = NULL;

	spin_lock(&session->s_blkcache_emlock);
	while (session->s_blk_emlist) {
		sab = session->s_blk_emlist;
		session->s_blk_emlist = sab->next;
		session->s_blkcache_empages--;
		spin_unlock(&session->s_blkcache_emlock);

		vfree(sab->page);
		inc_put_pages(session);
		kmem_cache_free(session->s_blkcachep, sab);
		spin_lock(&session->s_blkcache_emlock);
	}
	spin_unlock(&session->s_blkcache_emlock);
}

static SA_INLINE void sa_update_session_rc_depth_stats(struct session_struct *session, unsigned long long sdepth)
{
	if (sdepth > session->s_maxrcdepth)
		session->s_maxrcdepth = sdepth;
	if (sdepth > SNAP_RCDEPTH0) {
		session->s_rcdepthcnt[0]++;
		if (sdepth > SNAP_RCDEPTH1) {
			session->s_rcdepthcnt[1]++;
			if (sdepth > SNAP_RCDEPTH2) {
				session->s_rcdepthcnt[2]++;
				if (sdepth > SNAP_RCDEPTH3) {
					session->s_rcdepthcnt[3]++;
				}
			}
		}
	}
}

SA_STATIC int sa_cache_chain_read(struct session_struct *session, struct sa_chain* chain,
		void *data, unsigned long long bno, int mode, unsigned int flags)
{
	struct sa_page *prev = NULL;
	struct sa_page **head = &chain->busy;
	struct sa_page *sab = NULL;
	int idx = 0, bppage = session->s_bppage, ret = 0;
	unsigned long long sdepth = 0;

	session->s_rccalls++;
	sab = find_block_in_chain(chain->busy, bppage, bno, &idx, &prev, &sdepth);
	if (sab)
		goto copy_data;

	prev = NULL;
	head = &chain->free;
	sab = find_block_in_chain(chain->free, bppage, bno, &idx, &prev, &sdepth);
	if (sab)
		goto copy_data;
	/* not found */
	goto out;

copy_data:
	if (mode == FAKE_READ)
		goto arrange_lists;
	memcpy(data, sab->page + idx * session->s_bsize, session->s_bsize);
	session->s_rcblocks++;

arrange_lists:
	sa_debug(DEBUG_CACHE, "mode=%d flags=%u bno=%llu\n", mode, flags, bno);
	ret = session->s_bsize;
	if (!(flags & SNAP_READ_ONCE))
		goto out;
	session->s_fcblocks++;
	free_block_on_page(sab, idx);
	/* remove from list */
	if (prev)
		prev->next = sab->next;
	else
		*head = sab->next;
	if (bppage == 1 || !blocks_on_page(sab, bppage)) {
		sa_cache_emput(session, sab);
		goto out;
	}
	insert_into_free_list(chain, sab);
out:
	sa_update_session_rc_depth_stats(session, sdepth);
	return ret;
}

struct level0entry {
	unsigned long long key;
	unsigned long long value;
};

#define STOP_ENTRY(SP) 	((void*)SP->entry - page_address(SP->page) > \
			PAGE_SIZE - sizeof(struct level_entry))

SA_STATIC void map_free(struct session_struct *session)
{
	struct group_map *map = &session->s_groupmap;
	struct stack_entry *sp = NULL, *end = NULL;

	end = sp = map->stack + map->level;
	sp->page = map->root;
	if (sp > map->stack)
		sp->entry = page_address(sp->page);
	do {
		while (sp > map->stack) {
			sp--;
			sp->page = (sp + 1)->entry->page;
			if (sp - map->stack)
				sp->entry = page_address(sp->page);
		}
		do  {
			put_page(sp->page);
			inc_put_pages(session);
			if (++sp > end)
				break;
			sp->entry++;
		} while (STOP_ENTRY(sp) || !sp->entry->page);
	} while(sp <= end);
}

SA_STATIC void update_ioctl_counters(struct session_struct *session)
{
	sa_debug(DEBUG_INTERNALS, "s=%p(%x)\n", session, session->s_kdev);
	session->s_simulate_tm = jiffies + IOCTL_SIM_INTERVAL;
	session->s_ioctlcnt++;
	if (session->s_pid_info)
		atomic_inc(&session->s_pid_info->sn_ioctls);
}

SA_STATIC void simulate_ioctl(struct session_struct *session)
{
	if (time_after(jiffies, session->s_simulate_tm))
		update_ioctl_counters(session);
}

SA_STATIC int map_init(struct session_struct *session, unsigned long uaddr, unsigned n)
{
	int ret = 0;
	struct page *destpage = NULL, *bubble = NULL;
	struct group_map *map = &session->s_groupmap;
	struct stack_entry *sp = NULL, *max_sp = map->stack;

	memset(map->stack, 0, sizeof(map->stack));
	while (n) {
		unsigned copy_count;
		unsigned copy_size;
		unsigned long long max_key;
		struct level0entry* dest;

		ret = -ENOMEM;
		destpage = alloc_page(GFP_HIGHUSER);
		if (!destpage)
			break;
		inc_get_pages(session);
		dest = (struct level0entry*)kmap(destpage);
		if (!dest)
			break;
		ret = 0;
		copy_count = PAGE_SIZE / sizeof(struct level0entry);
		while (copy_count > n)
			dest[--copy_count].key = ~0;
		copy_size = copy_count * sizeof(struct level0entry);
		if (copy_from_user(dest, (void*)uaddr, copy_size)) {
			ret = -EACCES;
			kunmap(destpage);
			break;
		}
		uaddr += copy_size;
		n -= copy_count;
		bubble = map->stack[0].page;
		max_key = map->stack[0].max_key;
		map->stack[0].page = destpage;
		map->stack[0].max_key = dest[copy_count - 1].key;
		kunmap(destpage);
		destpage = 0;
		for (sp = &map->stack[1]; bubble; sp++) {
			if (!sp->page) {
				sp->page = alloc_page(GFP_KERNEL);
				if (!sp->page) {
					ret = -ENOMEM;
					break;
				}
				inc_get_pages(session);
				sp->entry = page_address(sp->page);
			}
			sp->entry->page = bubble;
			sp->entry->max_key = sp->max_key = max_key;
			sp->entry++;
			if (STOP_ENTRY(sp)) {
				bubble = sp->page;
				sp->page = 0;
			} else {
				/*sp->entry->page = 0; ???*/
				bubble = 0;
			}
		}
		if (--sp > max_sp)
			max_sp = sp;
	}
	for (sp = &map->stack[1]; sp <= max_sp; sp++) {
		if (!sp->page) {
			sp->page = alloc_page(GFP_KERNEL);
			if (!sp->page) {
				ret = -ENOMEM;
				break;
			}
			inc_get_pages(session);
			sp->entry = page_address(sp->page);
		}
		sp->entry->page = (sp - 1)->page;
		sp->entry->max_key = map->stack[0].max_key;
		sp->entry++;
		(sp - 1)->page = 0;
		for (; !STOP_ENTRY(sp); sp->entry++) {
			sp->entry->max_key = ~0;
			sp->entry->page = 0;
		}
	}
	map->max_key = map->stack[0].max_key;
	map->level = --sp - map->stack;
	map->root = sp->page;
	sp->page = 0;
	if (destpage) {
		put_page(destpage);
		inc_put_pages(session);
	}
	if (bubble) {
		put_page(bubble);
		inc_put_pages(session);
	}
	for (sp = map->stack; sp <= max_sp; sp++)
		if (sp->page) {
			put_page(sp->page);
			inc_put_pages(session);
		}
	if (ret)
		map_free(session);
	return ret;
}

SA_STATIC void map_init_iterator(struct group_map* map)
{
	struct stack_entry *sp = NULL;

	map->stack[map->level].page = map->root;
	for (sp = map->stack + map->level; sp > map->stack; ) {
		sp->entry = page_address(sp->page);
		sp--;
		sp->page = (sp+1)->entry->page;
	}
	map->stack[0].entry = kmap(map->stack[0].page);
}

SA_STATIC struct level0entry* map_iterator_get_value(struct group_map* map)
{
	return (struct level0entry*)map->stack[0].entry;
}

SA_STATIC int map_iterator_next(struct group_map* map)
{
	struct stack_entry *sp = NULL;

	struct stack0entry {
		struct page* page;
		struct level0entry* entry;
	} *sp0 = (struct stack0entry*)map->stack;

	sp0->entry++;

	if ((void*)(sp0->entry + 1) > page_address(sp0->page) + PAGE_SIZE ||
					sp0->entry->key > map->max_key) {
		kunmap(sp0->page);
		for (sp = map->stack + 1; sp <= map->stack + map->level; sp++) {
			sp->entry++;
			if (!STOP_ENTRY(sp) && sp->entry->page)
				break;
		}
		if (sp > map->stack + map->level)
			return 0;

		while (sp > map->stack) {
			sp--;
			sp->page = (sp+1)->entry->page;
			sp->entry = sp - map->stack ? page_address(sp->page)
							: kmap(sp->page);
		}
	}
	return 1;
}

SA_STATIC void map_iterator_stop(struct group_map* map)
{
	kunmap(map->stack[0].page);
}

SA_STATIC struct level0entry* map_search(struct group_map* map, unsigned long long key,
						struct page** entry_page)
{
	int level;
	struct page *page = map->root;
	int i, l, r;
	struct level0entry *array0 = NULL;

	if (key > map->max_key)
		return 0;

	for (level = map->level; level; level--) {
		struct level_entry *array = page_address(page);

		l = 0;
		r = PAGE_SIZE / sizeof(struct level_entry) - 1;
		do {
			i = (l + r)/2;
			if (array[i].max_key >= key)
				r = i;
			else
				l = i + 1;
		} while (r != l);
		page = array[r].page;
	}

	array0 = kmap(page);
	l = 0;
	r = PAGE_SIZE / sizeof(struct level0entry) - 1;
	do {
		i = (l + r)/2;
		if (array0[i].key > key)
			r = i - 1;
		else if (array0[i].key < key)
			l = i + 1;
		else {
			*entry_page = page;
			return &array0[i];
		}
	} while (r >= l);
	entry_page = 0;
	kunmap(page);
	return 0;
}

#define sa_cache_chain_remove(session, chain, bno) \
	sa_cache_chain_read(session, chain, 0, bno, FAKE_READ, SNAP_READ_ONCE)

SA_STATIC int sa_cache_save(struct session_struct *session, void *data,
					unsigned long long bno)
{
	struct sa_page *sab = NULL;
	struct sa_chain *chain = NULL;
	int idx = 0, bppage = session->s_bppage, ret = 1, new_page = 0;
	struct group_entry *entry = NULL;
	struct page *entry_page = NULL;

	sa_debug(DEBUG_API, "bno=%llu\n", bno);

	if (session->s_state == SNAP_READINGMAP && session->s_usemap)
		entry = (struct group_entry*)map_search(&session->s_groupmap, bno, &entry_page);

	chain = sa_get_blk_chain(session, bno);
	spin_lock(&chain->lock);

	/* The block may be already read while we were waiting on bio */
	if (!(session->s_state == SNAP_READINGMAP && session->s_usemap ?
			!!entry :
			!!is_block_in_map(&session->s_blkmap, bno))) 
	{
		session->s_rwcolls++;
		ret = 0;
		goto out_unlock;
	}

	if (session->s_state == SNAP_READINGMAP)
		sa_cache_chain_remove(session, chain, bno);

	if (bppage > 1 && chain->free) {
		sab = chain->free;
		idx = find_free_on_page(sab, bppage, bno);
		goto copy_data;
	}
	sab = sa_cache_emget(session);
	if (!sab)
		goto out_unlock;

	sab->bno = bno;
	new_page = 1;
	if (bppage > 1)
		init_sa_page(sab, bppage);

copy_data:
	memcpy(sab->page + (idx * session->s_bsize), data, session->s_bsize);

	if (session->s_state == SNAP_READINGMAP && session->s_usemap) {
		if (!entry->init)
			sa_debug(DEBUG_API, "INITING group %u bno = %llu\n",
						entry->group, entry->bno);
		entry->init = entry->cached = 1;
	} else if (session->s_state != SNAP_READINGMAP)
		clear_block_in_map(&session->s_blkmap, bno);

	session->s_cblocks++;
	if (session->s_cblocks - session->s_fcblocks > session->s_mcblocks)
		session->s_mcblocks = session->s_cblocks - session->s_fcblocks;

	ret = 0;
	if (bppage == 1) {
		insert_into_busy_list(chain, sab);
	} else if (new_page) {
		insert_into_free_list(chain, sab);
	} else if (blocks_on_page(sab, bppage) == bppage) {
		remove_from_free_list(chain, sab);
		insert_into_busy_list(chain, sab);
	}

out_unlock:
	spin_unlock(&chain->lock);
	if (entry_page)
		kunmap(entry_page);
	return ret;
}

/* return number of read bytes or error */
SA_STATIC int sa_cache_read(struct session_struct *session, void *data,
		unsigned long long bno, int mode, unsigned int flags)
{
	struct sa_chain *chain = sa_get_blk_chain(session, bno);
	int ret;

	spin_lock(&chain->lock);

	ret = sa_cache_chain_read(session, chain, data, bno, mode, flags);

	spin_unlock(&chain->lock);
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
SA_STATIC void sa_cache_bio_end_io(struct bio *bio, int err)
#else
SA_STATIC void sa_cache_bio_end_io(struct bio *bio)
#endif // LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
{
	complete((struct completion *)bio->bi_private);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
  SA_STATIC void sa_pending_bio_end_io(struct bio *bio, int err)
#else
  SA_STATIC void sa_pending_bio_end_io(struct bio *bio)
#endif
{
	unsigned long flags;

	struct pending_request *preq = (struct pending_request*)
							bio->bi_private;
	struct pending_queue *pq = preq->pr_queue;
	int qstate, not_ready;

	spin_lock_irqsave(&pq->pq_lock, flags);

	qstate = pq->pq_state;
	preq->pr_ready++;

	if (unlikely(preq->pr_ready != preq->pr_count)) {
		spin_unlock_irqrestore(&pq->pq_lock, flags);
		return;
	}

	/*
	 * All pq_bios are completed, so add request to ready requests
	 * list for later handling in process context.
	 */

	not_ready = atomic_dec_return(&pq->pq_notready_req);
	atomic_inc(&pq->pq_ready_req);

	pqueue_add_request(pq, preq);

	spin_unlock_irqrestore(&pq->pq_lock, flags);

	BUG_ON(not_ready < 0);
	BUG_ON(qstate != PQ_RUNNING && qstate != PQ_CLOSED);

	complete(&pq->pq_bio_done);
}

SA_STATIC struct pending_request* alloc_pending_request(int count)
{
	unsigned size = sizeof(struct pending_request) +
			count * sizeof(struct pending_read_request);
	struct pending_request *req = kzalloc(size, GFP_NOWAIT);

	if (req != NULL) {
		req->pr_count = count;
	}
	return req;
}

SA_STATIC struct pending_request* increase_pending_request
			(struct pending_request* oreq, unsigned count)
{
	unsigned ocount = oreq->pr_count;
	unsigned osize = sizeof(struct pending_request) +
			ocount * sizeof(struct pending_read_request);
	unsigned nsize = osize + count * sizeof(struct pending_read_request);
	struct pending_request *nreq = kzalloc(nsize, GFP_NOWAIT);

	if (nreq) {
		memcpy(nreq, oreq, osize);
		nreq->pr_count = count + ocount;
		kfree(oreq);
	} else {
		nreq = oreq;
	}
	return nreq;
}

SA_STATIC int submit_pending_request(struct session_struct *session,
	struct pending_request *preq, struct bio *wbio)
{
	struct pending_queue *pq = &session->s_pending_queue;
	int ready, not_ready, qstate;
	int ret, i;
	int pr_count;

	spin_lock_irq(&pq->pq_lock);
	ready = atomic_read(&pq->pq_ready_req);
	not_ready = atomic_read(&pq->pq_notready_req);

	qstate = pq->pq_state;

	if (unlikely(ready + not_ready > session->s_blkcache_emmin)) {
		session->s_async_retr++;
		ret = -EAGAIN;
		goto out_err;
	}

	if (unlikely(qstate != PQ_RUNNING)) {
		/* Seems pending queue was closed */
		ret = -EBADFD;
		goto out_err;
	}

	atomic_inc(&pq->pq_notready_req);
	spin_unlock_irq(&pq->pq_lock);

	preq->pr_next = NULL;
	preq->pr_wbio = wbio;
	preq->pr_queue = pq;

	pr_count = preq->pr_count;
	
	for (i = 0; i < pr_count; i++) {
		struct bio *rbio = preq->pr_bios[i].rbio;
		rbio->bi_private = preq;
		rbio->bi_end_io = sa_pending_bio_end_io;
	}

	if (wbio)
		dump_bio(wbio, "sa_cache_block async case write");

	for (i = 0; i < pr_count; i++) {
		struct bio *rbio = preq->pr_bios[i].rbio;
		dump_bio(rbio, "sa_cache_block async case read");
		sn_submit_bio(READ, rbio);
	}

	return 0;

out_err:
	spin_unlock_irq(&pq->pq_lock);
	return ret;
}

SA_STATIC int sa_cache_save_bio(struct session_struct *session, struct bio *bio,
		unsigned long long bno)
{
	unsigned pg_idx;

	if (sn_is_error_bio(bio)) {
		sn_set_mb(session->s_state, SNAP_READING_ERR);
		return 1;
	}
	for (pg_idx = 0; pg_idx < bio->bi_vcnt; pg_idx++) {
		struct bio_vec *bvec = NULL;	/* bio_vec of this page */
		unsigned int pg_off;	/* block offset withing page */

		bvec = bio->bi_io_vec + pg_idx;
		for (pg_off = 0; pg_off < bvec->bv_len; pg_off +=session->s_bsize) {
			if (sa_cache_save(session, page_address(bvec->bv_page) +
					pg_off + bvec->bv_offset, bno++))
				return 1;
		}
	}
	return 0;
}

SA_STATIC void destroy_cached_bio(struct session_struct *session, struct bio *bio)
{
	int i;
	unsigned nr_pages;

	if (!bio)
		return;

	nr_pages = bio->bi_vcnt;
	for (i = 0; i < nr_pages; i++) {
		if (bio->bi_io_vec[i].bv_page) {
			put_page(bio->bi_io_vec[i].bv_page);
			inc_put_pages(session);
		}
	}
	bio_put(bio);
}

SA_STATIC struct bio* sa_bio_alloc(struct session_struct *session, int nr_pages)
{
#ifdef HAVE_BIO_ALLOC_2ARGS
	/* LINUX_VERSION_CODE <= KERNEL_VERSION(5,18,0) ? */
	return bio_alloc(GFP_NOIO, nr_pages);
#else
	return bio_alloc(SN_BDEV(session->s_bdev), nr_pages, 0, GFP_NOIO);
#endif
}

static noinline struct bio* sa_cache_alloc_bio(struct session_struct *session,
		unsigned long long bno, int nr_pages)
{
	struct page *page = NULL;
	struct bio *bio = sa_bio_alloc(session, nr_pages);
	int i = 0;

	if (bio == NULL)
		goto out;

#ifdef HAVE_BVEC_ITER
	bio->bi_iter.bi_sector = ((sector_t) bno) * session->s_spb;
#else
	bio->bi_sector = ((sector_t) bno) * session->s_spb;
#endif

#ifdef HAVE_BIO_ALLOC_2ARGS

#ifndef HAVE_BIO_SET_DEV
	bio->bi_bdev = SN_BDEV(session->s_bdev);
#else
	bio_set_dev(bio, SN_BDEV(session->s_bdev));
#endif

#endif /* HAVE_BIO_ALLOC_2ARGS */

	for (i = 0; i < nr_pages; i++) {
		page = alloc_page(GFP_NOIO);
		if (!page)
			goto out;
		inc_get_pages(session);
		if (unlikely(!bio_add_page(bio, page, PAGE_SIZE, 0))) {
			put_page(page);
			inc_put_pages(session);
			if (!session->s_mbio || session->s_mbio > i)
				session->s_mbio = i;
			break;
		}
	}

	return bio;
out:
	sa_warn("Memory shortage: pages=%d, i=%d\n", nr_pages, i);
	destroy_cached_bio(session, bio);
	return 0;
}

static noinline void destroy_pending_request(struct session_struct *session,
					struct pending_request *preq)
{
	int i;

	if (!preq)
		return;

	for (i = 0; i < preq->pr_count; i++) {
		struct bio* rbio = preq->pr_bios[i].rbio;
		if (rbio != NULL) {
			destroy_cached_bio(session, rbio);
		}
	}
	kfree(preq);
}

static noinline int sa_cache_block(struct session_struct *session,
		struct bio *orig_bio, unsigned long long bno,
		unsigned int nr_blocks,	int *pended)
{
	int i, nr_pages, nr_bios, iprs;
	struct pending_request *preq = NULL;
	int ret = -ENOMEM;

	sa_debug(DEBUG_BIO, "s=%p, orig_bio=%p, bno=%llu, nr_block=%u, pended=%p\n", 
			session, orig_bio, bno, nr_blocks, pended);

	nr_pages = ((nr_blocks - 1) / session->s_bppage) + 1;
	nr_bios = ((nr_pages - 1) / MAX_RDPAGES) + 1;

	preq = alloc_pending_request(nr_bios);
	if (preq == NULL)
		goto out;

	sa_debug(DEBUG_BIO, "s=%p, allocated preq=%p, nr_bios=%d\n", session, preq, nr_bios);

	iprs = i = 0;
	do {
		unsigned bsize;
		unsigned int bi_size;

		const int count = MAX_RDPAGES < nr_pages ? MAX_RDPAGES : nr_pages;
		struct pending_read_request* pr_bios = &preq->pr_bios[i];
		struct bio* p_rbio = sa_cache_alloc_bio(session, bno, count);

		if (p_rbio == NULL)
			goto out;

		sa_debug(DEBUG_BIO, "s=%p, allocated rbio=%p, bno=%llu, count=%d\n", session, p_rbio, bno, count);

		pr_bios->rbio = p_rbio; 
		pr_bios->rblkno = bno;

		bi_size = sn_bio_bi_size(p_rbio);
		bsize = bi_size >> PAGE_SHIFT;
		bno += bsize * session->s_bppage;
		nr_pages -= bsize;

		dump_bio(p_rbio, "sa_cache_block read ");

		i++;

		sa_debug(DEBUG_BIO, "s=%p, nr_pages=%d, bno=%llu, i=%d, nr_bios=%d\n", session, nr_pages, bno, i, nr_bios);

		if (nr_pages && i == nr_bios) {
			unsigned incr = ((nr_pages - 1) / MAX_RDPAGES) + 1;
			struct pending_request* preq2 = increase_pending_request(preq, incr);

			sa_debug(DEBUG_BIO, "s=%p, increased preq=%p, incr=%u\n", session, preq2, incr);

			session->s_iprcnt++;
			iprs++;

			if (preq2 == preq) {
				sa_warn("Increase preq failed. inc=%u\n", incr);
				goto out;
			}
			else {
				preq = preq2;
				nr_bios = preq->pr_count;
			}
		}
	} while (nr_pages);

	if (iprs > session->s_mipr)
		session->s_mipr = iprs;

	preq->pr_count = i;
	
	sa_debug(DEBUG_BIO, "s=%p, Request inited: blocks=%u, bios=%d\n",
						session, nr_blocks, preq->pr_count);

resubmit:
	ret = submit_pending_request(session, preq, orig_bio);
	if (unlikely(ret == -EAGAIN)) {
		schedule();
		goto resubmit;
	}
	if (unlikely(ret))
		goto out;
	*pended = 1;
	session->s_async_req++;
	return 0;

out:
	sa_kdebug( "out: s=%p, preq=%p", session, preq);
	destroy_pending_request(session, preq);
	return ret;
}

static noinline int sa_cache_bio(struct session_struct *session, struct bio *bio,
								int *pended)
{
	unsigned long long sbno, ebno, i;
	unsigned long long sbno_cow, ebno_cow;
	sector_t start, end; /* relative to part start */

	dump_bio(bio, "sa_cache_bio");

	start = sn_bio_bi_sector(bio) - session->s_pstart;
	if (sn_bio_bi_sector(bio) < session->s_pstart)
		start = 0;
	end = sn_bio_bi_sector(bio) + (sn_bio_bi_size(bio) >> SECTOR_SHIFT) - session->s_pstart;
	if (end > session->s_plen)
		end = session->s_plen;
	sbno = start >> session->s_spbshift;
	ebno = (end + session->s_spb - 1) >> session->s_spbshift;
	sbno_cow = ebno + 1;
	ebno_cow = sbno;
	for (i = sbno; i < ebno; i++) {
		if (is_block_in_map(&session->s_blkmap, i)) {
			sbno_cow = i;
			ebno_cow = i + 1;
			break;
		}
	}

	/* Where is no block in map */
	if (sbno_cow > ebno) {
		*pended = 0;
		return 0;
	}

	for (i = ebno - 1; i > sbno_cow; i--) {
		if (is_block_in_map(&session->s_blkmap, i)){
			ebno_cow = i + 1;
			break;
		}
	}

	if (sa_cache_block(session, bio, sbno_cow, ebno_cow - sbno_cow, pended))
		return 1;

	return 0;
}

static noinline int sa_save_bio_to_cache(struct session_struct *session,
							struct bio *bio)
{
	unsigned int pg_idx;
	unsigned long long bno;
	sector_t start; /* relative to part start */

	start = sn_bio_bi_sector(bio) - session->s_pstart;
	if (sn_bio_bi_sector(bio) < session->s_pstart)
		start = 0;
	bno = start >> session->s_spbshift;

	for (pg_idx = 0; pg_idx < bio->bi_vcnt; pg_idx++) {
		struct bio_vec *bvec = NULL;	/* bio_vec of this page */
		unsigned int pg_off;	/* block offset withing page */

		bvec = bio->bi_io_vec + pg_idx;
		for (pg_off = 0; pg_off < bvec->bv_len; pg_off +=session->s_bsize) {
			if (sa_cache_save(session, page_address(bvec->bv_page) +
					pg_off + bvec->bv_offset, bno++))
				return 1;
		}
	}
	return 0;
}

static noinline void wait_for_users(struct session_struct *session)
{
	spin_lock(&sessions_lock);
	while (!atomic_dec_and_test(&session->s_users)) {
		atomic_inc(&session->s_users);
		spin_unlock(&sessions_lock);
		schedule();
		spin_lock(&sessions_lock);
	}
	atomic_inc(&session->s_users);
}

static noinline int session_handle_bio(struct session_struct *session,
					struct bio *bio, int *pended)
{
	const int state = session->s_state;

	dump_bio(bio, "session_make_request write");

	switch(state)
	{
	case SNAP_FREEZING:
	case SNAP_FROZEN:
	case SNAP_INITINGMAP:
	{
		if (!delay_bio(session, bio)) {
			*pended = 1;
			return 0;
		}
		sn_set_mb(session->s_state, SNAP_FREEZE_ERR);
		sa_debug(DEBUG_API, "SNAP_FREEZE_ERR s=%p\n", session);
		unregister_make_request(session);

		sn_thaw_bdev(session);

		/* pass bh to original handler */
		break;
	}
	case SNAP_MAPPED:
	{
		if (!sa_cache_bio(session, bio, pended))
			return 0;

		sn_set_mb(session->s_state, SNAP_READING_ERR);

		sa_debug(DEBUG_API, "SNAP_MAPPED s=%p\n", session);

		unregister_make_request(session);
		break;
	} 
	case SNAP_READINGMAP:
	{
		*pended = 0;
		if (!sa_save_bio_to_cache(session, bio))
			return 0;

		sn_set_mb(session->s_state, SNAP_READING_ERR);

		sa_debug(DEBUG_API, "SNAP_READINGMAP s=%p\n", session);

		unregister_make_request(session);
		break;
	}
	default:
		sa_info("Default state: %d", state);
	}
	return 1;
}

SA_STATIC void handle_pending_request(struct session_struct *session)
{
	struct pending_queue *pq = &session->s_pending_queue;
	struct pending_request *preq = NULL;
	int i, ready;

	spin_lock_irq(&pq->pq_lock);
	preq = pqueue_get_request(pq);
	ready = atomic_dec_return(&pq->pq_ready_req);
	spin_unlock_irq(&pq->pq_lock);

	BUG_ON(ready < 0);
	BUG_ON(!preq);
	for (i = 0; i < preq->pr_count; i++) {
		struct bio *rbio = preq->pr_bios[i].rbio;
		unsigned long long rblkno = preq->pr_bios[i].rblkno;

		BUG_ON(!rbio);
		if (sa_cache_save_bio(session, rbio, rblkno)) {
			sn_set_mb(session->s_state, SNAP_READING_ERR);
			sa_debug(DEBUG_API, "SNAP_READING_ERR s=%p\n", session);
			unregister_make_request(session);
		}
	}

	if (preq->pr_wbio)
		sn_make_request(preq->pr_wbio);

	destroy_pending_request(session, preq);
}

/*
 * Worker thread that handles pending bios, to avoid blocking in our
 * make_request_fn.
 */
SA_STATIC int pending_req_handler_thread(void *data)
{
	struct session_struct *session = data;
	struct pending_queue *pq =  &session->s_pending_queue;
	int qstate;
	atomic_inc(&session->s_users);
	/*current->flags |= PF_NOFREEZE;*/
	set_user_nice(current, -20);
	spin_lock_irq(&pq->pq_lock);
	qstate = pq->pq_state;
	pq->pq_state = PQ_RUNNING;
	spin_unlock_irq(&pq->pq_lock);
	BUG_ON(qstate != PQ_STOPPED);
	/*
	 * complete it, we are running
	 */
	complete(&pq->pq_done);

	while (1) {
		if (wait_for_completion_interruptible(&pq->pq_bio_done)) {
			if (!session->s_simulate_freeze)
				snapapi_try_to_freeze();
			continue;
		}

		if (!atomic_read(&pq->pq_ready_req)) {
			/*
			 * ->pq_bio_done was completed but queue is empty.
			 * This fake event was generated by session unregister
			 * routine. We have to wait untill all notready pending
			 * requests become ready. After all pending requests
			 * will be handled we may safely exit.
		 	 */
			spin_lock_irq(&pq->pq_lock);
			if (pq->pq_state != PQ_CLOSED) {
				sa_debug(DEBUG_API, "close queue notready=%d\n",
						atomic_read(&pq->pq_ready_req));
				pq->pq_state = PQ_CLOSED;
			}
			spin_unlock_irq(&pq->pq_lock);
			goto check_queue;
		}

		handle_pending_request(session);
check_queue:
		if (pq->pq_state == PQ_CLOSED) {
			spin_lock_irq(&pq->pq_lock);
			if (!atomic_read(&pq->pq_notready_req) &&
					!atomic_read(&pq->pq_ready_req)) {
				/* All pending requests was handled */
				spin_unlock_irq(&pq->pq_lock);
				break;
			}
			spin_unlock_irq(&pq->pq_lock);
		}
	}
	pq->pq_state = PQ_STOPPED;
	complete(&pq->pq_done);
	atomic_dec(&session->s_users);
	return 0;
}

SA_STATIC int start_req_handler_thread(struct session_struct *session)
{
	int ret;
	struct task_struct *th = kthread_create(pending_req_handler_thread, session, "snapapi_prht");
	if (IS_ERR(th)) {
		ret = PTR_ERR(th);
		sa_debug(DEBUG_API, "Can't create thread err=%d.\n", ret);
		return ret;
	}
	wake_up_process(th);
	wait_for_completion(&session->s_pending_queue.pq_done);
	return 0;
}

SA_STATIC void stop_req_handler_thread(struct session_struct *session, int wait)
{
	int ready, not_ready, qstate;
	struct pending_queue *pq = &session->s_pending_queue;

restart:
	spin_lock_irq(&pq->pq_lock);
	ready = atomic_read(&pq->pq_ready_req);
	not_ready = atomic_read(&pq->pq_notready_req);
	spin_unlock_irq(&pq->pq_lock);
	qstate = pq->pq_state;

	if (wait && (ready + not_ready)) {
		schedule();
		goto restart;
	}
	if (qstate != PQ_STOPPED) {
		/* Send close event to pending queue and
		 * wait while it stopped */
		complete(&pq->pq_bio_done);
		wait_for_completion(&pq->pq_done);
		BUG_ON(pq->pq_state != PQ_STOPPED);
	}
}

#ifdef HAVE_BDOPS_SUBMIT_BIO
#ifdef HAVE_PRINTK_INDEX
static MAKE_REQUEST_RETURN_VALUE (*_sn_blk_mq_submit_bio)(struct bio *) = (BLK_MQ_SUBMIT_BIO_ADDR != 0) ?
        (MAKE_REQUEST_RETURN_VALUE (*)(struct bio *)) (BLK_MQ_SUBMIT_BIO_ADDR + (long long)(((void *)_printk) - (void *)_PRINTK_ADDR)) : NULL;
#else
static MAKE_REQUEST_RETURN_VALUE (*_sn_blk_mq_submit_bio)(struct bio *) = (BLK_MQ_SUBMIT_BIO_ADDR != 0) ?
        (MAKE_REQUEST_RETURN_VALUE (*)(struct bio *)) (BLK_MQ_SUBMIT_BIO_ADDR + (long long)(((void *)printk) - (void *)PRINTK_ADDR)) : NULL;
#endif //HAVE_PRINTK_INDEX

SA_STATIC MAKE_REQUEST_RETURN_VALUE sn_blk_mq_submit_bio(struct bio *bio)
{
	struct request_queue *q = sn_bio_queue(bio);

	percpu_ref_get(&q->q_usage_counter);
	return _sn_blk_mq_submit_bio(bio);
}

SA_STATIC make_request_fn *sn_get_make_request_fn(struct session_struct *session)
{
	return session->s_queue_mq_based ? sn_blk_mq_submit_bio : sn_make_request_fn(session);
}

#elif defined(HAVE_BLK_MQ_MAKE_REQUEST)
SA_STATIC MAKE_REQUEST_RETURN_VALUE sn_mq_make_request(struct request_queue *q, struct bio *bio)
{
	percpu_ref_get(&q->q_usage_counter);
	return blk_mq_make_request(q, bio);
}

SA_STATIC make_request_fn *sn_get_make_request_fn(struct session_struct *session)
{
	return session->s_queue_mq_based ? sn_mq_make_request : sn_make_request_fn(session);
}
#else /* HAVE_BDOPS_SUBMIT_BIO */
SA_STATIC make_request_fn *sn_get_make_request_fn(struct session_struct *session)
{
	return sn_make_request_fn(session);
}
#endif /* HAVE_BDOPS_SUBMIT_BIO */

#ifdef HAVE_BDOPS_SUBMIT_BIO
SA_STATIC MAKE_REQUEST_RETURN_VALUE snapapi_ops_submit_bio(struct bio *bio)
{
	struct request_queue *q = sn_bio_queue(bio);
#else
SA_STATIC MAKE_REQUEST_RETURN_VALUE snapapi_make_request(struct request_queue *q, struct bio *bio)
{
#endif
	struct session_struct *session = NULL;
	make_request_fn *fn = NULL;
	int pended = 0;
	int state;

#ifdef HAVE_BDOPS_SUBMIT_BIO
#ifdef HAVE_BIO_BI_BDEV
	const struct block_device_operations *fops = bio->bi_bdev->bd_disk->fops;
#else
	const struct block_device_operations *fops = bio->bi_disk->fops;
#endif
#endif

	while (1) {
		spin_lock(&sessions_lock);
		if (!session)
#ifdef HAVE_BDOPS_SUBMIT_BIO
			session = find_by_fops(fops);
		else
			session = find_by_fops_next(fops, session);
#else
			session = find_by_queue(bio, q);
		else
			session = find_by_queue_next(bio, q, session);
#endif
		if (!session) {
			spin_unlock(&sessions_lock);
			break;
		}
		atomic_inc(&session->s_users);
		spin_unlock(&sessions_lock);
		if (!fn)
			fn = sn_get_make_request_fn(session);

		if (!sn_op_is_write(bio) || !sn_bio_bi_size(bio)) {
			dump_bio(bio, "sesson_make_request read");
			atomic_dec(&session->s_users);
			break;
		}

		if (session->s_request_queue != q)
			goto next_session;

		state = session->s_state;
		if (state == SNAP_FREEZING) /* freeze whole device */
			goto next_session;
		/*
		 * We assume what bio already remapped to disk by
		 * sn_make_request(), so device cant be partition here.
		 */
#ifdef HAVE_BIO_SET_DEV
#ifdef HAVE_BI_PARTNO
		if (bio->bi_partno) {
#else
		if (bio->bi_bdev->bd_partno && !bio_flagged(bio, BIO_REMAPPED)) {
#endif
			sa_warn("device bio_dev(%x) is a partition\n", bio_dev(bio));
		}
#else
		if (bio->bi_bdev->bd_contains != bio->bi_bdev) {
			dev_t ddev;
			ddev = bio->bi_bdev->bd_contains ? bio->bi_bdev->bd_contains->bd_dev : 0;
			sa_warn("bi_dev(%x) != bd_contains(%x)\n", bio->bi_bdev->bd_dev, ddev);
		}
#endif
		if (snapapi_is_not_our_bio(session, bio))
			goto next_session;
		session_handle_bio(session, bio, &pended);
		if (pended) {
			/* bio was pended and will be handled anisochronous */
			atomic_dec(&session->s_users);
			return MAKE_REQUEST_EXIT_STATUS;
		}
next_session:
		atomic_dec(&session->s_users);
	}
	if (unlikely(!fn)) {
#ifdef HAVE_BDOPS_SUBMIT_BIO
		fn = fops->submit_bio;
		if (!fn)
			fn = sn_blk_mq_submit_bio;
#else
		fn = q->make_request_fn;
#endif
		if (!fn) {
#ifdef HAVE_BLK_MQ_MAKE_REQUEST
			fn = sn_mq_make_request;
#else
			goto out_err;
#endif
		}
#ifndef HAVE_BDOPS_SUBMIT_BIO
		if (fn == snapapi_make_request)
#else
		if (fn == snapapi_ops_submit_bio)
#endif
			goto out_err;
	}

#ifdef HAVE_BDOPS_SUBMIT_BIO
	return fn(bio);
#else
	return fn(q, bio);
#endif

out_err:
	bio_io_error(bio);
	return MAKE_REQUEST_EXIT_STATUS;
}

SA_STATIC int register_make_request(struct session_struct *session)
{
	struct request_queue *q = NULL;
	struct list_head *tmp = NULL;
#ifdef HAVE_BDOPS_SUBMIT_BIO
	struct block_device_operations *new_fops = NULL;
#endif
	sa_debug(DEBUG_API, "\n");
	q = bdev_get_queue(SN_BDEV(session->s_bdev));
	if (!q)
		return 1;
	spin_lock(&sessions_lock);
	list_for_each(tmp, &sessions_list) {
		struct session_struct *tmp_s = NULL;
		tmp_s = list_entry(tmp, struct session_struct, s_list);
#ifdef HAVE_BDOPS_SUBMIT_BIO
		if (tmp_s->s_request_queue && SN_BDEV(session->s_bdev)->bd_disk->fops == SN_BDEV(tmp_s->s_bdev)->bd_disk->fops) {
			session->old_fops = tmp_s->old_fops;
#else
		if (tmp_s->s_request_queue == q) {
			session->s_make_request_fn = tmp_s->s_make_request_fn;
#endif
			session->s_request_queue = q;
			session->s_queue_mq_based = tmp_s->s_queue_mq_based;
			spin_unlock(&sessions_lock);
			sa_debug(DEBUG_API, "Keep queue as is.\n");
			return 0;
		}
	}
	spin_unlock(&sessions_lock);
	session->s_request_queue = q;
#ifndef HAVE_BDOPS_SUBMIT_BIO
	session->s_make_request_fn = q->make_request_fn;
#else
	sa_debug(DEBUG_API, "saving original fops %p in s %p", SN_BDEV(session->s_bdev)->bd_disk->fops, session);
	session->old_fops = SN_BDEV(session->s_bdev)->bd_disk->fops;
	new_fops = kmalloc(sizeof(struct block_device_operations), GFP_ATOMIC);
	if (unlikely(!new_fops)) {
		BUG();
		return 1;
	}
	*new_fops = *session->old_fops;
	new_fops->submit_bio = snapapi_ops_submit_bio;
#endif
	if (!sn_make_request_fn(session)) {
#if !(defined HAVE_BDOPS_SUBMIT_BIO) && !(defined HAVE_BLK_MQ_MAKE_REQUEST)
		sa_warn("s=%p(%x) queue make_request_fn is NULL and blk_mq_make_request is not defined",
				session, session->s_kdev);
		return 1;
#endif
		sa_debug(DEBUG_API, "s=%p(%x) s_queue_mq_based is 1", session, session->s_kdev);
		session->s_queue_mq_based = 1;
	}
	snapapi_lock_dev_queue(q);
#ifndef HAVE_BDOPS_SUBMIT_BIO
	q->make_request_fn = snapapi_make_request;
#else
	sa_debug(DEBUG_API, " Replacing original fops %p for disk %s", SN_BDEV(session->s_bdev)->bd_disk->fops, SN_BDEV(session->s_bdev)->bd_disk->disk_name);
	SN_BDEV(session->s_bdev)->bd_disk->fops = new_fops;
#endif
	snapapi_unlock_dev_queue(q);
	sa_kdebug("OK. dev=%d:%d, mq=%u.\n", MAJOR(session->s_kdev), MINOR(session->s_kdev), session->s_queue_mq_based);
	return 0;
}

SA_STATIC void unregister_make_request(struct session_struct *session)
{
	struct request_queue *q = NULL;
	struct list_head *tmp = NULL;
#ifdef HAVE_BDOPS_SUBMIT_BIO
	const struct block_device_operations *new_fops = NULL;
#endif
	sa_debug(DEBUG_API, "s=%p\n", session);

	q = session->s_request_queue;
	if (!q)
		return;

	if (!sn_make_request_fn(session) && !session->s_queue_mq_based) {
		sa_warn("s=%p(%x) queue s_make_request_fn is NULL for non mq-based session", session, session->s_kdev);
		return;
	}

	spin_lock(&sessions_lock);
	list_for_each(tmp, &sessions_list) {
		struct session_struct *tmp_s = NULL;
		tmp_s = list_entry(tmp, struct session_struct, s_list);
#ifdef HAVE_BDOPS_SUBMIT_BIO
		if (tmp_s->s_request_queue && tmp_s != session &&
			SN_BDEV(session->s_bdev)->bd_disk->fops == SN_BDEV(tmp_s->s_bdev)->bd_disk->fops) {
			session->old_fops = NULL;
#else
		if (tmp_s->s_request_queue == q && tmp_s != session) {
			session->s_make_request_fn = NULL;
#endif
			session->s_request_queue = NULL;
			session->s_queue_mq_based = 0;
			spin_unlock(&sessions_lock);
			sa_debug(DEBUG_API, "Keep queue as is. s=%p\n", session);
			return;
		}
	}
	spin_unlock(&sessions_lock);
#ifndef HAVE_BDOPS_SUBMIT_BIO
	snapapi_lock_dev_queue(q);
	q->make_request_fn = session->s_make_request_fn;
	snapapi_unlock_dev_queue(q);
	session->s_make_request_fn = NULL;
#else
	BUG_ON(!session->old_fops);
	snapapi_lock_dev_queue(q);
	sa_debug(DEBUG_API, " Restoring original fops %p for disk %s", session->old_fops, SN_BDEV(session->s_bdev)->bd_disk->disk_name);
	new_fops = SN_BDEV(session->s_bdev)->bd_disk->fops;
	SN_BDEV(session->s_bdev)->bd_disk->fops = session->old_fops;
	snapapi_unlock_dev_queue(q);
	session->old_fops = NULL;
	kfree(new_fops);
#endif
	session->s_request_queue = NULL;
	session->s_queue_mq_based = 0;
	sa_debug(DEBUG_API, "make_request deinstalled OK. s=%p\n", session);
}

SA_STATIC int do_resolver(void)
{
	struct session_struct *session = NULL;
	sa_debug(DEBUG_API, "\n");

	spin_lock(&sessions_lock);
	session = find_deadlocked();
	if (!session) {
		spin_unlock(&sessions_lock);
		return 0;
	}
	atomic_inc(&session->s_users);
	spin_unlock(&sessions_lock);

	sn_set_mb(session->s_state, SNAP_FREEZE_ERR);
	unregister_make_request(session);
	sa_info("Real cleanup started... s=%p(%x)", session, session->s_kdev);
	sn_thaw_bdev(session);
	cleanup_biolist(session);
	atomic_dec(&session->s_users);
	return 1;
}

SA_STATIC int resolver_loop(void *flag)
{
	sa_debug(DEBUG_API, "\n");

	while (1) {
		snapapi_try_to_freeze();
		set_current_state(TASK_INTERRUPTIBLE);
		if (!resolver_thread_continue)
			break;

		schedule();
		if (resolver_thread_continue)
			while (do_resolver())
				;
		else
			break;
		if (signal_pending(current))
			flush_signals(current);
	}
	sa_debug(DEBUG_API, "exiting\n");
	sa_complete_and_exit(&resolver_thread_exited, 0);
	return 0;
}

#ifdef HAVE_INIT_TIMER
SA_STATIC void heartbeat_timer_func(unsigned long __data)
#else
SA_STATIC void heartbeat_timer_func(struct timer_list *t)
#endif
{
#ifdef HAVE_INIT_TIMER
	struct session_struct *session = (struct session_struct *) __data;
#else
	struct session_struct *session =  from_timer(session, t, s_timer);
#endif
	int ioctls = atomic_read(&session->s_pid_info->sn_ioctls);

	if (!session->s_heartbeat_active || ioctls != session->s_ioctlcnt_prev) {
		sa_debug(DEBUG_API, "s=%p(%x) %d %u %u %u\n", session, session->s_kdev,
			session->s_heartbeat_active,
			ioctls, session->s_ioctlcnt_prev, session->s_ioctlcnt);
		if (session->s_heartbeat_active)
			mod_timer(&session->s_timer, jiffies + TIMER_INTERVAL);
		session->s_ioctlcnt_prev = ioctls;
		return;
	}
	sa_info("Deadlock detected.dev=%x, cnt=%d, state=%d. Unfreezing...\n",
			session->s_kdev, ioctls, session->s_state);
	sn_set_mb(session->s_state, SNAP_DEADLOCK_ERR);
	wake_up_process(resolver_thread);
}

SA_STATIC void sa_heartbeat_stop(struct session_struct *session)
{
	spin_lock_bh(&session->s_misc_lock);
	session->s_heartbeat_active = 0;
	spin_unlock_bh(&session->s_misc_lock);
	if (session->s_timer.function) {
		del_timer_sync(&session->s_timer);
		session->s_timer.function = NULL;
	}
}

SA_STATIC void sa_heartbeat_start(struct session_struct *session)
{
	spin_lock_bh(&session->s_misc_lock);
	session->s_heartbeat_active = 1;
	session->s_ioctlcnt_prev = atomic_read(&session->s_pid_info->sn_ioctls);
#ifdef HAVE_INIT_TIMER
	init_timer(&session->s_timer);
	session->s_timer.function = &heartbeat_timer_func;
	session->s_timer.data = (unsigned long)session;
#else
	timer_setup(&session->s_timer, heartbeat_timer_func, 0);
#endif
	session->s_timer.expires = jiffies + TIMER_INTERVAL;
	add_timer(&session->s_timer);
	spin_unlock_bh(&session->s_misc_lock);
}

int validate_kernel_version(void)
{
#ifdef HAVE_BDOPS_SUBMIT_BIO
	// checking the applicability of utsname()
	if (current->nsproxy != NULL) {
		if (strncmp(UTS_RELEASE, utsname()->release, strlen(UTS_RELEASE)) != 0)
			return 1;
#if defined(CHECK_UTS_VERSION)
		if (strncmp(UTS_VERSION, utsname()->version, strlen(UTS_VERSION)) != 0)
			return 1;
#endif
	}
#endif
	return 0;
}

#ifdef HAVE_BDOPS_SUBMIT_BIO
SA_STATIC bool init_sn_blk_submit_bio(void);
#endif

SA_STATIC int session_freeze(struct session_struct *session)
{
	int ret = -EINVAL;
	struct request_queue *q = NULL;

	sa_debug(DEBUG_API, "s=%p(%x)\n", session, session->s_kdev);

#ifdef HAVE_BDOPS_SUBMIT_BIO
	if (validate_kernel_version() != 0) {
#if defined(CHECK_UTS_VERSION)
		sa_warn("snapapi26 module was built for another kernel, have %s %s expecting %s %s.",
				utsname()->release, utsname()->version, UTS_RELEASE, UTS_VERSION);
#else
		sa_warn("snapapi26 module was built for another kernel, have %s expecting %s.",
				utsname()->release, UTS_RELEASE);
#endif
		if (!init_sn_blk_submit_bio()) {
			sa_error("snapapi26 cannot be initialized. Exiting...");
			return -ENXIO;
		}
	}
#endif
	down(&session->s_sem);

	if (sn_make_request_fn(session)|| session->s_queue_mq_based || session->s_state != SNAP_INITED)
		goto out_up;
/* sync !!! */
	sn_freeze_bdev(session);
	if (!session->s_sb) {
		sa_debug(DEBUG_INTERNALS, "Can't find super, dev %x, freeze.\n", session->s_kdev);
#if 0
		sa_warn("Can't find super, device %x, freeze.\n", session->s_kdev);
		sn_set_mb(session->s_state, SNAP_FREEZE_ERR);
		ret = -ESRCH;
		goto out_up;
#endif
	}
	sn_set_mb(session->s_state, SNAP_FREEZING);
	if (register_make_request(session)) {
		sa_warn("Device %x does not have a queue.\n", session->s_kdev);
		sn_set_mb(session->s_state, SNAP_FREEZE_ERR);
		sn_thaw_bdev(session);
		goto out_up;
	}
/* The queue exists. It has been checked in register_make_request */
	q = bdev_get_queue(SN_BDEV(session->s_bdev));
	set_current_state(TASK_UNINTERRUPTIBLE);
#if defined (HAVE_REQUEST_QUEUE_RQS) || defined (HAVE_REQUEST_LIST_COUNT)
	do {
#ifdef HAVE_REQUEST_QUEUE_RQS
		const int rq_cnt = q->nr_rqs[WRITE];
#else
		const int rq_cnt = q->rq.count[WRITE];
#endif
		if (rq_cnt == 0)
			break;
		schedule_timeout(HZ / 20);
		sa_debug(DEBUG_INTERNALS, "count=%d, nr_requests=%lu\n",
			rq_cnt, q->nr_requests);
	} while (1);
#endif /* HAVE_REQUEST_QUEUE_RQS || HAVE_REQUEST_LIST_COUNT */
#ifdef HAVE_UNDERLINE_STATE
	current->__state = TASK_RUNNING;
#else
	current->state = TASK_RUNNING;
#endif
	sn_set_mb(session->s_state, SNAP_FROZEN);

	sa_heartbeat_start(session);
	ret = 0;

out_up:
	up(&session->s_sem);
	return ret;
}

SA_STATIC int session_unfreeze(struct session_struct *session)
{
	int ret;

	sa_debug(DEBUG_API, "s=%p(%x)\n", session, session->s_kdev);
	ret = -EINVAL;
	down(&session->s_sem);
	if (session->s_state != SNAP_FROZEN && session->s_state != SNAP_FREEZE_ERR)
		goto out_up;
	up(&session->s_sem);
	ret = 0;
	close_session(session, 0);
	return ret;

out_up:
	up(&session->s_sem);
	return ret;
}

SA_STATIC void session_stat(struct sn_state *sn)
{
	sa_warn("dev=%d:%d state=%d blksize=%d mmapsize=%d\n",
		sn->major, sn->minor, sn->state, sn->blksize, sn->mmapsize);
	sa_warn("psize=%llu pstrt=%llu mshft=%d ioctls=%u\n",
		sn->partsize, sn->partstrt, sn->minorshft, sn->ioctlcnt);
	sa_warn("bhpgs=%d bhcnt=%d abhs=%llu fbhs=%llu dbhs=%llu\n",
		sn->bhpages, sn->bhcount, sn->abhs, sn->fbhs, sn->dbhs);

	sa_warn("gpgs=%llu ppgs=%llu emmax=%d emmin=%d emcur=%d cached=%d\n",
		sn->gpages, sn->ppages, sn->emmax, sn->emmin, sn->emcur,
		sn->cachepages);

	sa_warn("rblk=%llu cblk=%llu rcblk=%llu rc2blk=%llu mcblk=%llu"
		" rwcolls=%llu\n", sn->rblocks, sn->cblocks,
		sn->rcblocks, sn->rc2blocks, sn->mcblocks, sn->rwcolls);

	sa_warn("sync=%u async=%u aretr=%u mipr=%u iprcnt=%u\n",
		sn->sync_req, sn->async_req, sn->async_retr,
		sn->mipr, sn->iprcnt);
	sa_warn("mbio=%u ioctlcnt=%u ioctlpid=%u\n",
		sn->mbio, sn->ioctlcnt, sn->ioctlpid);

	sa_warn("rccalls=%llu maxrcdepth=%llu rcdepthcnts=(%llu, %llu, %llu, %llu)\n",
		sn->rccalls, sn->maxrcdepth,
		sn->rcdepthcnt[0], sn->rcdepthcnt[1], sn->rcdepthcnt[2], sn->rcdepthcnt[3]);
	sa_warn("flags=%llu\n", sn->flags);
}

SA_STATIC void fill_state(struct session_struct *session, struct sn_state *out)
{
	out->state = session->s_state;
	out->major = MAJOR(session->s_kdev);
	out->minor = MINOR(session->s_kdev);
	out->blksize = session->s_bsize;
	out->mmapsize = session->s_maxmsize * PAGE_SIZE;

	out->partstrt = session->s_pstart;
	out->minorshft = 0;
	out->partsize = session->s_plen;

	out->bhpages = session->s_biopages;
	out->bhcount = session->s_biocount;
	out->emmax = session->s_blkcache_emmax;
	out->emmin = session->s_blkcache_emmin;
	out->emcur = session->s_blkcache_empages;
	out->cachepages = session->s_blkcache_pages;

	out->gpages = read_get_pages(session);
	out->ppages = read_put_pages(session);
	out->abhs = session->s_abios;
	out->fbhs = session->s_fbios;
	out->dbhs = session->s_dbios;
	out->rblocks = session->s_rblocks;
	out->cblocks = session->s_cblocks;
	out->rcblocks = session->s_rcblocks;
	out->fcblocks = session->s_fcblocks;
	out->mcblocks = session->s_mcblocks;
	out->rwcolls = session->s_rwcolls;
	out->rc2blocks = session->s_rc2blocks;
	out->sync_req = session->s_sync_req;
	out->mipr = session->s_mipr;
	out->async_req = session->s_async_req;
	out->iprcnt = session->s_iprcnt;
	out->async_retr = session->s_async_retr;
	out->mbio = session->s_mbio;
	out->ioctlcnt = session->s_ioctlcnt;
	out->ioctlpid = session->s_pid_info ? atomic_read(&session->s_pid_info->sn_ioctls) : 0;
	out->version =  (COMMON_VMAJOR << 16) + (COMMON_VMINOR << 8) +
							COMMON_VSUBMINOR;

	out->extrasize = sizeof(struct sn_state) - offsetof(struct sn_state, extrasize);
	out->rccalls = session->s_rccalls;
	out->maxrcdepth = session->s_maxrcdepth;
	out->rcdepthcnt[0] = session->s_rcdepthcnt[0];
	out->rcdepthcnt[1] = session->s_rcdepthcnt[1];
	out->rcdepthcnt[2] = session->s_rcdepthcnt[2];
	out->rcdepthcnt[3] = session->s_rcdepthcnt[3];
	out->flags = 0;
	if (validate_kernel_version() != 0)
	  out->flags |= KERNEL_NOT_MATCHED;
}

SA_STATIC int session_state(struct session_struct *session, struct sn_state *state,
						unsigned int size)
{
	int ret;
	struct sn_state out = {0};

	sa_debug(DEBUG_API, "s=%p, state=%p\n", session, state);
	fill_state(session, &out);
	if (size > sizeof(out))
		size = sizeof(out);
	ret = copy_to_user(state, &out, size);
	if (ret)
		return -EACCES;
	return 0;
}

#if 0
SA_STATIC void dump_sessions(void)
{
	struct session_struct *session = NULL;
	sa_warn("Start sessions dump\n");
	list_for_each_entry(session, &sessions_list, s_list) {
		sa_warn("dev=%d:%d state=%u blksize=%u mmapsize=%d queue=%p\n",
			MAJOR(session->s_kdev), MINOR(session->s_kdev), session->s_state,
			session->s_bsize,  (int)(session->s_maxmsize * PAGE_SIZE),
			session->s_request_queue);
		sa_warn("psize=%llu pstrt=%llu mshft=%d ioctls=%d\n",
			session->s_plen, session->s_pstart, 0, session->s_ioctlcnt);
		sa_warn("bhpgs=%d bhcnt=%d abhs=%llu fbhs=%llu dbhs=%llu\n",
			session->s_biopages, session->s_biocount, session->s_abios, session->s_fbios,
			session->s_dbios);
		sa_warn("gpgs=%llu ppgs=%llu emmax=%d emmin=%d emcur=%d"
			" cached=%d\n", read_get_pages(s), read_get_pages(s),
			session->s_blkcache_emmax, session->s_blkcache_emmin,
			session->s_blkcache_empages, session->s_blkcache_pages);
		sa_warn("rblk=%llu cblk=%llu rcblk=%llu rc2blk=%llu mcblk=%llu"
			" rwcolls=%llu\n", session->s_rblocks, session->s_cblocks,
			session->s_rcblocks, session->s_rc2blocks, session->s_mcblocks,
			session->s_rwcolls);
	}
	sa_warn("End of sessions dump\n");
}
#endif

#define _READS ios[0]
#define _WRITES ios[1]
#define _READ_SECTORS sectors[0]
#define _WRITE_SECTORS sectors[1]

SA_STATIC sn_bdev_open_t *sn_blkdev_get_by_dev(dev_t kdev, fmode_t mode, void* holder)
{
	sn_bdev_open_t *_bdev = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
	_bdev = bdev_file_open_by_dev(kdev, mode, holder, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
	_bdev = bdev_open_by_dev(kdev, mode, holder, NULL);
#elif defined(HAVE_BDGET)
	_bdev = bdget(kdev);
	sa_debug(DEBUG_API, "kdev=%x bdev=%p\n", kdev, _bdev);
	if (!_bdev)
		return NULL;
	if (blkdev_get(_bdev, mode) < 0)
		return NULL;
	sa_debug(DEBUG_API, "bd_part=%p bd_contains=%p\n", _bdev->bd_part,
			_bdev->bd_contains);
#elif defined(HAVE_BLKDEV_GET_4ARGS)
	_bdev = blkdev_get_by_dev(kdev, mode, holder, NULL);
#else
	_bdev = blkdev_get_by_dev(kdev, mode, holder);
#endif
	if (IS_ERR(_bdev))
		return NULL;
	sa_debug(DEBUG_API, "kdev=%x bdev=%p\n", kdev, SN_BDEV(_bdev));
	return _bdev;
}

SA_STATIC int session_devinfo(struct session_struct *session, dev_t kdev,
				struct sn_devinfo *info, unsigned int size)
{
	int ret;
	struct sn_devinfo out = {0};
	sn_bdev_open_t *_bdev = NULL;

	sa_debug(DEBUG_API, "s=%p, devinfo=%p\n", session, info);
	out.major = MAJOR(kdev);
	out.minor = MINOR(kdev);
	_bdev = sn_blkdev_get_by_dev(kdev, BLK_OPEN_READ, NULL);
	if (!_bdev)
		return -ENODEV;
	out.partstrt = get_start_sect(SN_BDEV(_bdev));
#ifdef HAVE_BDEV_IS_PARTITION
	if (bdev_is_partition(SN_BDEV(_bdev))) {
#else
	if (SN_BDEV(_bdev)->bd_part) {
#endif
#ifdef HAVE_BDEV_NR_SECTORS
		out.partsize = bdev_nr_sectors(SN_BDEV(_bdev));
#else
		out.partsize = SN_BDEV(_bdev)->bd_part->nr_sects;
#endif
#ifndef HAVE_BD_PART
		out.reads = part_stat_read(SN_BDEV(_bdev), _READS);
		out.read_sectors = part_stat_read(SN_BDEV(_bdev), _READ_SECTORS);
		out.writes = part_stat_read(SN_BDEV(_bdev), _WRITES);
		out.write_sectors = part_stat_read(SN_BDEV(_bdev), _WRITE_SECTORS);
#else
		out.reads = part_stat_read(SN_BDEV(_bdev)->bd_part, _READS);
		out.read_sectors = part_stat_read(SN_BDEV(_bdev)->bd_part, _READ_SECTORS);
		out.writes = part_stat_read(SN_BDEV(_bdev)->bd_part, _WRITES);
		out.write_sectors = part_stat_read(SN_BDEV(_bdev)->bd_part, _WRITE_SECTORS);
#endif /*HAVE_BD_PART*/
	} else if (SN_BDEV(_bdev)->bd_disk) {
		out.partsize = get_capacity(SN_BDEV(_bdev)->bd_disk);
#ifndef HAVE_BD_PART
		out.reads = part_stat_read(SN_BDEV(_bdev), _READS);
		out.read_sectors = part_stat_read(SN_BDEV(_bdev), _READ_SECTORS);
		out.writes = part_stat_read(SN_BDEV(_bdev), _WRITES);
		out.write_sectors = part_stat_read(SN_BDEV(_bdev), _WRITE_SECTORS);
#else
		out.reads = part_stat_read(&SN_BDEV(_bdev)->bd_disk->part0, _READS);
		out.read_sectors = part_stat_read(&SN_BDEV(_bdev)->bd_disk->part0, _READ_SECTORS);
		out.writes = part_stat_read(&SN_BDEV(_bdev)->bd_disk->part0, _WRITES);
		out.write_sectors = part_stat_read(&SN_BDEV(_bdev)->bd_disk->part0, _WRITE_SECTORS);
#endif /*HAVE_BD_PART*/
	}
	else
		sa_warn("Can't detect device %x size.\n", kdev);
	out.blksize = block_size(SN_BDEV(_bdev));
	sn_blkdev_put(_bdev, BLK_OPEN_READ, NULL);
	if (size > sizeof(out))
		size = sizeof(out);
	ret = copy_to_user(info, &out, size);
	if (ret)
		return -EACCES;
	return 0;
}

SA_STATIC int session_getbno(struct session_struct *session, unsigned long long *data)
{
	unsigned long long bno;
	int err;

	if (!session->s_blkmap.blkmap || session->s_state != SNAP_MAPPED) {
		sa_warn("session_getbno failed. state=%d\n", session->s_state);
		return -EINVAL;
	}
	down(&session->s_sem);
	bno = any_block_in_cache(session);
	up(&session->s_sem);
	sa_debug(DEBUG_BREAD, "s=%p, bno=%llu\n", session, bno);
	err = put_user(bno, data);
	if (err)
		sa_warn("session_getbno failed. err=%d\n", err);

	return err;
}

SA_STATIC int session_rdcache(struct session_struct *session, struct sn_rdcache *req,
						unsigned int size)
{
	int ret;
	struct sn_rdcache rdc = {0};
	struct page *page = NULL;
	unsigned int max_blocks;
	char *data = NULL;
	unsigned long long bno;
	unsigned int i;

	sa_debug(DEBUG_API, "s=%p, req=%p\n", session, req);
	if (!session->s_blkmap.blkmap || session->s_state != SNAP_MAPPED)
		return -EINVAL;
	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	if (size > sizeof(rdc))
		size = sizeof(rdc);
	ret = copy_from_user(&rdc, req, size);
	if (ret || rdc.buf == 0 || rdc.size == 0) {
		put_page(page);
		return  -EACCES;
	}
	down(&session->s_sem);
	rdc.bno = any_block_in_cache(session);
	if (rdc.bno == ~0ULL)
		goto out_up;
	max_blocks = rdc.size / session->s_bsize;
	data = rdc.buf;
	bno = rdc.bno;
	for (i = 0; i < max_blocks; i++, bno++, data += session->s_bsize) {
		ret = sa_cache_read(session, page_address(page), bno,
				READ_KERNEL1, SNAP_READ_ONCE);
		if (!ret)
			break;
		ret = copy_to_user(data, page_address(page), session->s_bsize);
		if (ret) {
			ret = -EACCES;
			break;
		}
		session->s_rc2blocks++;
	}
	rdc.count = bno - rdc.bno;
out_up:
	up(&session->s_sem);
	put_page(page);
	if (ret)
		return ret;
	ret = copy_to_user(req, &rdc, size);
	if (ret)
		return -EACCES;
	sa_debug(DEBUG_BREAD, "s=%p, bno=%llu count=%u\n", session, rdc.bno, rdc.count);
	return 0;
}

SA_STATIC int session_bfree(struct session_struct *session, unsigned long long bno,
				unsigned long long count)
{
	int ret;
	unsigned long long end;

	ret = -EINVAL;
	sa_debug(DEBUG_BREAD, "s=%p, bno=%llu, count=%llu\n", session, bno, count);
	down(&session->s_sem);
	if (!session->s_blkmap.blkmap)
		goto out;
	end = bno + count;
	if (end < bno || end > session->s_blkmap.size)
		goto out;
	if (session->s_state != SNAP_MAPPED)
		goto out;

	for (; count; bno++, count--) {
		if (clear_block_in_map(&session->s_blkmap, bno) == 0)
			sa_cache_read(session, NULL, bno, FAKE_READ, SNAP_READ_ONCE);
 	}
	ret = 0;

out:
	up(&session->s_sem);
	return ret;
}

static SA_INLINE char * bread_data_addr(struct session_struct *session, int i)
{
	if (session->s_bppage == 1)
		return (session->s_mpages + (i << PAGE_SHIFT));
	return (session->s_mpages + ((i / session->s_bppage) << PAGE_SHIFT) +
			(i % session->s_bppage) * session->s_bsize);
}

SA_STATIC void bread_submit_bios(struct session_struct *session,
		unsigned long long bno, int count)
{
	struct bio *bio = NULL;
	struct page *page = NULL;
	int i, k;
	int vecs, page_idx, last_len;

	i = 0;
	page_idx = 0;
	last_len = count % session->s_bppage;
	session->s_rblocks += count;

	while (count > 0) {
repeate:
		vecs = sn_div_round(count, session->s_bppage);

		bio = sa_bio_alloc(session, vecs);
		if (!bio) {
			schedule();
			goto repeate;
		}
		session->s_abios++;
#ifdef HAVE_BIO_ALLOC_2ARGS
#ifndef HAVE_BIO_SET_DEV
		bio->bi_bdev = SN_BDEV(session->s_bdev);
#else
		bio_set_dev(bio, SN_BDEV(session->s_bdev));
#endif
#endif

#ifdef HAVE_BVEC_ITER
		bio->bi_iter.bi_sector = ((sector_t) bno) * session->s_spb;
#else
		bio->bi_sector = ((sector_t) bno) * session->s_spb;
#endif
		init_completion(&session->s_local_bios[i].event);
		bio->bi_private = &session->s_local_bios[i].event;
		bio->bi_end_io = sa_cache_bio_end_io;

		for (k = 0; k < vecs; k++) {
			int vec_len = PAGE_SIZE;
			page = vmalloc_to_page(session->s_mpages + (page_idx << PAGE_SHIFT));
			if (count == last_len)
				vec_len = last_len * session->s_bsize;
			if (bio_add_page(bio, page, vec_len , 0) < vec_len)
				break;
			count -= vec_len / session->s_bsize;
			page_idx++;
		}

		session->s_local_bios[i].bio = bio;
		bno += sn_bio_bi_size(bio) / session->s_bsize;
		sn_submit_bio(READ, bio);
		i++;
	}
}

SA_STATIC int bread_from_cache(struct session_struct *session, unsigned long long bno,
		unsigned int count, unsigned int flags)
{
	int i, numread, ret;

	sa_debug(DEBUG_BREAD, "s=%p, bno=%llu, count=%u\n",
				session, bno, count);
	numread = 0;
	for (i = 0; i < count; i++, bno++) {
		char * data;

		data = bread_data_addr(session, i);
		ret = sa_cache_read(session, data, bno, READ_KERNEL1, flags);
		if (ret)
			numread++;
	}
	return numread;
}

SA_STATIC int bread_wait_submitted(struct session_struct *session,
				unsigned long long bno, unsigned int count)
{
	int i, ret;
	int reqs;

	ret = 0;
	reqs = session->s_msize;
	for (i = 0; i < reqs; i++) {
		if (!session->s_local_bios[i].bio)
			continue;
		wait_for_completion(&session->s_local_bios[i].event);
		if (sn_is_error_bio(session->s_local_bios[i].bio))
			ret = -EIO;
	}
	return ret;
}

#if 0
static SA_INLINE void dump_data(void *data, int offset, char *pref)
{
	unsigned char *p = (unsigned char *)data + offset;
	sa_debug(DEBUG_BREAD, "%s %x:%x %x %x %x %x %x %x %x %x %x %x %x %x"
		" %x %x %x\n",
		pref, offset,
		*p, *(p+1), *(p+2), *(p+3), *(p+4), *(p+5), *(p+6), *(p+7),
		*(p+8), *(p+9), *(p+10), *(p+11), *(p+12), *(p+13), *(p+14),
		*(p+15));
}
#endif
SA_STATIC int session_bread_fast(struct session_struct *session, unsigned long long bno,
			unsigned int count, unsigned int flags,
			unsigned long long *bincache)
{
	int ret, ccnt, i;
	unsigned long long cachecnt;
	unsigned int rcount;	/* saved count */
	unsigned int reqs;

	ret = ccnt = 0;
	rcount = count;

	sa_debug(DEBUG_BREAD, "s=%p, bno=%llu, count=%u\n",
				session, bno, count);
	if (bno + count > (session->s_plen >> session->s_spbshift))
		count = (session->s_plen >> session->s_spbshift) - bno;
	bread_submit_bios(session, bno, count);
	ret = bread_wait_submitted(session, bno, count);
	if (!ret) /* read from cache only requested blocks */ {
		if (flags & SNAP_READ_ONCE)
			for (i = 0; i < rcount; i++)
				clear_block_in_map(&session->s_blkmap, bno + i);
		ccnt = bread_from_cache(session, bno, rcount, flags);
	}
	reqs = session->s_msize;
	for (i = 0; i < reqs; i++) {
		if (session->s_local_bios[i].bio) {
			bio_put(session->s_local_bios[i].bio);
			session->s_local_bios[i].bio = NULL;
			session->s_fbios++;
		}
	}
	cachecnt = 0;
	if (!(flags & SNAP_READ_ONCE))
		/* wakeup user level cache in none SNAP_READ_ONCE mode only */
		cachecnt = session->s_cblocks - session->s_fcblocks;
	sa_debug(DEBUG_BREAD, "s=%p, bno=%llu, L=%u, R=%d, C=%d\n",
				session, bno, count, rcount, ccnt);
	sa_debug(DEBUG_CACHE, "cached=%llu, read=%llu, incache=%llu\n",
					session->s_cblocks, session->s_rcblocks, cachecnt);
/*	dump_data(session->s_mpages, 0, "session_bread_fast"); */
	up(&session->s_sem);
	if (!ret && copy_to_user(bincache, &cachecnt, sizeof(cachecnt)))
		return -EACCES;
	return ret;
}

static SA_INLINE int sn_page_mapcount(struct page *page)
{
#ifdef HAVE_PAGE_UMAPCOUNT
	return atomic_read(&page->_mapcount) + 1;
#elif defined(HAVE_PAGE_MAPCOUNT)
	return page_mapcount(page);
#else
	return (page->mapcount);
#endif
}

SA_STATIC int session_copy_to_cow(struct session_struct *session, char *data, unsigned int count)
{
	char *page_ref = NULL;
	int size = PAGE_SIZE;

	for (page_ref = session->s_mpages; count; data += PAGE_SIZE) {
		struct page *page = NULL;

		if (count < session->s_bppage) {
			size = count * session->s_bsize;
			count = 0;
		} else
			count -= session->s_bppage;

		page = vmalloc_to_page(page_ref);
		if (page && !sn_page_mapcount(page))
			if (copy_to_user(data, page_ref, size))
				return -EACCES;
		page_ref += PAGE_SIZE;
	}
	return 0;
}

SA_STATIC int session_bread(struct session_struct *session, unsigned long long bno,
			unsigned int count, char *data, unsigned int flags,
			unsigned long long *bincache)
{
	int ret;
	unsigned long long end;

	ret = -EINVAL;

	sa_debug(DEBUG_BREAD, "s=%p, bno=%llu, count=%u\n", session, bno, count);
	down(&session->s_sem);
	if (!session->s_blkmap.blkmap)
		goto out;
	end = bno + count;
	if (end < bno || end > session->s_blkmap.size)
		goto out;
	if (session->s_state != SNAP_MAPPED)
		goto out;

	if (session->s_vma && data == (char *)session->s_vma->vm_start &&
				count * session->s_bsize <= PAGE_SIZE * session->s_msize) {
		ret = session_bread_fast(session, bno, count, flags, bincache);
		/* coping data up to user COW'ed pages if any*/
		if (!ret && session->s_vma->anon_vma)
			ret = session_copy_to_cow(session, data, count);
		return ret;
	}
	ret = -EINVAL;
	sa_warn("Interface error.%s","\n");
out:
	up(&session->s_sem);
	return ret;
}

SA_STATIC int session_ldmap(struct session_struct *session, unsigned long long size,
								void *map)
{
	int ret;

	ret = -EINVAL;
	sa_debug(DEBUG_API, "size=%llu\n", size);
	down(&session->s_sem);
	if (session->s_state != SNAP_FROZEN)
		goto out_up;
	sn_set_mb(session->s_state, SNAP_INITINGMAP);
#ifdef USE_VZ_VZSNAP
	if (session->s_veid) /* block_map already filled by block_map_init_vzsnap */
		ret = 0;
	else
#endif
	ret = block_map_init(session, size, map, 1);
	sa_heartbeat_stop(session);
	if (ret) {
		sn_set_mb(session->s_state, SNAP_MAP_ERR);
		goto out_unlock;
	}

	wait_for_users(session);
	sn_set_mb(session->s_state, SNAP_MAPPED);
	spin_unlock(&sessions_lock);

	ret = start_req_handler_thread(session);
	if (ret < 0)
		goto out_unlock;
	/* push delayed bios */
	cleanup_biolist(session);
	ret = 0;

out_unlock:
	sn_thaw_bdev(session);
out_up:
	up(&session->s_sem);
	return ret;
}

SA_STATIC void copy_page_bits_slow(void* dst, unsigned int dstbit, void* src,
				unsigned int srcbit, unsigned int len)
{
	while (len--) {
		if (test_bit(srcbit++, src))
			set_bit(dstbit++, dst);
		else
			clear_bit(dstbit++, dst);
	}
}

/* !NOTE!: we assume dst and src both are points to page start */

SA_STATIC void copy_page_bits(unsigned int* dst, unsigned int dstbit,
				unsigned int* src, unsigned int srcbit,
				unsigned int len)
{
	unsigned int *srcend = NULL;
	unsigned int headlen;

	/* normalize destination ptr and bitno by 4-byte boundary */
	dst += dstbit >> 5;
	dstbit &= 31;
	headlen = 32 - dstbit;
	if (len < headlen)
		headlen = len;
	copy_page_bits_slow(dst++, dstbit, src, srcbit, headlen);
	len -= headlen;
	if (!len)
		return;
	srcbit += headlen;
	/* normalize source ptr and bitno by 4-byte boundary*/
	src += srcbit >> 5;
	srcbit &= 31;
	/* processing the full DWORD's, DWORD-count is len/32 */
	srcend = src + (len >> 5);
	for (; src != srcend; src++)
		*dst++ = *(unsigned long long*)src >> srcbit;
	/* processing the tail, tail length is low 5 bits of len */
	copy_page_bits_slow(dst, 0, src, srcbit, len & 31);
}

SA_STATIC void copy_block_to_bitmap(struct session_struct *session, unsigned long long dest_bit,
						unsigned int len, void* array)
{
	unsigned int src_bit;

	src_bit = 0;
	while (len) {
		struct page *page = NULL;
		void *kaddr = NULL;
		unsigned int count;
		unsigned int bitno;	/* start bit on destination page */

		page = blkmap_page(session->s_blkmap.blkmap,
					dest_bit >> (PAGE_SHIFT + 3));
		bitno = dest_bit & (BITS_ON_PAGE - 1);
		count = BITS_ON_PAGE - bitno;
		if (count > len)
			count = len;
		kaddr = sn_kmap_atomic(page);
		copy_page_bits(kaddr, bitno, array, src_bit, count);
		sn_kunmap_atomic(kaddr);
		dest_bit += count;
		src_bit +=count;
		len -= count;
	}
}

SA_STATIC int compute_bitmap_ext2(struct session_struct *session)
{
	unsigned long long fblock;	/* first data block */
	unsigned int bpgroup;		/* blocks per group */
	unsigned int lgroup; 		/* last group */
	struct page *block_page = NULL;
	void *block = NULL;
	unsigned int count;

	count = 0;
	fblock = session->s_fblock;
	lgroup = session->s_gcount - 1;
	bpgroup =session->s_bpgroup;

	block_page = alloc_page(GFP_KERNEL);
	if (!block_page)
		return -1;
	block = page_address(block_page);
	while (1) {
		unsigned long long group;
		unsigned long long cblock;	/* current block */
		unsigned long long gstart_bit;
		int copy_count;

		cblock = any_block_in_cache(session);
		if (cblock == ~0ULL)
			break;
		group = cblock;
		gstart_bit = cblock - do_div(group, bpgroup) + fblock;
		if (sa_cache_read(session, block, cblock, 0, SNAP_READ_ONCE)
							!= session->s_bsize)
			break;
		count++;
		copy_count = bpgroup;
		if (group == lgroup)
			copy_count = session->s_blkmap.size - gstart_bit;
		copy_block_to_bitmap(session, gstart_bit, copy_count, block);
	}

	put_page(block_page);
	return count;
}

SA_STATIC int copy_bitmap_to_user(struct session_struct *session, char* bitmap)
{
	void *taddr = NULL;
	struct page *tpage = NULL;
	int ret;
	unsigned int pageno;
	unsigned long long bytes;

	ret = -ENOMEM;
	bytes = (session->s_blkmap.size + 7) >> 3;
	tpage = alloc_page(GFP_KERNEL);
	if (!tpage)
		goto out;
	taddr = page_address(tpage);
	ret = 0;
	for (pageno = 0; bytes; bitmap += PAGE_SIZE, pageno++) {
		unsigned int copy_count;
		struct page *page = NULL;
		char *kaddr = NULL;

		page = blkmap_page(session->s_blkmap.blkmap, pageno);
		/* checking for last group */
		copy_count = bytes > PAGE_SIZE ? PAGE_SIZE : bytes;
		if (page) {
			kaddr = sn_kmap_atomic(page);
			memcpy(taddr, kaddr, copy_count);
			sn_kunmap_atomic(kaddr);
		} else
			memset(taddr, 0, PAGE_SIZE);
		ret = copy_to_user(bitmap, taddr, copy_count);
		if (ret) {
			ret = -EACCES;
			break;
		}
		bytes -= copy_count;
	}

out:
	if (tpage)
		put_page(tpage);
	return ret;
}

SA_STATIC int check_session_params(struct session_struct *session)
{
	if (session->s_state != SNAP_FROZEN) {
		sa_warn("Session must be frozen (state=%d)\n", session->s_state);
		return -EINVAL;
	}

	if (!session->s_sb && !session->s_ok_freeze && !session->s_simulate_freeze) {
		sa_warn("No superblock info for s=%p\n", session);
		return -EINVAL;
	}

	if (session->s_sb && strncmp(session->s_sb->s_type->name, "ext", 3)) {
		sa_warn("Invalid partition type (%s)\n", session->s_sb->s_type->name);
		return -EINVAL;
	}
	return 0;
}

#ifdef USE_VZ_VZSNAP
SA_STATIC int vzsnap_getmap(struct session_struct *session)
{
	int ret;

	ret = -EINVAL;
	sn_set_mb(session->s_state, SNAP_MAP_ERR);
	if (session->s_vzs)
		return ret;
	session->s_vzs = vzsnap_get_map(session->s_veid, SN_BDEV(session->s_bdev));
	if (session->s_vzs == NULL) {
		vzsnap_release_map(session->s_vzs);
		return ret;
	}
	ret = block_map_init_vzsnap(session, session->s_vzs);
	vzsnap_release_map(session->s_vzs);
	session->s_vzs = NULL;
	if (ret)
		return ret;
	sn_set_mb(session->s_state, SNAP_FROZEN);
	return 0;
}
#endif //USE_VZ_VZSNAP

SA_STATIC int session_getmap(struct session_struct *session, unsigned long long size,
		void* bitmap, unsigned long bsize, unsigned long fblock,
		unsigned long bpgroup, unsigned long gcount)
{
	int ret;
	int pended;
	int bcount;
	unsigned long long bno;

	sa_debug(DEBUG_API, "s=%p size=%llu, bmap=%p, bsize=%lu, fblock=%lu,"
			" bpgroup=%lu, gcount=%lu\n", session, size, bitmap, bsize,
			fblock, bpgroup, gcount);
	bcount = 0;
	ret = -EINVAL;
	if (!bitmap || !size)
		return ret;

	down(&session->s_sem);
	ret = check_session_params(session);
	if (ret)
		goto out_up;

	session->s_fblock = fblock;
	session->s_gcount = gcount;
	session->s_bpgroup = bpgroup;
	session->s_bmsize = size;

	sn_set_mb(session->s_state, SNAP_INITINGMAP);
	sa_heartbeat_stop(session);
#ifdef USE_VZ_VZSNAP
	if (session->s_veid) {
		ret = vzsnap_getmap(session);
		if (ret)
			goto out_thaw;
		goto out_copy;
	}
#endif
	ret = block_map_init(session, size, bitmap, 0);
	if (ret) {
		sa_warn("block_map_init failed\n");
		goto out_thaw;
	}
	simulate_ioctl(session);
	wait_for_users(session);
	sn_set_mb(session->s_state, SNAP_READINGMAP);
	sn_set_mb(session->s_usemap, 0);
	spin_unlock(&sessions_lock);

	ret = start_req_handler_thread(session);
	if (ret < 0)
		goto out_thaw;

	flush_biolist(session);
	sn_thaw_bdev(session);

	/* Reading bitmap from device */
	bno = 0;
	while (1) {

		bno = find_next_block(&session->s_blkmap, bno);
		if (bno == ~0ULL)
			break;

		if (sa_cache_block(session, NULL, bno, 1, &pended)) {
			sa_warn("reading bitmap: sa_cache_block(%llu)\n", bno);
			goto out_destroy;
		}

		simulate_ioctl(session);

		bno++;
		bcount++;
	}

	stop_req_handler_thread(session, 1);
	sn_freeze_bdev(session);
	wait_for_users(session);
	sn_set_mb(session->s_state, SNAP_FROZEN);
	spin_unlock(&sessions_lock);

	ret = compute_bitmap_ext2(session);
	if (bcount != ret) {
		ret = -EPROTO;
		sa_warn("computing bitmap: %d!=%d\n", bcount, ret);
		goto out_thaw;
	}
/*	Setting bits at start of bitmap till FirstDataBlock	*/
/*	Moved to userspace 					*/
/*	for (bno = 0; bno < fblock; bno++)
		set_block_in_map(&session->s_blkmap, bno);
*/
#ifdef USE_VZ_VZSNAP
out_copy:
#endif
	simulate_ioctl(session);
	ret = copy_bitmap_to_user(session, bitmap);
	if (ret)
		goto out_thaw;

	simulate_ioctl(session);
	sa_heartbeat_start(session);
	up(&session->s_sem);
	return 0;

out_thaw:
	sn_thaw_bdev(session);

out_destroy:
	block_map_destroy(session);
	sn_set_mb(session->s_state, SNAP_MAP_ERR);

out_up:
	up(&session->s_sem);

	return ret;
}

SA_STATIC int copy_bits_to_user(unsigned long* map, unsigned long long bitno,
		unsigned long* src, unsigned int count)
{
	unsigned int rel;
	unsigned long uval;
	unsigned int offset = 0;
	int ret = 0;

	sa_debug(DEBUG_API, "map=%p bitno=%llu count=%u\n", map, bitno, count);
	if (bitno & 7) {
		/* Here target begin (and possibly end) is *not* aligned on byte border,
		   so we have to copy everything manually. */
		map += bitno / BITS_PER_LONG;

		/* First we copy all the bits until target hits 'long' border */
		ret = get_user(uval, map);
		if (ret)
			goto out;
		for (rel = bitno & (BITS_PER_LONG - 1);
				rel < BITS_PER_LONG && offset < count; ++rel, ++offset) {
			if (test_bit(offset, src))
				set_bit(rel, &uval);
			else
				clear_bit(rel, &uval);
		}
		ret = put_user(uval, map++);
		if (ret)
			goto out;

		/* Now our target is aligned on 'long' border, so we can copy data using full longs
		   up until last 'long' that possibly should not be copied fully.
		   Required bits of last 'long' will be copied later */
		while (count - offset >= BITS_PER_LONG) {
			uval = 0;
			for (rel = 0; rel < BITS_PER_LONG; ++rel, ++offset) {
				if (test_bit(offset, src))
					set_bit(rel, &uval);
			}
			ret = put_user(uval, map++);
			if (ret)
				goto out;
		}
	}
	else {
		/* Here we know that the target begin is aligned on byte border,
		   but the target end can still be not aligned on byte if count&7 != 0.
		   So we use copy_to_user to copy all whole bytes
		   and leave the bits in last non-whole byte to be copied on the next step. */
		/* uval is the number of bits to copy in last byte if it is not copied fully*/
		uval = (bitno + count) & 7;
		if (uval < count) {
			unsigned int bcnt = (count - uval) >> 3;
			ret = copy_to_user((unsigned char*)map + (bitno >> 3), src, bcnt);
			if (ret)
				goto out;
			offset = bcnt << 3;
		}
		map += (bitno + offset) / BITS_PER_LONG;
	}

	if (offset < count) {
		/* Here we copy last bits of bitmap when target's end in not aligned
		   on either unsigned long or byte depending on the branch that was taken previously.*/
		ret = get_user(uval, map);
		if (ret)
			goto out;
		for (rel = (bitno + offset) & (BITS_PER_LONG - 1); offset < count;
							++rel, ++offset) {
			if (test_bit(offset, src))
				set_bit(rel, &uval);
			else
				clear_bit(rel, &uval);
		}
		ret = put_user(uval, map);
		if (ret)
			goto out;
	}

out:
	return ret;
}

SA_STATIC int collect_bitmap_to_user(struct session_struct *session, void* map)
{
	int ret;
	struct page *block_page = NULL;
	void *block = NULL;

	sa_debug(DEBUG_API, "s=%p map=%p\n", session, map);
	ret = 0;
	block_page = alloc_page(GFP_KERNEL);
	if (!block_page)
		return -ENOMEM;
	block = page_address(block_page);

	map_init_iterator(&session->s_groupmap);
	ret = -EINVAL;
	do {
		unsigned long long bitno;
		unsigned long copy_count;
		struct group_entry *entry = NULL;

		entry = (void*)map_iterator_get_value(&session->s_groupmap);
		BUG_ON(!entry);

		bitno = (unsigned long long)entry->group * session->s_bpgroup + session->s_fblock;

		copy_count = session->s_bpgroup;
		if (entry->group == session->s_gcount - 1)
			copy_count = session->s_bmsize - bitno;

		if (!entry->cached)
			memset(block, 0, (copy_count + 7) >> 3);
		else if (sa_cache_read(session, block, entry->bno, 0,
						SNAP_READ_ONCE)	!= session->s_bsize) {
			sa_warn("cache block %llu can't be read\n", entry->bno);
			map_iterator_stop(&session->s_groupmap);
			break;
		}

		ret = copy_bits_to_user(map, bitno, block, copy_count);
		if (ret) {
			sa_warn("copy_bits_to_user failed (%d)\n", ret);
			break;
		}
	} while (map_iterator_next(&session->s_groupmap));

	put_page(block_page);
	return ret;
}

SA_STATIC int session_getsparsedmap(struct session_struct *session,
		unsigned long long size, void *bitmap, unsigned long bsize,
		unsigned long fblock, unsigned long bpgroup,
		unsigned long gcount, unsigned long groups)
{
	int ret;
	int pended;
	struct group_entry *entry = NULL;

	sa_debug(DEBUG_API, "s=%p size=%llu bsize=%lu fblock=%lu bpgroup=%lu "
			"gcount=%lu groups=%lu\n", 
		session, size, bsize, fblock, bpgroup,
			gcount, groups);

	ret = -EINVAL;
	if (!bitmap || !size || !gcount || !session->s_sb)
		return ret;

	down(&session->s_sem);
	if (session->s_state != SNAP_FROZEN) {
		sa_warn("Session must be frozen (state=%d)\n", session->s_state);
		goto out_up;
	}

	if (strcmp(session->s_sb->s_type->name, "ext2") &&
	    strcmp(session->s_sb->s_type->name, "ext3") &&
	    strcmp(session->s_sb->s_type->name, "ext4"))
	{
		sa_warn("Invalid partition type (%s)\n", session->s_sb->s_type->name);
		goto out_up;
	}
	sn_set_mb(session->s_state, SNAP_INITINGMAP);

	session->s_fblock = fblock;
	session->s_gcount = gcount;
	session->s_bpgroup = bpgroup;
	session->s_bmsize = size;

	ret = map_init(session, groups, gcount);
	if (ret)
		goto out_thaw;

	simulate_ioctl(session);

	map_init_iterator(&session->s_groupmap);
	wait_for_users(session);
	sn_set_mb(session->s_state, SNAP_READINGMAP);
	sn_set_mb(session->s_usemap, 1);
	spin_unlock(&sessions_lock);

	sa_heartbeat_stop(session);
	ret = start_req_handler_thread(session);
	if (ret < 0)
		goto out_thaw;

	flush_biolist(session);
	sn_thaw_bdev(session);

	do {
		simulate_ioctl(session);
		entry = (struct group_entry*)map_iterator_get_value(&session->s_groupmap);

		BUG_ON(!entry);

		if (entry->init
		    && !entry->cached 
		    && sa_cache_block(session, NULL, entry->bno, 1, &pended))
		{
			sa_warn("caching block of %llu failed\n" , entry->bno);
			map_iterator_stop(&session->s_groupmap);
			goto out_destroy;
		}

	} while (map_iterator_next(&session->s_groupmap));

	stop_req_handler_thread(session, 1);
	sn_freeze_bdev(session);
	wait_for_users(session);
	sn_set_mb(session->s_state, SNAP_FROZEN);
	spin_unlock(&sessions_lock);

	ret = collect_bitmap_to_user(session, bitmap);
	if (ret)
		goto out_thaw;

	map_free(session);
	sa_heartbeat_start(session);
	simulate_ioctl(session);
	up(&session->s_sem);
	return 0;

out_thaw:
	sn_set_mb(session->s_state, SNAP_MAP_ERR);
	sn_thaw_bdev(session);

out_destroy:
	map_free(session);
	sn_set_mb(session->s_state, SNAP_MAP_ERR);

out_up:
	up(&session->s_sem);
	return ret;
}

SA_STATIC int do_init_session(struct session_struct *session, dev_t kdev, int prealloc)
{
	int ret;
	int sa_page_size;
	struct request_queue *q = NULL;

	ret = -ENODEV;
	session->s_bdev = sn_blkdev_get_by_dev(kdev, BLK_OPEN_READ, NULL);
	if (!session->s_bdev)
		goto out;
	ret = -ENODEV;
#ifdef HAVE_BDEV_WHOLE
	if (!bdev_whole(SN_BDEV(session->s_bdev)))
#else
	if (!SN_BDEV(session->s_bdev)->bd_contains)
#endif
		goto out_blk_put;
	session->s_sb = sn_get_super(SN_BDEV(session->s_bdev));
	sa_debug(DEBUG_INTERNALS, "session->s_sb=%p\n", session->s_sb);
	if (!session->s_sb) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0) || defined(HAVE_BD_SUPER)
		session->s_simulate_freeze = 1;
#endif
	} else {
		if (strcmp(session->s_sb->s_type->name, "vfat") == 0)
			session->s_simulate_freeze = 1;
		sn_drop_super(session->s_sb);
		session->s_sb = NULL;
	}
	session->s_bsize = (block_size(SN_BDEV(session->s_bdev)) > PAGE_SIZE) ? PAGE_SIZE : block_size(SN_BDEV(session->s_bdev));
	session->s_bppage = PAGE_SIZE / session->s_bsize;
	session->s_spb = session->s_bsize >> SECTOR_SHIFT;
	if (!session->s_spb) {
		sa_warn("Device %x has incorrect block size %d\n", kdev,
								session->s_bsize);
		goto out_blk_put;
	}
	session->s_spbshift = ffz(~session->s_spb);
	session->s_pstart = get_start_sect(SN_BDEV(session->s_bdev));
#ifdef HAVE_BDEV_IS_PARTITION
	if (bdev_is_partition(SN_BDEV(session->s_bdev)))
#else
	if (SN_BDEV(session->s_bdev)->bd_part)
#endif
#ifdef HAVE_BDEV_NR_SECTORS
		session->s_plen = bdev_nr_sectors(SN_BDEV(session->s_bdev));
#else
		session->s_plen = SN_BDEV(session->s_bdev)->bd_part->nr_sects;
#endif
	else if (SN_BDEV(session->s_bdev)->bd_disk)
		session->s_plen = get_capacity(SN_BDEV(session->s_bdev)->bd_disk);
	else
		sa_warn("Can't detect device %x size.\n", kdev);

	q = bdev_get_queue(SN_BDEV(session->s_bdev));
	if (!q) {
		sa_warn("Device %x does not have a queue.\n", kdev);
		goto out_blk_put;
	}

	sa_debug(DEBUG_API, "s_bsize=%d s_bppage=%d s_spb=%d s_spbshift=%d"
		" s_plen=%llu s_pstart=%llu\n",
		session->s_bsize, session->s_bppage, session->s_spb, session->s_spbshift, session->s_plen,
		session->s_pstart);

	ret = -ENOMEM;

	session->s_bioarr = (struct bio***)get_zeroed_page(GFP_KERNEL);
	if (!session->s_bioarr)
		goto out_blk_put;
	inc_get_pages(session);

	sprintf(session->s_blkcachename, "snapapi_blk_%lu", (unsigned long)atomic_inc_return(&slab_uid));
	sa_page_size = sizeof(struct sa_page) +
				sizeof(unsigned long long) * (session->s_bppage - 1);
	session->s_blkcachep = kmem_cache_create(session->s_blkcachename, sa_page_size,
											 0, SN_SLAB_FLAGS, NULL);
	if (!session->s_blkcachep)
		goto out_free;

	ret = sa_blkchains_init(session);
	if (ret)
		goto out_destroy_blkchains;

	ret = sa_cache_emlist_init(session, prealloc);
	if (ret)
		goto out_destroy;

	session->s_maxmsize = MAX_MMPAGES;
	session->s_ahead_bno = ~0ULL;
	/* pending queue init */
	session->s_pending_queue.pq_req = NULL;
	session->s_pending_queue.pq_reqtail = NULL;
	session->s_pending_queue.pq_state = 0;
	init_completion(&session->s_pending_queue.pq_done);
	init_completion(&session->s_pending_queue.pq_bio_done);
	atomic_set(&session->s_pending_queue.pq_ready_req, 0);
	atomic_set(&session->s_pending_queue.pq_notready_req, 0);
	session->s_pending_queue.pq_state = PQ_STOPPED;

	sn_set_mb(session->s_state, SNAP_INITED);
	return 0;

out_destroy:
	sa_cache_emlist_destroy(session);
out_destroy_blkchains:
	sa_blkchains_destroy(session);
out_free:
	free_page((unsigned long)session->s_bioarr);
	inc_put_pages(session);
	session->s_bioarr = NULL;
out_blk_put:
	sn_blkdev_put(session->s_bdev, BLK_OPEN_READ, NULL);
out:
	sn_set_mb(session->s_state, SNAP_NOTINITED);
	session->s_bdev = NULL;
	return ret;
}

SA_STATIC void mpages_destroy(struct session_struct *session)
{
	sa_debug(DEBUG_API, "s=%p\n", session);

	if (session->s_mpages) {
		vfree(session->s_mpages);
		session->s_mpages = NULL;
	}
	if (session->s_local_bios) {
		sa_debug(DEBUG_INTERNALS, "s=%p, free local_bios(%p)\n",
				session, session->s_local_bios);
		kfree(session->s_local_bios);
		session->s_local_bios = NULL;
	}

	session->s_msize = 0;
}

#define	DL_READ 0
#define	DL_WRITE 1

SA_STATIC const char* devlock_name(unsigned lock_type)
{
	return lock_type == DL_WRITE ? "write" : "read";
}

SA_STATIC struct locked_dev* find_lockeddev(struct session_struct *session,
					dev_t dev)
{
	struct locked_dev *idev = devlocked;
	struct locked_dev *end = devlocked + MAX_LOCKEDDEVS;

	for (; idev != end; idev++)
		if (idev->dev == dev && idev->sess == session)
			return idev;
	return 0;
}

SA_STATIC struct locked_dev* create_lockeddev(struct session_struct *session,
			sn_bdev_open_t *_bdev, dev_t dev, unsigned lock_type)
{
	struct locked_dev *idev = devlocked;
	struct locked_dev *end = devlocked + MAX_LOCKEDDEVS;

	for (; idev != end; idev++)
		if (!idev->dev) {
			idev->dev = dev;
			idev->d_bdev = _bdev;
			idev->sess = session;
			idev->lock_type = lock_type;
			lockedcnt++;
			return idev;
		}
	return 0;
}

SA_STATIC void remove_lockeddev(struct locked_dev* ldev)
{
	memset(ldev, 0, sizeof(struct locked_dev));
	lockedcnt--;
}

SA_STATIC int _sn_lockdev_check_sb(struct block_device *bdev)
{
	struct super_block *sb = sn_get_super(bdev);
	if (sb) {
		sn_drop_super(sb);
		return -EBUSY;
	}
	return 0;
}

SA_STATIC int _sn_lockdev(dev_t dev, void* holder, sn_bdev_open_t **rbdev)
{
	int ret;
	sn_bdev_open_t *_bdev = sn_blkdev_get_by_dev(dev, BLK_OPEN_READ, NULL);

	if (!_bdev)
		return -ENODEV;

	ret = _sn_lockdev_check_sb(SN_BDEV(_bdev));
	sn_blkdev_put(_bdev, BLK_OPEN_READ, NULL);
	if (ret)
		return ret;

	*rbdev = sn_blkdev_get_by_dev(dev, BLK_OPEN_READ | BLK_OPEN_EXCL, holder);
	if (!*rbdev)
		return -EBUSY;

	return 0;
}

SA_STATIC void _sn_unlockdev(sn_bdev_open_t *_bdev, void *holder)
{
	sn_blkdev_put(_bdev, BLK_OPEN_READ | BLK_OPEN_EXCL, holder);
}

static noinline int session_lockdev(struct session_struct *session, dev_t dev,
						unsigned lock_type)
{
	int ret;
	struct locked_dev *ldev = NULL;
	sn_bdev_open_t *_bdev = NULL;
	void *holder = NULL;

	sa_debug(DEBUG_API, "s=%p, dev=%x, type=%s\n", session,
			dev, devlock_name(lock_type));
	ret = -ENOMEM;

	down(&devlocked_sem);
	if (lockedcnt >= MAX_LOCKEDDEVS || !devlocked)
		goto out_up;
	ret = -ENODEV;
	ldev = find_lockeddev(session, dev);
	if (ldev) {
		ret = -EEXIST;
		sa_warn("Device %X already have %s-lock for session %p.\n",
			dev, devlock_name(ldev->lock_type), session);
		goto out_up;
	}

	holder = lock_type == DL_WRITE ? session : (void *)session_lockdev;
	ret = _sn_lockdev(dev, holder, &_bdev);
	if (ret)
		goto out_up;

	ldev = create_lockeddev(session, _bdev, dev, lock_type);
	if (!ldev) {
		sa_warn("All devlocked slots are exhausted\n");
		ret = -ENOMEM;
		goto out_release;
	}
	up(&devlocked_sem);
	return 0;

out_release:
	_sn_unlockdev(_bdev, holder);
out_up:
	up(&devlocked_sem);
	return ret;
}

SA_STATIC int session_unlockdev(struct session_struct *session, dev_t dev,
						unsigned lock_type)
{
	int ret;
	struct locked_dev *ldev = NULL;
	void *holder = NULL;

	sa_debug(DEBUG_API, "s=%p, dev=%x, type=%s\n", session,
			dev, devlock_name(lock_type));
	ret = -ENOMEM;
	down(&devlocked_sem);
	if (!devlocked)
		goto out_up;
	ret = -ESRCH;
	ldev = find_lockeddev(session, dev);
	if (!ldev) {
		sa_warn("No lock for device (%X) in session (%p)\n", dev, session);
		goto out_up;
	}
	ret = -EINVAL;
	if (ldev->lock_type != lock_type) {
		sa_warn("Lock for device (%X) in session (%p) is of type %s\n",
			dev, session, devlock_name(lock_type));
		goto out_up;
	}

	holder = lock_type == DL_WRITE ? session : (void *)session_lockdev;
	_sn_unlockdev(ldev->d_bdev, holder);

	remove_lockeddev(ldev);
	ret = 0;

out_up:
	up(&devlocked_sem);
	return ret;
}

SA_STATIC void unlock_sessiondevs(struct session_struct *session)
{
	struct locked_dev* idev = NULL, *end = NULL;
	void *holder = NULL;

	sa_debug(DEBUG_API, "\n");

	down(&devlocked_sem);
	if (!devlocked)
		goto out_up;
	end = devlocked + MAX_LOCKEDDEVS;

	for (idev = devlocked; idev != end; idev++) {
		if (!idev->d_bdev || idev->sess != session)
			continue;

		holder = idev->lock_type == DL_WRITE ? session : (void *)session_lockdev;
		_sn_unlockdev(idev->d_bdev, holder);
		remove_lockeddev(idev);
	}
out_up:
	up(&devlocked_sem);
}

SA_STATIC int session_set_pidinfo(struct session_struct *session)
{
	int i;
	struct sn_pid_info* free_p = NULL;
	struct sn_pid_info* curr_p = pid_info_p;
	pid_t pid = current->pid;

	for (i = 0; i < MAX_PID_INFO; i++, curr_p++) {
		if (!curr_p->sn_pid && !free_p)
			free_p = curr_p;
		if (curr_p->sn_pid == pid) {
			atomic_inc(&curr_p->sn_refs);
			session->s_pid_info = curr_p;
			return 0;
		}
	}
	if (free_p) {
		free_p->sn_pid = pid;
		session->s_pid_info = free_p;
		atomic_inc(&free_p->sn_refs);
		return 0;
	}
	return 1;
}

SA_STATIC void session_reset_pidinfo(struct session_struct *session)
{
	if (!session->s_pid_info)
		return;

	if (atomic_dec_and_test(&session->s_pid_info->sn_refs)) {
		session->s_pid_info->sn_pid = 0;
		atomic_set(&session->s_pid_info->sn_ioctls, 0);
	}
	session->s_pid_info = NULL;
}

SA_STATIC void close_session(struct session_struct *session, int do_free)
{
	sa_debug(DEBUG_API, "s=%p\n", session);
	down(&session->s_sem);
	sa_heartbeat_stop(session);
	unregister_make_request(session);
	stop_req_handler_thread(session, 0);
	sa_debug(DEBUG_API, "s=%p, users=%d, do_free=%d\n", session,
					atomic_read(&session->s_users), do_free);
	wait_for_users(session);
	spin_unlock(&sessions_lock);
	if (session->s_state == SNAP_FROZEN) {
		sn_thaw_bdev(session);
	}
	mpages_destroy(session);
	sa_cache_emlist_destroy(session);
	cleanup_biolist(session);
	cleanup_snapshot(session);
	if (session->s_bdev) {
		sn_blkdev_put(session->s_bdev, BLK_OPEN_READ, NULL);
		session->s_bdev = NULL;
	}
	block_map_destroy(session);
	sa_blkchains_destroy(session);
	unlock_sessiondevs(session);

	if (session->s_kdev != 0 && session->s_rblocks) {
		struct sn_state out = {0};
		fill_state(session, &out);
		session_stat(&out);
	}
	spin_lock(&sessions_lock);
	list_del_init(&session->s_list);
	if (!do_free)
		list_add(&session->s_list, &notinited_list);
	session_reset_pidinfo(session);
	sn_set_mb(session->s_state, SNAP_NOTINITED);
	session->s_kdev = 0;
	spin_unlock(&sessions_lock);
	up(&session->s_sem);
	if (do_free)
		kfree(session);
}
#if 0
SA_STATIC int chk_conflicts(dev_t kdev)
{
	struct list_head *tmp = NULL

	list_for_each(tmp, &sessions_list) {
		struct session_struct *session = NULL

		session = list_entry(tmp, struct session_struct, s_list);
		/* one queue per device */
		if (MAJOR(session->s_kdev) == MAJOR(kdev))
			return 1;
	}
	return 0;
}
#endif
SA_STATIC int session_init(struct session_struct *session, dev_t kdev, int prealloc)
{
	int ret;

	sa_debug(DEBUG_API, "s=%p, dev=%x, prealloc=%d\n", session, kdev, prealloc);
	ret = -EBUSY;
	down(&session->s_sem);
	if (session->s_state != SNAP_NOTINITED)
		goto out;

	spin_lock(&sessions_lock);
/*
	if (chk_conflicts(kdev)) {
		spin_unlock(&sessions_lock);
		goto out;
	}
*/
	if (session_set_pidinfo(session)!= 0) {
		spin_unlock(&sessions_lock);
		sa_warn("No free pid_info, max %ld, device %x\n",
						MAX_PID_INFO, kdev);
		goto out;
	}

	list_del_init(&session->s_list);
	session->s_kdev = kdev;
	sn_set_mb(session->s_state, SNAP_ININIT);
	list_add_tail(&session->s_list, &sessions_list);
	spin_unlock(&sessions_lock);
	ret = do_init_session(session, kdev, prealloc);
	if (ret) {
		spin_lock(&sessions_lock);
		list_del_init(&session->s_list);
		session->s_kdev = 0;
		session_reset_pidinfo(session);
		sn_set_mb(session->s_state, SNAP_NOTINITED);
		list_add(&session->s_list, &notinited_list);
		spin_unlock(&sessions_lock);
		goto out;
	}
	sa_kdebug("OK. dev=%d:%d, bs=%d.\n", MAJOR(session->s_kdev), MINOR(session->s_kdev),
								session->s_bsize);
out:
	up(&session->s_sem);
	return ret;
}

SA_STATIC int session_messqstate(struct session_struct *session, unsigned int *state)
{
	int ret = -EFAULT;
	unsigned int out = 0;
	struct list_head *tmp = NULL;

	sa_debug(DEBUG_API,"s=%p\n", session);

	down(&messages_sem);
	spin_lock(&sessions_lock);
	list_for_each(tmp, &sessions_list) {
		struct session_struct *sp = NULL;

		sp = list_entry(tmp, struct session_struct, s_list);
		/* one queue per device */
		sa_debug(DEBUG_API,"sp=%p, sp->mess_pos=%d, mess_pos=%d\n", sp,
					sp->s_mess_pos, messages_pos);
		if (sp->s_mess_pos != messages_pos) {
			out = 1;
			goto out_up;
		}
	}
	list_for_each(tmp, &notinited_list) {
		struct session_struct *sp;

		sp = list_entry(tmp, struct session_struct, s_list);
		/* one queue per device */
		sa_debug(DEBUG_API,"sp=%p, sp->mess_pos=%d, mess_pos=%d\n", sp,
					sp->s_mess_pos, messages_pos);
		if (sp->s_mess_pos != messages_pos) {
			out = 1;
			break;
		}
	}
out_up:
	spin_unlock(&sessions_lock);
	up(&messages_sem);
	if (copy_to_user(state, &out, sizeof(*state)))
		goto out;

	ret = 0;
out:
	return ret;
}

SA_STATIC struct inode* sn_get_inode(struct file *filep)
{
#ifdef HAVE_FILE_F_DENTRY
	return filep->f_dentry->d_inode;
#else
	return file_inode(filep);
#endif
}

SA_STATIC struct dentry* sn_get_dentry(struct file *filep)
{
#ifdef HAVE_FILE_F_DENTRY
	return filep->f_dentry;
#else
	return filep->f_path.dentry;
#endif
}

SA_STATIC int session_resetatime(struct session_struct *session, unsigned int fd)
{
	int ret;
	struct file *file = NULL;
	struct inode *inode = NULL;

	sa_debug(DEBUG_API,"s=%p\n", session);
	down(&session->s_sem);
	ret = -ESRCH;
	file = fget(fd);
	if (!file)
		goto out_up;
	if (!sn_get_dentry(file) || !sn_get_inode(file))
		goto out_put;
	inode = sn_get_inode(file);
	inode->i_flags |= S_NOATIME;
	ret = 0;
out_put:
	fput(file);
out_up:
	up(&session->s_sem);
	return ret;
}

long snapapi3_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;
	struct session_struct *session = file->private_data;

	sa_debug(DEBUG_IOCTL, "cmd=%x\n", cmd);
	if (!session)
		return -EINVAL;
	err = -EFAULT;

	update_ioctl_counters(session);

	switch (cmd) {
	    case SNAPCTL_INIT: {
			struct snapctl_init s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_init(session, MKDEV(s.major, s.minor),
								s.prealloc);
		}
		break;
	    case SNAPCTL_FREEZE:
			err = session_freeze(session);
		break;
	    case SNAPCTL_UNFREEZE:
			err = session_unfreeze(session);
		break;
	    case SNAPCTL_GETMAP: {
			struct snapctl_getmap s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_getmap(session, s.map_size, s.map,
					(unsigned long)s.bsize,
					(unsigned long)s.fblock,
					(unsigned long)s.bpgroup,
					(unsigned long)s.gcount);
		}
		break;
	    case SNAPCTL_GETSPARSEDMAP: {
			struct snapctl_getsparsedmap s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_getsparsedmap(session, s.map_size, s.map,
					(unsigned long)s.bsize,
					(unsigned long)s.fblock,
					(unsigned long)s.bpgroup,
					(unsigned long)s.gcount,
					(unsigned long)s.groups);
		}
		break;
	    case SNAPCTL_LDMAP: {
			struct snapctl_ldmap s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_ldmap(session, s.map_size, s.map);
		}
		break;
	    case SNAPCTL_GETBNO: {
			struct snapctl_getbno s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_getbno(session, s.bno);
		}
		break;
	    case SNAPCTL_BFREE: {
			struct snapctl_bfree s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_bfree(session, s.bstart, s.count);
		}
		break;
	    case SNAPCTL_BREAD: {
			struct snapctl_bread s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_bread(session, s.bstart, s.count, s.data,
				s.flags,
				&(((struct snapctl_bread*)arg)->bincache));
		}
		break;
	    case SNAPCTL_STATE: {
			struct snapctl_state s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_state(session, s.state, s.size);
		}
		break;
	    case SNAPCTL_DEVINFO: {
			struct snapctl_devinfo s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_devinfo(session, MKDEV(s.major, s.minor),
								s.info, s.size);
		}
		break;
	    case SNAPCTL_DEVLOCK: {
			struct snapctl_devlock s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_lockdev(session, MKDEV(s.major, s.minor), DL_WRITE);
		}
		break;
	    case SNAPCTL_DEVUNLOCK: {
			struct snapctl_devunlock s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_unlockdev(session, MKDEV(s.major, s.minor), DL_WRITE);
		}
		break;
	    case SNAPCTL_DEVLOCKREAD: {
			struct snapctl_devlockread s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_lockdev(session, MKDEV(s.major, s.minor), DL_READ);
		}
		break;
	    case SNAPCTL_DEVUNLOCKREAD: {
			struct snapctl_devunlockread s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_unlockdev(session, MKDEV(s.major, s.minor), DL_READ);
		}
		break;
	    case SNAPCTL_MESSQSTATE: {
			struct snapctl_messqstate s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_messqstate(session, s.state);
		}
		break;
	    case SNAPCTL_RESETATIME: {
			struct snapctl_resetatime s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_resetatime(session, s.fd);
		}
		break;
	    case SNAPCTL_RDCACHE: {
			struct snapctl_rdcache s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = session_rdcache(session, s.data, s.size);
		}
		break;
#ifdef USE_VZ_VZSNAP
	    case SNAPCTL_SET_VEID: {
			unsigned int s;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			session->s_veid = s;
			err = 0;
		}
		break;
#endif
	    default:
		err = -ENOTTY;
		break;
	}
	if (err)
		sa_debug(DEBUG_API, "cmd=%x err=%d\n", cmd, -err);
	return err;
}

#ifndef HAVE_UNLOCKED_IOCTL
int snapapi4_ioctl(struct inode *ino, struct file *file, unsigned int cmd,
		unsigned long arg)
{
	return snapapi3_ioctl(file, cmd, arg);
}
#endif

#ifdef HAVE_IOCTL32_CONVERSION
SA_STATIC int snapapi_compat_ioctl(unsigned int fd, unsigned int cmd,
			unsigned long arg, struct file *filep)
{
	sa_debug(DEBUG_IOCTL, "cmd=%x\n", cmd);
	return snapapi3_ioctl(filep, cmd, arg);
}
#endif

#ifdef HAVE_COMPAT_IOCTL
long snapapi_compat_ioctl(struct file *filep, unsigned int cmd,
			unsigned long arg)
{
	sa_debug(DEBUG_IOCTL, "cmd=%x\n", cmd);
	return snapapi3_ioctl(filep, cmd, arg);
}
#endif

int snapapi_open(struct inode *ino, struct file *file)
{
	struct session_struct *session = NULL;

	sa_debug(DEBUG_API,"%s\n","enter");

	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session)
		return -ENOMEM;
	if (!try_module_get(THIS_MODULE)) {
		kfree(session);
		return -ENODEV;
	}
	INIT_LIST_HEAD(&session->s_list);
	sema_init(&session->s_sem, 1); /* unlocked state */
	session->s_heartbeat_active = 0;
	session->s_usemap = 0;
	spin_lock_init(&session->s_misc_lock);
	spin_lock_init(&session->s_biolist_lock);
	spin_lock_init(&session->s_blkcache_emlock);
	spin_lock_init(&session->s_pending_queue.pq_lock);
	spin_lock_init(&session->s_stat_lock);
	atomic_set(&session->s_users, 1);

	down(&messages_sem);
	session->s_mess_pos = messages_pos;
	up(&messages_sem);
	spin_lock(&sessions_lock);
	list_add(&session->s_list, &notinited_list);
	spin_unlock(&sessions_lock);

	file->private_data = session;
	sa_debug(DEBUG_API, "OK s=%p tgid=%d\n", session, current->tgid);
	return 0;
}

int snapapi_release(struct inode *ino, struct file *file)
{
	struct session_struct *session = file->private_data;

	sa_debug(DEBUG_API,"%s\n","enter");
	if (!session)
		return -EINVAL;
	file->private_data = NULL;

	close_session(session, 1);
	module_put(THIS_MODULE);
	sa_debug(DEBUG_API, "OK s=%p tgid=%d\n", session, current->tgid);
	return 0;
}

SA_STATIC struct page * snapapi_vm_nopage(struct vm_area_struct * vma,
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
	sa_debug(DEBUG_API,"s=%p, vma=%p, address=%lx, pgoff=%lu\n", session, vma,
			address, vma->vm_pgoff);

	i = (address - vma->vm_start) >> PAGE_SHIFT;

	if (i >= session->s_msize) {
		sa_warn("Incorrect address.%s", "\n");
		return (struct page *)VM_FAULT_ERROR;
	}

	page = vmalloc_to_page(session->s_mpages + (i << PAGE_SHIFT));
	get_page(page);

	sa_debug(DEBUG_ALLOC, "s=%p, nopage=%p(%d)\n", session, page,
					page_count(page));

	return page;
}

SA_STATIC VMFAULT_RETURN_VALUE snapapi_vm_fault(struct vm_area_struct * vma, struct vm_fault *vmf)
{
#ifdef HAVE_VMFAULT_VIRTUAL_ADDRESS
	unsigned long address = (unsigned long) vmf->virtual_address;
#else
	unsigned long address = (unsigned long) vmf->address;
#endif
#ifdef HAVE_VM_FAULT_2ARGS
	vmf->page = snapapi_vm_nopage(vma, address, 0);
#else
	vmf->page = snapapi_vm_nopage(vmf->vma, address, 0);
#endif
	if (vmf->page == (struct page *)VM_FAULT_ERROR)
		return VM_FAULT_ERROR;
	return 0;
}

SA_STATIC void snapapi_vm_open(struct vm_area_struct * vma)
{
	struct session_struct *session = NULL;

	if (!vma->vm_file) {
		sa_warn("vma does not have a file attached.%s", "\n");
		return;
	}
	session = vma->vm_file->private_data;
	sa_debug(DEBUG_API,"s=%p, vma=%p, users=%d\n", session, vma,
				atomic_read(&session->s_vma_users));
	atomic_inc(&session->s_vma_users);
}

SA_STATIC void snapapi_vm_close(struct vm_area_struct * vma)
{
	struct session_struct *session = NULL;

	if (!vma->vm_file) {
		sa_warn("vma does not have a file attached.%s", "\n");
		return;
	}
	session = vma->vm_file->private_data;
	sa_debug(DEBUG_API,"s=%p, vma=%p, users=%d\n", session, vma,
				atomic_read(&session->s_vma_users));
	if (!atomic_dec_and_test(&session->s_vma_users))
		return;

	session->s_vma = NULL;
	mpages_destroy(session);
}

static const struct vm_operations_struct snapctl_vm_ops = {
	open:	snapapi_vm_open,
	fault:	snapapi_vm_fault,
	close:	snapapi_vm_close,
};

int snapapi_mmap(struct file * file, struct vm_area_struct * vma)
{
	struct session_struct *session = file->private_data;
	int ret, size;

	sa_debug(DEBUG_API,"s=%p, vma=%p,%lx-%lx %lx %lx\n", session, vma,
						vma->vm_start, vma->vm_end,
						vma->vm_flags, vma->vm_pgoff);
	if (!session)
		return -EBADF;
	if (!(vma->vm_flags & VM_READ)
			|| (vma->vm_flags & VM_SHARED))
		return -EINVAL;

	ret = -EINVAL;
	down(&session->s_sem);
	if (session->s_vma || session->s_state < SNAP_INITED || vma->vm_pgoff != 0)
		goto out_up;

	ret = -ENOMEM;
	size = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	if (size > session->s_maxmsize || size < 1)
		goto out_up;

	session->s_msize = size; /* mmap size in pages */
	session->s_local_bios = kzalloc(sizeof(struct bio_req) * size, GFP_KERNEL);
	if (!session->s_local_bios)
		goto out_up;
	sa_debug(DEBUG_INTERNALS, "s=%p, mmap pages=%d, local_bios==%p\n", session,
						size, session->s_local_bios);

	session->s_mpages = sn_vmalloc_pages(size, GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO);
	if (!session->s_mpages) {
		goto out_destroy;
	}

	ret = 0;
	session->s_vma = vma;
	vma->vm_ops = &snapctl_vm_ops;
	atomic_set(&session->s_vma_users, 1);
	goto out_up;

out_destroy:
	session->s_vma = NULL;
	mpages_destroy(session);
out_up:
	up(&session->s_sem);
	return ret;
}

ssize_t snapapi_read(struct file * filp, char * buf, size_t count,
								loff_t *ppos)
{
	struct session_struct *session = filp->private_data;
	ssize_t size, read, ret;
	int idx;

	sa_debug(DEBUG_MESS, "s=%p, buf=%p, count=%lu, ppos=%lld\n", session,
				buf, (unsigned long)count, (long long)*ppos);
	if (!session)
		return -EBADF;
	if (count % MESSAGE_SIZE)
		return -EINVAL;
	if (*ppos != filp->f_pos)
		return -ESPIPE;
	/* Null write succeeds.  */
	if (count == 0)
		return 0;
	ret = -ERESTARTSYS;
	down(&session->s_sem);
	if (down_interruptible(&messages_sem))
		goto out_nolock;
	if (signal_pending(current))
		goto out;
	ret = 0;
	/* Always work in NONBLOCK mode */
	if (session->s_mess_pos == messages_pos)
		goto out;
	size = (messages_pos > session->s_mess_pos) ? messages_pos - session->s_mess_pos :
		MAX_MESSAGES - session->s_mess_pos + messages_pos;
	size *= MESSAGE_SIZE;
	if (size > count)
		size = count;
	idx = session->s_mess_pos + 1;
	read = 0;
	ret = -EFAULT;
	while (size > 0) {
		idx %= MAX_MESSAGES;
		if (copy_to_user(buf, &messages_buf[idx++], MESSAGE_SIZE))
			goto out;
		read += MESSAGE_SIZE;
		size -= MESSAGE_SIZE;
	}
	session->s_mess_pos = (idx - 1) % MAX_MESSAGES;
	ret = read;

out:
	up(&messages_sem);
out_nolock:
	up(&session->s_sem);
	return ret;
}

ssize_t snapapi_write(struct file *filp, const char *buf, size_t count,
								loff_t *ppos)
{
	struct session_struct *session = filp->private_data;
	int idx;
	ssize_t ret;

	sa_debug(DEBUG_MESS,"s=%p, buf=%p, count=%lu, ppos=%lld, f_pos=%lld\n",
			session, buf, (unsigned long)count, *ppos, filp->f_pos);
	if (!session)
		return -EBADF;
	if (count != MESSAGE_SIZE)
		return -EINVAL;
	if (*ppos != filp->f_pos)
		return -ESPIPE;
	/* Null write succeeds.  */
	if (count == 0)
		return 0;
	ret = -ERESTARTSYS;
	down(&session->s_sem);
	if (down_interruptible(&messages_sem))
		goto out_nolock;
	if (signal_pending(current))
		goto out;
	ret = -EFAULT;
	idx = (messages_pos + 1) % MAX_MESSAGES;
	if (copy_from_user(&messages_buf[idx], buf, MESSAGE_SIZE))
		goto out;
	messages_pos = idx;
	ret =  MESSAGE_SIZE;
	/* Signal readers asynchronously that there is more data.  */
	sa_debug(DEBUG_MESS, "s=%p, wake_up_interruptible\n", session);
	wake_up_interruptible(&select_wait);

out:
	up(&messages_sem);
out_nolock:
	up(&session->s_sem);
	return ret;
}

unsigned int snapapi_poll(struct file *filp, poll_table *wait)
{
	struct session_struct *session = filp->private_data;
	unsigned int mask;

	sa_debug(DEBUG_MESS, "s=%p\n", session);
	if (!session)
		return POLLERR;
	poll_wait(filp, &select_wait, wait);
	down(&session->s_sem);
	down(&messages_sem);
	mask = 0;
	if (session->s_mess_pos != messages_pos) {
		sa_debug(DEBUG_MESS,"s=%p, message ready\n", session);
		mask = POLLIN | POLLRDNORM;
	}
	up(&messages_sem);
	up(&session->s_sem);
	return mask;
}

void register_ioctl32(void)
{
#ifdef HAVE_IOCTL32_CONVERSION
	register_ioctl32_conversion(SNAPCTL_INIT, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_FREEZE, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_LDMAP, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_GETMAP, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_GETBNO, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_BREAD, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_BFREE, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_STATE, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_DEVINFO, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_DEVLOCK, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_DEVUNLOCK, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_UNFREEZE, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_MESSQSTATE, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_RESETATIME, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_RDCACHE, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_SET_VEID, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_START_SWAP_THREAD, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_STOP_SWAP_THREAD, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_DEVLOCKREAD, snapapi_compat_ioctl);
	register_ioctl32_conversion(SNAPCTL_DEVUNLOCKREAD, snapapi_compat_ioctl);
#endif
}

void unregister_ioctl32(void)
{
#ifdef HAVE_IOCTL32_CONVERSION
	unregister_ioctl32_conversion(SNAPCTL_INIT);
	unregister_ioctl32_conversion(SNAPCTL_FREEZE);
	unregister_ioctl32_conversion(SNAPCTL_LDMAP);
	unregister_ioctl32_conversion(SNAPCTL_GETMAP);
	unregister_ioctl32_conversion(SNAPCTL_GETBNO);
	unregister_ioctl32_conversion(SNAPCTL_BREAD);
	unregister_ioctl32_conversion(SNAPCTL_BFREE);
	unregister_ioctl32_conversion(SNAPCTL_STATE);
	unregister_ioctl32_conversion(SNAPCTL_DEVINFO);
	unregister_ioctl32_conversion(SNAPCTL_DEVLOCK);
	unregister_ioctl32_conversion(SNAPCTL_DEVUNLOCK);
	unregister_ioctl32_conversion(SNAPCTL_UNFREEZE);
	unregister_ioctl32_conversion(SNAPCTL_MESSQSTATE);
	unregister_ioctl32_conversion(SNAPCTL_RESETATIME);
	unregister_ioctl32_conversion(SNAPCTL_RDCACHE);
	unregister_ioctl32_conversion(SNAPCTL_SET_VEID);
	unregister_ioctl32_conversion(SNAPCTL_START_SWAP_THREAD);
	unregister_ioctl32_conversion(SNAPCTL_STOP_SWAP_THREAD);
	unregister_ioctl32_conversion(SNAPCTL_DEVLOCKREAD);
	unregister_ioctl32_conversion(SNAPCTL_DEVUNLOCKREAD);
#endif
}

int get_drv_pages(void)
{
	do
	{
		messages_buf = (struct snap_message *)get_zeroed_page(GFP_KERNEL);
		if (!messages_buf)
			break;

		devlocked = (struct locked_dev *)get_zeroed_page(GFP_KERNEL);
		if (!devlocked)
			break;

		pid_info_p = (struct sn_pid_info *)get_zeroed_page(GFP_KERNEL);
		if (!pid_info_p)
			break;

		return 0;
	} while (0);

	if (devlocked) {
		free_page((unsigned long)devlocked);
		devlocked = NULL;
	}
	if (messages_buf) {
		free_page((unsigned long)messages_buf);
		messages_buf = NULL;
	}

	return -ENOMEM;
}

void free_drv_pages(void)
{
	down(&devlocked_sem);
	if (devlocked) {
		free_page((unsigned long)devlocked);
		devlocked = NULL;
	}
	up(&devlocked_sem);
	down(&messages_sem);
	if (messages_buf) {
		free_page((unsigned long)messages_buf);
		messages_buf = NULL;
	}
	up(&messages_sem);
	if (pid_info_p) {
		free_page((unsigned long)pid_info_p);
		pid_info_p = NULL;
	}
}

void init_select_wait(void)
{
	init_waitqueue_head(&select_wait);
}

int start_resolver_thread(void)
{
	resolver_thread = kthread_create(resolver_loop, NULL, "snapapid");
	if (IS_ERR(resolver_thread)) {
		return PTR_ERR(resolver_thread);
	}
	wake_up_process(resolver_thread);
	return 0;
}

void stop_resolver_thread(void)
{
	if (!IS_ERR_OR_NULL(resolver_thread)) {
		resolver_thread_continue = 0;
		wmb();
		wake_up_process(resolver_thread);
		wait_for_completion(&resolver_thread_exited);
	}
}

#if defined(HAVE_BDOPS_SUBMIT_BIO)

#define NAME_BUFFER_SIZE 2048
#define MAX_TRIES_PATH_ALLOC 10
#define STR_ADDRESS_SIZE 16
#define SEPARATOR_SIZE 2 // symbol + whitespace (look into System.map)

SA_STATIC struct file *file_open(const char *path, int flags, int rights)
{
	struct file *filp = filp_open(path, flags, rights);
	int err = 0;

	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		sa_warn("snapapi26: could not open file %s, error: %d", path, err);
		return NULL;
	}
	return filp;
}

SA_STATIC void  file_close(struct file * filp)
{
	filp_close(filp, NULL);
}

SA_STATIC loff_t file_size(struct file * filp)
{
	if (!filp)
		return -EINVAL;

	return  vfs_llseek(filp, 0, SEEK_END);
}

SA_STATIC bool parse_buffer(const char * name, const char * buffer, int size, unsigned long long *pointer)
{
	const int address_size = STR_ADDRESS_SIZE;
	const int separator_size = SEPARATOR_SIZE;
	char addr [STR_ADDRESS_SIZE + 1]; // +1 for null-terminator
	char *ptr = NULL;
	int base = 16;

	if (size <= (address_size + separator_size))
		return false;

	ptr = strstr(buffer, name);
	if (!ptr)
		return false;

	ptr -= separator_size;
	if (ptr >= buffer + size)
		return false;
	ptr -= address_size;

	memcpy(addr, ptr, address_size);
	addr[STR_ADDRESS_SIZE] = '\0';

	return kstrtoull(addr, base, pointer) == 0 ? true : false;
}

SA_STATIC unsigned long long find_pointer(struct file * filp, const char * name)
{
	const int size = NAME_BUFFER_SIZE;
	unsigned long long pointer = 0;
	loff_t f_pos = 0;
	int read_size = 0;
	char *buffer = NULL;
	char *new_line = NULL;
	int distance;
	bool found;

	ssize_t bytes_count = file_size(filp);
	ssize_t max_tries = (bytes_count * 2) / size;

	buffer = (char*)kvmalloc(size + 1, GFP_KERNEL); // +1 for null-terminator

	if (buffer == NULL)
		return 0;

	while(max_tries--)
	{
		read_size = kernel_read(filp, buffer, size, &f_pos);
		if(read_size <= 0)
			break;

		// here no buffer overrun in case of read_size is max (real_size == size)
		// because real buffer length is size + 1, look at the buffer allocation
		buffer[read_size] = '\0';
		found = parse_buffer(name, buffer, read_size, &pointer);
		if (found)
			break;

		// returning file cursor to the beggining of the line, to scan whole line on the next iteration
		// first find a newline address, second calculate position of file_cursor
		new_line  = strrchr(buffer, '\n');
		distance = new_line ? &buffer[read_size - 1] - new_line : 0;
		f_pos -= distance;
	}

	kvfree((const void*)buffer);

	return pointer;
}

SA_STATIC bool init_sn_blk_submit_bio(void)
{
	unsigned long long blk_pointer = 0;
	unsigned long long printk_pointer = 0;
	struct file * filp = NULL;
	int size = NAME_BUFFER_SIZE;
	char * path = NULL;

	int result_size = 0;
	int max_tries = MAX_TRIES_PATH_ALLOC;
	bool result = false;

	do {
		path = (char*)kvmalloc(size, GFP_KERNEL);
		result_size = snprintf(path, size, "/boot/System.map-%s", utsname()->release);

		//in case we do not have enough memory for /boot/System.map-%s path, we have to realloc it
		if (result_size > size)
		{
			kvfree((const void*)path);
			path = NULL;
			size = result_size;
		} else {
			result = true;
		}
	} while (!result && --max_tries);

	if (!path)
		return false;

	filp = file_open(path, O_RDONLY, 0);
	kvfree((const void*)path);

	if (!filp)
		return false;

	blk_pointer = find_pointer(filp, " blk_mq_submit_bio\n");

#ifdef HAVE_PRINTK_INDEX
	printk_pointer = find_pointer(filp, " _printk\n");
#else
	printk_pointer = find_pointer(filp, " printk\n");
#endif

	file_close(filp);
	if (!blk_pointer || !printk_pointer)
	{
		_sn_blk_mq_submit_bio = NULL;
		return false;
	}

#ifdef HAVE_PRINTK_INDEX
	_sn_blk_mq_submit_bio =
		(MAKE_REQUEST_RETURN_VALUE (*)(struct bio *)) (blk_pointer + (long long)(((void *)_printk) - (void *)printk_pointer));
#else
	_sn_blk_mq_submit_bio =
		(MAKE_REQUEST_RETURN_VALUE (*)(struct bio *)) (blk_pointer + (long long)(((void *)printk) - (void *)printk_pointer));
#endif
	return _sn_blk_mq_submit_bio ? true : false;
}
#endif /* HAVE_BDOPS_SUBMIT_BIO */

