#ifndef SNCONFIG_H
#define SNCONFIG_H

#if defined(HAVE_GENERATED_AUTOCONF)
#include <generated/autoconf.h>
#elif defined(HAVE_LINUX_AUTOCONF)
#include <linux/autoconf.h>
#elif defined(HAVE_LINUX_CONFIG)
#include <linux/config.h>
#else
#warning "neither linux/config.h nor linux/autoconf.h or generated/autoconf.h found"
#endif

#ifdef HAVE_SCHED_SIGNAL_H
#include <linux/sched/signal.h>
#endif

#ifdef HAVE_BLK_CGROUP_H
#include <linux/blkdev.h>
#include <linux/cgroup.h>
#include <linux/blk-cgroup.h>
#endif

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
# error "use a 3.0.0 kernel or later, please"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
#include <asm/system.h>
#endif
#include <asm/div64.h>
#include <asm/uaccess.h>
#include <asm/bitops.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/smp.h>

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/interrupt.h> /* for in_interrupt */
#include <linux/poll.h>
#include <linux/timer.h>
#ifdef HAVE_IOCTL32_CONVERSIONS
#include <linux/ioctl32.h>
#endif
#ifdef HAVE_FREEZER_H
#include <linux/freezer.h>
#endif
#if defined(CONFIG_VZ_VZSNAP) || defined(CONFIG_VZ_VZSNAP_MODULE)
#define USE_VZ_VZSNAP
#include <linux/vzsnap.h>
#endif

#ifdef HAVE_PART_STAT_H
#  include <linux/part_stat.h>
#endif

#ifdef HAVE_BLK_MQ_MAKE_REQUEST
#  include <linux/blk-mq.h>
#endif

#ifdef HAVE_BIO_ENDIO_2ARGS
#	define sn_bio_endio(x) bio_endio(x, 0)
#else
#	define sn_bio_endio(x) bio_endio(x)
#endif /* HAVE_BIO_ENDIO_2ARGS */

#ifdef HAVE_KMAP_ATOMIC_2ARGS
#	define sn_kmap_atomic(a) kmap_atomic(a, KM_USER0)
#	define sn_kunmap_atomic(a) kunmap_atomic(a, KM_USER0)
#else /* 1 argument */
#	define sn_kmap_atomic(a) kmap_atomic(a)
#	define sn_kunmap_atomic(a) kunmap_atomic(a)
#endif

#ifdef HAVE_VMALLOC_3ARGS
#	define sn_vmalloc_page(a) __vmalloc(PAGE_SIZE, a, PAGE_KERNEL)
#	define sn_vmalloc_pages(a, b) __vmalloc((a) << PAGE_SHIFT, b, PAGE_KERNEL)
#else
#	define sn_vmalloc_page(a) __vmalloc(PAGE_SIZE, a)
#	define sn_vmalloc_pages(a, b) __vmalloc((a) << PAGE_SHIFT, b)
#endif

#ifdef HAVE_ASM_HAVE_SET_MB
#	define sn_set_mb set_mb
#else
#	define sn_set_mb smp_store_mb
#endif

#ifndef HAVE_VM_FAULT_2ARGS
#	define snapapi_vm_fault(a, b) snapapi_vm_fault(b)
#endif

#ifdef HAVE_VMFAULT_T
#	define VMFAULT_RETURN_VALUE vm_fault_t
#else
#	define VMFAULT_RETURN_VALUE int
#endif

#ifndef HAVE_FMODE_T
typedef unsigned int fmode_t;
#endif

#ifndef BLK_OPEN_READ
#	define BLK_OPEN_READ FMODE_READ
#endif

#ifndef BLK_OPEN_WRITE
#	define BLK_OPEN_WRITE FMODE_WRITE
#endif

#ifndef BLK_OPEN_EXCL
#	define BLK_OPEN_EXCL FMODE_EXCL
#endif

#if defined(__x86_64) && defined(HAVE_IOCTL32_H) && defined(CONFIG_COMPAT) && !defined(HAVE_COMPAT_IOCTL)
#	define HAVE_IOCTL32_CONVERSION
#endif

#ifdef HAVE_BDOPS_RELEASE_VOID
#	define BLK_OPS_RELEASE_RETURN_VALUE void
#	define BLK_OPS_RELEASE_RETURN_STATUS
#else
#	define BLK_OPS_RELEASE_RETURN_VALUE int
#	define BLK_OPS_RELEASE_RETURN_STATUS 0
#endif

#ifdef HAVE_BD_SUPER
#	define sn_get_super(bdev) (bdev)->bd_super
#	define sn_drop_super(sb)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#	define sn_get_super(bdev) get_super(bdev)
#	define sn_drop_super(sb) drop_super(sb)
#else
#	define sn_get_super(bdev) (NULL)
#	define sn_drop_super(sb)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,0) && LINUX_VERSION_CODE < KERNEL_VERSION(4,20,0)
#	define SN_SLAB_FLAGS	SLAB_TYPESAFE_BY_RCU
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
#	define SN_SLAB_FLAGS	SLAB_RECLAIM_ACCOUNT
#else
#	define SN_SLAB_FLAGS	(SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD)
#endif

#if defined (HAVE_BDOPS_SUBMIT_BIO_BLK_QC_T) || defined(HAVE_BDOPS_SUBMIT_BIO_VOID)
#	define HAVE_BDOPS_SUBMIT_BIO 1
#endif

#ifdef HAVE_BDOPS_SUBMIT_BIO
#include <linux/utsname.h>
#include <generated/utsrelease.h>

#ifdef HAVE_COMPILE_H
#include <generated/compile.h>
#endif

#ifdef HAVE_UTS_VERSION_H
#include <generated/utsversion.h>
#endif

/* Ubuntu 2304 dosn't open UTS_VERSION for public */

#ifndef UTS_VERSION
#	define UTS_VERSION "'no uts version'"
#else
#	define CHECK_UTS_VERSION 1
#endif

#ifdef HAVE_BDOPS_SUBMIT_BIO_VOID
#	define MAKE_REQUEST_RETURN_VALUE void
#	define MAKE_REQUEST_EXIT_STATUS
#else
#	define MAKE_REQUEST_RETURN_VALUE blk_qc_t
#	define MAKE_REQUEST_EXIT_STATUS 0
#endif

#define sn_make_request submit_bio_noacct
#define sn_make_request_fn(s) ((s)->old_fops ? (s)->old_fops->submit_bio : NULL)

typedef MAKE_REQUEST_RETURN_VALUE (make_request_fn) (struct bio *bio);

#else /* HAVE_BDOPS_SUBMIT_BIO */

#ifdef HAVE_MAKE_REQUEST_INT
#	define MAKE_REQUEST_EXIT_STATUS 0
#	define MAKE_REQUEST_RETURN_VALUE int
#elif defined(HAVE_MAKE_REQUEST_BLK_QC_T)
#	define MAKE_REQUEST_EXIT_STATUS 0
#	define MAKE_REQUEST_RETURN_VALUE blk_qc_t
#else
#	define MAKE_REQUEST_EXIT_STATUS
#	define MAKE_REQUEST_RETURN_VALUE void
#endif

#define sn_make_request generic_make_request
#define sn_make_request_fn(s) ((s)->s_make_request_fn)

#endif /* HAVE_BDOPS_SUBMIT_BIO */

#ifdef HAVE_BLKDEV_PUT_INT
#	define MAKE_BLKDEV_RETURN_VALUE int
#else
#	define MAKE_BLKDEV_RETURN_VALUE void
#endif

#ifndef BIO_MAX_PAGES
#	define BIO_MAX_PAGES BIO_MAX_VECS
#endif

#ifndef SECTOR_SHIFT
#	define SECTOR_SHIFT 9
#endif
#ifndef SECTOR_SIZE
#	define SECTOR_SIZE (1 << SECTOR_SHIFT)
#endif

#define sn_div_round(a,b)	(((a) + (b) - 1) / (b))
#define sn_round_up(a,b)	(sn_div_round(a,b) * (b))
#define sn_is_power_of_2(x)	((x) != 0 && (((x) & ((x) - 1)) == 0))

static __always_inline bool sn_op_is_write(struct bio *bio)
{
	return bio_data_dir(bio) != 0;
}

static __always_inline sector_t sn_bio_bi_sector(struct bio *bio)
{
#ifdef HAVE_BVEC_ITER
	return bio->bi_iter.bi_sector;
#else
	return bio->bi_sector;
#endif
}

static __always_inline unsigned int sn_bio_bi_size(struct bio *bio)
{
#ifdef HAVE_BVEC_ITER
	return bio->bi_iter.bi_size;
#else
	return bio->bi_size;
#endif
}

#endif // SNCONFIG_H
