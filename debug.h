#ifndef _DEBUG_H
#define _DEBUG_H

#define DEBUG_API	(1 << 1)
#define DEBUG_ALLOC	(1 << 2)
#define DEBUG_BIO	(1 << 3)
#define DEBUG_BIOQUE	(1 << 4)
#define DEBUG_CACHE	(1 << 5)
#define DEBUG_BREAD	(1 << 6)
#define DEBUG_INTERNALS	(1 << 7)
#define DEBUG_DUMP	(1 << 8)
#define DEBUG_LOCK	(1 << 9)
#define DEBUG_IOCTL	(1 << 10)
#define DEBUG_MESS	(1 << 11)
#define DEBUG_BMAP	(1 << 12)

#define DEBUG_LEVEL 	(DEBUG_API)

#ifdef DEBUG
#  define SA_STATIC static noinline
#  define SA_INLINE noinline
#else
#  define SA_STATIC static
#  define SA_INLINE __always_inline
#endif

static __always_inline int sn_printk_rate_limit(void)
{
	static unsigned long count, last;

	if (jiffies - last > HZ)
		count = 0;
	if (count >= 10)
		return 0;
	last = jiffies;
	count++;
	return 1;
}

#ifdef DEBUG
#define sa_debug(level, fmt, arg...)					\
	do {												\
		static const char *func = __FUNCTION__;			\
		if (((level) & DEBUG_LEVEL) && sn_printk_rate_limit())\
			printk(KERN_DEBUG "%s(%s,%d): " fmt, func,	\
				current->comm, current->pid, ##arg);	\
	} while (0)
#else
#define sa_debug(level, fmt, arg...) do { } while (0)
#endif /* DEBUG */

#define sa_kdebug(fmt, arg...)							\
	do {												\
		static const char *func= __FUNCTION__;			\
		if (sn_printk_rate_limit())						\
			printk(KERN_DEBUG "%s(%s,%d): " fmt, func,	\
			current->comm, current->pid, ##arg);		\
	} while (0)

#define sa_info(fmt, arg...)							\
	do {												\
		static const char *func = __FUNCTION__;			\
		if (sn_printk_rate_limit())						\
			printk(KERN_INFO "%s(%s,%d): " fmt, func,	\
			current->comm, current->pid, ##arg);		\
	} while (0)

#define sa_warn(fmt, arg...)							\
	do {												\
		static const char *func = __FUNCTION__;			\
		if (sn_printk_rate_limit())						\
			printk(KERN_WARNING "%s(%s,%d): " fmt, func,\
			current->comm, current->pid, ##arg);		\
	} while (0)

#define sa_error(fmt, arg...)							\
	do {												\
		static const char *func = __FUNCTION__;			\
		if (sn_printk_rate_limit())						\
			printk(KERN_ERR "%s(%s,%d): " fmt, func,	\
			current->comm, current->pid, ##arg);		\
	} while (0)

#define sa_BUG(fmt, arg...)								\
	do {												\
		static const char *func = __FUNCTION__;			\
		printk(KERN_CRIT "%s(%s,%d): " fmt, func,		\
			current->comm, current->pid, ##arg);		\
		BUG();						\
	} while (0)


#ifdef DEBUG
#ifdef HAVE_OP_IS_WRITE
#  define BIO_RW_RETURN_VALUE unsigned int
#else
#  define BIO_RW_RETURN_VALUE unsigned long
#endif /* HAVE_OP_IS_WRITE */

static __always_inline BIO_RW_RETURN_VALUE get_bio_req_flags(struct bio *bio)
{
#ifdef HAVE_BIO_OPF
	return bio->bi_opf;
#else
	return bio->bi_rw;
#endif /* HAVE_BIO_OPF */
}
#endif /* DEBUG */

#if defined(DEBUG) && (DEBUG_LEVEL & DEBUG_BIO)
static SA_INLINE sector_t sn_bio_bi_sector(struct bio *bio);
static SA_INLINE unsigned int sn_bio_bi_size(struct bio *bio);

static __always_inline void print_bio(struct bio *bio, char *pref)
{
	sa_warn("%s bio=%p, dev=%x, sector=%llu, bi_flags=%x"
		" bi_rw=%x bi_size=%d bi_vcnt=%d bi_io_vec=%p"
		" bi_max_vecs=%d\n", pref, bio,
		bio->bi_bdev ? bio->bi_bdev->bd_dev : -1,
		(unsigned long long)sn_bio_bi_sector(bio), bio->bi_flags,
		get_bio_req_flags(bio), sn_bio_bi_size(bio), bio->bi_vcnt, bio->bi_io_vec,
		bio->bi_max_vecs);
}

#  define dump_bio(x, y) print_bio(x, y)
#else
#  define dump_bio(x, y)
#endif

#endif // _DEBUG_H
