#ifndef _LINUX_SNAPAPICALLUSER_H
#define _LINUX_SNAPAPICALLUSER_H

/* snapapi.h
   Copyright (C) Acronis, 2004
   Copyright (C) CyberProtect
*/

#ifdef __linux__
#include <linux/types.h>
#include <linux/ioctl.h>
#endif
#include "sn_huge_ptr.h"
#include "version.h"

#define SNAPCTL_NAME "snapctl"

#pragma pack(1)

struct snapctl_init {
	unsigned int major;
	unsigned int minor;
	int prealloc;			/* flag to allocate cache in advance */
};

struct snapctl_ldmap {
	unsigned long long map_size;	/* size of map in bits */
	SN_HUGE_PTR(void *map);		/* bitmap itself */
};

struct snapctl_getmap {
	unsigned long long map_size;	/* size of map in bits [in]*/
	SN_HUGE_PTR(void *map);		/* bitmap itself [in, out]*/
	unsigned int bsize;		/* BlockSize */
	unsigned int fblock;		/* FirstDataBlock */
	unsigned int bpgroup;		/* BlocksPerGroup */
	unsigned int gcount;		/* GroupCount */
};

struct group_entry {
	unsigned long long bno;
	unsigned int group;
	char init;
	char cached;
	unsigned char pad[2];
};

struct snapctl_getsparsedmap {
	unsigned long long map_size;	/* size of map in bits [in]*/
	SN_HUGE_PTR(void *map);		/* bitmap itself [in, out]*/
	unsigned int bsize;		/* BlockSize */
	unsigned int fblock;		/* FirstDataBlock */
	unsigned int bpgroup;		/* BlocksPerGroup */
	unsigned int gcount;		/* GroupCount */
	SN_HUGE_PTR2(struct group_entry* groups); /* array of groups */
};

struct snapctl_getbno {
	SN_HUGE_PTR(unsigned long long *bno);	/* user-level buffer */
};

struct sn_rdcache {
	unsigned long long bno;		/* bno from cache */
	unsigned int count;		/* count of blocks */
	unsigned int size;		/* size of buf in bytes */
	SN_HUGE_PTR(void *buf);		/* user space buffer */
};

struct snapctl_rdcache {
	SN_HUGE_PTR(struct sn_rdcache *data);
	unsigned int size;		/* size of sn_rdcache */
};

struct snapctl_bread {
	unsigned long long bstart;	/* start block number*/
	unsigned int count;		/* count */
	unsigned int flags;		/* flags */
#define SNAP_READ_ONCE	1
	SN_HUGE_PTR(void *data);	/* data */
	unsigned long long bincache;	/* Blocks in cache */
};

struct snapctl_bfree {
	unsigned long long bstart;	/* start block number*/
	unsigned long long count;	/* count */
};

/* cut points for s_rcdepthcnt stats */
#define SNAP_RCDEPTH0 128
#define SNAP_RCDEPTH1 (8 * SNAP_RCDEPTH0)
#define SNAP_RCDEPTH2 (8 * SNAP_RCDEPTH1)
#define SNAP_RCDEPTH3 (8 * SNAP_RCDEPTH2)

struct sn_state {
	unsigned version;		/* snapapi version */
	unsigned int major;
	unsigned int minor;
	unsigned int state;		/* session state */
	int blksize;
	int mmapsize;			/* mmap max size in bytes */
	int minorshft;			/* device minor shift */
	unsigned long long partsize;	/* partition size in Kbytes */
	unsigned long long partstrt;	/* partition start in sectors */
					/* current values */
	int bhpages;			/* delayed bhs pages */
	int bhcount;			/* delayed bhs count */
	int emmax;			/* emergency buffer max size(pages) */
	int emmin;			/* emergency buffer min size*/
	int emcur;			/* emergency buffer current pages */
	int cachepages;			/* pages in cache */

	unsigned long long gpages;	/* got pages */
	unsigned long long ppages;	/* put pages */
	unsigned long long abhs;	/* allocated bhs */
	unsigned long long fbhs;	/* freed bhs */
	unsigned long long dbhs;	/* delayed bhs */
	unsigned long long rblocks;	/* read blocks */
	unsigned long long cblocks;	/* cached blocks */
	unsigned long long rcblocks;	/* read from cache */
	unsigned long long fcblocks;	/* freed cache blocks */
	unsigned long long mcblocks;	/* max blocks in cache */
	unsigned long long rwcolls;	/* read/write collisions */
	unsigned long long rc2blocks;	/* read to cache2 blocks */
	unsigned int sync_req;		/* sync requests  */
	unsigned int mipr;		/* max increase pending requests */
	unsigned int async_req;		/* async requests  */
	unsigned int iprcnt;		/* increase pending requests count */
	unsigned int async_retr;  	/* async retries */
	unsigned int mbio;  		/* min bio size */

	unsigned int ioctlcnt;
	unsigned int ioctlpid;

	/* Can be used by userspace to determine which part of extra state was filled by snapapi */
	unsigned int extrasize;		/* = sizeof(sn_state) - offsetof(sn_state, extrasize). */

	/* extra state */
	unsigned long long rccalls;		/* total number of searches in blkcache (sa_cache_chain_read calls) */
	unsigned long long maxrcdepth;		/* length of the deepest search in any blkcache chain */
	unsigned long long rcdepthcnt[4];	/* total counts of blkcache searches with depth > SNAP_RCDEPTHi */
	unsigned long long flags;		/* flags with info about kernel module. f.e. if it built exactly for running kernel*/
#define KERNEL_NOT_MATCHED		(1ULL << 0)
};

struct snapctl_state {
	SN_HUGE_PTR(struct sn_state *state);	/* user-level buffer */
	unsigned int size;		/* size of user buf */
/* session states */
#define SNAP_NOTINITED		0
#define SNAP_ININIT		1
#define SNAP_INITED		2
#define SNAP_FREEZING		3
#define SNAP_FROZEN		4
#define SNAP_INITINGMAP		5
#define SNAP_MAPPED		6
#define SNAP_CLOSING		7
#define SNAP_CLOSED		8
#define SNAP_READINGMAP		9

#define SNAP_FREEZE_ERR		(1 << 8)
#define SNAP_MAP_ERR		(2 << 8)
#define SNAP_READING_ERR	(3 << 8)
#define SNAP_DEADLOCK_ERR	(4 << 8)
};

/* not related to session helpers */
struct sn_devinfo {
	unsigned int major;
	unsigned int minor;
	int blksize;
	unsigned long long partsize;	/* partition size in sectors */
	unsigned long long partstrt;	/* partition start in sectors */
	int minorshft;			/* device minor shift */
	unsigned long long reads, read_sectors, writes, write_sectors;
};

struct snapctl_devinfo {
	unsigned int major;
	unsigned int minor;
	SN_HUGE_PTR(struct sn_devinfo *info);	/* user-level buffer */
	unsigned int size;		/* size of user buf */
};

struct snapctl_devlock {
	unsigned int major;
	unsigned int minor;
};

struct snapctl_devunlock {
	unsigned int major;
	unsigned int minor;
};

struct snapctl_devlockread {
	unsigned int major;
	unsigned int minor;
};

struct snapctl_devunlockread {
	unsigned int major;
	unsigned int minor;
};

struct snapctl_disklock {
	unsigned int major;
	unsigned int minor;
	SN_HUGE_PTR(void *info);	/* user-level buffer */
	unsigned int size;		/* size of user buf */
};

struct snapctl_diskunlock {
	unsigned int major;
	unsigned int minor;
};

struct snapctl_messqstate {
	SN_HUGE_PTR(unsigned int *state);
};

struct snapctl_resetatime {
	unsigned int fd;		/* file descriptor */
};

#define SNAPCTL_INIT		_IOW(CTLTYPE, 0,			\
					struct snapctl_init)
#define SNAPCTL_FREEZE		_IO(CTLTYPE, 1)
#define SNAPCTL_LDMAP		_IOW(CTLTYPE, 2,			\
					struct snapctl_ldmap)
#define SNAPCTL_GETBNO		_IOW(CTLTYPE, 3,			\
					struct snapctl_getbno)
#define SNAPCTL_BREAD		_IOW(CTLTYPE, 4,			\
					struct snapctl_bread)
#define SNAPCTL_BFREE		_IOW(CTLTYPE, 5,			\
					struct snapctl_bfree)
#define SNAPCTL_STATE		_IOW(CTLTYPE, 6,			\
					struct snapctl_state)
#define SNAPCTL_DEVINFO		_IOW(CTLTYPE, 7,			\
					struct snapctl_devinfo)
#define SNAPCTL_DEVLOCK		_IOW(CTLTYPE, 8,			\
					struct snapctl_devlock)
#define SNAPCTL_DEVUNLOCK	_IOW(CTLTYPE, 9,			\
					struct snapctl_devunlock)
#define SNAPCTL_UNFREEZE	_IO(CTLTYPE, 10)
#define SNAPCTL_MESSQSTATE	_IOW(CTLTYPE, 11,			\
					struct snapctl_messqstate)
#define SNAPCTL_RESETATIME	_IOW(CTLTYPE, 12,			\
					struct snapctl_resetatime)
#define SNAPCTL_RDCACHE		_IOW(CTLTYPE, 13,			\
					struct snapctl_rdcache)
#define SNAPCTL_REGISTER_BLKDEV	_IOW(CTLTYPE, 14,			\
					struct snapctl_register_blkdev)
#define SNAPCTL_UNREGISTER_BLKDEV _IO(CTLTYPE, 15)

#define SNAPCTL_SET_VEID	_IOW(CTLTYPE, 16,			\
					unsigned int)
/* ioctls for snapshot block device */
#define SNAPCTL_START_SWAP_THREAD	_IO(CTLTYPE, 17)
#define SNAPCTL_STOP_SWAP_THREAD	_IO(CTLTYPE, 18)
#define SNAPCTL_GETMAP		_IOW(CTLTYPE, 19,			\
					struct snapctl_getmap)
#define SNAPCTL_DEVLOCKREAD		_IOW(CTLTYPE, 20,		\
					struct snapctl_devlockread)
#define SNAPCTL_DEVUNLOCKREAD		_IOW(CTLTYPE, 21,		\
					struct snapctl_devunlockread)
#define SNAPCTL_GETSPARSEDMAP		_IOW(CTLTYPE, 22,		\
					struct snapctl_getsparsedmap)

struct snap_message {
	unsigned int code;
	unsigned int major;
	unsigned int minor;
	unsigned long long begin;
	unsigned long long size;
	unsigned int pad;
}; /* PAGE_SIZE % sizeof(struct snap_message) must be == 0 */
#pragma pack()

#ifdef __KERNEL__
#define SNAP_PREALLOC_DEFAULT	0
#define SNAP_PREALLOC_FORCE_ON	1
#define SNAP_PREALLOC_FORCE_OFF	2

#define SNAP_EMERGENCY_SIZE_MIN	1024

#ifdef HAVE_UNLOCKED_IOCTL
long snapapi3_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
#else
int snapapi4_ioctl(struct inode *ino, struct file *file, unsigned int cmd,
				   unsigned long arg);
#endif
#ifdef HAVE_COMPAT_IOCTL
long snapapi_compat_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
#endif
int snapapi_open(struct inode *ino, struct file *file);
ssize_t snapapi_read(struct file * filp, char * buf, size_t count, loff_t *ppos);
ssize_t snapapi_write(struct file *filp, const char *buf, size_t count, loff_t *ppos);
unsigned int snapapi_poll(struct file *filp, poll_table *wait);
int snapapi_mmap(struct file * file, struct vm_area_struct * vma);
int snapapi_release(struct inode *ino, struct file *file);

int validate_kernel_version(void);
int get_drv_pages(void);
void free_drv_pages(void);
void init_select_wait(void);
int start_resolver_thread(void);
void stop_resolver_thread(void);
void register_ioctl32(void);
void unregister_ioctl32(void);
int sa_sysfs_create(void);
void sa_sysfs_remove(void);
#endif /* __KERNEL__ */

#endif /* _LINUX_SNAPAPICALLUSER_H */
