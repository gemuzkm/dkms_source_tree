#ifndef _LINUX_SNUMBDCALLUSER_H
#define _LINUX_SNUMBDCALLUSER_H

/* snumbd.h
   Copyright (C) Acronis, 2004
   Copyright (C) CyberProtect
*/

#ifdef __linux__
#include <linux/types.h>
#include <linux/ioctl.h>
#endif
#include "sn_huge_ptr.h"
#include "version.h"

#define SNUMBD_NAME "snumbd"
#define SNUMBDCTL_NAME "snumbdctl"

#pragma pack(1)

struct snumbdctl_init {
	unsigned long long scount;	/* sectors count (sector = 512) */
	int dev_ro;			/* read-only mode */
};

struct snumbdctl_init_v2 {
	unsigned long long scount;	/* blocks count */
	unsigned int sector_size;    /* block size */
	int dev_ro;			/* read-only mode */
};

struct snumbd_req {			/* to user level */
	unsigned int cmd;
	unsigned int offset;
	unsigned long long sno;		/* sector no */
	unsigned int len;
#define READ_DATA	0
#define WRITE_DATA	1
#define STOP		2
#define ERROR_FLAG	(1<<(sizeof(unsigned int)*8 - 1))
};

struct snumbdctl_req {			/* to user level */
	SN_HUGE_PTR(struct snumbd_req *req);	/* user-level buffer */
	unsigned int size;		/* size of user buf */
};

struct snumbdctl_dataready {
	SN_HUGE_PTR(const struct snumbd_req *req);/* user-level buffer */
	unsigned int size;
};

struct snumbd_state {
	unsigned int version;
	unsigned int major;
	unsigned int minor;
	unsigned int state;	/* session state */
	unsigned int hpid;	/* usermode host pid */
	unsigned long long scount;	/* blocks count (512 <= block <= 4096) */
	int mmapsize;		/* mmap max size in bytes */
				/* current values */
	unsigned int sessions;	/* total number of sessions */
	unsigned int gpages;		/* got pages */
	unsigned int ppages;		/* put pages */
	unsigned int ioctlcnt;
	int users;
/* session states */
#define SNUM_NOTINITED		0
#define SNUM_ININIT		1
#define SNUM_INITED		2
#define SNUM_WAKEUP_REQ		3
#define SNUM_REQ_RECV		4
#define SNUM_DATA_READY		5

#define SNUM_ACTIVATING_ERR		(1 << 8)
#define SNUM_SESSION_ERR		(2 << 8)
#define SNUM_DEADLOCK_ERR		(3 << 8)
#define IS_ERROR_STATE(x)		((x) >= SNUM_ACTIVATING_ERR)
};

struct snumbdctl_state { 		/* current session state */
	SN_HUGE_PTR(struct snumbd_state *state);/* user-level buffer */
	unsigned int size;		/* size of user buf */
};

struct snumbdctl_states {		/* all sessions states */
	SN_HUGE_PTR(struct snumbd_state *state);/* user-level buffer */
	unsigned int size;		/* size of user buf */
};

struct snumbdctl_pgrp {		/* Allowed PGRP */
	pid_t allowed_pgrp;
};

#define SNUMBDCTL_INIT		_IO(CTLTYPE, 0)
#define SNUMBDCTL_STOP		_IO(CTLTYPE, 1)
#define SNUMBDCTL_REQ		_IOW(CTLTYPE, 2,			\
					struct snumbdctl_req)
#define SNUMBDCTL_DATAREADY	_IOW(CTLTYPE, 3,			\
					struct snumbdctl_dataready)
#define SNUMBDCTL_STATE		_IOW(CTLTYPE, 4,			\
					struct snumbdctl_state)
#define SNUMBDCTL_STATES	_IOW(CTLTYPE, 5,			\
					struct snumbdctl_state)
#define SNUMBDCTL_INIT_V2	_IO(CTLTYPE, 6)
#define SNUMBDCTL_PGRP		_IOW(CTLTYPE, 7,			\
					struct snumbdctl_pgrp)
#pragma pack()

#ifdef __KERNEL__
#ifdef HAVE_UNLOCKED_IOCTL
long snumbdctl3_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
#else
int snumbdctl4_ioctl(struct inode *ino, struct file *file, unsigned int cmd,
					 unsigned long arg);
#endif
#ifdef HAVE_COMPAT_IOCTL
long snumbdctl_compat_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
#endif
int snumbdctl_open(struct inode *ino, struct file *file);
ssize_t snumbdctl_read(struct file * filp, char * buf, size_t count, loff_t *ppos);
ssize_t snumbdctl_write(struct file *filp, const char *buf, size_t count, loff_t *ppos);
unsigned int snumbdctl_poll(struct file *filp, poll_table *wait);
int snumbdctl_mmap(struct file * file, struct vm_area_struct * vma);
int snumbdctl_release(struct inode *ino, struct file *file);

void register_ioctl32(void);
void unregister_ioctl32(void);
#endif /* __KERNEL__ */

#endif /* _LINUX_SNUMBDCALLUSER_H */
