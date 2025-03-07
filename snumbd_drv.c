/* snumbd_drv.c
   Copyright (C) Acronis, 2004
   Copyright (c) CyberProtect
*/

#include "snconfig.h"
#include "snumbd.h"
#include "debug.h"
#include "version.h"


static int snumbdctl_major;
static int snumbd_major;
const int * const snumbd_major_p = &snumbd_major;

static const struct file_operations snumbdctl_fops = {
	owner: THIS_MODULE,
#ifdef HAVE_UNLOCKED_IOCTL
	unlocked_ioctl: snumbdctl3_ioctl,
#else
	ioctl: snumbdctl4_ioctl,
#endif
	open: snumbdctl_open,
	read: snumbdctl_read,
	write: snumbdctl_write,
	poll: snumbdctl_poll,
	mmap:  snumbdctl_mmap,
	release: snumbdctl_release,
#ifdef HAVE_COMPAT_IOCTL
	compat_ioctl: snumbdctl_compat_ioctl,
#endif
};

static int __init snumbd_init(void)
{
	int ret;

	ret = register_chrdev(0, SNUMBDCTL_NAME, &snumbdctl_fops);
	if (ret < 0)
		goto out_info;
	snumbdctl_major = ret;

	ret = register_blkdev(0, SNUMBD_NAME);
	if (ret < 0) {
		unregister_chrdev(snumbdctl_major, SNUMBDCTL_NAME);
		goto out_info;
	}
	snumbd_major = ret;

	register_ioctl32();
	ret = 0;

out_info:
	sa_info("Snumbd(v%d.%d.%d.%d) init %s. Ctl major %d, blk major %d.\n",
				COMMON_VMAJOR, COMMON_VMINOR, COMMON_VSUBMINOR, BUILD_NUMBER,
				!ret ? "OK" : "failed",
				snumbdctl_major, snumbd_major);
	return ret;
}

static void __exit snumbd_exit(void)
{
	unregister_chrdev(snumbdctl_major, SNUMBDCTL_NAME);
	unregister_blkdev(snumbd_major, SNUMBD_NAME);
	unregister_ioctl32();
	sa_info("Snumbd unloading...%s", "\n");
}

module_init(snumbd_init);
module_exit(snumbd_exit);
MODULE_AUTHOR("CyberProtect");
MODULE_DESCRIPTION("CyberProtect User Mode Block Device");
MODULE_LICENSE("GPL");
MODULE_VERSION(COMMON_MOD_VERSION);
MODULE_INFO(supported, "external");
