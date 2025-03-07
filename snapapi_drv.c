/* snapapi_drv.c
   Copyright (C) Acronis, 2004
   Copyright (c) CyberProtect
*/

#include "snconfig.h"
#include "snapapi.h"
#include "debug.h"
#include "version.h"

#ifdef HAVE_BDOPS_SUBMIT_BIO
#include "kernel_config.h"
#endif

extern int snap_emergency_size;
extern const int session_struct_size;
extern const int blk_chains;

static int snapctl_major;
static int snap_emergency_size_max;
const int * const snap_emergency_size_max_p = &snap_emergency_size_max;

static const struct file_operations snapctl_fops = {
	owner: THIS_MODULE,
#ifdef HAVE_UNLOCKED_IOCTL
	unlocked_ioctl: snapapi3_ioctl,
#else
	ioctl: snapapi4_ioctl,
#endif
	open: snapapi_open,
	read: snapapi_read,
	write: snapapi_write,
	poll: snapapi_poll,
	mmap:  snapapi_mmap,
	release: snapapi_release,
#ifdef HAVE_COMPAT_IOCTL
	compat_ioctl: snapapi_compat_ioctl,
#endif
};

static int __init snapapi_init(void)
{
	struct sysinfo i;
	int ret;

	init_select_wait();
	si_meminfo(&i);
	snap_emergency_size_max = snap_emergency_size = sn_round_up(i.totalram >> 8, 1024);

	ret = start_resolver_thread();
	if (ret) {
		goto err;
	}

	ret = get_drv_pages();
	if (ret) {
		goto err;
	}

	ret = register_chrdev(0, SNAPCTL_NAME, &snapctl_fops);
	if (ret < 0)
		goto err;
	snapctl_major = ret;

	ret = sa_sysfs_create();
	if (ret)
		goto err;

	register_ioctl32();
	ret = 0;

out_info:
	sa_info("Snapapi(v%d.%d.%d.%d) init %s. Session size %d. Em size %d. "
		"Ctl major %d. chains %d\n", COMMON_VMAJOR, COMMON_VMINOR, COMMON_VSUBMINOR, BUILD_NUMBER,
		!ret ? "OK" : "failed",	session_struct_size,
		snap_emergency_size, snapctl_major, blk_chains);
#ifdef HAVE_BDOPS_SUBMIT_BIO
	sa_warn("snapapi26: built for %s %s kernel using %s.", UTS_RELEASE, UTS_VERSION, SNAPAPI_SYSTEM_MAP);
	if (validate_kernel_version() != 0)
		sa_warn("snapapi26 module was built for another kernel, have %s %s expecting %s %s.", utsname()->release, utsname()->version, UTS_RELEASE, UTS_VERSION);
#endif
	return ret;

err:
	if (snapctl_major > 0)
		unregister_chrdev(snapctl_major, SNAPCTL_NAME);
	free_drv_pages();
	stop_resolver_thread();
	goto out_info;
}

static void __exit snapapi_exit(void)
{
	sa_sysfs_remove();
	unregister_chrdev(snapctl_major, SNAPCTL_NAME);
	unregister_ioctl32();
	free_drv_pages();
	stop_resolver_thread();
	sa_info("Snapapi unloading...%s", "\n");
}


module_init(snapapi_init);
module_exit(snapapi_exit);
MODULE_AUTHOR("CyberProtect");
MODULE_DESCRIPTION("CyberProtect Snapshot kernel API module");
MODULE_LICENSE("GPL");
MODULE_VERSION(COMMON_MOD_VERSION);
MODULE_INFO(supported, "external");
