$(info $$srctree is [${srctree}])

KERNEL_INC:=/lib/modules/$(KERNELRELEASE)/build

ifeq ($(wildcard ${KERNEL_INC}),)
    KERNEL_INC:=$(srctree)
endif

ifeq ($(filter clean snapapi_system_map,$(MAKECMDGOALS)),)

SNAPAPI_FLAGS :=

ifeq ($(notdir $(wildcard $(KERNEL_INC)/include/generated/autoconf.h)),autoconf.h)
	SNAPAPI_FLAGS += -DHAVE_GENERATED_AUTOCONF
else ifeq ($(notdir $(wildcard $(KERNEL_INC)/include/linux/autoconf.h)),autoconf.h)
	SNAPAPI_FLAGS += -DHAVE_LINUX_AUTOCONF
else ifeq ($(notdir $(wildcard $(KERNEL_INC)/include/linux/config.h)),config.h)
	SNAPAPI_FLAGS += -DHAVE_LINUX_CONFIG
endif
ifeq ($(notdir $(wildcard $(KERNEL_INC)/include/generated/compile.h)),compile.h)
	SNAPAPI_FLAGS += -DHAVE_COMPILE_H
endif
ifeq ($(notdir $(wildcard $(KERNEL_INC)/include/generated/utsversion.h)),utsversion.h)
	SNAPAPI_FLAGS += -DHAVE_UTS_VERSION_H
endif
ifeq ($(notdir $(wildcard $(srctree)/include/linux/ioctl32.h)),ioctl32.h)
	SNAPAPI_FLAGS += -DHAVE_IOCTL32_H
endif
ifeq ($(notdir $(wildcard $(srctree)/include/linux/sched/signal.h)),signal.h)
	SNAPAPI_FLAGS += -DHAVE_SCHED_SIGNAL_H
endif
ifeq ($(notdir $(wildcard $(srctree)/include/linux/blk-cgroup.h)),blk-cgroup.h)
	SNAPAPI_FLAGS += -DHAVE_BLK_CGROUP_H
endif
ifeq ($(notdir $(wildcard $(srctree)/include/linux/part_stat.h)),part_stat.h)
	SNAPAPI_FLAGS += -DHAVE_PART_STAT_H
endif
SNAPAPI_FLAGS += $(shell \
	grep -q page_mapcount $(srctree)/include/linux/mm.h && \
		echo -DHAVE_PAGE_MAPCOUNT)
SNAPAPI_FLAGS += $(shell \
	grep -qw "_mapcount" $(srctree)/include/linux/mm_types.h && \
		echo -DHAVE_PAGE_UMAPCOUNT)
SNAPAPI_FLAGS += $(shell \
	grep -qw SPIN_LOCK_UNLOCKED $(srctree)/include/linux/spinlock_types.h \
	$(srctree)/include/linux/spinlock.h && \
		echo -DHAVE_SPIN_LOCK_UNLOCKED)
SNAPAPI_FLAGS += $(shell \
	grep -qw queue_max_hw_sectors $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_QUEUE_MAX_HW_SECTORS)
SNAPAPI_FLAGS += $(shell \
	grep -qw fmode_t $(srctree)/include/linux/types.h && \
		echo -DHAVE_FMODE_T)
SNAPAPI_FLAGS += $(shell 							\
	if grep -q try_to_freeze $(srctree)/include/linux/freezer.h; then	\
	     echo -DHAVE_TRY_TO_FREEZE_NO_ARGS -DHAVE_FREEZER_H;			\
	elif grep -qw "try_to_freeze(unsigned.*)" $(srctree)/include/linux/sched.h; then 	\
	     echo -DHAVE_TRY_TO_FREEZE_ONE_ARG;						\
	elif grep -qw "try_to_freeze(void)" $(srctree)/include/linux/sched.h; then 	\
	     echo -DHAVE_TRY_TO_FREEZE_NO_ARGS;						\
	fi)
SNAPAPI_FLAGS += $(shell \
	grep -qw unlocked_ioctl $(srctree)/include/linux/fs.h && \
		echo -DHAVE_UNLOCKED_IOCTL)
SNAPAPI_FLAGS += $(shell \
	if grep -qw "extern int blkdev_put.*,.*" $(srctree)/include/linux/fs.h; then \
		echo -DHAVE_BLKDEV_PUT_2ARGS; \
		echo -DHAVE_BLKDEV_PUT_INT; \
	elif grep -qw "extern void blkdev_put.*,.*" $(srctree)/include/linux/fs.h; then \
		echo -DHAVE_BLKDEV_PUT_2ARGS; \
	elif grep -qw "void blkdev_put.*,.*void.*" $(srctree)/include/linux/blkdev.h; then \
		echo -DHAVE_BLKDEV_PUT_2ARG_FLAG; \
	elif grep -qw "void blkdev_put.*,.*" $(srctree)/include/linux/blkdev.h; then \
		echo -DHAVE_BLKDEV_PUT_2ARGS; \
	fi)
SNAPAPI_FLAGS += $(shell \
	if grep -qw "extern int blkdev_get.*,.*,.*unsigned.*" $(srctree)/include/linux/fs.h; then \
		echo -DHAVE_BLKDEV_GET_3ARG_FLAG;						\
	elif grep -qw "extern int blkdev_get.*,.*,.*" $(srctree)/include/linux/fs.h; then	\
		echo -DHAVE_BLKDEV_GET_3ARGS;							\
	elif grep -qw "int blkdev_get.*,.*,.*" $(srctree)/include/linux/blkdev.h; then		\
		echo -DHAVE_BLKDEV_GET_3ARGS;							\
	fi)
SNAPAPI_FLAGS += $(shell \
	if grep -qw ''static.*kmap_atomic\(.*page.*,.*\)'\|'define\ kmap_atomic\(page,.*\)'' $(srctree)/include/linux/highmem.h; then \
		echo -DHAVE_KMAP_ATOMIC_2ARGS;						\
	fi)
SNAPAPI_FLAGS += $(shell \
	if grep -qw "extern void \*__vmalloc.*,.*,.*pgprot_t.*" $(srctree)/include/linux/vmalloc.h; then \
		echo -DHAVE_VMALLOC_3ARGS;							\
	fi)
SNAPAPI_FLAGS += $(shell \
	if grep -qw "nr_rqs.*" $(srctree)/include/linux/blkdev.h; then \
		echo -DHAVE_REQUEST_QUEUE_RQS;						       \
	elif test -f $(srctree)/include/linux/blk_types.h && grep -qw "struct request_list     rq" $(srctree)/include/linux/blk_types.h; then  \
		echo -DHAVE_REQUEST_LIST_COUNT;						                                                       \
	fi)
SNAPAPI_FLAGS += $(shell \
	grep -qw "typedef int (make_request_fn)" $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_MAKE_REQUEST_INT)
SNAPAPI_FLAGS += $(shell \
	grep -qw "typedef blk_qc_t (make_request_fn)" $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_MAKE_REQUEST_BLK_QC_T)
SNAPAPI_FLAGS += $(shell \
	test -f $(srctree)/include/linux/blk_types.h && \
	grep -qw "struct bvec_iter" $(srctree)/include/linux/blk_types.h && \
		echo -DHAVE_BVEC_ITER)
SNAPAPI_FLAGS += $(shell \
	grep -qw "pid_ns_for_children" $(srctree)/include/linux/nsproxy.h && \
		echo -DHAVE_PID_NS_CHILDREN)
SNAPAPI_FLAGS += $(shell \
	grep -v '^//' $(srctree)/include/linux/fs.h | grep -qw "f_dentry" && \
		echo -DHAVE_FILE_F_DENTRY)
SNAPAPI_FLAGS += $(shell \
	grep -qw "spinlock_t.\squeue_lock" $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_QUEUE_LOCK_NPTR)
SNAPAPI_FLAGS += $(shell \
	grep -qw "set_mb" $(srctree)/arch/x86/include/asm/barrier.h \
	$(srctree)/arch/x86/include/asm/system.h \
	$(srctree)/include/asm/system.h \
	$(srctree)/include/asm-generic/system.h	&& \
		echo -DHAVE_ASM_HAVE_SET_MB)
SNAPAPI_FLAGS += $(shell \
	if grep -qw "extern void bio_endio(.*bio.*,.*)" $(srctree)/include/linux/bio.h; then \
		echo -DHAVE_BIO_ENDIO_2ARGS;						\
	fi)

SNAPAPI_FLAGS += $(shell \
	if grep -qw "BIO_UPTODATE" $(srctree)/include/linux/blk_types.h 		\
	$(srctree)/include/linux/bio.h ; then 						\
		echo -DHAVE_BIO_UPTODATE;						\
	elif test -f $(srctree)/include/linux/blk_types.h && grep -qw "bi_error" $(srctree)/include/linux/blk_types.h; then		\
		echo -DHAVE_BIO_BI_ERROR;						\
	fi)

SNAPAPI_FLAGS += $(shell \
	grep -qw "submit_bio(struct bio \*)\|submit_bio(struct bio \*bio)" $(srctree)/include/linux/fs.h \
       		 $(srctree)/include/linux/bio.h && \
		echo -DHAVE_SUBMIT_BIO_ONEARG)

ifeq ($(notdir $(wildcard $(srctree)/include/linux/blk_types.h)),blk_types.h)
# not defined in 6.2+
# void bio_set_op_attrs in kernel < 6.2.0
# define bio_set_op_attrs in kernel 4.8
SNAPAPI_FLAGS += $(shell \
		 grep -qw "bio_set_op_attrs" $(srctree)/include/linux/blk_types.h && \
		 echo -DHAVE_BIO_SET_OP_ATTRS)
endif
SNAPAPI_FLAGS += $(shell \
	grep -qw "op_is_write" $(srctree)/include/linux/fs.h \
       		$(srctree)/include/linux/blk_types.h && \
		echo -DHAVE_OP_IS_WRITE)
SNAPAPI_FLAGS += $(shell \
	grep -qw "bi_opf" $(srctree)/include/linux/fs.h \
       		$(srctree)/include/linux/blk_types.h && \
		echo -DHAVE_BIO_OPF)
SNAPAPI_FLAGS += $(shell \
	grep -qw "virtual_address;" $(srctree)/include/linux/mm.h && \
		echo -DHAVE_VMFAULT_VIRTUAL_ADDRESS)
SNAPAPI_FLAGS += $(shell \
	grep -qw "fault.(.*,.*)" $(srctree)/include/linux/mm.h && \
		echo -DHAVE_VM_FAULT_2ARGS)
SNAPAPI_FLAGS += $(shell \
	if grep -qw "bio_set_dev" $(srctree)/include/linux/bio.h; then \
		echo -DHAVE_BIO_SET_DEV;						\
	fi)

SNAPAPI_FLAGS += $(shell \
	if grep -qw "init_timer" $(srctree)/include/linux/timer.h; then \
		echo -DHAVE_INIT_TIMER;						\
	fi)
SNAPAPI_FLAGS += $(shell \
	grep -qw blk_queue_make_request $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BLK_QUEUE_MAKE_REQUEST)
SNAPAPI_FLAGS += $(shell \
	grep -qw blk_alloc_queue_rh $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BLK_ALLOC_QUEUE_RH)
SNAPAPI_FLAGS += $(shell \
	grep -qw "blk_alloc_queue(gfp_t)" $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BLK_ALLOC_QUEUE_ONE_ARG_GFP)

SNAPAPI_FLAGS += $(shell \
	grep -qw "blk_alloc_queue(int node_id)" $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BLK_ALLOC_QUEUE_ONE_ARG_NODE_ID)

ifeq ($(notdir $(wildcard $(srctree)/include/linux/genhd.h)),genhd.h)
SNAPAPI_FLAGS += $(shell \
	grep -qw "bd_set_nr_sectors" $(srctree)/include/linux/genhd.h && \
		echo -DHAVE_BD_SET_NR_SECTORS)

SNAPAPI_FLAGS += $(shell \
	grep -qw "void add_disk(struct gendisk.*)" $(srctree)/include/linux/genhd.h && \
		echo -DVOID_ADD_DISK)

SNAPAPI_FLAGS += $(shell \
	grep -qw "set_device_ro" $(srctree)/include/linux/genhd.h && \
		echo -DHAVE_SET_DEVICE_RO)

SNAPAPI_FLAGS += $(shell \
	grep -qw "blk_alloc_disk" $(srctree)/include/linux/genhd.h $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BLK_ALLOC_DISK)

SNAPAPI_FLAGS += $(shell \
	grep -qw "bdev_nr_sectors" $(srctree)/include/linux/genhd.h $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BDEV_NR_SECTORS)
else

SNAPAPI_FLAGS += $(shell \
	grep -qw "blk_alloc_disk" $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BLK_ALLOC_DISK)

SNAPAPI_FLAGS += $(shell \
	grep -qw "bdev_nr_sectors" $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BDEV_NR_SECTORS)
endif

SNAPAPI_FLAGS += $(shell \
	grep -qw vm_fault_t $(srctree)/include/linux/mm_types.h && \
		echo -DHAVE_VMFAULT_T)

SNAPAPI_FLAGS += $(shell \
	test -e $(srctree)/include/linux/blk-mq.h && \
		grep -qw blk_mq_make_request $(srctree)/include/linux/blk-mq.h && \
		echo -DHAVE_BLK_MQ_MAKE_REQUEST)

SNAPAPI_FAGS += $(shell \
	test -e $(srctree)/block/blk.h && \
		grep -qw blk_cleanup_queue $(srctree)/block/blk.h && \
		echo -DHAVE_BLK_CORE_BLK_CLEANUP_QUEUE)
SNAPAPI_FLAGS += $(shell \
	grep -qw "bi_bdev" $(srctree)/include/linux/blk_types.h \
		$(srctree)/include/linux/bio.h && \
		echo -DHAVE_BIO_BI_BDEV)

SNAPAPI_FLAGS += $(shell \
	grep -qw "bd_super" $(srctree)/include/linux/blk_types.h && \
		echo -DHAVE_BD_SUPER)

SNAPAPI_FLAGS += $(shell \
	grep -qw "bdget" $(srctree)/include/linux/fs.h && \
		echo -DHAVE_BDGET)

SNAPAPI_FLAGS += $(shell \
	grep -qw "thaw_bdev(.*,.*)" $(srctree)/include/linux/fs.h \
		$(srctree)/include/linux/buffer_head.h \
		$(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_THAW_BDEV_2ARGS)

SNAPAPI_FLAGS += $(shell \
	grep -qw "blkdev_get_by_dev.*,.*,.*,.*" $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BLKDEV_GET_4ARGS)

SNAPAPI_FLAGS += $(shell \
	grep -qw bi_partno $(srctree)/include/linux/blk_types.h && \
		echo -DHAVE_BI_PARTNO)

SNAPAPI_FLAGS += $(shell \
	grep -qw "bdev_is_partition" $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BDEV_IS_PARTITION)

SNAPAPI_FLAGS += $(shell \
	grep -qw "bd_part" $(srctree)/include/linux/blk_types.h \
		$(srctree)/include/linux/fs.h && \
		echo -DHAVE_BD_PART)

SNAPAPI_FLAGS += $(shell \
	grep -qw bdev_whole $(srctree)/include/linux/blk_types.h && \
		echo -DHAVE_BDEV_WHOLE)

SNAPAPI_FLAGS += $(shell \
	grep -qw submit_bio_noacct $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_SUBMIT_BIO_BIO_NOACCT)

SNAPAPI_FLAGS += $(shell \
	grep -qw "blk_qc_t (\*submit_bio)[[:space:]]*(struct bio \*bio)" $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BDOPS_SUBMIT_BIO_BLK_QC_T)

SNAPAPI_FLAGS += $(shell \
	grep -qw "void (\*submit_bio)[[:space:]]*(struct bio \*bio)" $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BDOPS_SUBMIT_BIO_VOID)

SNAPAPI_FLAGS += $(shell \
	grep -qw "int (\*open)[[:space:]]*(struct gendisk \*disk,.*)" $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BDOPS_OPEN_ARG_GENDISK)

SNAPAPI_FLAGS += $(shell \
	grep -qw "void (\*release)[[:space:]]*(.*)" $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BDOPS_RELEASE_VOID)

SNAPAPI_FLAGS += $(shell \
	grep -qw "int freeze_bdev" $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_FREEZE_BDEV_INT)

SNAPAPI_FLAGS += $(shell \
	grep -qw blk_queue_split $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BLK_QUEUE_SPLIT)
SNAPAPI_FLAGS += $(shell \
	grep -qw "blk_queue_split.*,.*,.*" $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BLK_QUEUE_SPLIT_3ARGS)
SNAPAPI_FLAGS += $(shell \
	grep -qw bio_split_to_limits $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BIO_SPLIT_TO_LIMITS)

SNAPAPI_FLAGS += $(shell \
	grep -qw "__state;" $(srctree)/include/linux/sched.h && \
		echo -DHAVE_UNDERLINE_STATE)

SNAPAPI_FLAGS += $(shell \
	grep -qw "blk_alloc_disk" $(srctree)/include/linux/genhd.h $(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BLK_ALLOC_DISK)

SNAPAPI_FLAGS += $(shell \
	grep -qw "blk_cleanup_disk" $(srctree)/include/linux/genhd.h \
		$(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BLK_CLEANUP_DISK)

SNAPAPI_FLAGS += $(shell \
	grep -qw "blk_cleanup_queue" $(srctree)/include/linux/genhd.h \
		$(srctree)/include/linux/blkdev.h && \
		echo -DHAVE_BLK_CLEANUP_QUEUE)

SNAPAPI_FLAGS += $(shell \
	grep -qw "CONFIG_PRINTK_INDEX" $(srctree)/include/linux/printk.h && \
		echo -DHAVE_PRINTK_INDEX)

SNAPAPI_FLAGS += $(shell \
	grep -qw "kthread_complete_and_exit" $(srctree)/include/linux/kthread.h && \
		echo -DHAVE_KTHREAD_COMPLETE_AND_EXIT)

SNAPAPI_FLAGS += $(shell \
	grep -qw "complete_and_exit" $(srctree)/include/linux/kernel.h && \
		echo -DHAVE_COMPLETE_AND_EXIT)

SNAPAPI_FLAGS += $(shell \
	grep -qw "bio_alloc(.*,.*)" $(srctree)/include/linux/bio.h && \
		echo -DHAVE_BIO_ALLOC_2ARGS)

#SNAPAPI_FLAGS += $(shell \
#		test "4.15.3-177-hardened" = "$(KERNELRELEASE)" && \
#		echo -DDEBUG)

#SNAPAPI_FLAGS += $(shell \
#		test "4.15.3-177-hardened" = "$(KERNELRELEASE)" && \
#		echo -g)

ifeq (${DO_NOT_BUILD_DEBUG},)
SNAPAPI_FLAGS += -g
endif

$(info SNAPAPI_FLAGS='${SNAPAPI_FLAGS}')

EXTRA_CFLAGS += $(SNAPAPI_FLAGS) $(DKMS_CFLAGS)

endif

SYSTEM_MAP_PATHFILE := snapapi_system_map
SNAPAPI_BUILDSYSTEM_BUILD_FLAGPATH := .buildsystem

ifneq ($(wildcard $(SNAPAPI_BUILDSYSTEM_BUILD_FLAGPATH)),)
OPTIONAL_GENCONFIG_BUILDSYSTEM_FLAG := --buildsystem
endif

$(info SA_CFLAGS='${SA_CFLAGS}')

obj-m				+= snapapi26.o
snapapi26-y			+= snapapi.o
snapapi26-y			+= snapapi_sysfs.o
snapapi26-y			+= snapapi_drv.o

obj-m				+= snumbd26.o
snumbd26-y			+= snumbd.o
snumbd26-y			+= snumbd_drv.o

ccflags-y			+= $(SA_CFLAGS)

.PHONY: clean clean-$(SYSTEM_MAP_PATHFILE)

clean: clean-$(SYSTEM_MAP_PATHFILE)

clean-$(SYSTEM_MAP_PATHFILE):
	if [ -r $(SYSTEM_MAP_PATHFILE) ]; then \
		rm -f `cat '$(SYSTEM_MAP_PATHFILE)'` '$(SYSTEM_MAP_PATHFILE)'; \
	fi
	rm -f kernel_config.h
	$(MAKE) -C $(KERNEL_INC) M=$(PWD) clean

$(SYSTEM_MAP_PATHFILE):
	$(eval TMP_SYSTEM_MAP_FILE := $(shell mktemp /tmp/Cyberprotect.System.map.XXXXXX))
	@echo SnapAPI System.map file will be located at '$(TMP_SYSTEM_MAP_FILE)'
	echo '$(TMP_SYSTEM_MAP_FILE)' > $@
	./snapapi_genconfig.sh --map='$(TMP_SYSTEM_MAP_FILE)' --kver='$(KERNELRELEASE)' --kernel_src_dir='$(srctree)'\
		$(OPTIONAL_GENCONFIG_BUILDSYSTEM_FLAG)
