/* snapapi_sysfs.c
   Copyright (C) Acronis, 2004
   Copyright (c) CyberProtect
*/

#include "snconfig.h"
#include "snapapi.h"


extern int snap_prealloc_force;
extern int snap_emergency_size;
extern const int * const snap_emergency_size_max_p;


#define sn_kattr_to_snap_attr(__kattr) \
	container_of(__kattr, struct snap_attribute, attr)

struct snap_attribute {
	struct attribute attr;
	ssize_t (*show) (struct snap_attribute *snap_attr, char *buf);
	ssize_t (*store) (struct snap_attribute *snap_attr, const char *buf, size_t count);
};

static ssize_t sa_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct snap_attribute *snap_attr = sn_kattr_to_snap_attr(attr);
	return snap_attr->show(snap_attr, buf);
}

static ssize_t sa_store(struct kobject *kobj, struct attribute *attr, const char *buf, size_t count)
{
	struct snap_attribute *snap_attr = sn_kattr_to_snap_attr(attr);
	return snap_attr->store(snap_attr, buf, count);
}

static ssize_t sa_prealloc_show(struct snap_attribute *snap_attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", snap_prealloc_force);
}

static ssize_t sa_prealloc_store(struct snap_attribute *snap_attr, const char *buf, size_t count)
{
	int prealloc;
	if (kstrtoint(buf, 10, &prealloc) < 0)
		return -EINVAL;

	switch(prealloc) {
		case SNAP_PREALLOC_DEFAULT:
		case SNAP_PREALLOC_FORCE_ON:
		case SNAP_PREALLOC_FORCE_OFF:
			snap_prealloc_force = prealloc;
			break;
		default:
			return -EINVAL;
	}
	return count;
}

static struct snap_attribute snap_prealloc_attr =
	__ATTR(prealloc_force, 0644, sa_prealloc_show, sa_prealloc_store);

static ssize_t sa_max_emergency_show(struct snap_attribute *snap_attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", *snap_emergency_size_max_p);
}

static struct snap_attribute snap_max_emergency_attr =
	__ATTR(max_emergency_pages, 0444, sa_max_emergency_show, NULL);

static ssize_t sa_min_emergency_show(struct snap_attribute *snap_attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", SNAP_EMERGENCY_SIZE_MIN);
}

static struct snap_attribute snap_min_emergency_attr =
	__ATTR(min_emergency_pages, 0444, sa_min_emergency_show, NULL);

static ssize_t sa_emergency_show(struct snap_attribute *snap_attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", snap_emergency_size);
}

static ssize_t sa_emergency_store(struct snap_attribute *snap_attr, const char *buf, size_t count)
{
	int emergency_size;
	if (kstrtoint(buf, 10, &emergency_size) < 0)
		return -EINVAL;

	if (emergency_size < SNAP_EMERGENCY_SIZE_MIN || emergency_size > *snap_emergency_size_max_p)
		return -EINVAL;
	snap_emergency_size = emergency_size;
	return count;
}

static struct snap_attribute snap_emergency_attr =
	__ATTR(emergency_pages, 0644, sa_emergency_show, sa_emergency_store);

static struct attribute *snap_attrs[] = {
	&snap_prealloc_attr.attr,
	&snap_max_emergency_attr.attr,
	&snap_min_emergency_attr.attr,
	&snap_emergency_attr.attr,
	NULL
};

static const struct attribute_group snap_attr_group = {
	.attrs = snap_attrs,
};

static struct kobject snap_kobj;

static struct sysfs_ops snap_sysfs_ops = {
	.show = sa_show,
	.store = sa_store
};

static struct kobj_type snap_ktype = {
	.sysfs_ops = &snap_sysfs_ops,
	.release = NULL,
};

int sa_sysfs_create(void)
{
	int ret;

	do {
		kobject_init(&snap_kobj, &snap_ktype);
		ret = kobject_add(&snap_kobj, fs_kobj, "%s", SNAPCTL_NAME);
		if (ret)
			break;

		ret = sysfs_create_group(&snap_kobj, &snap_attr_group);
		if (ret)
			break;

		return 0;
	} while (0);

	kobject_del(&snap_kobj);

	return ret;
}

void sa_sysfs_remove(void)
{
	kobject_del(&snap_kobj);
}
