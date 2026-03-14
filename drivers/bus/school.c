// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2026, Alex Elder <elder@umn.edu> */

#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/mod_devicetable.h>
#include <linux/string.h>
#include <linux/types.h>

/* The name used for this driver, its bus type, and devices of this type */
#define SCHOOL_NAME		"school"	/* 30 or fewere characters */

#define SCHOOL_DEVICE_ID_MAX	15
#define MAX_DEV_NAME_LENGTH	23	/* Not including terminating '\0' */

/* Space characters as defined by isspace() in the "C" and "POSIX" locales */
#define	SPACES			" \f\n\r\t\v"

static int school_device_create(const char *name, size_t size);
static int school_device_destroy(const char *name);

struct school_device {
	struct device dev;
	char name[MAX_DEV_NAME_LENGTH + 1];
	size_t size;
	struct blk_mq_tag_set tag_set;
	struct gendisk *disk;
	struct list_head links;		/* List of school_devices */
};

/* Major block device number used for the school bus */
static unsigned int school_major;

static DEFINE_IDA(school_ida);		/* Unique school device IDs */

static DEFINE_MUTEX(school_devices_mutex);
static LIST_HEAD(school_devices);	/* Protected by school_devices_mutex */

/* Assumes name is from 1 to MAX_DEV_NAME_LENGTH long, and NUL-terminated */
static bool name_valid(const char *name)
{
	if (!isalpha(*name++))
		return false;

	while (*name == '-' || isalnum(*name))
		name++;

	return !*name;
}

/*
 * Skip over space characters at the beginning of the buffer, and advance
 * the buffer pointer whose address is provided to point to the first
 * non-space character.  Return the length of the token that begins at
 * that spot.
 *
 * XXX
 * This should be revised to take into account the number of
 * bytes in the buffer.  Maybe using strsep().
 */
static size_t next_token(const char **buf)
{
	*buf += strspn(*buf, SPACES);

	return strcspn(*buf, SPACES);
}

/**
 * add_store() - Add a new device to the school bus
 * @bus_type:	School bus type
 * @buf:	Buffer containing the parameters for the add
 * @count:	Number of bytes passed via the buffer
 *
 * Return:	Number of bytes written (count), or a negative error code
 *
 * The buffer should contain two whitespace-separated values:
 * - The name to be used for the new device
 * - The size in bytes of the new device
 */
static ssize_t
add_store(const struct bus_type *bus_type, const char *buf, size_t count)
{
	unsigned long long size;
	char *name;
	size_t len;
	int ret;

	len = next_token(&buf);
	if (!len || len > MAX_DEV_NAME_LENGTH)
		return -EINVAL;

	/* Copy the name so we can NUL-terminate it */
	name = kmemdup(buf, len + 1, GFP_KERNEL);
	if (!name)
		return -ENOMEM;
	*(name + len) = '\0';

	if (!name_valid(name)) {
		ret = -EINVAL;
		goto err_free_name;
	}

	buf += len;
	len = next_token(&buf);
	ret = kstrtoull(buf, 0, &size);
	if (ret)
		goto err_free_name;

	ret = school_device_create(name, size);

	kfree(name);

        return ret ? : count;

err_free_name:
	kfree(name);

	return ret;
}

/**
 * list_show() - List all devices on the school bus
 * @bus_type:	School bus type
 * @buf:	Buffer into which device list should be written
 * Return:	Number of bytes read, or a negative error code
 *
 * The buffer should contain the name of the device to be removed
 */
static ssize_t
list_show(const struct bus_type *bus_type, char *buf)
{
	unsigned int school_count = 0;
	struct school_device *sdev;
	ssize_t resid = PAGE_SIZE;
	char *bp = buf;
	int ret;

	mutex_lock(&school_devices_mutex);

	ret = snprintf(bp, resid, "%-9s  %-*s  %s\n", "device",
		       MAX_DEV_NAME_LENGTH, "name", "size (bytes)");
	if (ret < 0)
		return ret;
	bp += ret;
	resid -= ret;

	list_for_each_entry(sdev, &school_devices, links) {
		ret = snprintf(bp, resid, "%-9s  %-*s  0x%zx\n",
			       dev_name(&sdev->dev), MAX_DEV_NAME_LENGTH,
			       sdev->name, sdev->size);
		if (ret < 0)
			return ret;
		bp += ret;
		resid -= ret;
		school_count++;
	}

	mutex_unlock(&school_devices_mutex);

	ret = snprintf(bp, resid, "%u device%s\n", school_count,
			school_count == 1 ? "" : "s");
	if (ret > resid)
		return -EINVAL;

	resid -= ret;

	return PAGE_SIZE - resid;
}

/**
 * remove_store() - Remove a device from the school bus
 * @bus_type:	Bus type
 * @buf:	Buffer containing the parameters for the add
 * @count:	Number of bytes passed via the buffer
 * Return:	Number of bytes written (count), or a negative error code
 *
 * The buffer should contain the name of the device to be removed
 */
static ssize_t
remove_store(const struct bus_type *bus_type, const char *buf, size_t count)
{
	size_t len;
	char *name;
	int ret;

	len = next_token(&buf);
	if (!len)
		return -EINVAL;

	/* Copy the name so we can NUL-terminate it */
	name = kmemdup(buf, len + 1, GFP_KERNEL);
	if (!name)
		return -ENOMEM;
	*(name + len) = '\0';

	ret = school_device_destroy(name);

	kfree(name);

	if (ret)
		return ret;

	return count;
}

static BUS_ATTR_WO(add);
static BUS_ATTR_RO(list);
static BUS_ATTR_WO(remove);

static struct attribute *school_bus_attrs[] = {
        &bus_attr_add.attr,
        &bus_attr_list.attr,
        &bus_attr_remove.attr,
        NULL,
};

static const struct attribute_group school_bus_group = {
        .attrs		= school_bus_attrs,
};
__ATTRIBUTE_GROUPS(school_bus);

static const struct bus_type school_bus_type = {
	.name		= SCHOOL_NAME,
	.dev_name	= SCHOOL_NAME,
	.bus_groups	= school_bus_groups,
};

static struct device school_bus = {
	.init_name	= SCHOOL_NAME,
};

static void school_device_release(struct device *dev)
{
	struct school_device *sdev;
	int id = dev->id;

	sdev = container_of(dev, struct school_device, dev);

	del_gendisk(sdev->disk);
	put_disk(sdev->disk);
	blk_mq_free_tag_set(&sdev->tag_set);
	kfree(sdev);
	ida_free(&school_ida, id);
}

static const struct device_type school_device_type = {
	.name		= SCHOOL_NAME,
	.release	= school_device_release,
};

static int __init school_bus_init(void)
{
	int ret;

	ret = register_blkdev(0, SCHOOL_NAME);
	if (ret < 0)
		return ret;
	school_major = ret;

	ret = device_register(&school_bus);
	if (ret) {
		put_device(&school_bus);
		goto err_unregister_major;
	}

	ret = bus_register(&school_bus_type);
	if (ret) {
		device_unregister(&school_bus);
		goto err_unregister_major;
	}

	return 0;

err_unregister_major:
	unregister_blkdev(school_major, SCHOOL_NAME);
	school_major = 0;

	return ret;
}

static void __exit school_bus_exit(void)
{
	bus_unregister(&school_bus_type);
	device_unregister(&school_bus);
	unregister_blkdev(school_major, SCHOOL_NAME);
	school_major = 0;
}

struct school_device_request {
	u32	foo;
};

static blk_status_t school_queue_rq(struct blk_mq_hw_ctx *hctx,
				    const struct blk_mq_queue_data *bd)
{
	return BLK_STS_OK;
}

struct blk_mq_ops school_mq_ops = {
	.queue_rq	= school_queue_rq,
};

static int school_device_create(const char *name, size_t size)
{
	struct blk_mq_tag_set *tag_set;
	struct school_device *sdev;
	struct gendisk *disk;
	struct device *dev;
	unsigned int id;
	int ret = 0;

	/* Make sure the name isn't already in use */

	mutex_lock(&school_devices_mutex);

	list_for_each_entry(sdev, &school_devices, links) {
		if (!strcmp(sdev->name, name)) {
			ret = -EEXIST;
			break;
		}
	}

	if (ret)
		goto out_unlock;

	/* Get a minor device number for the new device */
	BUILD_BUG_ON(SCHOOL_DEVICE_ID_MAX >= 1 << MINORBITS);
	ret = ida_alloc_max(&school_ida, SCHOOL_DEVICE_ID_MAX, GFP_KERNEL);
	if (id < 0)
		goto out_unlock;
	id = ret;

	sdev = kzalloc(sizeof(*sdev), GFP_KERNEL);
	if (!sdev) {
		ret = -ENOMEM;
		goto err_free_id;
	}

	/* OK we can proceed with creating the device */
	strncpy(sdev->name, name, sizeof(sdev->name));
	sdev->size = size;

	/*
	 * Modern storage devices (like SSDs) support multiple request
	 * queues.  This allows more I/O requests to be in flight for the
	 * device, taking advantage of parallelism such devices offer.  A
	 * generic blk-mq API was developed to provide this capability.
	 *
	 * This API includes the notion of a *tag* associated with each
	 * I/O request.  When a submitted request completes, the block
	 * layer will notify the initiator, providing this tag.  We need
	 * to initialize a per-device tag_set structure to use this.
	 */
	tag_set = &sdev->tag_set;
	tag_set->ops = &school_mq_ops;
	tag_set->nr_hw_queues = num_present_cpus();
	tag_set->queue_depth = BLKDEV_DEFAULT_RQ;
	tag_set->cmd_size = sizeof(struct school_device_request);
	tag_set->numa_node = NUMA_NO_NODE;
	// tag_set->driver_data = sdev;
	// tag_set->flags = BLK_MQ_F_BLOCKING;

	ret = blk_mq_alloc_tag_set(tag_set);
	if (ret)
		goto err_free_sdev;

	disk = blk_mq_alloc_disk(tag_set, NULL, sdev);
	if (IS_ERR(disk)) {
		ret = PTR_ERR(disk);
		goto err_free_tag_set;
	}
	sdev->disk = disk;

	/* Max minor number is at most 2 decimal digits wide */
	(void)snprintf(disk->disk_name, DISK_NAME_LEN, SCHOOL_NAME "%u", id);

	disk->major = school_major;
	disk->first_minor = id;
	disk->minors = SCHOOL_DEVICE_ID_MAX + 1;
	disk->private_data = sdev;
	set_capacity(disk, size / SECTOR_SIZE);

	dev = &sdev->dev;
	dev->parent = &school_bus;
	dev->type = &school_device_type;
	dev->bus = &school_bus_type;
	dev->id = id;

	/* The next two are just device_register() */
	device_initialize(dev);
	ret = device_add(dev);
	if (!ret)
		list_add_tail(&sdev->links, &school_devices);

	mutex_unlock(&school_devices_mutex);

	ret = device_add_disk(dev, disk, NULL);
	if (ret)
		put_device(dev);

	return ret;

err_free_tag_set:
	blk_mq_free_tag_set(tag_set);
err_free_sdev:
	kfree(sdev);
err_free_id:
	ida_free(&school_ida, id);
out_unlock:
	mutex_unlock(&school_devices_mutex);

	return ret;
}

static int school_device_destroy(const char *name)
{
	struct school_device *sdev;
	int ret = -ENOENT;

	mutex_lock(&school_devices_mutex);

	/* Find the device with this name and remove it from the list */
	list_for_each_entry(sdev, &school_devices, links) {
		if (!strcmp(sdev->name, name)) {
			list_del(&sdev->links);
			ret = 0;
			break;
		}
	}

	mutex_unlock(&school_devices_mutex);

	if (ret)
		return -ENOENT;

	device_unregister(&sdev->dev);

	return 0;
}

module_init(school_bus_init);
module_exit(school_bus_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("School bus driver");
