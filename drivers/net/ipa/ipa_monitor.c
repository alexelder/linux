// SPDX-License-Identifier: GPL-2.0

/* Copyright (C) 2022 Linaro Ltd. */

#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/pm_runtime.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include <linux/stat.h>

#include <uapi/linux/qcom_ipa_monitor.h>

#include "ipa.h"
#include "ipa_data.h"
#include "ipa_endpoint.h"
#include "ipa_monitor.h"

/* Name of the IPA monitor misc device; %u is replaced with the IPA instance */
#define IPA_MONITOR_NAME	"qcom_ipa%u_monitor"

/* Name of the IPA ADPL and ODL control misc devices */
#define IPA_ADPL_NAME		"ipa_adpl"
#define IPA_ODL_CTL_NAME	"ipa_odl_ctl"

/* Definitions for /dev/ipa_odl_ctl IOCTL requests */

struct ipa_odl_ep_info {
	u32 cons_pipe_num;
	u32 prod_pipe_num;
	u32 peripheral_iface_id;
	u32 ep_type;
};

#define IPA_IOC_ODL_QUERY_ADAPL_EP_INFO \
		_IOWR(0xcf, 61, struct ipa_odl_ep_info)

struct ipa_odl_modem_config {
	u8 config_status;
};

#define IPA_IOC_ODL_QUERY_MODEM_CONFIG \
		_IOWR(0xcf, 63, struct ipa_odl_modem_config)

/* Definitions for /dev/ipa_adpl IOCTL requests */
struct odl_agg_pipe_info {
         u16 agg_byte_limit;
};

#define IPA_IOC_ODL_GET_AGG_BYTE_LIMIT \
		_IOWR(0xcf, 62, struct odl_agg_pipe_info)

/**
 * struct ipa_monitor_buffer - IPA buffer for monitor data
 * @page:	Page (possibly compound) holding received data
 * @offset:	Offset in page to start of valid data
 * @resid:	Number of valid bytes (remaining) in page starting at offset
 */
struct ipa_monitor_buffer {
	struct page *page;
	u32 offset;
	u32 resid;
};

/**
 * enum ipa_monitor_flag:	IPA monitor flags
 * @IPA_MONITOR_FLAG_OPEN:	Whether the monitor function is opened
 * @IPA_MONITOR_FLAG_COUNT:	Number of defined monitor flags
 */
enum ipa_monitor_flag {
	IPA_MONITOR_FLAG_OPEN,
	IPA_MONITOR_FLAG_COUNT,		/* Last; not a flag */
};

/**
 * struct ipa_monitor - IPA monitor information
 * @endpoint:	IPA monitor endpoint
 * @buffers:	Array of IPA buffer structures
 * @count:	Number of entries in the buffers[] array
 * @free:	Index of next available buffer (modulo count)
 * @used:	If != free, index of first used (modulo count)
 * @file:	File pointer if the monitor device file is open
 * @wait:	Wait queue head for monitor device file blocking read
 * @misc:	Monitor miscellaneous device structure
 * @adpl_misc:	ADPL miscellaneous device structure
 * @odl_ctl_file: File pointer for /dev/ipa_odl_ctl (when open)
 * @saved_file:	Copy of monitor file, used by ODL control file
 * @odl_ctl_wait: Wait queue head for ODL control file blocking read
 * @odl_ctl_misc: ODL control file device structure
 * @flags:	Bitmap of flags (including open flag)
 *
 * The @buffers[] array is used as a circular FIFO, with each entry able
 * to hold a page that had been provided to hardware as a receive buffer.
 * The number of entries in @buffers[] is a power of 2, and the values of
 * @free and @used are initially equal (meaning no entries are used).
 * Entries are allocated by incrementing @free, and freed by incrementing
 * @used.  The index values are always taken modulo @count, so there's no
 * need to reset them to 0 to ensure they're in range.
 *
 * When the device file is opened, we stash the address of the monitor
 * structure in the file's private data.  The @file pointer is non-null
 * when the device file is open.  If the file was open at the time the
 * driver exits, we reset the file's private_data pointer to NULL.  The
 * file operations check for this and return an error if it occurs, to
 * avoid bad pointer references.
 */
struct ipa_monitor {
	struct ipa_endpoint *endpoint;

	struct ipa_monitor_buffer *buffers;
	u32 count;
	atomic_t free;
	atomic_t used;

	struct file *file;
	wait_queue_head_t wait;
	struct miscdevice misc;
	struct miscdevice adpl_misc;

	struct file *odl_ctl_file;
	struct file *saved_file;
	wait_queue_head_t odl_ctl_wait;
	struct miscdevice odl_ctl_misc;

	DECLARE_BITMAP(flags, IPA_MONITOR_FLAG_COUNT);
};

/* Return the next used buffer, or a null pointer if none available */
static struct ipa_monitor_buffer *
ipa_monitor_buffer_next(struct ipa_monitor *monitor)
{
	u32 used;

	/* If used == free, there are no buffers available */
	used = (u32)atomic_read(&monitor->used);
	if (used == (u32)atomic_read(&monitor->free))
		return NULL;

	/* The modulo operator handles either/both wrapping like magic */

	return &monitor->buffers[used % monitor->count];
}

static void ipa_monitor_replenish(struct ipa_monitor *monitor)
{
	if (test_bit(IPA_MONITOR_FLAG_OPEN, monitor->flags))
		ipa_endpoint_replenish(monitor->endpoint);
}

/* Hold a monitor receive buffer so it can be read */
static void ipa_monitor_buffer_hold(struct ipa_monitor *monitor,
				    struct page *page, u32 len)
{
	struct ipa_monitor_buffer *buffer;
	u32 free;

	/* If the monitor device isn't open, or if there's no data in
	 * the buffer, we're done.  These are unlikely, but either way
	 * we still need to consume the page.
	 */
	if (!test_bit(IPA_MONITOR_FLAG_OPEN, monitor->flags) || !len) {
		put_page(page);
		ipa_monitor_replenish(monitor);
		return;
	}

	/* Use the next available buffer structure */
	free = (u32)atomic_read(&monitor->free);
	buffer = &monitor->buffers[free % monitor->count];
	buffer->page = page;
	buffer->offset = NET_SKB_PAD;
	buffer->resid = len;

	/* Make sure buffer entry is up-to-date before we let it be used */
	smp_mb__before_atomic();
	atomic_inc(&monitor->free);

	/* There could be reader waiting for a buffer to arrive */
	wake_up_interruptible(&monitor->wait);
}

/* Drop the first used buffer structure */
static void ipa_monitor_buffer_drop(struct ipa_monitor *monitor,
				    struct ipa_monitor_buffer *buffer)
{
	put_page(buffer->page);

	atomic_inc(&monitor->used);
}

/* Drop all used buffers */
static void ipa_monitor_buffer_drop_all(struct ipa_monitor *monitor)
{
	struct ipa_monitor_buffer *buffer;

	while ((buffer = ipa_monitor_buffer_next(monitor)))
		ipa_monitor_buffer_drop(monitor, buffer);
}

/** ipa_monitor_open() - Opens the IPA monitor interface */
int ipa_monitor_open(struct ipa *ipa)
{
	struct ipa_monitor *monitor = ipa->monitor;
	struct device *dev = ipa->dev;
	int ret;

	if (!ipa->setup_complete)
		return -ENXIO;

	if (test_and_set_bit(IPA_MONITOR_FLAG_OPEN, monitor->flags))
		return -EBUSY;

	ret = pm_runtime_get_sync(dev);
	if (ret < 0)
		goto err_power_put;

	/* The monitor endpoint is RX (with no matching TX endpoint) */
	ret = ipa_endpoint_enable_one(monitor->endpoint);
	if (ret)
		goto err_power_put;

	pm_runtime_mark_last_busy(dev);
	(void)pm_runtime_put_autosuspend(dev);

	return 0;

err_power_put:
	pm_runtime_put_noidle(dev);

	return ret;
}

void ipa_monitor_close(struct ipa *ipa)
{
	struct ipa_monitor *monitor = ipa->monitor;
	struct device *dev = ipa->dev;

	if (pm_runtime_get_sync(dev) < 0) {
		pm_runtime_put_noidle(dev);

		return;
	}

	ipa_endpoint_disable_one(monitor->endpoint);

	pm_runtime_mark_last_busy(dev);
	(void)pm_runtime_put_autosuspend(dev);

	/* Release any held buffers */
	ipa_monitor_buffer_drop_all(monitor);

	clear_bit(IPA_MONITOR_FLAG_OPEN, monitor->flags);
}

void ipa_monitor_suspend(struct ipa *ipa)
{
	struct ipa_monitor *monitor = ipa->monitor;

	if (!monitor || !test_bit(IPA_MONITOR_FLAG_OPEN, monitor->flags))
		return;

	ipa_endpoint_suspend_one(monitor->endpoint);
}

void ipa_monitor_resume(struct ipa *ipa)
{
	struct ipa_monitor *monitor = ipa->monitor;

	if (!monitor || !test_bit(IPA_MONITOR_FLAG_OPEN, monitor->flags))
		return;

	ipa_endpoint_resume_one(monitor->endpoint);
}

/* Returns true if the received data is for the monitor endpoint */
bool ipa_monitor_receive(struct ipa_endpoint *endpoint,
			 struct page *page, u32 len)
{
	struct ipa_monitor *monitor = endpoint->ipa->monitor;

	/* If it's not a monitor buffer there's nothing to do */
	if (!monitor || endpoint != monitor->endpoint)
		return false;

	ipa_monitor_buffer_hold(monitor, page, len);

	return true;
}

/* Copy monitor entries to a user buffer.  Return value is either
 * the number of bytes copied or a negative error code.  A zero
 * return value indicates the user buffer size is not sufficient to
 * hold the next monitor entry.  If -EAGAIN is returned it means
 * nothing was copied and no monitor data is available.  -EFAULT is
 * returned for a bad user buffer.
 *
 * Note that size is assumed to be non-zero.
 */
static int
ipa_monitor_read(struct ipa_monitor *monitor, char __user *buf, size_t size)
{
	struct ipa_monitor_buffer *buffer = NULL;
	char __user *bufp = buf;
	u32 resid = size;

	do {
		const void *data;
		size_t copy;

		/* Get the next buffer if necessary */
		if (!buffer) {
			buffer = ipa_monitor_buffer_next(monitor);
			if (!buffer)
				break;	/* No available buffers */
		}

		/* See how much we can copy */
		copy = min_t(u32, resid, buffer->resid);

		if (copy) {
			data = page_address(buffer->page) + buffer->offset;
			if (copy_to_user(bufp, data, copy))
				return -EFAULT;

			bufp += copy;
			resid -= copy;

			buffer->offset += copy;
			buffer->resid -= copy;
		} else {
			printk(" === zero-length copy???\n");
			break;
		}

		/* Consume the buffer if we're done with it */
		if (!buffer->resid) {
			ipa_monitor_buffer_drop(monitor, buffer);
			ipa_monitor_replenish(monitor);
			buffer = NULL;
		}
	} while (resid);


	/* Return the number of bytes copied if non-zero */
	if (size > resid)
		return size - resid;

	/* If the user buffer was too small for the first entry, return 0 */
	if (buffer)
		return 0;

	/* Otherwise there is no monitor data is available to read */

	return -EAGAIN;
}

/* Update the monitor pointer stashed in the given file structure */
static void file_monitor_stash(struct file *file, struct ipa_monitor *monitor)
{
	/* We use the file private_data field to hold the monitor pointer.
	 * The pointer is reset to NULL if the driver shuts down.
	 */
	file->private_data = monitor;

	wmb();	/* XXX Check this */
}

/* Get the monitor pointer stashed in the given file structure */
static struct ipa_monitor *file_monitor_fetch(struct file *file)
{
	rmb();	/* XXX Check this*/

	return file->private_data;
}

/* Returns true when more data available, false if interrupted */
static bool ipa_monitor_wait(struct ipa_monitor *monitor)
{
	return !wait_event_interruptible(monitor->wait,
					 !!ipa_monitor_buffer_next(monitor));
}

/* We set this file up as a stream, so the offset is always a null pointer */
static ssize_t
monitor_read(struct file *file, char __user *buf, size_t size, loff_t *off)
{
	struct ipa_monitor *monitor;
	char __user *bufp = buf;
	u32 resid = size;
	int ret;

	monitor = file_monitor_fetch(file);
	if (!monitor)
		return -EIO;		/* Device went away */

	/* Keep reading until there isn't room for the next entry */
	while (resid) {
		ret = ipa_monitor_read(monitor, bufp, resid);
		if (ret > 0) {
			/* We read some bytes, update and get some more */
			bufp += ret;
			resid -= ret;
			continue;
		}

		/* Return now if insufficient space in the user buffer */
		if (!ret)
			break;

		/* If any "real" error occurred, return it */
		if (ret != -EAGAIN)
			return ret;

		/* Nothing to read; we're done if we've copied anything */
		if (size > resid)
			break;

		/* Avoid blocking if requested */
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		/* Otherwise, wait for something to arrive and try again */
		if (!ipa_monitor_wait(monitor))
			return -EINTR;

		if (!file_monitor_fetch(file))
			return -EIO;	/* Device went away */
	}

	return size - resid;	/* Return the number of bytes consumed */
}

static __poll_t monitor_poll(struct file *file, poll_table *wait)
{
	struct ipa_monitor *monitor = file_monitor_fetch(file);

	if (!monitor)
		return EPOLLERR;	/* Device went away */

	poll_wait(file, &monitor->wait, wait);

	if (!file_monitor_fetch(file))
		return EPOLLERR;	/* Device went away */

	if (!!ipa_monitor_buffer_next(monitor))
		return EPOLLIN | EPOLLRDNORM;

	return 0;			/* No buffers to read */
}

static int monitor_open_common(struct inode *inode, struct file *file,
			       struct ipa_monitor *monitor)
{
	int ret;

	ret = ipa_monitor_open(monitor->endpoint->ipa);
	if (ret)
		return ret;

	/* Stash the monitor pointer (instead of the misc device) */
	file_monitor_stash(file, monitor);

	/* This produces a stream of data; there is no "current position." */
	(void)stream_open(inode, file);

	monitor->file = file;	/* Mark the device file as open */

	return 0;
}

static int monitor_open(struct inode *inode, struct file *file)
{
	struct miscdevice *misc = file->private_data;
	struct ipa_monitor *monitor;

	monitor = container_of(misc, struct ipa_monitor, misc);

	return monitor_open_common(inode, file, monitor);
}

static int monitor_release(struct inode *inode, struct file *file)
{
	struct ipa_monitor *monitor = file_monitor_fetch(file);

	if (!monitor)
		return -EIO;		/* Device went away */

	monitor->file = NULL;

	ipa_monitor_close(monitor->endpoint->ipa);

	return 0;
}

static const struct file_operations ipa_monitor_fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.read		= monitor_read,
	.poll		= monitor_poll,
	.open		= monitor_open,
	.release	= monitor_release,
};

static int adpl_open(struct inode *inode, struct file *file)
{
	struct miscdevice *misc = file->private_data;
	struct ipa_monitor *monitor;

	monitor = container_of(misc, struct ipa_monitor, adpl_misc);

	return monitor_open_common(inode, file, monitor);
}

static long adpl_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ipa_monitor *monitor = file_monitor_fetch(file);
	struct odl_agg_pipe_info agg_pipe_info = { };
	struct odl_agg_pipe_info __user *dest;
	u32 limit;

	if (!monitor)
		return -EIO;		/* Device went away */

	if (cmd != IPA_IOC_ODL_GET_AGG_BYTE_LIMIT)
		return -EINVAL;

	limit = ipa_endpoint_aggr_bytes(monitor->endpoint);
	if (!limit)
		return -ENOTTY;

	agg_pipe_info.agg_byte_limit = limit;

	dest = (struct odl_agg_pipe_info __user *)arg;
	if (copy_to_user(dest, &agg_pipe_info, sizeof(*dest)))
		return -EFAULT;

	dev_info(monitor->endpoint->ipa->dev, "ODL buffer size %u\n",
		 agg_pipe_info.agg_byte_limit);

	return 0;
}

static const struct file_operations ipa_adpl_fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.read		= monitor_read,
	.poll		= monitor_poll,
	.unlocked_ioctl	= adpl_ioctl,
	.compat_ioctl	= adpl_ioctl,
	.open		= adpl_open,
	.release	= monitor_release,
};

static ssize_t
odl_ctl_read(struct file *file, char __user *buf, size_t size, loff_t *off)
{
	struct ipa_monitor *monitor = file_monitor_fetch(file);
	u8 adpl_open;

	if (!monitor)
		return -EIO;		/* Device went away */

	if (*off)
		return 0;		/* File is only one byte long */

	adpl_open = monitor->file ? 1 : 0;
	if (copy_to_user(buf, &adpl_open, sizeof(adpl_open)))
		return -EFAULT;

	*off += sizeof(adpl_open);

	return sizeof(adpl_open);
}

/* This is assumed to not be called concurrently */
static bool monitor_status_changed(struct ipa_monitor *monitor)
{
	if (monitor->file == monitor->saved_file)
		return false;

	monitor->saved_file = monitor->file;

	return true;
}

static __poll_t odl_ctl_poll(struct file *file, poll_table *wait)
{
	struct ipa_monitor *monitor = file_monitor_fetch(file);

	if (!monitor)
		return EPOLLERR;	/* Device went away */

	if (monitor_status_changed(monitor))
		return EPOLLIN | EPOLLRDNORM;

	/* Wait for the ADPL file to be opened/closed */
	poll_wait(file, &monitor->odl_ctl_wait, wait);

	if (!file_monitor_fetch(file))
		return EPOLLERR;	/* Device went away */

	if (monitor_status_changed(monitor))
		return EPOLLIN | EPOLLRDNORM;

	return 0;			/* No buffers to read */
}

static long
odl_ctl_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ipa_monitor *monitor = file_monitor_fetch(file);
	struct ipa_odl_modem_config modem_config = { };
	struct ipa_odl_modem_config __user *src;
	struct ipa_odl_ep_info __user *dest;
	struct ipa_odl_ep_info ep_info;
	struct ipa_endpoint *endpoint;
	struct device *dev;
	u8 config_status;

	if (!monitor)
		return -EIO;		/* Device went away */

	endpoint = monitor->endpoint;
	dev = endpoint->ipa->dev;

	switch (cmd) {
	case IPA_IOC_ODL_QUERY_ADAPL_EP_INFO:
		ep_info.cons_pipe_num = U32_MAX;	/* No consumer */
		ep_info.prod_pipe_num = endpoint->endpoint_id;
		ep_info.peripheral_iface_id = 3;	/* ODL_EP_PERIPHERAL */
		ep_info.ep_type = 2;			/* HSUSB */

		dest = (struct ipa_odl_ep_info __user *)arg;
		if (copy_to_user(dest, &ep_info, sizeof(*dest)))
			return -EFAULT;

		dev_info(dev, "ODL endpoint id %u\n", endpoint->endpoint_id);
		break;

	case IPA_IOC_ODL_QUERY_MODEM_CONFIG:
		src = (struct ipa_odl_modem_config __user *)arg;
		if (copy_from_user(&modem_config, src, sizeof(modem_config)))
			return -EFAULT;

		config_status = modem_config.config_status;
		dev_info(dev, "ODL modem config %u (%s)\n", config_status,
			 config_status == 1 ? "SUCCESS" : "???");
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static int odl_ctl_open(struct inode *inode, struct file *file)
{
	struct miscdevice *misc = file->private_data;
	static DEFINE_MUTEX(odl_ctl_mutex);
	struct ipa_monitor *monitor;

	monitor = container_of(misc, struct ipa_monitor, odl_ctl_misc);

	mutex_lock(&odl_ctl_mutex);

	if (monitor->odl_ctl_file) {
		mutex_unlock(&odl_ctl_mutex);
		return -EBUSY;
	}

	/* Stash the monitor pointer (instead of the misc device) */
	file_monitor_stash(file, monitor);
	monitor->odl_ctl_file = file;

	/* Record the monitor file's current state (open or closed) */
	monitor->saved_file = monitor->file;

	mutex_unlock(&odl_ctl_mutex);

	return 0;
}

static int odl_ctl_release(struct inode *inode, struct file *file)
{
	struct ipa_monitor *monitor = file_monitor_fetch(file);

	if (!monitor)
		return -EIO;		/* Device went away */

	monitor->odl_ctl_file = NULL;

	return 0;
}

static const struct file_operations ipa_odl_ctl_fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.read		= odl_ctl_read,
	.poll		= odl_ctl_poll,
	.unlocked_ioctl	= odl_ctl_ioctl,
	.compat_ioctl	= odl_ctl_ioctl,
	.open		= odl_ctl_open,
	.release	= odl_ctl_release,
};

/* Preallocate an array of buffer structures.  There will be one for each
 * possible "in flight" receive buffer in the monitor endpoint transfer ring.
 * Round it up to the next power of 2, so we can use a simple counter to keep
 * track of the next free slot (modulo the number of entries in the array).
 */
static int ipa_monitor_buffer_init(struct ipa_monitor *monitor)
{
	struct ipa_endpoint *endpoint = monitor->endpoint;
	struct gsi *gsi = &endpoint->ipa->gsi;
	struct ipa_monitor_buffer *buffers;
	u32 tre_max;
	u32 count;

	/* Allocate enough buffers for all TREs in the monitor transfer ring */
	tre_max = gsi_channel_tre_max(gsi, endpoint->channel_id);
	count = __roundup_pow_of_two(tre_max);

	buffers = kcalloc(count, sizeof(*buffers), GFP_KERNEL);
	if (!buffers)
		return -ENOMEM;

	monitor->buffers = buffers;
	monitor->count = count;
	atomic_set(&monitor->free, 0);
	atomic_set(&monitor->used, 0);

	return 0;
}

static void ipa_monitor_buffer_exit(struct ipa_monitor *monitor)
{
	ipa_monitor_buffer_drop_all(monitor);

	kfree(monitor->buffers);
	atomic_set(&monitor->used, 0);
	atomic_set(&monitor->free, 0);
	monitor->count = 0;
	monitor->buffers = NULL;
}

static char *ipa_monitor_file_name(struct ipa *ipa, const char *proto)
{
	size_t size = strlen(proto) + 1;
	u32 unit = ipa->dev->id;
	char *name;

	/* We replace "%u" in the prototype with the IPA instance number */
	if (WARN_ON(unit > 99))
		return NULL;

	name = kzalloc(size, GFP_KERNEL);
	if (!name)
		return NULL;

	/* Incorporate the IPA instance number in the file name */
	(void)snprintf(name, size, proto, unit);

	return name;
}

int ipa_monitor_init(struct ipa *ipa)
{
	struct ipa_endpoint *endpoint;
	struct ipa_monitor *monitor;
	struct miscdevice *misc;
	const char *name;
	int ret;

	/* No monitor function if there's no monitor endoint */
	endpoint = ipa->name_map[IPA_ENDPOINT_AP_MONITOR_RX];
	if (!endpoint)
		return 0;	/* Not a problem, just not present */

	monitor = kzalloc(sizeof(*monitor), GFP_KERNEL);
	if (!monitor)
		return -ENOMEM;

	monitor->endpoint = endpoint;

	ret = ipa_monitor_buffer_init(monitor);
	if (ret)
		goto err_monitor_free;

	clear_bit(IPA_MONITOR_FLAG_OPEN, monitor->flags);

	/* Now set up the monitor device file */
	name = ipa_monitor_file_name(ipa, IPA_MONITOR_NAME);
	if (!name) {
		ret = -ENOMEM;
		goto err_buffer_exit;
	}

	monitor->file = NULL;
	init_waitqueue_head(&monitor->wait);

	misc = &monitor->misc;
	misc->minor = MISC_DYNAMIC_MINOR;
	misc->name = name;
	misc->fops = &ipa_monitor_fops;
	misc->mode = S_IRUSR;

	ret = misc_register(misc);
	if (ret) {
		dev_err(ipa->dev, "error %d registering %s\n", ret, name);
		goto err_free_name;
	}

	/* Now set up the ADPL device file */
	misc = &monitor->adpl_misc;
	misc->minor = MISC_DYNAMIC_MINOR;
	misc->name = IPA_ADPL_NAME;
	misc->fops = &ipa_adpl_fops;
	misc->mode = S_IRUSR;

	ret = misc_register(misc);
	if (ret) {
		dev_err(ipa->dev, "error %d registering %s\n",
			ret, IPA_ADPL_NAME);
		goto err_deregister_monitor;
	}

	/* Set up the ODL control device file */
	monitor->odl_ctl_file = NULL;
	init_waitqueue_head(&monitor->odl_ctl_wait);

	misc = &monitor->odl_ctl_misc;
	misc->minor = MISC_DYNAMIC_MINOR;
	misc->name = IPA_ODL_CTL_NAME;
	misc->fops = &ipa_odl_ctl_fops;
	misc->mode = S_IRUSR;

	ret = misc_register(misc);
	if (ret) {
		dev_err(ipa->dev, "error %d registering %s\n",
			ret, IPA_ODL_CTL_NAME);
		goto err_deregister_adpl;
	}

	ipa->monitor = monitor;

	return 0;

err_deregister_adpl:
	misc_deregister(&monitor->adpl_misc);
err_deregister_monitor:
	misc_deregister(&monitor->misc);
err_free_name:
	kfree(name);
err_buffer_exit:
	ipa_monitor_buffer_exit(monitor);
err_monitor_free:
	kfree(monitor);

	return ret;
}

void ipa_monitor_exit(struct ipa *ipa)
{
	struct ipa_monitor *monitor = ipa->monitor;

	if (!monitor)
		return;
	ipa->monitor = NULL;

	/* Try to prevent bad accesses if the monitor device file was open */
	if (monitor->file)
		file_monitor_stash(monitor->file, NULL);
	if (monitor->odl_ctl_file)
		file_monitor_stash(monitor->odl_ctl_file, NULL);

	/* Unblock any waiters so they can return an error */
	wake_up_interruptible(&monitor->wait);

	misc_deregister(&monitor->odl_ctl_misc);
	misc_deregister(&monitor->adpl_misc);
	misc_deregister(&monitor->misc);

	ipa_monitor_buffer_exit(monitor);

	kfree(monitor);
}
