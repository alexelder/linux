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

static size_t qcom_dplv2_entry_size(const void *data, u32 len)
{
	const struct qcom_dplv2_header *header = data;
	u16 pkt_len;

	/* Buffer must start with an IPA status header */
	if (len < sizeof(*header))
		return 0;
	len -= sizeof(*header);

	/* Adjust the packet length; packet is padded to 4-byte alignment */
	pkt_len = round_up(le16_to_cpu(header->pkt_len), 4);

	/* Remainder of the buffer must be big enough to hold the packet data */

	return len < pkt_len ? 0 : sizeof(*header) + pkt_len;
}

static size_t qcom_dplv3_entry_size(const void *data, u32 len)
{
	const struct qcom_dplv3_header *header = data;
	u16 pkt_len;

	/* Buffer must start with an IPA status header */
	if (len < sizeof(*header))
		return 0;
	len -= sizeof(*header);

	/* Get the packet length and adjust for padding to 8 byte alignment */

	pkt_len = le64_get_bits(header->flags1, IPA_DPLv3_FLAGS1_PKT_LEN_FMASK);
	pkt_len = round_up(pkt_len, 8);

	/* Remainder of buffer must be big enough to hold the packet data */

	return len < pkt_len ? 0 : sizeof(*header) + pkt_len;
}

/* Return the size of entry at the data pointer, or 0 if invalid */
static size_t
qcom_dpl_entry_size(struct ipa_monitor *monitor, const void *data, u32 len)
{
	struct ipa *ipa = monitor->endpoint->ipa;

	if (ipa->version < IPA_VERSION_4_5)
		return qcom_dplv2_entry_size(data, len);

	return qcom_dplv3_entry_size(data, len);
}

static size_t ipa_monitor_buffer_max(struct ipa_monitor *monitor,
				     struct ipa_monitor_buffer *buffer, u32 len)
{
	void *data = page_address(buffer->page) + buffer->offset;
	u32 resid = buffer->resid;
	size_t max = 0;
	size_t size;

	/* Get the size of the next entry in the buffer */
	while ((size = qcom_dpl_entry_size(monitor, data, resid))) {
		/* If it won't fit, we're done */
		if (len < size)
			break;

		/* Otherwise account for it, and keep going */
		max += size;
		len -= size;

		data += size;
		resid -= size;
	}

	return max;
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
		if (resid < buffer->resid) {
			/* Limited by the what's left in the user buffer */
			copy = ipa_monitor_buffer_max(monitor, buffer, resid);
			if (!copy)
				break;	/* Not enough room for next entry */
		} else {
			/* Limited by what's left in the page */
			copy = ipa_monitor_buffer_max(monitor, buffer,
						      buffer->resid);
			/* Skip the rest if it's too small (not expected) */
			if (!copy)
				buffer->resid = 0;
		}

		if (copy) {
			data = page_address(buffer->page) + buffer->offset;
			if (copy_to_user(bufp, data, copy))
				return -EFAULT;

			bufp += copy;
			resid -= copy;

			buffer->offset += copy;
			buffer->resid -= copy;
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

static int monitor_open(struct inode *inode, struct file *file)
{
	struct miscdevice *misc = file->private_data;
	struct ipa_monitor *monitor;
	int ret;

	monitor = container_of(misc, struct ipa_monitor, misc);
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

	ipa->monitor = monitor;

	return 0;

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

	/* Unblock any waiters so they can return an error */
	wake_up_interruptible(&monitor->wait);

	misc_deregister(&monitor->misc);

	ipa_monitor_buffer_exit(monitor);

	kfree(monitor);
}
