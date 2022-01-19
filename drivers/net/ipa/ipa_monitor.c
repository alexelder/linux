// SPDX-License-Identifier: GPL-2.0

/* Copyright (C) 2022 Linaro Ltd. */

#include <linux/device.h>
#include <linux/errno.h>
#include <linux/pm_runtime.h>

#include <uapi/linux/qcom_ipa_monitor.h>

#include "ipa.h"
#include "ipa_data.h"
#include "ipa_endpoint.h"
#include "ipa_monitor.h"

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
 * @flags:	Bitmap of flags (including open flag)
 *
 * The @buffers[] array is used as a circular FIFO, with each entry able
 * to hold a page that had been provided to hardware as a receive buffer.
 * The number of entries in @buffers[] is a power of 2, and the values of
 * @free and @used are initially equal (meaning no entries are used).
 * Entries are allocated by incrementing @free, and freed by incrementing
 * @used.  The index values are always taken modulo @count, so there's no
 * need to reset them to 0 to ensure they're in range.
 */
struct ipa_monitor {
	struct ipa_endpoint *endpoint;

	struct ipa_monitor_buffer *buffers;
	u32 count;
	atomic_t free;
	atomic_t used;

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
}

/* Drop the first used buffer structure */
static void ipa_monitor_buffer_drop(struct ipa_monitor *monitor,
				    struct ipa_monitor_buffer *buffer)
{
	put_page(buffer->page);
	buffer->page = NULL;

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

int ipa_monitor_init(struct ipa *ipa)
{
	struct ipa_endpoint *endpoint;
	struct ipa_monitor *monitor;
	int ret;

	(void)ipa_monitor_read;		/* XXX */

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

	ipa->monitor = monitor;

	return 0;

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

	ipa_monitor_buffer_exit(monitor);

	kfree(monitor);
}
