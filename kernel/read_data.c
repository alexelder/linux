#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/spinlock_types.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "read_data.h"

#define DATA_RECORD_COUNT 10

static struct data kernel_data[DATA_RECORD_COUNT];

static long counter = 5980;

static unsigned long write_next;
static unsigned long read_next;
static unsigned long avail;

DEFINE_SPINLOCK(lock);

/* Assumes spin lock held */
static unsigned long advance_read(void)
{
	avail--;

	return read_next++ % DATA_RECORD_COUNT;
}

/* Assumes spin lock held */
static unsigned long advance_write(void)
{
	/*
	 * If the buffer is currently full, this write will overwrite the
	 * oldest data in the array.  In that case, advance the read index
	 * so it still refers to the oldest available entry.
	 */
	if (avail++ == DATA_RECORD_COUNT)
		advance_read();

	return write_next++ % DATA_RECORD_COUNT;
}

static long do_read_one(struct data __user *dest)
{
	struct data src;
	bool copy;

	spin_lock(&lock);

	copy = avail != 0;
	if (copy)
		src = kernel_data[advance_read()];

	spin_unlock(&lock);

	if (!copy)
		return 0;

	if (copy_to_user(dest, &src, sizeof(*dest)))
		return -EFAULT;

	return sizeof(*dest);
}


long do_read_data(struct data __user *dest, size_t size)
{
	size_t total = 0;

	while (size >= sizeof(*dest)) {
		long ret;

		ret = do_read_one(dest++);
		if (ret < 0)
			return ret;
		if (!ret)
			return total;

		total += ret;
		size -= ret;
	}

	return total;
}

long do_save_data(long data)
{
	struct data *dest;

	spin_lock(&lock);

	dest = &kernel_data[advance_write()];

	dest->data = data;
	dest->counter = counter++;

	spin_unlock(&lock);

	return 0;
}
