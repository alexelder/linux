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
static void advance_read(void)
{
	read_next = (read_next + 1) % DATA_RECORD_COUNT;
	avail--;
}

/* Assumes spin lock held */
static void advance_write(void)
{
	write_next = (write_next + 1) % DATA_RECORD_COUNT;

	/*
	 * If the buffer is full, advance read pointer to the next entry.
	 * If we were full, advance_read will undo our increment.
	 */
	if (avail++ == DATA_RECORD_COUNT)
		advance_read();
}

static long do_read_one(struct data __user *dest)
{
	struct data src;
	bool copy;

	spin_lock(&lock);

	copy = avail != 0;
	if (copy) {
		src = kernel_data[read_next];
		advance_read();
	}

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

	dest = &kernel_data[write_next];

	dest->data = data;
	dest->counter = counter++;

	advance_write();

	spin_unlock(&lock);

	return 0;
}
