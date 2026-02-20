#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/spinlock_types.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "read_data.h"

#define DATA_RECORD_COUNT 10

static long counter = 5980;
static struct data kernel_data[DATA_RECORD_COUNT];
static unsigned write_next = 0;
static unsigned read_next = 0;
static unsigned num_items = 0;

DEFINE_SPINLOCK(data_lock);

static void advance_read(void)
{
    read_next = (read_next + 1) % DATA_RECORD_COUNT;
    num_items--;
}

static void advance_write(void)
{
    write_next = (write_next + 1) % DATA_RECORD_COUNT;
    if (num_items == DATA_RECORD_COUNT) {
        /* Write to an already full buffer */
        /* Bump read pointer forward to oldest entry in buffer */
        advance_read();
    }
    /* Ok to increment this even in full buffer case */
    /* Full case: We just undo the decrement in advance_read() */
    num_items++;
}

static long do_read_one(struct data __user *dest)
{
    struct data src;

    spin_lock(&data_lock);
    if (num_items == 0) {
        spin_unlock(&data_lock);
        return 0;
    }
    src = kernel_data[read_next];
    advance_read();
    spin_unlock(&data_lock);

    if (copy_to_user(dest, &src, sizeof(*dest)))
        return -EFAULT;

    return sizeof(*dest);
}


long do_read_data(struct data __user *dest, size_t size)
{
    size_t total_bytes_read;
    long current_bytes_read;

    if (size < sizeof(*dest))
        return 0;

    total_bytes_read = 0;
    while (total_bytes_read < size) {
        current_bytes_read = do_read_one(dest);
        if (current_bytes_read == 0)
            return total_bytes_read;
        if (current_bytes_read < 0)
            return current_bytes_read;

        total_bytes_read += current_bytes_read;
        dest++;
    }
    return total_bytes_read;
}

long do_save_data(long data)
{
    spin_lock(&data_lock);
    kernel_data[write_next].data = data;
    kernel_data[write_next].counter = counter;
    counter++;
    advance_write();
    spin_unlock(&data_lock);
    return 0;
}
