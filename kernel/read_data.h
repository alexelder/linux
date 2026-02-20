#ifndef KERNEL_READ_DATA_H
#define KERNEL_READ_DATA_H
// SPDX-License-Identifier: GPL-2.0

struct data {
    long counter;
    long data;
};

#ifdef CONFIG_READ_DATA
/* Copy a constant long value into the provided user buffer */
long do_read_data(struct data __user *dest, size_t size);

long do_save_data(long data);
#else
static inline long do_read_data(struct data __user *dest, size_t size)
{
    return -ENOSYS;
}

static inline long do_save_data(long data)
{
    return -EINVAL;
}
#endif

#endif /* KERNEL_READ_DATA_H */
