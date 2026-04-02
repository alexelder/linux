// SPDX-License-Identifier: GPL-2.0-only

#include <linux/blkdev.h>
#include <linux/module.h>

#define DRIVER_NAME	"csci5980_blk"

/* Allocated major device number */
static unsigned int major;

static int __init csci5980_init(void)
{
	int ret;

	ret = register_blkdev(0, DRIVER_NAME);
	if (ret < 0)
		return ret;

	major = ret;
	printk(" === major device number %u\n", major);

	return 0;
}

static void __exit csci5980_exit(void)
{
	unregister_blkdev(major, DRIVER_NAME);
}

MODULE_DESCRIPTION("U of M CSCi 5980 block device driver");
MODULE_LICENSE("GPL");

module_init(csci5980_init);
module_exit(csci5980_exit);
