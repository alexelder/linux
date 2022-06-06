// SPDX-License-Identifier: GPL-2.0

/*
 * University of Minnesota "Hello, world!" driver.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>

static int __init hello_world_init(void)
{
	printk("Hello, world!\n");

	return 0;
}

static void __exit hello_world_exit(void)
{
	printk("Goodbye, world!\n");
}

MODULE_DESCRIPTION("University of Minnesota 'Hello, world!' driver");
MODULE_AUTHOR("Alex Elder <elder@kernel.org>");
MODULE_LICENSE("GPLv2");

module_init(hello_world_init);
module_exit(hello_world_exit);
