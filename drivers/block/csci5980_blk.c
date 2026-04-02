// SPDX-License-Identifier: GPL-2.0-only

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/module.h>

#define DRIVER_NAME	"csci5980_blk"

/* Allocated major device number */
static unsigned int major;

/* Tag set used for requests */
static struct blk_mq_tag_set tag_set;

static blk_status_t csci5980_queue_rq(struct blk_mq_hw_ctx *hctx,
				      const struct blk_mq_queue_data *bd)
{
	return BLK_STS_OK;
}

struct blk_mq_ops csci5980_mq_ops = {
	.queue_rq	= csci5980_queue_rq,
};

static int __init csci5980_init(void)
{
	int ret;

	ret = register_blkdev(0, DRIVER_NAME);
	if (ret < 0)
		return ret;

	major = ret;
	printk(" === major device number %u\n", major);

	tag_set.ops = &csci5980_mq_ops;
	tag_set.nr_hw_queues = 1;
	tag_set.queue_depth = BLKDEV_DEFAULT_RQ;
	tag_set.numa_node = NUMA_NO_NODE;
	ret = blk_mq_alloc_tag_set(&tag_set);
	if (ret)
		goto err_unregister_blkdev;

	return 0;

err_unregister_blkdev:
	unregister_blkdev(major, DRIVER_NAME);

	return ret;
}

static void __exit csci5980_exit(void)
{
	blk_mq_free_tag_set(&tag_set);
	unregister_blkdev(major, DRIVER_NAME);
}

MODULE_DESCRIPTION("U of M CSCi 5980 block device driver");
MODULE_LICENSE("GPL");

module_init(csci5980_init);
module_exit(csci5980_exit);
