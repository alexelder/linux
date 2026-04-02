// SPDX-License-Identifier: GPL-2.0-only

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/vmalloc.h>

#define DRIVER_NAME	"csci5980_blk"

/* Size of the buffer */
#define DISK_SIZE	SZ_1M

/* Buffer pointer */
static void *data;

/* Allocated major device number */
static unsigned int major;

/* Tag set used for requests */
static struct blk_mq_tag_set tag_set;

/* Generic disk structure representing our disk */
static struct gendisk *disk;

static blk_status_t csci5980_queue_rq(struct blk_mq_hw_ctx *hctx,
				      const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	struct req_iterator iter;
	struct bio_vec bvec;
	bool from_device;
	void *buf;

	from_device = rq_data_dir(rq) == READ;
	buf = data + blk_rq_pos(rq) * SECTOR_SIZE;

	rq_for_each_segment(bvec, rq, iter) {
		if (from_device)
			memcpy_to_bvec(&bvec, buf);
		else
			memcpy_from_bvec(buf, &bvec);
		buf += bvec.bv_len;
	}
	blk_mq_end_request(rq, BLK_STS_OK);

	return BLK_STS_OK;
}

struct blk_mq_ops csci5980_mq_ops = {
	.queue_rq	= csci5980_queue_rq,
};

static const struct block_device_operations csci5980_blk_fops = {
	.owner		= THIS_MODULE,
};

static int __init csci5980_init(void)
{
	int ret;

	data = vzalloc(DISK_SIZE);
	if (!data)
		return -ENOMEM;

	ret = register_blkdev(0, DRIVER_NAME);
	if (ret < 0)
		goto err_free_data;

	major = ret;
	printk(" === major device number %u\n", major);

	tag_set.ops = &csci5980_mq_ops;
	tag_set.nr_hw_queues = 1;
	tag_set.queue_depth = BLKDEV_DEFAULT_RQ;
	tag_set.numa_node = NUMA_NO_NODE;
	ret = blk_mq_alloc_tag_set(&tag_set);
	if (ret)
		goto err_unregister_blkdev;

	disk = blk_mq_alloc_disk(&tag_set, NULL, NULL);
	if (IS_ERR(disk)) {
		ret = PTR_ERR(disk);
		goto err_free_tag_set;
	}

	disk->major = major;
	disk->first_minor = 0;
	disk->minors = 1;
	strcpy(disk->disk_name, DRIVER_NAME);
	disk->fops = &csci5980_blk_fops;
	set_capacity(disk, DISK_SIZE / SECTOR_SIZE);

	ret = add_disk(disk);
	if (ret)
		goto err_put_disk;

	return 0;

err_put_disk:
	put_disk(disk);
err_free_tag_set:
	blk_mq_free_tag_set(&tag_set);
err_unregister_blkdev:
	unregister_blkdev(major, DRIVER_NAME);
err_free_data:
	vfree(data);

	return ret;
}

static void __exit csci5980_exit(void)
{
	del_gendisk(disk);
	put_disk(disk);
	blk_mq_free_tag_set(&tag_set);
	blk_mq_free_tag_set(&tag_set);
	unregister_blkdev(major, DRIVER_NAME);
	vfree(data);
}

MODULE_DESCRIPTION("U of M CSCi 5980 block device driver");
MODULE_LICENSE("GPL");

module_init(csci5980_init);
module_exit(csci5980_exit);
