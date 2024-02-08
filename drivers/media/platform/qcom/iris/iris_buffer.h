/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _IRIS_BUFFER_H_
#define _IRIS_BUFFER_H_

#include <media/v4l2-dev.h>
#include <media/videobuf2-v4l2.h>

struct iris_inst;

enum iris_buffer_type {
	BUF_NONE,
	BUF_INPUT,
	BUF_OUTPUT,
	BUF_BIN,
	BUF_ARP,
	BUF_COMV,
	BUF_NON_COMV,
	BUF_LINE,
	BUF_DPB,
	BUF_PERSIST,
	BUF_VPSS,
	BUF_SCRATCH,
	BUF_SCRATCH_1,
};

enum iris_buffer_attributes {
	BUF_ATTR_DEFERRED		= BIT(0),
	BUF_ATTR_PENDING_RELEASE	= BIT(1),
	BUF_ATTR_QUEUED			= BIT(2),
	BUF_ATTR_DEQUEUED		= BIT(3),
	BUF_ATTR_BUFFER_DONE		= BIT(4),
};

/**
 * struct iris_buffer
 *
 * @vb2: v4l2 vb2 buffer
 * @list: list head for the buffers queue
 * @inst: iris instance structure
 * @type: enum for type of iris buffer
 * @index: identifier for the iris buffer
 * @fd: file descriptor of the buffer
 * @buffer_size: accessible buffer size in bytes starting from addr_offset
 * @data_offset: accessible buffer offset from base address
 * @data_size: data size in bytes
 * @device_addr: device address of the buffer
 * @kvaddr: kernel virtual address of the buffer
 * @dma_attrs: dma attributes
 * @flags: buffer flags. It is represented as bit masks.
 * @timestamp: timestamp of the buffer in nano seconds (ns)
 * @attr: enum for iris buffer attributes
 */
struct iris_buffer {
	struct vb2_v4l2_buffer		vb2;
	struct list_head		list;
	struct iris_inst		*inst;
	enum iris_buffer_type		type;
	u32				index;
	int				fd;
	u32				buffer_size;
	u32				data_offset;
	u32				data_size;
	u64				device_addr;
	void				*kvaddr;
	unsigned long			dma_attrs;
	u32				flags;
	u64				timestamp;
	enum iris_buffer_attributes	attr;
};

struct iris_buffers {
	struct list_head	list;
	u32			min_count;
	u32			actual_count;
	u32			size;
};

struct iris_buffers_info {
	struct iris_buffers	input;
	struct iris_buffers	output;
	struct iris_buffers	bin;
	struct iris_buffers	arp;
	struct iris_buffers	comv;
	struct iris_buffers	non_comv;
	struct iris_buffers	line;
	struct iris_buffers	dpb;
	struct iris_buffers	persist;
	struct iris_buffers	vpss;
	struct iris_buffers	scratch;
	struct iris_buffers	scratch1;
};

int iris_get_buffer_size(struct iris_inst *inst,
			 enum iris_buffer_type buffer_type);
struct iris_buffers *iris_get_buffer_list(struct iris_inst *inst,
					  enum iris_buffer_type buffer_type);
int iris_get_internal_buffers(struct iris_inst *inst,
			      u32 plane);
int iris_create_input_internal_buffers(struct iris_inst *inst);
int iris_create_output_internal_buffers(struct iris_inst *inst);
int iris_queue_input_internal_buffers(struct iris_inst *inst);
int iris_queue_output_internal_buffers(struct iris_inst *inst);
int iris_destroy_internal_buffer(struct iris_inst *inst,
				 struct iris_buffer *buffer);
int iris_destroy_internal_buffers(struct iris_inst *inst,
				  u32 plane);
int iris_alloc_and_queue_persist_bufs(struct iris_inst *inst);
int iris_alloc_and_queue_input_int_bufs(struct iris_inst *inst);

#endif
