// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */
#include <media/v4l2-mem2mem.h>

#include "iris_buffer_helpers.h"
#include "iris_hfi_2_defines.h"
#include "iris_instance.h"
#include "iris_vpu_buffer.h"

#define MB_IN_PIXEL (16 * 16)
#define NUM_MBS_4k (((4096 + 15) >> 4) * ((2304 + 15) >> 4))

static u32 iris_buffer_size(u32 colorformat,
			    u32 pix_width,
			    u32 pix_height)
{
	u32 y_plane, uv_plane, y_stride, uv_stride, y_sclines, uv_sclines;
	u32 uv_meta_stride, uv_meta_plane;
	u32 y_meta_stride, y_meta_plane;
	u32 size = 0;

	if (!pix_width || !pix_height)
		goto invalid_input;

	switch (colorformat) {
	case V4L2_PIX_FMT_NV12:
		y_stride = ALIGN(pix_width, 128);
		uv_stride = ALIGN(pix_width, 128);
		y_sclines = ALIGN(pix_height, 32);
		uv_sclines = ALIGN((pix_height + 1) >> 1, 16);
		y_plane = y_stride * y_sclines;
		uv_plane = uv_stride * uv_sclines;
		size = y_plane + uv_plane;
		break;
	case V4L2_PIX_FMT_QC08C:
		y_meta_stride = ALIGN(DIV_ROUND_UP(pix_width, 32), 64);
		y_meta_plane = y_meta_stride * ALIGN(DIV_ROUND_UP(pix_height, 8), 16);
		y_meta_plane = ALIGN(y_meta_plane, SZ_4K);

		y_stride = ALIGN(pix_width, 128);
		y_plane = ALIGN(y_stride * ALIGN(pix_height, 32), SZ_4K);

		uv_meta_stride = ALIGN(DIV_ROUND_UP(pix_width / 2, 16), 64);
		uv_meta_plane = uv_meta_stride * ALIGN(DIV_ROUND_UP(pix_height / 2, 8), 16);
		uv_meta_plane = ALIGN(uv_meta_plane, SZ_4K);

		uv_stride = ALIGN(pix_width, 128);
		uv_plane = ALIGN(uv_stride * ALIGN(pix_height / 2, 32), SZ_4K);

		size =  y_meta_plane + y_plane + uv_meta_plane + uv_plane;
	default:
		break;
	}

invalid_input:
	return ALIGN(size, 4096);
}

static u32 iris_input_buffer_size(struct iris_inst *inst)
{
	u32 base_res_mbs = NUM_MBS_4k;
	u32 frame_size, num_mbs;
	struct v4l2_format *f;
	u32 div_factor;

	f = inst->fmt_src;

	num_mbs = iris_get_mbpf(inst);
	if (num_mbs > NUM_MBS_4k) {
		div_factor = 4;
		base_res_mbs = inst->cap[MBPF].value;
	} else {
		base_res_mbs = NUM_MBS_4k;
		div_factor = 2;
	}

	frame_size = base_res_mbs * MB_IN_PIXEL * 3 / 2 / div_factor;

	return ALIGN(frame_size, SZ_4K);
}

static u32 iris_output_buffer_size(struct iris_inst *inst)
{
	struct v4l2_format *f;

	f = inst->fmt_dst;

	return iris_buffer_size(f->fmt.pix_mp.pixelformat, f->fmt.pix_mp.width,
				f->fmt.pix_mp.height);
}

static u32 iris_dpb_buffer_size(struct iris_inst *inst)
{
	struct v4l2_format *f;

	f = inst->fmt_dst;

	return iris_buffer_size(V4L2_PIX_FMT_QC08C, f->fmt.pix_mp.width,
				f->fmt.pix_mp.height);
}

int iris_get_buffer_size(struct iris_inst *inst,
			 enum iris_buffer_type buffer_type)
{
	switch (buffer_type) {
	case BUF_INPUT:
		return iris_input_buffer_size(inst);
	case BUF_OUTPUT:
		return iris_output_buffer_size(inst);
	case BUF_DPB:
		return iris_dpb_buffer_size(inst);
	default:
		return 0;
	}
}

struct iris_buffers *iris_get_buffer_list(struct iris_inst *inst,
					  enum iris_buffer_type buffer_type)
{
	switch (buffer_type) {
	case BUF_INPUT:
		return &inst->buffers.input;
	case BUF_OUTPUT:
		return &inst->buffers.output;
	case BUF_BIN:
		return &inst->buffers.bin;
	case BUF_ARP:
		return &inst->buffers.arp;
	case BUF_COMV:
		return &inst->buffers.comv;
	case BUF_NON_COMV:
		return &inst->buffers.non_comv;
	case BUF_LINE:
		return &inst->buffers.line;
	case BUF_DPB:
		return &inst->buffers.dpb;
	case BUF_PERSIST:
		return &inst->buffers.persist;
	case BUF_VPSS:
		return &inst->buffers.vpss;
	case BUF_SCRATCH:
		return &inst->buffers.scratch;
	case BUF_SCRATCH_1:
		return &inst->buffers.scratch1;
	default:
		return NULL;
	}
}

static int iris_get_internal_buf_info(struct iris_inst *inst,
				      enum iris_buffer_type buffer_type)
{
	struct iris_buffers *buffers;
	struct iris_core *core;

	core = inst->core;

	buffers = iris_get_buffer_list(inst, buffer_type);
	if (!buffers)
		return -EINVAL;

	buffers->size = iris_vpu_buf_size(inst, buffer_type);
	buffers->min_count = iris_vpu_buf_count(inst, buffer_type);

	dev_dbg(core->dev, "buffer type %d count %d size %d",
		buffer_type, buffers->min_count, buffers->size);

	return 0;
}

int iris_get_internal_buffers(struct iris_inst *inst,
			      u32 plane)
{
	const u32 *internal_buf_type;
	u32 internal_buffer_count;
	int ret = 0;
	u32 i = 0;

	if (V4L2_TYPE_IS_OUTPUT(plane)) {
		internal_buf_type = inst->core->platform_data->dec_ip_int_buf_tbl;
		internal_buffer_count = inst->core->platform_data->dec_ip_int_buf_tbl_size;
		for (i = 0; i < internal_buffer_count; i++) {
			ret = iris_get_internal_buf_info(inst, internal_buf_type[i]);
			if (ret)
				return ret;
		}
	} else {
		internal_buf_type = inst->core->platform_data->dec_op_int_buf_tbl;
		internal_buffer_count = inst->core->platform_data->dec_op_int_buf_tbl_size;
		for (i = 0; i < internal_buffer_count; i++) {
			ret = iris_get_internal_buf_info(inst, internal_buf_type[i]);
			if (ret)
				return ret;
		}
	}

	return ret;
}

static int iris_create_internal_buffer(struct iris_inst *inst,
				       enum iris_buffer_type buffer_type, u32 index)
{
	struct iris_buffers *buffers;
	struct iris_buffer *buffer;
	struct iris_core *core;

	core = inst->core;

	buffers = iris_get_buffer_list(inst, buffer_type);
	if (!buffers)
		return -EINVAL;

	if (!buffers->size)
		return 0;

	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	INIT_LIST_HEAD(&buffer->list);
	buffer->type = buffer_type;
	buffer->index = index;
	buffer->buffer_size = buffers->size;
	buffer->dma_attrs = DMA_ATTR_WRITE_COMBINE | DMA_ATTR_NO_KERNEL_MAPPING;
	list_add_tail(&buffer->list, &buffers->list);

	buffer->kvaddr = dma_alloc_attrs(core->dev, buffer->buffer_size,
					 &buffer->device_addr, GFP_KERNEL, buffer->dma_attrs);
	if (!buffer->kvaddr)
		return -ENOMEM;

	return 0;
}

static int iris_create_internal_buffers(struct iris_inst *inst,
					enum iris_buffer_type buffer_type)
{
	struct iris_buffers *buffers;
	int ret = 0;
	int i;

	buffers = iris_get_buffer_list(inst, buffer_type);
	if (!buffers)
		return -EINVAL;

	for (i = 0; i < buffers->min_count; i++) {
		ret = iris_create_internal_buffer(inst, buffer_type, i);
		if (ret)
			return ret;
	}

	return ret;
}

int iris_create_input_internal_buffers(struct iris_inst *inst)
{
	const u32 *internal_buf_type;
	u32 internal_buffer_count;
	int ret = 0;
	u32 i = 0;

	internal_buf_type = inst->core->platform_data->dec_ip_int_buf_tbl;
	internal_buffer_count = inst->core->platform_data->dec_ip_int_buf_tbl_size;
	for (i = 0; i < internal_buffer_count; i++) {
		ret = iris_create_internal_buffers(inst, internal_buf_type[i]);
		if (ret)
			return ret;
	}

	return ret;
}

int iris_create_output_internal_buffers(struct iris_inst *inst)
{
	const u32 *internal_buf_type;
	u32 internal_buffer_count;
	int ret = 0;
	u32 i = 0;

	internal_buf_type = inst->core->platform_data->dec_op_int_buf_tbl;
	internal_buffer_count = inst->core->platform_data->dec_op_int_buf_tbl_size;

	for (i = 0; i < internal_buffer_count; i++) {
		ret = iris_create_internal_buffers(inst, internal_buf_type[i]);
		if (ret)
			return ret;
	}

	return ret;
}

static int iris_set_num_comv(struct iris_inst *inst)
{
	struct iris_core *core;
	u32 num_comv;

	core = inst->core;

	num_comv = inst->cap[NUM_COMV].value;

	return core->hfi_ops->session_set_property(inst,
						   HFI_PROP_COMV_BUFFER_COUNT,
						   HFI_HOST_FLAGS_NONE,
						   HFI_PORT_BITSTREAM,
						   HFI_PAYLOAD_U32,
						   &num_comv, sizeof(u32));
}

static int iris_queue_internal_buffers(struct iris_inst *inst,
				       enum iris_buffer_type buffer_type)
{
	struct iris_buffer *buffer, *next;
	struct iris_buffers *buffers;
	struct iris_core *core;
	int ret = 0;

	core = inst->core;

	if (buffer_type == BUF_COMV) {
		ret = iris_set_num_comv(inst);
		if (ret)
			return ret;
	}

	buffers = iris_get_buffer_list(inst, buffer_type);
	if (!buffers)
		return -EINVAL;

	list_for_each_entry_safe(buffer, next, &buffers->list, list) {
		if (buffer->attr & BUF_ATTR_PENDING_RELEASE)
			continue;
		if (buffer->attr & BUF_ATTR_QUEUED)
			continue;
		ret = iris_queue_buffer(inst, buffer);
		if (ret)
			return ret;
	}

	return ret;
}

int iris_queue_input_internal_buffers(struct iris_inst *inst)
{
	const u32 *internal_buf_type;
	u32 internal_buffer_count;
	int ret = 0;
	u32 i = 0;

	internal_buf_type = inst->core->platform_data->dec_ip_int_buf_tbl;
	internal_buffer_count = inst->core->platform_data->dec_ip_int_buf_tbl_size;

	for (i = 0; i < internal_buffer_count; i++) {
		ret = iris_queue_internal_buffers(inst, internal_buf_type[i]);
		if (ret)
			return ret;
	}

	return ret;
}

int iris_queue_output_internal_buffers(struct iris_inst *inst)
{
	const u32 *internal_buf_type;
	u32 internal_buffer_count;
	int ret = 0;
	u32 i = 0;

	internal_buf_type = inst->core->platform_data->dec_op_int_buf_tbl;
	internal_buffer_count = inst->core->platform_data->dec_op_int_buf_tbl_size;

	for (i = 0; i < internal_buffer_count; i++) {
		ret = iris_queue_internal_buffers(inst, internal_buf_type[i]);
		if (ret)
			return ret;
	}

	return ret;
}

int iris_destroy_internal_buffer(struct iris_inst *inst,
				 struct iris_buffer *buffer)
{
	struct iris_buffer *buf, *next;
	struct iris_buffers *buffers;
	struct iris_core *core;

	core = inst->core;

	buffers = iris_get_buffer_list(inst, buffer->type);
	if (!buffers)
		return -EINVAL;

	list_for_each_entry_safe(buf, next, &buffers->list, list) {
		if (buf->device_addr == buffer->device_addr) {
			list_del(&buf->list);
			dma_free_attrs(core->dev, buf->buffer_size, buf->kvaddr,
				       buf->device_addr, buf->dma_attrs);
			buf->kvaddr = NULL;
			buf->device_addr = 0;
			kfree(buf);
			break;
		}
	}

	return 0;
}

int iris_destroy_internal_buffers(struct iris_inst *inst,
				  u32 plane)
{
	const u32 *internal_buf_type = NULL;
	struct iris_buffer *buf, *next;
	struct iris_buffers *buffers;
	int ret = 0;
	u32 i, len = 0;

	if (V4L2_TYPE_IS_OUTPUT(plane)) {
		internal_buf_type = inst->core->platform_data->dec_ip_int_buf_tbl;
		len = inst->core->platform_data->dec_ip_int_buf_tbl_size;
	} else {
		internal_buf_type = inst->core->platform_data->dec_op_int_buf_tbl;
		len = inst->core->platform_data->dec_op_int_buf_tbl_size;
	}

	for (i = 0; i < len; i++) {
		buffers = iris_get_buffer_list(inst, internal_buf_type[i]);
		if (!buffers)
			return -EINVAL;

		list_for_each_entry_safe(buf, next, &buffers->list, list) {
			ret = iris_destroy_internal_buffer(inst, buf);
			if (ret)
				return ret;
		}
	}

	return ret;
}

static int iris_release_internal_buffers(struct iris_inst *inst,
					 enum iris_buffer_type buffer_type)
{
	struct iris_buffer *buffer, *next;
	struct iris_buffers *buffers;
	struct iris_core *core;
	int ret = 0;

	core = inst->core;

	buffers = iris_get_buffer_list(inst, buffer_type);
	if (!buffers)
		return -EINVAL;

	list_for_each_entry_safe(buffer, next, &buffers->list, list) {
		if (buffer->attr & BUF_ATTR_PENDING_RELEASE)
			continue;
		if (!(buffer->attr & BUF_ATTR_QUEUED))
			continue;
		ret = core->hfi_ops->session_release_buf(inst, buffer);
		if (ret)
			return ret;
		buffer->attr |= BUF_ATTR_PENDING_RELEASE;
	}

	return ret;
}

static int iris_release_input_internal_buffers(struct iris_inst *inst)
{
	const u32 *internal_buf_type;
	u32 internal_buffer_count;
	int ret = 0;
	u32 i = 0;

	internal_buf_type = inst->core->platform_data->dec_ip_int_buf_tbl;
	internal_buffer_count = inst->core->platform_data->dec_ip_int_buf_tbl_size;

	for (i = 0; i < internal_buffer_count; i++) {
		ret = iris_release_internal_buffers(inst, internal_buf_type[i]);
		if (ret)
			return ret;
	}

	return ret;
}

int iris_alloc_and_queue_persist_bufs(struct iris_inst *inst)
{
	int ret;

	ret = iris_get_internal_buf_info(inst, BUF_PERSIST);
	if (ret)
		return ret;

	ret = iris_create_internal_buffers(inst, BUF_PERSIST);
	if (ret)
		return ret;

	return iris_queue_internal_buffers(inst, BUF_PERSIST);
}

int iris_alloc_and_queue_input_int_bufs(struct iris_inst *inst)
{
	int ret;

	ret = iris_get_internal_buffers(inst, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE);
	if (ret)
		return ret;

	ret = iris_release_input_internal_buffers(inst);
	if (ret)
		return ret;

	ret = iris_create_input_internal_buffers(inst);
	if (ret)
		return ret;

	return iris_queue_input_internal_buffers(inst);
}
