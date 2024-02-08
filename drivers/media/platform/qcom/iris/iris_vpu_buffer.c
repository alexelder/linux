// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include "iris_instance.h"
#include "iris_vpu_buffer.h"

static inline u32 iris_vpu_dec_bin_size(struct iris_inst *inst)
{
	u32 width, height, num_vpp_pipes;
	struct iris_core *core;
	struct v4l2_format *f;

	core = inst->core;

	num_vpp_pipes = core->cap[NUM_VPP_PIPE].value;

	f = inst->fmt_src;
	width = f->fmt.pix_mp.width;
	height = f->fmt.pix_mp.height;

	return hfi_buffer_bin_h264d(width, height, num_vpp_pipes);
}

static inline u32 iris_vpu_dec_comv_size(struct iris_inst *inst)
{
	u32 width, height, num_comv;
	struct v4l2_format *f;

	f = inst->fmt_src;
	width = f->fmt.pix_mp.width;
	height = f->fmt.pix_mp.height;

	num_comv = inst->buffers.output.min_count;

	return hfi_buffer_comv_h264d(width, height, num_comv);
}

static inline u32 iris_vpu_dec_persist_size(struct iris_inst *inst)
{
	return hfi_buffer_persist_h264d();
}

static inline u32 iris_vpu_dec_dpb_size(struct iris_inst *inst)
{
	if (iris_split_mode_enabled(inst))
		return iris_get_buffer_size(inst, BUF_DPB);
	else
		return 0;
}

static inline u32 iris_vpu_dec_non_comv_size(struct iris_inst *inst)
{
	u32 width, height, num_vpp_pipes;
	struct iris_core *core;
	struct v4l2_format *f;

	core = inst->core;

	num_vpp_pipes = core->cap[NUM_VPP_PIPE].value;

	f = inst->fmt_src;
	width = f->fmt.pix_mp.width;
	height = f->fmt.pix_mp.height;

	return hfi_buffer_non_comv_h264d(width, height, num_vpp_pipes);
}

static inline u32 iris_vpu_dec_line_size(struct iris_inst *inst)
{
	u32 width, height, out_min_count, num_vpp_pipes;
	struct iris_core *core;
	struct v4l2_format *f;
	bool is_opb = false;

	core = inst->core;
	num_vpp_pipes = core->cap[NUM_VPP_PIPE].value;

	if (iris_split_mode_enabled(inst))
		is_opb = true;

	f = inst->fmt_src;
	width = f->fmt.pix_mp.width;
	height = f->fmt.pix_mp.height;
	out_min_count = inst->buffers.output.min_count;

	return hfi_buffer_line_h264d(width, height, is_opb,
				     num_vpp_pipes);
}

static inline u32 iris_vpu_dec_scratch1_size(struct iris_inst *inst)
{
	return iris_vpu_dec_comv_size(inst) +
		iris_vpu_dec_non_comv_size(inst) +
		iris_vpu_dec_line_size(inst);
}

struct iris_vpu_buf_type_handle {
	enum iris_buffer_type type;
	u32 (*handle)(struct iris_inst *inst);
};

int iris_vpu_buf_size(struct iris_inst *inst, enum iris_buffer_type buffer_type)
{
	const struct iris_vpu_buf_type_handle *buf_type_handle_arr = NULL;
	u32 size = 0, buf_type_handle_size = 0;
	int i;

	static const struct iris_vpu_buf_type_handle dec_internal_buf_type_handle[] = {
		{BUF_BIN,         iris_vpu_dec_bin_size             },
		{BUF_COMV,        iris_vpu_dec_comv_size            },
		{BUF_NON_COMV,    iris_vpu_dec_non_comv_size        },
		{BUF_LINE,        iris_vpu_dec_line_size            },
		{BUF_PERSIST,     iris_vpu_dec_persist_size         },
		{BUF_DPB,         iris_vpu_dec_dpb_size             },
		{BUF_SCRATCH,     iris_vpu_dec_bin_size             },
		{BUF_SCRATCH_1,   iris_vpu_dec_scratch1_size        },
	};

	buf_type_handle_size = ARRAY_SIZE(dec_internal_buf_type_handle);
	buf_type_handle_arr = dec_internal_buf_type_handle;

	if (!buf_type_handle_arr || !buf_type_handle_size)
		return size;

	for (i = 0; i < buf_type_handle_size; i++) {
		if (buf_type_handle_arr[i].type == buffer_type) {
			size = buf_type_handle_arr[i].handle(inst);
			break;
		}
	}

	return size;
}

static inline int iris_vpu_dpb_count(struct iris_inst *inst)
{
	int count = 0;

	if (iris_split_mode_enabled(inst)) {
		count = inst->fw_min_count ?
			inst->fw_min_count : inst->buffers.output.min_count;
	}

	return count;
}

int iris_vpu_buf_count(struct iris_inst *inst, enum iris_buffer_type buffer_type)
{
	switch (buffer_type) {
	case BUF_INPUT:
		return MIN_BUFFERS;
	case BUF_OUTPUT:
		return inst->fw_min_count;
	case BUF_BIN:
	case BUF_COMV:
	case BUF_NON_COMV:
	case BUF_LINE:
	case BUF_PERSIST:
	case BUF_SCRATCH:
	case BUF_SCRATCH_1:
		return INTERAL_BUF_COUNT;
	case BUF_DPB:
		return iris_vpu_dpb_count(inst);
	default:
		return 0;
	}
}
