// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */
#include <linux/types.h>

#include "iris_instance.h"

bool iris_res_is_less_than(u32 width, u32 height,
			   u32 ref_width, u32 ref_height)
{
	u32 num_mbs = NUM_MBS_PER_FRAME(height, width);
	u32 max_side = max(ref_width, ref_height);

	if (num_mbs < NUM_MBS_PER_FRAME(ref_height, ref_width) &&
	    width < max_side &&
	    height < max_side)
		return true;

	return false;
}

int iris_get_mbpf(struct iris_inst *inst)
{
	int height = 0, width = 0;
	struct v4l2_format *inp_f;

	inp_f = inst->fmt_src;
	width = max(inp_f->fmt.pix_mp.width, inst->crop.width);
	height = max(inp_f->fmt.pix_mp.height, inst->crop.height);

	return NUM_MBS_PER_FRAME(height, width);
}

bool iris_split_mode_enabled(struct iris_inst *inst)
{
	if (inst->fmt_dst->fmt.pix_mp.pixelformat == V4L2_PIX_FMT_NV12)
		return true;

	return false;
}

int iris_wait_for_session_response(struct iris_inst *inst, bool is_flush)
{
	u32 hw_response_timeout_val;
	struct iris_core *core;
	int ret;

	core = inst->core;
	hw_response_timeout_val = core->cap[HW_RESPONSE_TIMEOUT].value;

	mutex_unlock(&inst->lock);
	if (is_flush)
		ret = wait_for_completion_timeout(&inst->flush_completion,
						  msecs_to_jiffies(hw_response_timeout_val));
	else
		ret = wait_for_completion_timeout(&inst->completion,
						  msecs_to_jiffies(hw_response_timeout_val));
	mutex_lock(&inst->lock);
	if (!ret) {
		iris_inst_change_state(inst, IRIS_INST_ERROR);
		ret = -ETIMEDOUT;
	} else {
		ret = 0;
	}

	return ret;
}

struct iris_inst *iris_get_instance(struct iris_core *core, u32 session_id)
{
	struct iris_inst *inst = NULL;

	mutex_lock(&core->lock);
	list_for_each_entry(inst, &core->instances, list) {
		if (inst->session_id == session_id) {
			mutex_unlock(&core->lock);
			return inst;
		}
	}
	mutex_unlock(&core->lock);

	return NULL;
}

