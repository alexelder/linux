// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */
#include <linux/vmalloc.h>
#include <linux/types.h>
#include <linux/list.h>
#include <media/v4l2-mem2mem.h>

#include "iris_ctrls.h"
#include "iris_instance.h"
#include "iris_hfi_2_defines.h"

#define MIN_CAPTURE_BUFFERS 4
#define MIN_OUTPUT_BUFFERS 4

static bool iris_is_valid_cap_id(enum plat_inst_cap_type cap_id)
{
	return cap_id >= 0 && cap_id < INST_CAP_MAX;
}

static enum plat_inst_cap_type iris_get_cap_id(struct iris_inst *inst, u32 id)
{
	enum plat_inst_cap_type cap_id = 0;
	enum plat_inst_cap_type iter = 0;

	do {
		if (inst->cap[iter].v4l2_id == id) {
			cap_id = inst->cap[iter].cap_id;
			break;
		}
		iter++;
	} while (iter < INST_CAP_MAX);

	return cap_id;
}

static int iris_vdec_op_g_volatile_ctrl(struct v4l2_ctrl *ctrl)
{
	enum plat_inst_cap_type cap_id;
	struct iris_inst *inst = NULL;
	int ret = 0;

	inst = container_of(ctrl->handler, struct iris_inst, ctrl_handler);
	switch (ctrl->id) {
	case V4L2_CID_MIN_BUFFERS_FOR_CAPTURE:
		ctrl->val = inst->buffers.output.min_count;
		break;
	case V4L2_CID_MIN_BUFFERS_FOR_OUTPUT:
		ctrl->val = inst->buffers.input.min_count;
		break;
	default:
		cap_id = iris_get_cap_id(inst, ctrl->id);
		if (iris_is_valid_cap_id(cap_id))
			ctrl->val = inst->cap[cap_id].value;
		else
			ret = -EINVAL;
	}

	return ret;
}

static int iris_vdec_op_s_ctrl(struct v4l2_ctrl *ctrl)
{
	enum plat_inst_cap_type cap_id;
	struct plat_inst_cap *cap;
	struct iris_inst *inst;
	int ret = 0;

	inst = container_of(ctrl->handler, struct iris_inst, ctrl_handler);
	cap = &inst->cap[0];

	cap_id = iris_get_cap_id(inst, ctrl->id);
	if (!iris_is_valid_cap_id(cap_id))
		return -EINVAL;

	if (!iris_allow_s_ctrl(inst, cap_id))
		return -EBUSY;

	cap[cap_id].flags |= CAP_FLAG_CLIENT_SET;

	inst->cap[cap_id].value = ctrl->val;

	return ret;
}

static const struct v4l2_ctrl_ops iris_ctrl_ops = {
	.s_ctrl = iris_vdec_op_s_ctrl,
	.g_volatile_ctrl = iris_vdec_op_g_volatile_ctrl,
};

int iris_ctrls_init(struct iris_inst *inst)
{
	int num_ctrls = 0, ctrl_idx = 0;
	struct plat_inst_cap *cap;
	struct iris_core *core;
	int idx = 0;
	int ret = 0;

	core = inst->core;
	cap = &inst->cap[0];

	for (idx = 0; idx < INST_CAP_MAX; idx++) {
		if (cap[idx].v4l2_id)
			num_ctrls++;
	}
	if (!num_ctrls)
		return -EINVAL;

	ret = v4l2_ctrl_handler_init(&inst->ctrl_handler, num_ctrls);
	if (ret)
		return ret;

	for (idx = 0; idx < INST_CAP_MAX; idx++) {
		struct v4l2_ctrl *ctrl;

		if (!cap[idx].v4l2_id)
			continue;

		if (ctrl_idx >= num_ctrls) {
			ret = -EINVAL;
			goto error;
		}

		if (cap[idx].flags & CAP_FLAG_MENU) {
			ctrl = v4l2_ctrl_new_std_menu(&inst->ctrl_handler,
						      &iris_ctrl_ops,
						      cap[idx].v4l2_id,
						      cap[idx].max,
						      ~(cap[idx].step_or_mask),
						      cap[idx].value);
		} else {
			ctrl = v4l2_ctrl_new_std(&inst->ctrl_handler,
						 &iris_ctrl_ops,
						 cap[idx].v4l2_id,
						 cap[idx].min,
						 cap[idx].max,
						 cap[idx].step_or_mask,
						 cap[idx].value);
		}
		if (!ctrl) {
			ret = -EINVAL;
			goto error;
		}

		ret = inst->ctrl_handler.error;
		if (ret)
			goto error;

		if ((cap[idx].flags & CAP_FLAG_VOLATILE) ||
		    (ctrl->id == V4L2_CID_MIN_BUFFERS_FOR_CAPTURE ||
		     ctrl->id == V4L2_CID_MIN_BUFFERS_FOR_OUTPUT))
			ctrl->flags |= V4L2_CTRL_FLAG_VOLATILE;

		ctrl->flags |= V4L2_CTRL_FLAG_EXECUTE_ON_WRITE;
		ctrl_idx++;
	}
	inst->num_ctrls = num_ctrls;

	return 0;
error:
	v4l2_ctrl_handler_free(&inst->ctrl_handler);

	return ret;
}

int iris_core_init_caps(struct iris_core *core)
{
	struct plat_core_cap *core_platform_data;
	int i, num_core_caps;

	core_platform_data = core->platform_data->core_data;
	if (!core_platform_data)
		return -EINVAL;

	num_core_caps = core->platform_data->core_data_size;

	for (i = 0; i < num_core_caps && i < CORE_CAP_MAX; i++) {
		core->cap[core_platform_data[i].type].type = core_platform_data[i].type;
		core->cap[core_platform_data[i].type].value = core_platform_data[i].value;
	}

	return 0;
}

int iris_session_init_caps(struct iris_core *core)
{
	struct plat_inst_cap *inst_plat_cap_data;
	int i, num_inst_cap;
	u32 cap_id;

	inst_plat_cap_data = core->platform_data->inst_cap_data;
	if (!inst_plat_cap_data)
		return -EINVAL;

	num_inst_cap = core->platform_data->inst_cap_data_size;

	for (i = 0; i < num_inst_cap && i < INST_CAP_MAX; i++) {
		cap_id = inst_plat_cap_data[i].cap_id;
		if (!iris_is_valid_cap_id(cap_id))
			continue;

		core->inst_cap[cap_id].cap_id = inst_plat_cap_data[i].cap_id;
		core->inst_cap[cap_id].min = inst_plat_cap_data[i].min;
		core->inst_cap[cap_id].max = inst_plat_cap_data[i].max;
		core->inst_cap[cap_id].step_or_mask = inst_plat_cap_data[i].step_or_mask;
		core->inst_cap[cap_id].value = inst_plat_cap_data[i].value;
		core->inst_cap[cap_id].flags = inst_plat_cap_data[i].flags;
		core->inst_cap[cap_id].v4l2_id = inst_plat_cap_data[i].v4l2_id;
		core->inst_cap[cap_id].hfi_id = inst_plat_cap_data[i].hfi_id;
	}

	return 0;
}

void iris_get_capability(struct iris_inst *inst)
{
	struct iris_core *core;

	core = inst->core;
	memcpy(&inst->cap[0], &core->inst_cap[0],
	       (INST_CAP_MAX + 1) * sizeof(struct plat_inst_cap));
}

static u32 iris_get_port_info(struct iris_inst *inst,
			      enum plat_inst_cap_type cap_id)
{
	if (inst->cap[cap_id].flags & CAP_FLAG_INPUT_PORT)
		return HFI_PORT_BITSTREAM;
	else if (inst->cap[cap_id].flags & CAP_FLAG_OUTPUT_PORT)
		return HFI_PORT_RAW;

	return HFI_PORT_NONE;
}

int iris_set_u32_enum(struct iris_inst *inst, enum plat_inst_cap_type cap_id)
{
	u32 hfi_value = inst->cap[cap_id].value;
	u32 hfi_id = inst->cap[cap_id].hfi_id;
	struct iris_core *core = inst->core;

	return core->hfi_ops->session_set_property(inst, hfi_id,
						   HFI_HOST_FLAGS_NONE,
						   iris_get_port_info(inst, cap_id),
						   HFI_PAYLOAD_U32_ENUM,
						   &hfi_value, sizeof(u32));
}

int iris_set_u32(struct iris_inst *inst, enum plat_inst_cap_type cap_id)
{
	u32 hfi_value = inst->cap[cap_id].value;
	u32 hfi_id = inst->cap[cap_id].hfi_id;
	struct iris_core *core = inst->core;

	return core->hfi_ops->session_set_property(inst, hfi_id,
						   HFI_HOST_FLAGS_NONE,
						   iris_get_port_info(inst, cap_id),
						   HFI_PAYLOAD_U32,
						   &hfi_value, sizeof(u32));
}

int iris_set_stage(struct iris_inst *inst, enum plat_inst_cap_type cap_id)
{
	struct iris_core *core = inst->core;
	struct v4l2_format *inp_f;
	u32 work_mode = STAGE_2;
	u32 width, height;
	u32 hfi_id;

	hfi_id = inst->cap[cap_id].hfi_id;

	inp_f = inst->fmt_src;
	height = inp_f->fmt.pix_mp.height;
	width = inp_f->fmt.pix_mp.width;
	if (iris_res_is_less_than(width, height, 1280, 720))
		work_mode = STAGE_1;

	return core->hfi_ops->session_set_property(inst, hfi_id,
						   HFI_HOST_FLAGS_NONE,
						   iris_get_port_info(inst, cap_id),
						   HFI_PAYLOAD_U32,
						   &work_mode, sizeof(u32));
}

int iris_set_pipe(struct iris_inst *inst, enum plat_inst_cap_type cap_id)
{
	struct iris_core *core = inst->core;
	u32 work_route, hfi_id;

	work_route = inst->cap[PIPE].value;
	hfi_id = inst->cap[cap_id].hfi_id;

	return core->hfi_ops->session_set_property(inst, hfi_id,
						   HFI_HOST_FLAGS_NONE,
						   iris_get_port_info(inst, cap_id),
						   HFI_PAYLOAD_U32,
						   &work_route, sizeof(u32));
}

static int iris_set_cap(struct iris_inst *inst, enum plat_inst_cap_type cap_id)
{
	struct plat_inst_cap *cap;

	cap = &inst->cap[cap_id];
	if (!inst->cap[cap_id].cap_id)
		return 0;

	if (!cap->set)
		return 0;

	return cap->set(inst, cap_id);
}

int iris_set_properties(struct iris_inst *inst, u32 plane)
{
	struct iris_core *core = inst->core;
	struct plat_inst_cap *cap;
	int ret = 0;

	ret = core->hfi_ops->session_set_config_params(inst, plane);
	if (ret)
		return ret;

	for (int i = 1; i < INST_CAP_MAX; i++) {
		cap = &inst->cap[i];
		if (!iris_is_valid_cap_id(cap->cap_id))
			continue;

		ret = iris_set_cap(inst, cap->cap_id);
		if (ret)
			return ret;
	}

	return ret;
}
