// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include "iris_instance.h"

#define IRIS_STATE(name)[IRIS_CORE_##name] = "CORE_"#name

static const char * const iris_core_state_names[] = {
	IRIS_STATE(DEINIT),
	IRIS_STATE(INIT),
	IRIS_STATE(ERROR),
};

#undef IRIS_STATE

static const char *iris_core_state_name(enum iris_core_state state)
{
	if ((unsigned int)state < ARRAY_SIZE(iris_core_state_names))
		return iris_core_state_names[state];

	return "UNKNOWN_STATE";
}

static bool iris_allow_core_state_change(struct iris_core *core,
					 enum iris_core_state req_state)
{
	if (core->state == IRIS_CORE_DEINIT)
		return req_state == IRIS_CORE_INIT || req_state == IRIS_CORE_ERROR;
	else if (core->state == IRIS_CORE_INIT)
		return req_state == IRIS_CORE_DEINIT || req_state == IRIS_CORE_ERROR;
	else if (core->state == IRIS_CORE_ERROR)
		return req_state == IRIS_CORE_DEINIT;

	dev_warn(core->dev, "core state change %s -> %s is not allowed\n",
		 iris_core_state_name(core->state), iris_core_state_name(req_state));

	return false;
}

int iris_change_core_state_locked(struct iris_core *core,
				  enum iris_core_state request_state)
{
	int ret;

	if (!mutex_is_locked(&core->lock))
		return -EINVAL;

	if (core->state == request_state)
		return 0;

	if (!iris_allow_core_state_change(core, request_state))
		return -EINVAL;

	core->state = request_state;

	return ret;
}

int iris_change_core_state(struct iris_core *core,
			   enum iris_core_state request_state)
{
	int ret;

	mutex_lock(&core->lock);
	ret = iris_change_core_state_locked(core, request_state);
	mutex_unlock(&core->lock);

	return ret;
}

static bool iris_allow_inst_state_change(struct iris_inst *inst,
					 enum iris_inst_state req_state)
{
	switch (inst->state) {
	case IRIS_INST_INIT:
		if (req_state == IRIS_INST_INPUT_STREAMING ||
		    req_state == IRIS_INST_OUTPUT_STREAMING ||
		    req_state == IRIS_INST_DEINIT ||
		    req_state == IRIS_INST_ERROR)
			return true;
		break;
	case IRIS_INST_INPUT_STREAMING:
		if (req_state == IRIS_INST_INIT ||
		    req_state == IRIS_INST_STREAMING ||
		    req_state == IRIS_INST_DEINIT ||
		    req_state == IRIS_INST_ERROR)
			return true;
		break;
	case IRIS_INST_OUTPUT_STREAMING:
		if (req_state == IRIS_INST_INIT ||
		    req_state == IRIS_INST_STREAMING ||
		    req_state == IRIS_INST_DEINIT ||
		    req_state == IRIS_INST_ERROR)
			return true;
		break;
	case IRIS_INST_STREAMING:
		if (req_state == IRIS_INST_INPUT_STREAMING ||
		    req_state == IRIS_INST_OUTPUT_STREAMING ||
		    req_state == IRIS_INST_DEINIT ||
		    req_state == IRIS_INST_ERROR)
			return true;
		break;
	case IRIS_INST_DEINIT:
		if (req_state == IRIS_INST_INIT ||
		    req_state == IRIS_INST_ERROR)
			return true;
		break;
	default:
		return false;
	}

	return false;
}

int iris_inst_change_state(struct iris_inst *inst,
			   enum iris_inst_state request_state)
{
	if (IS_SESSION_ERROR(inst))
		return 0;

	if (inst->state == request_state)
		return 0;

	if (!iris_allow_inst_state_change(inst, request_state))
		return -EINVAL;

	dev_dbg(inst->core->dev, "state changed from %x to %x\n",
		inst->state, request_state);

	inst->state = request_state;

	return 0;
}

bool iris_allow_s_fmt(struct iris_inst *inst, u32 type)
{
	return (inst->state == IRIS_INST_DEINIT) ||
		(inst->state == IRIS_INST_INIT) ||
		(V4L2_TYPE_IS_CAPTURE(type) && inst->state == IRIS_INST_INPUT_STREAMING) ||
		(V4L2_TYPE_IS_OUTPUT(type) && inst->state == IRIS_INST_OUTPUT_STREAMING);
}

bool iris_allow_reqbufs(struct iris_inst *inst, u32 type)
{
	return (inst->state == IRIS_INST_DEINIT) ||
		(inst->state == IRIS_INST_INIT) ||
		(V4L2_TYPE_IS_CAPTURE(type) && inst->state == IRIS_INST_INPUT_STREAMING) ||
		(V4L2_TYPE_IS_OUTPUT(type) && inst->state == IRIS_INST_OUTPUT_STREAMING);
}

bool iris_allow_qbuf(struct iris_inst *inst, u32 type)
{
	return (V4L2_TYPE_IS_OUTPUT(type) && inst->state == IRIS_INST_INPUT_STREAMING) ||
		(V4L2_TYPE_IS_OUTPUT(type) && inst->state == IRIS_INST_STREAMING) ||
		(V4L2_TYPE_IS_CAPTURE(type) && inst->state == IRIS_INST_OUTPUT_STREAMING) ||
		(V4L2_TYPE_IS_CAPTURE(type) && inst->state == IRIS_INST_STREAMING);
}

bool iris_allow_streamon(struct iris_inst *inst, u32 type)
{
	return (V4L2_TYPE_IS_OUTPUT(type) && inst->state == IRIS_INST_INIT) ||
		(V4L2_TYPE_IS_OUTPUT(type) && inst->state == IRIS_INST_OUTPUT_STREAMING) ||
		(V4L2_TYPE_IS_CAPTURE(type) && inst->state == IRIS_INST_INIT) ||
		(V4L2_TYPE_IS_CAPTURE(type) && inst->state == IRIS_INST_INPUT_STREAMING);
}

bool iris_allow_streamoff(struct iris_inst *inst, u32 type)
{
	return (V4L2_TYPE_IS_OUTPUT(type) && inst->state == IRIS_INST_INPUT_STREAMING) ||
		(V4L2_TYPE_IS_OUTPUT(type) && inst->state == IRIS_INST_STREAMING) ||
		(V4L2_TYPE_IS_CAPTURE(type) && inst->state == IRIS_INST_OUTPUT_STREAMING) ||
		(V4L2_TYPE_IS_CAPTURE(type) && inst->state == IRIS_INST_STREAMING);
}

bool iris_allow_s_ctrl(struct iris_inst *inst, u32 cap_id)
{
	return ((inst->state == IRIS_INST_DEINIT) ||
		(inst->state == IRIS_INST_INIT) ||
		((inst->cap[cap_id].flags & CAP_FLAG_DYNAMIC_ALLOWED) &&
		(inst->state == IRIS_INST_INPUT_STREAMING ||
		inst->state == IRIS_INST_STREAMING)));
}

int iris_inst_state_change_streamon(struct iris_inst *inst, u32 plane)
{
	enum iris_inst_state new_state = IRIS_INST_ERROR;

	if (V4L2_TYPE_IS_OUTPUT(plane)) {
		if (inst->state == IRIS_INST_INIT)
			new_state = IRIS_INST_INPUT_STREAMING;
		else if (inst->state == IRIS_INST_OUTPUT_STREAMING)
			new_state = IRIS_INST_STREAMING;
	} else if (V4L2_TYPE_IS_CAPTURE(plane)) {
		if (inst->state == IRIS_INST_INIT)
			new_state = IRIS_INST_OUTPUT_STREAMING;
		else if (inst->state == IRIS_INST_INPUT_STREAMING)
			new_state = IRIS_INST_STREAMING;
	}

	return iris_inst_change_state(inst, new_state);
}

int iris_inst_state_change_streamoff(struct iris_inst *inst, u32 plane)
{
	enum iris_inst_state new_state = IRIS_INST_ERROR;

	if (V4L2_TYPE_IS_OUTPUT(plane)) {
		if (inst->state == IRIS_INST_INPUT_STREAMING)
			new_state = IRIS_INST_INIT;
		else if (inst->state == IRIS_INST_STREAMING)
			new_state = IRIS_INST_OUTPUT_STREAMING;
	} else if (V4L2_TYPE_IS_CAPTURE(plane)) {
		if (inst->state == IRIS_INST_OUTPUT_STREAMING)
			new_state = IRIS_INST_INIT;
		else if (inst->state == IRIS_INST_STREAMING)
			new_state = IRIS_INST_INPUT_STREAMING;
	}

	return iris_inst_change_state(inst, new_state);
}

static int iris_inst_allow_sub_state(struct iris_inst *inst, enum iris_inst_sub_state sub_state)
{
	if (!sub_state)
		return true;

	switch (inst->state) {
	case IRIS_INST_INIT:
		if (sub_state & IRIS_INST_SUB_LOAD_RESOURCES) // todo: confirm this
			return true;
		break;
	case IRIS_INST_INPUT_STREAMING:
		if (sub_state & (IRIS_INST_SUB_FIRST_IPSC | IRIS_INST_SUB_DRC |
			IRIS_INST_SUB_DRAIN | IRIS_INST_SUB_INPUT_PAUSE))
			return true;
		break;
	case IRIS_INST_OUTPUT_STREAMING:
		if (sub_state & (IRIS_INST_SUB_DRC_LAST |
			IRIS_INST_SUB_DRAIN_LAST | IRIS_INST_SUB_OUTPUT_PAUSE))
			return true;
		break;
	case IRIS_INST_STREAMING:
		if (sub_state & (IRIS_INST_SUB_DRC | IRIS_INST_SUB_DRAIN |
			IRIS_INST_SUB_DRC_LAST | IRIS_INST_SUB_DRAIN_LAST |
			IRIS_INST_SUB_INPUT_PAUSE | IRIS_INST_SUB_OUTPUT_PAUSE))
			return true;
		break;
	case IRIS_INST_DEINIT:
		if (sub_state & (IRIS_INST_SUB_DRC | IRIS_INST_SUB_DRAIN |
			IRIS_INST_SUB_DRC_LAST | IRIS_INST_SUB_DRAIN_LAST |
			IRIS_INST_SUB_INPUT_PAUSE | IRIS_INST_SUB_OUTPUT_PAUSE))
			return true;
		break;
	default:
		return false;
	}

	return false;
}

int iris_inst_change_sub_state(struct iris_inst *inst,
			       enum iris_inst_sub_state clear_sub_state,
			       enum iris_inst_sub_state set_sub_state)
{
	enum iris_inst_sub_state prev_sub_state;

	if (IS_SESSION_ERROR(inst))
		return 0;

	if (!clear_sub_state && !set_sub_state)
		return 0;

	if ((clear_sub_state & set_sub_state) ||
	    set_sub_state > IRIS_INST_MAX_SUB_STATE_VALUE ||
	    clear_sub_state > IRIS_INST_MAX_SUB_STATE_VALUE)
		return -EINVAL;

	prev_sub_state = inst->sub_state;

	if (!iris_inst_allow_sub_state(inst, set_sub_state))
		return -EINVAL;

	inst->sub_state |= set_sub_state;
	inst->sub_state &= ~clear_sub_state;

	if (inst->sub_state != prev_sub_state)
		dev_dbg(inst->core->dev, "sub_state changed from %x to %x\n",
			prev_sub_state, inst->sub_state);

	return 0;
}

int iris_inst_sub_state_change_drc(struct iris_inst *inst)
{
	enum iris_inst_sub_state set_sub_state = 0;

	if (inst->sub_state & IRIS_INST_SUB_DRC)
		return -EINVAL;

	if (inst->state == IRIS_INST_INPUT_STREAMING ||
	    inst->state == IRIS_INST_INIT)
		set_sub_state = IRIS_INST_SUB_INPUT_PAUSE | IRIS_INST_SUB_FIRST_IPSC;
	else
		set_sub_state = IRIS_INST_SUB_DRC | IRIS_INST_SUB_INPUT_PAUSE;

	return iris_inst_change_sub_state(inst, 0, set_sub_state);
}

int iris_inst_sub_state_change_drain_last(struct iris_inst *inst)
{
	enum iris_inst_sub_state set_sub_state = IRIS_INST_SUB_NONE;

	if (inst->sub_state & IRIS_INST_SUB_DRAIN_LAST)
		return -EINVAL;

	if (!(inst->sub_state & IRIS_INST_SUB_DRAIN))
		return -EINVAL;

	set_sub_state = IRIS_INST_SUB_DRAIN_LAST | IRIS_INST_SUB_OUTPUT_PAUSE;

	return iris_inst_change_sub_state(inst, 0, set_sub_state);
}

int iris_inst_sub_state_change_drc_last(struct iris_inst *inst)
{
	enum iris_inst_sub_state set_sub_state = IRIS_INST_SUB_NONE;

	if (inst->sub_state & IRIS_INST_SUB_DRC_LAST)
		return -EINVAL;

	if (!(inst->sub_state & IRIS_INST_SUB_DRC) ||
	    !(inst->sub_state & IRIS_INST_SUB_INPUT_PAUSE))
		return -EINVAL;

	if (inst->sub_state & IRIS_INST_SUB_FIRST_IPSC)
		return 0;

	set_sub_state = IRIS_INST_SUB_DRC_LAST | IRIS_INST_SUB_OUTPUT_PAUSE;

	return iris_inst_change_sub_state(inst, 0, set_sub_state);
}

int iris_inst_sub_state_change_pause(struct iris_inst *inst, u32 plane)
{
	enum iris_inst_sub_state set_sub_state = IRIS_INST_SUB_NONE;

	if (V4L2_TYPE_IS_OUTPUT(plane)) {
		if (inst->sub_state & IRIS_INST_SUB_DRC &&
		    !(inst->sub_state & IRIS_INST_SUB_DRC_LAST))
			return -EINVAL;

		if (inst->sub_state & IRIS_INST_SUB_DRAIN &&
		    !(inst->sub_state & IRIS_INST_SUB_DRAIN_LAST))
			return -EINVAL;

		set_sub_state = IRIS_INST_SUB_INPUT_PAUSE;
	} else {
		set_sub_state = IRIS_INST_SUB_OUTPUT_PAUSE;
	}

	return iris_inst_change_sub_state(inst, 0, set_sub_state);
}

static inline bool iris_drc_pending(struct iris_inst *inst)
{
	return inst->sub_state & IRIS_INST_SUB_DRC &&
		inst->sub_state & IRIS_INST_SUB_DRC_LAST;
}

static inline bool iris_drain_pending(struct iris_inst *inst)
{
	return inst->sub_state & IRIS_INST_SUB_DRAIN &&
		inst->sub_state & IRIS_INST_SUB_DRAIN_LAST;
}

bool iris_allow_cmd(struct iris_inst *inst, u32 cmd)
{
	if (cmd == V4L2_DEC_CMD_START) {
		if (inst->state == IRIS_INST_INPUT_STREAMING ||
		    inst->state == IRIS_INST_OUTPUT_STREAMING ||
		    inst->state == IRIS_INST_STREAMING)
			if (iris_drc_pending(inst) || iris_drain_pending(inst))
				return true;
	} else if (cmd == V4L2_DEC_CMD_STOP) {
		if (inst->state == IRIS_INST_INPUT_STREAMING ||
		    inst->state == IRIS_INST_STREAMING)
			if (inst->sub_state != IRIS_INST_SUB_DRAIN)
				return true;
	}

	return false;
}
