/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _IRIS_STATE_H_
#define _IRIS_STATE_H_

struct iris_core;
struct iris_inst;

enum iris_core_state {
	IRIS_CORE_DEINIT,
	IRIS_CORE_INIT,
	IRIS_CORE_ERROR,
};

enum iris_inst_state {
	IRIS_INST_DEINIT,
	IRIS_INST_INIT,
	IRIS_INST_INPUT_STREAMING,
	IRIS_INST_OUTPUT_STREAMING,
	IRIS_INST_STREAMING,
	IRIS_INST_ERROR,
};

#define IRIS_INST_SUB_NONE		0
#define IRIS_INST_SUB_STATES		8
#define IRIS_INST_MAX_SUB_STATE_VALUE	((1 << IRIS_INST_SUB_STATES) - 1)

enum iris_inst_sub_state {
	IRIS_INST_SUB_DRAIN		 = BIT(0),
	IRIS_INST_SUB_FIRST_IPSC = BIT(1),
	IRIS_INST_SUB_DRC		 = BIT(2),
	IRIS_INST_SUB_DRAIN_LAST	= BIT(3),
	IRIS_INST_SUB_DRC_LAST		= BIT(4),
	IRIS_INST_SUB_INPUT_PAUSE	= BIT(5),
	IRIS_INST_SUB_OUTPUT_PAUSE	= BIT(6),
	IRIS_INST_SUB_LOAD_RESOURCES		 = BIT(7),
};

#define IS_SESSION_ERROR(inst) ((inst)->state == IRIS_INST_ERROR)

int iris_change_core_state_locked(struct iris_core *core,
				  enum iris_core_state request_state);
int iris_change_core_state(struct iris_core *core,
			   enum iris_core_state request_state);

int iris_inst_change_state(struct iris_inst *inst,
			   enum iris_inst_state request_state);
int iris_inst_change_sub_state(struct iris_inst *inst,
			       enum iris_inst_sub_state clear_sub_state,
			       enum iris_inst_sub_state set_sub_state);

bool iris_allow_s_fmt(struct iris_inst *inst, u32 type);
bool iris_allow_reqbufs(struct iris_inst *inst, u32 type);
bool iris_allow_qbuf(struct iris_inst *inst, u32 type);
bool iris_allow_streamon(struct iris_inst *inst, u32 type);
bool iris_allow_streamoff(struct iris_inst *inst, u32 type);
bool iris_allow_s_ctrl(struct iris_inst *inst, u32 cap_id);

int iris_inst_state_change_streamon(struct iris_inst *inst, u32 plane);
int iris_inst_state_change_streamoff(struct iris_inst *inst, u32 plane);

int iris_inst_sub_state_change_drc(struct iris_inst *inst);
int iris_inst_sub_state_change_drain_last(struct iris_inst *inst);
int iris_inst_sub_state_change_drc_last(struct iris_inst *inst);
int iris_inst_sub_state_change_pause(struct iris_inst *inst, u32 plane);
bool iris_allow_cmd(struct iris_inst *inst, u32 cmd);

#endif
