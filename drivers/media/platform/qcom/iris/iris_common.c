// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */
#include <linux/types.h>

#include "iris_instance.h"

void iris_session_close(struct iris_inst *inst)
{
	u32 hw_response_timeout_val;
	bool wait_for_response;
	struct iris_core *core;
	int ret;

	if (inst->state == IRIS_INST_DEINIT || !inst->packet)
		return;

	core = inst->core;
	hw_response_timeout_val = core->cap[HW_RESPONSE_TIMEOUT].value;
	wait_for_response = true;

	reinit_completion(&inst->completion);

	ret = core->hfi_ops->session_close(inst);
	if (ret)
		wait_for_response = false;

	kfree(inst->packet);
	inst->packet = NULL;

	if (wait_for_response)
		iris_wait_for_session_response(inst, false);
}
