// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/delay.h>
#include <linux/pm_runtime.h>

#include "iris_core.h"
#include "iris_common.h"
#include "iris_firmware.h"
#include "iris_power.h"
#include "iris_state.h"
#include "iris_vpu_common.h"

int iris_core_deinit_locked(struct iris_core *core)
{
	int ret;

	if (!mutex_is_locked(&core->lock))
		return -EINVAL;

	if (core->state == IRIS_CORE_DEINIT)
		return 0;

	iris_hfi_core_deinit(core);

	iris_change_core_state_locked(core, IRIS_CORE_DEINIT);

	return ret;
}

int iris_core_deinit(struct iris_core *core)
{
	pm_runtime_resume_and_get(core->dev);

	mutex_lock(&core->lock);
	iris_core_deinit_locked(core);
	mutex_unlock(&core->lock);

	return pm_runtime_put_sync(core->dev);
}

static int iris_wait_for_system_response(struct iris_core *core)
{
	u32 hw_response_timeout_val;
	int ret;

	if (core->state == IRIS_CORE_ERROR)
		return -EIO;

	hw_response_timeout_val = core->cap[HW_RESPONSE_TIMEOUT].value;

	ret = wait_for_completion_timeout(&core->core_init_done,
					  msecs_to_jiffies(hw_response_timeout_val));
	if (!ret) {
		iris_change_core_state(core, IRIS_CORE_ERROR);
		ret = -ETIMEDOUT;
	} else {
		ret = 0;
	}

	return ret;
}

int iris_core_init(struct iris_core *core)
{
	int ret = 0;

	mutex_lock(&core->lock);
	if (core->state == IRIS_CORE_INIT) {
		goto exit;
	} else if (core->state == IRIS_CORE_ERROR) {
		ret = -EINVAL;
		goto error;
	}

	iris_change_core_state_locked(core, IRIS_CORE_INIT);

	ret = iris_hfi_queues_init(core);
	if (ret)
		goto error;

	ret = iris_power_on(core);
	if (ret)
		goto error_queue_deinit;

	ret = iris_fw_load(core);
	if (ret)
		goto error_power_off;

	ret = iris_vpu_boot_firmware(core);
	if (ret)
		goto error_power_off;

	ret = iris_hfi_core_init(core);
	if (ret)
		goto error_core_deinit;

	mutex_unlock(&core->lock);

	return iris_wait_for_system_response(core);

error_core_deinit:
	iris_core_deinit_locked(core);
error_power_off:
	iris_power_off(core);
error_queue_deinit:
	iris_hfi_queues_deinit(core);
error:
	iris_change_core_state_locked(core, IRIS_CORE_ERROR);
	dev_err(core->dev, "core init failed\n");
exit:
	mutex_unlock(&core->lock);

	return ret;
}
