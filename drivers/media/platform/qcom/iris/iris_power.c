// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */
#include <linux/pm_runtime.h>
#include <media/v4l2-mem2mem.h>

#include "iris_buffer_helpers.h"
#include "iris_instance.h"
#include "iris_power.h"
#include "iris_resources.h"
#include "iris_vpu_common.h"

static u32 iris_calc_bw(struct iris_inst *inst, struct bus_vote_data *data)
{
	const struct bw_info *bw_tbl = NULL;
	unsigned int num_rows = 0;
	unsigned int i, mbs, mbps;
	struct iris_core *core;
	u32 bus_bw = 0;

	if (!data)
		goto exit;

	core = inst->core;

	mbs = (ALIGN(data->height, 16) / 16) * (ALIGN(data->width, 16) / 16);
	mbps = mbs * data->fps;
	if (mbps == 0)
		goto exit;

	bw_tbl = core->platform_data->bw_tbl_dec;
	num_rows = core->platform_data->bw_tbl_dec_size;

	if (!bw_tbl || num_rows == 0)
		goto exit;

	for (i = 0; i < num_rows; i++) {
		if (i != 0 && mbps > bw_tbl[i].mbs_per_sec)
			break;

		bus_bw = bw_tbl[i].bw_ddr;
	}

	dev_info(core->dev, "bus_bw %u\n", bus_bw);

exit:
	return bus_bw;
}

static int iris_set_buses(struct iris_inst *inst)
{
	struct iris_inst *instance;
	struct iris_core *core;
	u64 total_bw_ddr = 0;
	int ret;

	core = inst->core;

	mutex_lock(&core->lock);
	list_for_each_entry(instance, &core->instances, list) {
		if (!instance->max_input_data_size)
			continue;

		total_bw_ddr += instance->power.bus_bw;
	}

	ret = iris_set_bus_bw(core, total_bw_ddr);

	mutex_unlock(&core->lock);

	return ret;
}

static int iris_vote_buses(struct iris_inst *inst)
{
	struct v4l2_format *out_f, *inp_f;
	struct bus_vote_data *vote_data;
	struct iris_core *core;

	core = inst->core;

	vote_data = &inst->bus_data;

	out_f = inst->fmt_dst;
	inp_f = inst->fmt_src;

	vote_data->width = inp_f->fmt.pix_mp.width;
	vote_data->height = inp_f->fmt.pix_mp.height;
	vote_data->fps = inst->max_rate;

	inst->power.bus_bw = iris_calc_bw(inst, vote_data);

	return iris_set_buses(inst);
}

static int iris_set_clocks(struct iris_inst *inst)
{
	struct iris_inst *instance;
	struct iris_core *core;
	int ret = 0;
	u64 freq;

	core = inst->core;

	mutex_lock(&core->lock);

	freq = 0;
	list_for_each_entry(instance, &core->instances, list) {
		if (!instance->max_input_data_size)
			continue;

		freq += instance->power.min_freq;
	}

	core->power.clk_freq = freq;

	ret = iris_opp_set_rate(core, freq);

	mutex_unlock(&core->lock);

	return ret;
}

static int iris_scale_clocks(struct iris_inst *inst)
{
	struct v4l2_m2m_ctx *m2m_ctx = inst->m2m_ctx;
	struct v4l2_m2m_buffer *buffer, *n;
	struct iris_buffer *buf = NULL;
	struct iris_core *core;
	u32 data_size = 0;

	core = inst->core;

	v4l2_m2m_for_each_src_buf_safe(m2m_ctx, buffer, n) {
		buf = to_iris_buffer(&buffer->vb);
		data_size = max(data_size, buf->data_size);
	}

	inst->max_input_data_size = data_size;

	inst->max_rate = DEFAULT_FPS;

	if (!inst->max_input_data_size)
		return 0;

	inst->power.min_freq = call_vpu_op(core, calc_freq, inst,
					   inst->max_input_data_size);

	return iris_set_clocks(inst);
}

int iris_scale_power(struct iris_inst *inst)
{
	struct iris_core *core;
	int ret;

	core = inst->core;

	if (pm_runtime_suspended(core->dev)) {
		ret = pm_runtime_resume_and_get(core->dev);
		if (ret < 0)
			return ret;

		ret = pm_runtime_put_autosuspend(core->dev);
		if (ret < 0)
			return ret;
	}

	ret = iris_scale_clocks(inst);
	if (ret)
		return ret;

	return iris_vote_buses(inst);
}

void iris_power_off(struct iris_core *core)
{
	if (!core->power_enabled)
		return;

	iris_vpu_power_off(core);
	core->power_enabled = false;
}

int iris_power_on(struct iris_core *core)
{
	int ret;

	if (core->power_enabled)
		return 0;

	ret = iris_vpu_power_on(core);
	if (ret) {
		dev_err(core->dev, "failed to power on, err: %d\n", ret);
		return ret;
	}

	core->power_enabled = true;

	return ret;
}

