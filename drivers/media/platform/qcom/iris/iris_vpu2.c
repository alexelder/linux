// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include "iris_instance.h"
#include "iris_platform_common.h"
#include "iris_vpu_common.h"
#include "iris_vpu2.h"

static u64 iris_vpu2_calc_freq(struct iris_inst *inst, u32 data_size)
{
	unsigned long vpp_freq = 0, vsp_freq = 0;
	u32 fps, mbpf, height = 0, width = 0;
	struct v4l2_format *inp_f;
	u32 mbs_per_second;

	inp_f = inst->fmt_src;
	width = max(inp_f->fmt.pix_mp.width, inst->crop.width);
	height = max(inp_f->fmt.pix_mp.height, inst->crop.height);

	mbpf = NUM_MBS_PER_FRAME(height, width);
	fps = inst->max_rate;
	mbs_per_second = mbpf * fps;

	vpp_freq = mbs_per_second * inst->cap[MB_CYCLES_VPP].value;

	/* 21 / 20 is overhead factor */
	vpp_freq += vpp_freq / 20;
	vsp_freq = mbs_per_second * inst->cap[MB_CYCLES_VSP].value;

	/* 10 / 7 is overhead factor */
	vsp_freq += ((fps * data_size * 8) * 10) / 7;

	return max(vpp_freq, vsp_freq);
}

static const struct vpu_ops iris_vpu2_ops = {
	.power_off_hw = iris_vpu_power_off_hw,
	.calc_freq = iris_vpu2_calc_freq,
};

void iris_vpu2_init(struct iris_core *core)
{
	core->vpu_ops = &iris_vpu2_ops;
}
