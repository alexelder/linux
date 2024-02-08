// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <dt-bindings/clock/qcom,gcc-sm8250.h>
#include <dt-bindings/clock/qcom,videocc-sm8250.h>
#include <media/v4l2-ctrls.h>

#include "iris_buffer.h"
#include "iris_ctrls.h"
#include "iris_platform_common.h"
#include "iris_resources.h"
#include "iris_hfi_1.h"
#include "iris_hfi_1_defines.h"
#include "iris_hfi_1_response.h"
#include "iris_vpu2.h"

#define MINIMUM_FPS         1
#define MAXIMUM_FPS       480

static struct plat_core_cap core_data_sm8250[] = {
	{DEC_CODECS, CODEC_H264},
	{MAX_SESSION_COUNT, 16},
	{MAX_MBPF, 139264}, /* ((8192x4352)/256) */
	{NUM_VPP_PIPE, 4},
	{HW_RESPONSE_TIMEOUT, HW_RESPONSE_TIMEOUT_VALUE},
	{DMA_MASK, GENMASK(31, 29) - 1},
	{CORE_ARCH, 0},
	{CP_START, 0},
	{CP_SIZE, 0x25800000},
	{CP_NONPIXEL_START, 0x01000000},
	{CP_NONPIXEL_SIZE, 0x24800000},
};

static struct plat_inst_cap instance_cap_data_sm8250[] = {
	{FRAME_WIDTH, 128, 8192, 1, 1920},

	{FRAME_HEIGHT, 128, 8192, 1, 1920},

	{MBPF, 64, 138240, 1, 138240},

	{MB_CYCLES_VPP, 200, 200, 1, 200},

	{MB_CYCLES_VSP, 25, 25, 1, 25},

	{PIPE,
		PIPE_1,
		PIPE_4, 1,
		PIPE_4,
		0,
		HFI_PROPERTY_PARAM_WORK_ROUTE,
		CAP_FLAG_NONE,
		iris_set_pipe},

	{STAGE,
		STAGE_1,
		STAGE_2, 1,
		STAGE_2,
		0,
		HFI_PROPERTY_PARAM_WORK_MODE,
		CAP_FLAG_NONE,
		iris_set_stage},

	{DEBLOCK,
		0, 1, 1, 0,
		V4L2_CID_MPEG_VIDEO_DECODER_MPEG4_DEBLOCK_FILTER,
		HFI_PROPERTY_CONFIG_VDEC_POST_LOOP_DEBLOCKER,
		CAP_FLAG_NONE,
		iris_set_u32},
};

static const struct bus_info sm8250_bus_table[] = {
	{ NULL, "cpu-cfg",    1000, 1000     },
	{ NULL, "video-mem",  1000, 15000000 },
};

static const char * const sm8250_clk_reset_table[] = { "bus", "core", NULL };

static const char * const sm8250_opp_pd_table[] = { "mx", NULL };

static const struct bw_info sm8250_bw_table_dec[] = {
	{ 2073600, 2403000, 4113000 },	/* 4096x2160@60 */
	{ 1036800, 1224000, 2079000 },	/* 4096x2160@30 */
	{  489600, 812000,  998000  },	/* 1920x1080@60 */
	{  244800, 416000,  509000  },	/* 1920x1080@30 */
};

static const struct reg_preset_info sm8250_reg_preset_table[] = {
	{ 0xB0088, 0x0 },
};

static const u32 sm8250_vdec_input_config_param[] = {
	HFI_PROPERTY_PARAM_FRAME_SIZE,
	HFI_PROPERTY_CONFIG_VIDEOCORES_USAGE,
	HFI_PROPERTY_PARAM_UNCOMPRESSED_FORMAT_SELECT,
	HFI_PROPERTY_PARAM_UNCOMPRESSED_PLANE_ACTUAL_CONSTRAINTS_INFO,
	HFI_PROPERTY_PARAM_BUFFER_COUNT_ACTUAL,
	HFI_PROPERTY_PARAM_VDEC_MULTI_STREAM,
	HFI_PROPERTY_PARAM_BUFFER_SIZE_ACTUAL,
	HFI_PROPERTY_PARAM_BUFFER_ALLOC_MODE,
};

static const u32 sm8250_dec_ip_int_buf_tbl[] = {
	BUF_SCRATCH,
	BUF_SCRATCH_1,
};

static const u32 sm8250_dec_op_int_buf_tbl[] = {
	BUF_DPB,
};

struct platform_data sm8250_data = {
	.init_hfi_ops = &iris_hfi_1_ops_init,
	.init_hfi_response_ops = iris_hfi_1_response_ops_init,
	.init_vpu = iris_vpu2_init,
	.bus_tbl = sm8250_bus_table,
	.bus_tbl_size = ARRAY_SIZE(sm8250_bus_table),
	.clk_rst_tbl = sm8250_clk_reset_table,
	.clk_rst_tbl_size = ARRAY_SIZE(sm8250_clk_reset_table),

	.bw_tbl_dec = sm8250_bw_table_dec,
	.bw_tbl_dec_size = ARRAY_SIZE(sm8250_bw_table_dec),

	.pmdomains = (const char *[]) { "venus", "vcodec0" },
	.pmdomains_count = 2,
	.opp_pd_tbl = sm8250_opp_pd_table,
	.opp_pd_tbl_size = ARRAY_SIZE(sm8250_opp_pd_table),

	.clks = (const char *[]) { "iface", "core", "vcodec0_core" },

	.reg_prst_tbl = sm8250_reg_preset_table,
	.reg_prst_tbl_size = ARRAY_SIZE(sm8250_reg_preset_table),
	.fwname = "qcom/vpu-1.0/venus",
	.pas_id = 9,

	.core_data = core_data_sm8250,
	.core_data_size = ARRAY_SIZE(core_data_sm8250),
	.inst_cap_data = instance_cap_data_sm8250,
	.inst_cap_data_size = ARRAY_SIZE(instance_cap_data_sm8250),

	.input_config_params =
		sm8250_vdec_input_config_param,
	.input_config_params_size =
		ARRAY_SIZE(sm8250_vdec_input_config_param),

	.dec_ip_int_buf_tbl = sm8250_dec_ip_int_buf_tbl,
	.dec_ip_int_buf_tbl_size = ARRAY_SIZE(sm8250_dec_ip_int_buf_tbl),
	.dec_op_int_buf_tbl = sm8250_dec_op_int_buf_tbl,
	.dec_op_int_buf_tbl_size = ARRAY_SIZE(sm8250_dec_op_int_buf_tbl),
};
