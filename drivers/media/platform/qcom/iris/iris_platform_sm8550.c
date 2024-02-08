// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <dt-bindings/clock/qcom,sm8550-gcc.h>
#include <dt-bindings/clock/qcom,sm8450-videocc.h>

#include <media/v4l2-ctrls.h>

#include "iris_buffer.h"
#include "iris_hfi_2.h"
#include "iris_hfi_2_defines.h"
#include "iris_hfi_2_response.h"
#include "iris_ctrls.h"
#include "iris_platform_common.h"
#include "iris_resources.h"
#include "iris_vpu3.h"

#define MINIMUM_FPS         1
#define MAXIMUM_FPS       480

#define VIDEO_ARCH_LX 1

static struct plat_core_cap core_data_sm8550[] = {
	{DEC_CODECS, CODEC_H264},
	{MAX_SESSION_COUNT, 16},
	{MAX_MBPF, 278528}, /* ((8192x4352)/256) * 2 */
	{NUM_VPP_PIPE, 4},
	{HW_RESPONSE_TIMEOUT, HW_RESPONSE_TIMEOUT_VALUE},
	{DMA_MASK, GENMASK(31, 29) - 1},
	{CORE_ARCH, VIDEO_ARCH_LX},
	{CP_START, 0},
	{CP_SIZE, 0x25800000},
	{CP_NONPIXEL_START, 0x01000000},
	{CP_NONPIXEL_SIZE, 0x24800000},
};

static struct plat_inst_cap instance_cap_data_sm8550[] = {
	{FRAME_WIDTH, 96, 8192, 1, 1920},

	{FRAME_HEIGHT, 96, 8192, 1, 1920},

	{MBPF, 36, 138240, 1, 138240},

	{MB_CYCLES_VPP, 200, 200, 1, 200},

	{MB_CYCLES_FW, 489583, 489583, 1, 489583},

	{MB_CYCLES_FW_VPP, 66234, 66234, 1, 66234},

	{NUM_COMV,
		0, INT_MAX, 1, 0},

	{PROFILE,
		V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE,
		V4L2_MPEG_VIDEO_H264_PROFILE_CONSTRAINED_HIGH,
		BIT(V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE) |
		BIT(V4L2_MPEG_VIDEO_H264_PROFILE_CONSTRAINED_HIGH) |
		BIT(V4L2_MPEG_VIDEO_H264_PROFILE_CONSTRAINED_BASELINE) |
		BIT(V4L2_MPEG_VIDEO_H264_PROFILE_MAIN) |
		BIT(V4L2_MPEG_VIDEO_H264_PROFILE_HIGH),
		V4L2_MPEG_VIDEO_H264_PROFILE_HIGH,
		V4L2_CID_MPEG_VIDEO_H264_PROFILE,
		HFI_PROP_PROFILE,
		CAP_FLAG_OUTPUT_PORT | CAP_FLAG_MENU,
		iris_set_u32_enum},

	{LEVEL,
		V4L2_MPEG_VIDEO_H264_LEVEL_1_0,
		V4L2_MPEG_VIDEO_H264_LEVEL_6_2,
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_1_0) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_1B) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_1_1) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_1_2) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_1_3) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_2_0) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_2_1) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_2_2) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_3_0) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_3_1) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_3_2) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_4_0) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_4_1) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_4_2) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_5_0) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_5_1) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_5_2) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_6_0) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_6_1) |
		BIT(V4L2_MPEG_VIDEO_H264_LEVEL_6_2),
		V4L2_MPEG_VIDEO_H264_LEVEL_6_1,
		V4L2_CID_MPEG_VIDEO_H264_LEVEL,
		HFI_PROP_LEVEL,
		CAP_FLAG_OUTPUT_PORT | CAP_FLAG_MENU,
		iris_set_u32_enum},

	{INPUT_BUF_HOST_MAX_COUNT,
		DEFAULT_MAX_HOST_BUF_COUNT, DEFAULT_MAX_HOST_BURST_BUF_COUNT,
		1, DEFAULT_MAX_HOST_BUF_COUNT,
		0,
		HFI_PROP_BUFFER_HOST_MAX_COUNT,
		CAP_FLAG_INPUT_PORT,
		iris_set_u32},

	{STAGE,
		STAGE_1,
		STAGE_2, 1,
		STAGE_2,
		0,
		HFI_PROP_STAGE,
		CAP_FLAG_NONE,
		iris_set_stage},

	{PIPE,
		PIPE_1,
		PIPE_4, 1,
		PIPE_4,
		0,
		HFI_PROP_PIPE,
		CAP_FLAG_NONE,
		iris_set_pipe},

	{POC, 0, 2, 1, 1,
		0,
		HFI_PROP_PIC_ORDER_CNT_TYPE},

	{CODED_FRAMES,
		CODED_FRAMES_PROGRESSIVE, CODED_FRAMES_PROGRESSIVE,
		0, CODED_FRAMES_PROGRESSIVE,
		0,
		HFI_PROP_CODED_FRAMES},

	{BIT_DEPTH, BIT_DEPTH_8, BIT_DEPTH_8, 1, BIT_DEPTH_8,
		0,
		HFI_PROP_LUMA_CHROMA_BIT_DEPTH},

	{DEFAULT_HEADER,
		0, 1, 1, 0,
		0,
		HFI_PROP_DEC_DEFAULT_HEADER},

	{RAP_FRAME,
		0, 1, 1, 1,
		0,
		HFI_PROP_DEC_START_FROM_RAP_FRAME,
		CAP_FLAG_INPUT_PORT,
		iris_set_u32},
};

static const struct bus_info sm8550_bus_table[] = {
	{ NULL, "iris-cnoc", 1000, 1000     },
	{ NULL, "iris-ddr",  1000, 15000000 },
};

static const char * const sm8550_clk_reset_table[] = { "video_axi_reset", NULL };

static const char * const sm8550_opp_pd_table[] = { "mxc", "mmcx", NULL };

static const struct bw_info sm8550_bw_table_dec[] = {
	{ 2073600, 1608000, 2742000 },	/* 4096x2160@60 */
	{ 1036800,  826000, 1393000 },	/* 4096x2160@30 */
	{  489600,  567000,  723000 },	/* 1920x1080@60 */
	{  244800,  294000,  372000 },	/* 1920x1080@30 */
};

static const struct reg_preset_info sm8550_reg_preset_table[] = {
	{ 0xB0088, 0x0 },
};

static struct ubwc_config_data ubwc_config_sm8550[] = {
	UBWC_CONFIG(8, 32, 16, 0, 1, 1, 1),
};

static const u32 sm8550_vdec_input_config_params[] = {
	HFI_PROP_BITSTREAM_RESOLUTION,
	HFI_PROP_CROP_OFFSETS,
	HFI_PROP_CODED_FRAMES,
	HFI_PROP_BUFFER_FW_MIN_OUTPUT_COUNT,
	HFI_PROP_PIC_ORDER_CNT_TYPE,
	HFI_PROP_PROFILE,
	HFI_PROP_LEVEL,
	HFI_PROP_SIGNAL_COLOR_INFO,
};

static const u32 sm8550_vdec_output_config_params[] = {
	HFI_PROP_COLOR_FORMAT,
	HFI_PROP_LINEAR_STRIDE_SCANLINE,
};

static const u32 sm8550_vdec_subscribe_input_properties[] = {
	HFI_PROP_NO_OUTPUT,
};

static const u32 sm8550_vdec_subscribe_output_properties[] = {
	HFI_PROP_PICTURE_TYPE,
	HFI_PROP_CABAC_SESSION,
};

static const u32 sm8550_dec_ip_int_buf_tbl[] = {
	BUF_BIN,
	BUF_COMV,
	BUF_NON_COMV,
	BUF_LINE,
};

static const u32 sm8550_dec_op_int_buf_tbl[] = {
	BUF_DPB,
};

struct platform_data sm8550_data = {
	.init_hfi_ops = iris_hfi_2_ops_init,
	.init_hfi_response_ops = iris_hfi_2_response_ops_init,
	.init_vpu = iris_vpu3_init,
	.bus_tbl = sm8550_bus_table,
	.bus_tbl_size = ARRAY_SIZE(sm8550_bus_table),
	.clk_rst_tbl = sm8550_clk_reset_table,
	.clk_rst_tbl_size = ARRAY_SIZE(sm8550_clk_reset_table),

	.bw_tbl_dec = sm8550_bw_table_dec,
	.bw_tbl_dec_size = ARRAY_SIZE(sm8550_bw_table_dec),

	.pmdomains = (const char *[]) { "iris-ctl", "vcodec" },
	.pmdomains_count = 2,
	.opp_pd_tbl = sm8550_opp_pd_table,
	.opp_pd_tbl_size = ARRAY_SIZE(sm8550_opp_pd_table),

	.clks = (const char *[]) { "video_axi_clk", "iris_ctl_clk", "vcodec_clk" },

	.reg_prst_tbl = sm8550_reg_preset_table,
	.reg_prst_tbl_size = ARRAY_SIZE(sm8550_reg_preset_table),
	.fwname = "vpu30_4v",
	.pas_id = 9,

	.core_data = core_data_sm8550,
	.core_data_size = ARRAY_SIZE(core_data_sm8550),
	.inst_cap_data = instance_cap_data_sm8550,
	.inst_cap_data_size = ARRAY_SIZE(instance_cap_data_sm8550),
	.ubwc_config = ubwc_config_sm8550,

	.input_config_params =
		sm8550_vdec_input_config_params,
	.input_config_params_size =
		ARRAY_SIZE(sm8550_vdec_input_config_params),
	.output_config_params =
		sm8550_vdec_output_config_params,
	.output_config_params_size =
		ARRAY_SIZE(sm8550_vdec_output_config_params),
	.dec_input_prop = sm8550_vdec_subscribe_input_properties,
	.dec_input_prop_size = ARRAY_SIZE(sm8550_vdec_subscribe_input_properties),
	.dec_output_prop = sm8550_vdec_subscribe_output_properties,
	.dec_output_prop_size = ARRAY_SIZE(sm8550_vdec_subscribe_output_properties),
	.dec_ip_int_buf_tbl = sm8550_dec_ip_int_buf_tbl,
	.dec_ip_int_buf_tbl_size = ARRAY_SIZE(sm8550_dec_ip_int_buf_tbl),
	.dec_op_int_buf_tbl = sm8550_dec_op_int_buf_tbl,
	.dec_op_int_buf_tbl_size = ARRAY_SIZE(sm8550_dec_op_int_buf_tbl),
};
