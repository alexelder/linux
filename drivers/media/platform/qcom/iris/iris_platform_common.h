/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _IRIS_PLATFORM_COMMON_H_
#define _IRIS_PLATFORM_COMMON_H_

#include <linux/bits.h>
#include <media/v4l2-ctrls.h>

struct iris_core;
struct iris_inst;

#define HW_RESPONSE_TIMEOUT_VALUE     (1000)
#define AUTOSUSPEND_DELAY_VALUE       (HW_RESPONSE_TIMEOUT_VALUE + 500)

#define BIT_DEPTH_8 (8 << 16 | 8)
#define BIT_DEPTH_10 (10 << 16 | 10)

#define CODEC_H264	BIT(0)

#define CODED_FRAMES_PROGRESSIVE 0x0
#define CODED_FRAMES_INTERLACE 0x1

#define DEFAULT_MAX_HOST_BUF_COUNT			64
#define DEFAULT_MAX_HOST_BURST_BUF_COUNT		256
#define DEFAULT_FPS        30

#define UBWC_CONFIG(mc, ml, hbb, bs1, bs2, bs3, bsp) \
{	                                                 \
	.max_channels = mc,                              \
	.mal_length = ml,                                \
	.highest_bank_bit = hbb,                         \
	.bank_swzl_level = bs1,                          \
	.bank_swz2_level = bs2,                          \
	.bank_swz3_level = bs3,                          \
	.bank_spreading = bsp,                           \
}

enum stage_type {
	STAGE_NONE = 0,
	STAGE_1 = 1,
	STAGE_2 = 2,
};

enum pipe_type {
	PIPE_NONE = 0,
	PIPE_1 = 1,
	PIPE_2 = 2,
	PIPE_4 = 4,
};

extern struct platform_data sm8550_data;
extern struct platform_data sm8250_data;

struct bw_info {
	u32 mbs_per_sec;
	u32 bw_ddr;
	u32 bw_ddr_10bit;
};

struct reg_preset_info {
	u32              reg;
	u32              value;
};

struct iris_core_power {
	u64 clk_freq;
	u64 bus_bw;
};

struct iris_inst_power {
	u64 min_freq;
	u32 bus_bw;
};

struct ubwc_config_data {
	u32	max_channels;
	u32	mal_length;
	u32	highest_bank_bit;
	u32	bank_swzl_level;
	u32	bank_swz2_level;
	u32	bank_swz3_level;
	u32	bank_spreading;
};

struct bus_vote_data {
	int height, width;
	u32 fps;
};

enum plat_core_cap_type {
	CORE_CAP_NONE = 0,
	DEC_CODECS,
	MAX_SESSION_COUNT,
	MAX_MBPF,
	NUM_VPP_PIPE,
	HW_RESPONSE_TIMEOUT,
	DMA_MASK,
	CORE_ARCH,
	CP_START,
	CP_SIZE,
	CP_NONPIXEL_START,
	CP_NONPIXEL_SIZE,
	CORE_CAP_MAX,
};

struct plat_core_cap {
	enum plat_core_cap_type type;
	u32 value;
};

enum plat_inst_cap_type {
	FRAME_WIDTH = 0,
	FRAME_HEIGHT,
	MBPF,
	MB_CYCLES_VPP,
	MB_CYCLES_VSP,
	MB_CYCLES_FW,
	MB_CYCLES_FW_VPP,
	NUM_COMV,
	PROFILE,
	LEVEL,
	DISPLAY_DELAY_ENABLE,
	DISPLAY_DELAY,
	OUTPUT_ORDER,
	INPUT_BUF_HOST_MAX_COUNT,
	STAGE,
	PIPE,
	POC,
	CODED_FRAMES,
	BIT_DEPTH,
	DEFAULT_HEADER,
	RAP_FRAME,
	DEBLOCK,
	CONCEAL_COLOR,
	INST_CAP_MAX,
};

enum plat_inst_cap_flags {
	CAP_FLAG_NONE			= 0,
	CAP_FLAG_DYNAMIC_ALLOWED	= BIT(0),
	CAP_FLAG_MENU			= BIT(1),
	CAP_FLAG_INPUT_PORT		= BIT(2),
	CAP_FLAG_OUTPUT_PORT		= BIT(3),
	CAP_FLAG_CLIENT_SET		= BIT(4),
	CAP_FLAG_BITMASK		= BIT(5),
	CAP_FLAG_VOLATILE		= BIT(6),
};

struct plat_inst_cap {
	enum plat_inst_cap_type cap_id;
	s64 min;
	s64 max;
	s64 step_or_mask;
	s64 value;
	u32 v4l2_id;
	u32 hfi_id;
	enum plat_inst_cap_flags flags;
	int (*set)(struct iris_inst *inst,
		   enum plat_inst_cap_type cap_id);
};

struct platform_data {
	void (*init_hfi_ops)(struct iris_core *core);
	void (*init_hfi_response_ops)(struct iris_core *core);
	void (*init_vpu)(struct iris_core *core);
	const struct bus_info *bus_tbl;
	unsigned int bus_tbl_size;
	const struct bw_info *bw_tbl_dec;
	unsigned int bw_tbl_dec_size;
	const char **pmdomains;
	unsigned int pmdomains_count;
	const char * const *opp_pd_tbl;
	unsigned int opp_pd_tbl_size;
	const char **clks;
	const char * const *clk_rst_tbl;
	unsigned int clk_rst_tbl_size;
	const struct reg_preset_info *reg_prst_tbl;
	unsigned int reg_prst_tbl_size;
	struct ubwc_config_data *ubwc_config;
	const char *fwname;
	u32 pas_id;
	struct plat_core_cap *core_data;
	u32 core_data_size;
	struct plat_inst_cap *inst_cap_data;
	u32 inst_cap_data_size;
	const u32 *input_config_params;
	unsigned int input_config_params_size;
	const u32 *output_config_params;
	unsigned int output_config_params_size;
	const u32 *dec_input_prop;
	unsigned int dec_input_prop_size;
	const u32 *dec_output_prop;
	unsigned int dec_output_prop_size;
	const u32 *dec_ip_int_buf_tbl;
	unsigned int dec_ip_int_buf_tbl_size;
	const u32 *dec_op_int_buf_tbl;
	unsigned int dec_op_int_buf_tbl_size;
};

#endif
