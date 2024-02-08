/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _IRIS_HFI_COMMON_H_
#define _IRIS_HFI_COMMON_H_

#include <linux/types.h>
#include <media/v4l2-device.h>

#include "iris_buffer.h"

struct iris_inst;
struct iris_core;

#define HFI_CMD_SETTINGS_CHANGE			0x0100000C

struct iris_hfi_prop_type_handle {
	u32 type;
	int (*handle)(struct iris_inst *inst);
};

struct iris_hfi_ops {
	int (*sys_init)(struct iris_core *core);
	int (*sys_image_version)(struct iris_core *core);
	int (*sys_pc_prep)(struct iris_core *core);
	int (*sys_interframe_powercollapse)(struct iris_core *core);
	int (*session_set_config_params)(struct iris_inst *inst, u32 plane);
	int (*session_open)(struct iris_inst *inst, u32 codec);
	int (*session_close)(struct iris_inst *inst);
	int (*session_start)(struct iris_inst *inst, u32 plane);
	int (*session_stop)(struct iris_inst *inst, u32 plane);
	int (*session_drain)(struct iris_inst *inst, u32 plane);
	int (*session_pause)(struct iris_inst *inst, u32 plane);
	int (*session_resume)(struct iris_inst *inst, u32 plane, u32 cmd);
	int (*session_queue_buf)(struct iris_inst *inst, struct iris_buffer *buffer);
	int (*session_release_buf)(struct iris_inst *inst, struct iris_buffer *buffer);
	int (*session_set_property)(struct iris_inst *inst,
				    u32 packet_type, u32 flag, u32 plane, u32 payload_type,
				    void *payload, u32 payload_size);
};

struct iris_hfi_response_ops {
	void (*hfi_response_handler)(struct iris_core *core);
};

struct hfi_subscription_params {
	u32	bitstream_resolution;
	u32	crop_offsets[2];
	u32	bit_depth;
	u32	coded_frames;
	u32	fw_min_count;
	u32	pic_order_cnt;
	u32	color_info;
	u32	profile;
	u32	level;
};

enum hfi_color_primaries {
	HFI_PRIMARIES_RESERVED		= 0,
	HFI_PRIMARIES_BT709		= 1,
	HFI_PRIMARIES_UNSPECIFIED	= 2,
	HFI_PRIMARIES_BT470_SYSTEM_M	= 4,
	HFI_PRIMARIES_BT470_SYSTEM_BG	= 5,
	HFI_PRIMARIES_BT601_525		= 6,
	HFI_PRIMARIES_SMPTE_ST240M	= 7,
	HFI_PRIMARIES_GENERIC_FILM	= 8,
	HFI_PRIMARIES_BT2020		= 9,
	HFI_PRIMARIES_SMPTE_ST428_1	= 10,
	HFI_PRIMARIES_SMPTE_RP431_2	= 11,
	HFI_PRIMARIES_SMPTE_EG431_1	= 12,
	HFI_PRIMARIES_SMPTE_EBU_TECH	= 22,
};

enum hfi_transfer_characteristics {
	HFI_TRANSFER_RESERVED		= 0,
	HFI_TRANSFER_BT709		= 1,
	HFI_TRANSFER_UNSPECIFIED	= 2,
	HFI_TRANSFER_BT470_SYSTEM_M	= 4,
	HFI_TRANSFER_BT470_SYSTEM_BG	= 5,
	HFI_TRANSFER_BT601_525_OR_625	= 6,
	HFI_TRANSFER_SMPTE_ST240M	= 7,
	HFI_TRANSFER_LINEAR		= 8,
	HFI_TRANSFER_LOG_100_1		= 9,
	HFI_TRANSFER_LOG_SQRT		= 10,
	HFI_TRANSFER_XVYCC		= 11,
	HFI_TRANSFER_BT1361_0		= 12,
	HFI_TRANSFER_SRGB_SYCC		= 13,
	HFI_TRANSFER_BT2020_14		= 14,
	HFI_TRANSFER_BT2020_15		= 15,
	HFI_TRANSFER_SMPTE_ST2084_PQ	= 16,
	HFI_TRANSFER_SMPTE_ST428_1	= 17,
	HFI_TRANSFER_BT2100_2_HLG	= 18,
};

enum hfi_matrix_coefficients {
	HFI_MATRIX_COEFF_SRGB_SMPTE_ST428_1		= 0,
	HFI_MATRIX_COEFF_BT709				= 1,
	HFI_MATRIX_COEFF_UNSPECIFIED			= 2,
	HFI_MATRIX_COEFF_RESERVED			= 3,
	HFI_MATRIX_COEFF_FCC_TITLE_47			= 4,
	HFI_MATRIX_COEFF_BT470_SYS_BG_OR_BT601_625	= 5,
	HFI_MATRIX_COEFF_BT601_525_BT1358_525_OR_625	= 6,
	HFI_MATRIX_COEFF_SMPTE_ST240			= 7,
	HFI_MATRIX_COEFF_YCGCO				= 8,
	HFI_MATRIX_COEFF_BT2020_NON_CONSTANT		= 9,
	HFI_MATRIX_COEFF_BT2020_CONSTANT		= 10,
	HFI_MATRIX_COEFF_SMPTE_ST2085			= 11,
	HFI_MATRIX_COEFF_SMPTE_CHROM_DERV_NON_CONSTANT	= 12,
	HFI_MATRIX_COEFF_SMPTE_CHROM_DERV_CONSTANT	= 13,
	HFI_MATRIX_COEFF_BT2100				= 14,
};

u32 iris_hfi_get_v4l2_color_primaries(u32 hfi_primaries);
u32 iris_hfi_get_v4l2_transfer_char(u32 hfi_characterstics);
u32 iris_hfi_get_v4l2_matrix_coefficients(u32 hfi_coefficients);
int iris_hfi_core_init(struct iris_core *core);
int iris_hfi_core_deinit(struct iris_core *core);
int iris_hfi_pm_suspend(struct iris_core *core);
int iris_hfi_pm_resume(struct iris_core *core);

irqreturn_t iris_hfi_isr(int irq, void *data);
irqreturn_t iris_hfi_isr_handler(int irq, void *data);

#endif
