/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _IRIS_VPU_COMMON_H_
#define _IRIS_VPU_COMMON_H_

#include <linux/types.h>

struct iris_core;

#define VCODEC_BASE_OFFS			0x00000000
#define CPU_BASE_OFFS				0x000A0000
#define WRAPPER_TZ_BASE_OFFS			0x000C0000
#define AON_BASE_OFFS				0x000E0000
#define AON_MVP_NOC_RESET			0x0001F000

#define CPU_CS_BASE_OFFS			(CPU_BASE_OFFS)
#define CPU_IC_BASE_OFFS			(CPU_BASE_OFFS)

#define CPU_CS_A2HSOFTINTCLR			(CPU_CS_BASE_OFFS + 0x1C)
#define CTRL_INIT				(CPU_CS_BASE_OFFS + 0x48)
#define CTRL_STATUS				(CPU_CS_BASE_OFFS + 0x4C)

#define CTRL_INIT_IDLE_MSG_BMSK			0x40000000
#define CTRL_ERROR_STATUS__M			0xfe
#define CTRL_STATUS_PC_READY			0x100

#define QTBL_INFO				(CPU_CS_BASE_OFFS + 0x50)
#define QTBL_ADDR				(CPU_CS_BASE_OFFS + 0x54)

#define CPU_CS_SCIACMDARG3			(CPU_CS_BASE_OFFS + 0x58)
#define SFR_ADDR				(CPU_CS_BASE_OFFS + 0x5C)

#define UC_REGION_ADDR				(CPU_CS_BASE_OFFS + 0x64)
#define UC_REGION_SIZE				(CPU_CS_BASE_OFFS + 0x68)

#define CPU_CS_H2XSOFTINTEN			(CPU_CS_BASE_OFFS + 0x148)
#define CPU_CS_AHB_BRIDGE_SYNC_RESET		(CPU_CS_BASE_OFFS + 0x160)
#define CPU_CS_X2RPMH				(CPU_CS_BASE_OFFS + 0x168)

#define CPU_IC_SOFTINT				(CPU_IC_BASE_OFFS + 0x150)
#define CPU_IC_SOFTINT_H2A_SHFT			0x0

#define WRAPPER_BASE_OFFS			0x000B0000
#define WRAPPER_INTR_STATUS			(WRAPPER_BASE_OFFS + 0x0C)
#define WRAPPER_INTR_STATUS_A2HWD_BMSK		0x8
#define WRAPPER_INTR_STATUS_A2H_BMSK		0x4

#define WRAPPER_INTR_MASK			(WRAPPER_BASE_OFFS + 0x10)
#define WRAPPER_INTR_MASK_A2HWD_BMSK		0x8
#define WRAPPER_INTR_MASK_A2HCPU_BMSK		0x4

#define WRAPPER_DEBUG_BRIDGE_LPI_CONTROL	(WRAPPER_BASE_OFFS + 0x54)
#define WRAPPER_DEBUG_BRIDGE_LPI_STATUS		(WRAPPER_BASE_OFFS + 0x58)
#define WRAPPER_IRIS_CPU_NOC_LPI_CONTROL	(WRAPPER_BASE_OFFS + 0x5C)
#define WRAPPER_IRIS_CPU_NOC_LPI_STATUS		(WRAPPER_BASE_OFFS + 0x60)

#define WRAPPER_CORE_POWER_STATUS		(WRAPPER_BASE_OFFS + 0x80)
#define WRAPPER_CORE_POWER_CONTROL		(WRAPPER_BASE_OFFS + 0x84)
#define WRAPPER_CORE_CLOCK_CONFIG		(WRAPPER_BASE_OFFS + 0x88)

#define WRAPPER_TZ_CPU_STATUS			(WRAPPER_TZ_BASE_OFFS + 0x10)
#define WRAPPER_TZ_CTL_AXI_CLOCK_CONFIG		(WRAPPER_TZ_BASE_OFFS + 0x14)
#define WRAPPER_TZ_QNS4PDXFIFO_RESET		(WRAPPER_TZ_BASE_OFFS + 0x18)

#define AON_WRAPPER_MVP_NOC_LPI_CONTROL		(AON_BASE_OFFS)
#define AON_WRAPPER_MVP_NOC_LPI_STATUS		(AON_BASE_OFFS + 0x4)
#define AON_WRAPPER_MVP_NOC_RESET_REQ		(AON_MVP_NOC_RESET + 0x000)
#define AON_WRAPPER_MVP_NOC_RESET_ACK		(AON_MVP_NOC_RESET + 0x004)

#define VCODEC_SS_IDLE_STATUSN			(VCODEC_BASE_OFFS + 0x70)

#define call_vpu_op(d, op, ...)			\
	(((d) && (d)->vpu_ops && (d)->vpu_ops->op) ? \
	((d)->vpu_ops->op(__VA_ARGS__)) : 0)

struct vpu_ops {
	void (*power_off_hw)(struct iris_core *core);
	u64 (*calc_freq)(struct iris_inst *inst, u32 data_size);
};

int iris_vpu_set_preset_registers(struct iris_core *core);

int iris_vpu_boot_firmware(struct iris_core *core);
void iris_vpu_raise_interrupt(struct iris_core *core);
void iris_vpu_clear_interrupt(struct iris_core *core);
int iris_vpu_watchdog(struct iris_core *core, u32 intr_status);
int iris_vpu_prepare_pc(struct iris_core *core);
int iris_vpu_power_on(struct iris_core *core);
void iris_vpu_power_off_hw(struct iris_core *core);
void iris_vpu_power_off(struct iris_core *core);

#endif
