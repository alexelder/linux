/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _IRIS_HFI_1_H_
#define _IRIS_HFI_1_H_

#include "iris_hfi_1_defines.h"

struct iris_core;
struct iris_inst;

#define IFACEQ_MAX_BUF_COUNT		50
#define IFACEQ_DFLT_QHDR		0x01010000

#define IFACEQ_MAX_PKT_SIZE		1024
#define IFACEQ_VAR_SMALL_PKT_SIZE	100
#define IFACEQ_VAR_LARGE_PKT_SIZE	512

void iris_hfi_1_ops_init(struct iris_core *core);

#endif
