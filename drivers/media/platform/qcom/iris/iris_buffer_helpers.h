/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _IRIS_BUFFER_HELPERS_H_
#define _IRIS_BUFFER_HELPERS_H_

#include "iris_buffer.h"

#define to_iris_buffer(ptr)	container_of(ptr, struct iris_buffer, vb2)

int iris_queue_buffer(struct iris_inst *inst, struct iris_buffer *buf);
int iris_queue_deferred_buffers(struct iris_inst *inst, enum iris_buffer_type buf_type);
int iris_vb2_buffer_done(struct iris_inst *inst,
			 struct iris_buffer *buf);
void iris_vb2_queue_error(struct iris_inst *inst);

#endif
