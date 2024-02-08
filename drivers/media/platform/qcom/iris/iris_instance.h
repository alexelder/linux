/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _IRIS_INSTANCE_H_
#define _IRIS_INSTANCE_H_

#include <media/v4l2-ctrls.h>

#include "iris_buffer.h"
#include "iris_core.h"
#include "iris_utils.h"

/**
 * struct iris_inst - holds per video instance parameters
 *
 * @list: used for attach an instance to the core
 * @core: pointer to core structure
 * @session_id: id of current video session
 * @ctx_q_lock: lock to serialize queues related ioctls
 * @lock: lock to seralise forward and reverse threads
 * @fh: reference of v4l2 file handler
 * @fmt_src: structure of v4l2_format for source
 * @fmt_dst: structure of v4l2_format for destination
 * @ctrl_handler: reference of v4l2 ctrl handler
 * @crop: structure of crop info
 * @packet: HFI packet
 * @packet_size: HFI packet size
 * @completions: structure of signal completions
 * @flush_completions: structure of signal completions for flush cmd
 * @cap: array of supported instance capabilities
 * @num_ctrls: supported number of controls
 * @caps_list: list head of capability
 * @codec: codec type
 * @buffers: structure of buffer info
 * @fw_min_count: minimnum count of buffers needed by fw
 * @state: instance state
 * @sub_state: instance sub state
 * @ipsc_properties_set: boolean to set ipsc properties to fw
 * @opsc_properties_set: boolean to set opsc properties to fw
 * @hfi_frame_info: structure of frame info
 * @src_subcr_params: subscription params to fw on input port
 * @dst_subcr_params: subscription params to fw on output port
 * @once_per_session_set: boolean to set once per session property
 * @max_rate: max input rate
 * @max_input_data_size: max size of input data
 * @power: structure of power info
 * @bus_data: structure of bus data
 * @subscriptions: variable to hold current events subscriptions
 * @m2m_dev:	a reference to m2m device structure
 * @m2m_ctx:	a reference to m2m context structure
 */

struct iris_inst {
	struct list_head		list;
	struct iris_core		*core;
	u32				session_id;
	struct mutex			ctx_q_lock;/* lock to serialize queues related ioctls */
	struct mutex			lock;
	struct v4l2_fh			fh;
	struct v4l2_format		*fmt_src;
	struct v4l2_format		*fmt_dst;
	struct v4l2_ctrl_handler	ctrl_handler;
	struct iris_hfi_rect_desc	crop;
	void				*packet;
	u32				packet_size;
	struct completion		completion;
	struct completion		flush_completion;
	struct plat_inst_cap		cap[INST_CAP_MAX];
	u32				num_ctrls;
	struct list_head		caps_list;
	u32				codec;
	struct iris_buffers_info	buffers;
	u32				fw_min_count;
	enum iris_inst_state		state;
	enum iris_inst_sub_state	sub_state;
	bool				ipsc_properties_set;
	bool				opsc_properties_set;
	struct iris_hfi_frame_info	hfi_frame_info;
	struct hfi_subscription_params	src_subcr_params;
	struct hfi_subscription_params	dst_subcr_params;
	bool				once_per_session_set;
	u32				max_rate;
	u32				max_input_data_size;
	struct iris_inst_power		power;
	struct bus_vote_data		bus_data;
	unsigned int			subscriptions;
	struct v4l2_m2m_dev		*m2m_dev;
	struct v4l2_m2m_ctx		*m2m_ctx;
};

#endif
