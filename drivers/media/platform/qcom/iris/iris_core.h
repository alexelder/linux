/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _IRIS_CORE_H_
#define _IRIS_CORE_H_

#include <linux/types.h>
#include <linux/pm_domain.h>
#include <media/v4l2-device.h>
#include <media/videobuf2-v4l2.h>
#include <media/v4l2-event.h>

#include "iris_common.h"
#include "iris_hfi_common.h"
#include "iris_hfi_queue.h"
#include "iris_state.h"
#include "iris_platform_common.h"
#include "iris_resources.h"

struct vpu_ops;

#define IRIS_FW_VERSION_LENGTH 128

/**
 * struct iris_core - holds core parameters valid for all instances
 *
 * @dev: reference to device structure
 * @reg_base: IO memory base address
 * @irq: iris irq
 * @v4l2_dev: a holder for v4l2 device structure
 * @vdev_dec: iris video device structure for decoder
 * @iris_v4l2_file_ops: iris v4l2 file ops
 * @iris_v4l2_ioctl_ops: iris v4l2 ioctl ops
 * @bus_tbl: table of iris buses
 * @bus_count: count of iris buses
 * @pmdomains: table of iris power domains
 * @clock_tbl: table of iris clocks
 * @clk_count: count of iris clocks
 * @reset_tbl: table of iris reset clocks
 * @reset_count: count of iris reset clocks
 * @vb2_ops: iris vb2 ops
 * @state: current state of core
 * @iface_q_table: Interface queue table memory
 * @command_queue: shared interface queue to send commands to firmware
 * @message_queue: shared interface queue to receive responses from firmware
 * @debug_queue: shared interface queue to receive debug info from firmware
 * @sfr: SFR register memory
 * @lock: a lock for this strucure
 * @packet: pointer to packet from driver to fw
 * @packet_size: size of packet
 * @response_packet: a pointer to response packet from fw to driver
 * @header_id: id of packet header
 * @packet_id: id of packet
 * @vpu_ops: a pointer to vpu ops
 * @session_ops: a pointer to session level ops
 * @platform_data: a structure for platform data
 * @cap: an array for supported core capabilities
 * @inst_cap: an array of supported instance capabilities
 * @instances: a list_head of all instances
 * @intr_status: interrupt status
 * @fw_version: firmware version
 * @power_enabled: a boolean to check if power is on or off
 * @power: a structure for clock and bw information
 * @hfi_ops: iris hfi ops
 * @core_init_done: structure of signal completion for system response
 * @sys_error_handler: a delayed work for handling system fatal error
 */

struct iris_core {
	struct device				*dev;
	void __iomem				*reg_base;
	int					irq;
	struct v4l2_device			v4l2_dev;
	struct video_device			*vdev_dec;
	const struct v4l2_file_operations	*iris_v4l2_file_ops;
	const struct v4l2_ioctl_ops		*iris_v4l2_ioctl_ops;
	struct bus_info				*bus_tbl;
	u32					bus_count;
	struct dev_pm_domain_list		*pmdomains;
	struct clk_bulk_data			*clock_tbl;
	u32					clk_count;
	struct reset_info			*reset_tbl;
	u32					reset_count;
	const struct vb2_ops			*iris_vb2_ops;
	enum iris_core_state			state;
	struct mem_desc				iface_q_table;
	struct iris_iface_q_info		command_queue;
	struct iris_iface_q_info		message_queue;
	struct iris_iface_q_info		debug_queue;
	struct mem_desc				sfr;
	struct mutex				lock; /* lock for core related operations */
	u8					*packet;
	u32					packet_size;
	u8					*response_packet;
	u32					header_id;
	u32					packet_id;
	const struct vpu_ops			*vpu_ops;
	const struct vpu_session_ops		*session_ops;
	const struct platform_data		*platform_data;
	struct plat_core_cap			cap[CORE_CAP_MAX + 1];
	struct plat_inst_cap			inst_cap[INST_CAP_MAX];
	struct list_head			instances;
	u32					intr_status;
	char					fw_version[IRIS_FW_VERSION_LENGTH];
	bool					power_enabled;
	struct iris_core_power			power;
	const struct iris_hfi_ops		*hfi_ops;
	const struct iris_hfi_response_ops	*hfi_response_ops;
	struct completion			core_init_done;
	struct delayed_work			sys_error_handler;
};

int iris_core_init(struct iris_core *core);
int iris_core_deinit(struct iris_core *core);
int iris_core_deinit_locked(struct iris_core *core);

#endif
