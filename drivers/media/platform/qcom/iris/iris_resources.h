/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _IRIS_RESOURCES_H_
#define _IRIS_RESOURCES_H_

struct clk_bulk_data;

struct bus_info {
	struct icc_path		*icc;
	const char		*name;
	u32			bw_min_kbps;
	u32			bw_max_kbps;
};

struct reset_info {
	struct reset_control	*rst;
	const char		*name;
};

int iris_enable_power_domains(struct iris_core *core, struct device *pd_dev);
int iris_disable_power_domains(struct iris_core *core, struct device *pd_dev);
int iris_unset_bus_bw(struct iris_core *core);
int iris_set_bus_bw(struct iris_core *core, unsigned long bus_bw);
int iris_reset_ahb2axi_bridge(struct iris_core *core);
int iris_opp_set_rate(struct iris_core *core, u64 freq);
int iris_disable_unprepare_clock(struct iris_core *core, const char *clk_name);
int iris_prepare_enable_clock(struct iris_core *core, const char *clk_name);
int iris_init_resources(struct iris_core *core);

#endif
