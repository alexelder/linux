// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/delay.h>
#include <linux/interconnect.h>
#include <linux/pm_domain.h>
#include <linux/pm_opp.h>
#include <linux/pm_runtime.h>
#include <linux/reset.h>
#include <linux/sort.h>

#include "iris_core.h"
#include "iris_platform_common.h"
#include "iris_resources.h"

#define BW_THRESHOLD 50000

static void iris_pd_release(void *pd)
{
	struct iris_core *core = (struct iris_core *)pd;

	dev_pm_domain_detach_list(core->pmdomains);
}

static int iris_pd_get(struct iris_core *core)
{
	int ret;

	struct dev_pm_domain_attach_data iris_pd_data = {
		.pd_names = core->platform_data->pmdomains,
		.num_pd_names = core->platform_data->pmdomains_count,
		.pd_flags = PD_FLAG_NO_DEV_LINK,
	};

	ret = dev_pm_domain_attach_list(core->dev, &iris_pd_data, &core->pmdomains);
	if (ret < 0)
		return ret;

	ret = devm_add_action_or_reset(core->dev, iris_pd_release, (void *)core);
	if (ret)
		return ret;

	return ret;
}

static void iris_opp_dl_release(void *res)
{
	struct device_link *link = (struct device_link *)res;

	device_link_del(link);
}

static int iris_opp_dl_get(struct device *dev, struct device *supplier)
{
	u32 flag = DL_FLAG_RPM_ACTIVE | DL_FLAG_PM_RUNTIME | DL_FLAG_STATELESS;
	struct device_link *link = NULL;
	int ret;

	link = device_link_add(dev, supplier, flag);
	if (!link)
		return -EINVAL;

	ret = devm_add_action_or_reset(dev, iris_opp_dl_release, (void *)link);

	return ret;
}

int iris_opp_set_rate(struct iris_core *core, u64 freq)
{
	unsigned long opp_freq = 0;
	struct dev_pm_opp *opp;
	int ret;

	opp_freq = freq;

	opp = dev_pm_opp_find_freq_ceil(core->dev, &opp_freq);
	if (IS_ERR(opp)) {
		opp = dev_pm_opp_find_freq_floor(core->dev, &opp_freq);
		if (IS_ERR(opp)) {
			dev_err(core->dev,
				"unable to find freq %lld in opp table\n", freq);
			return -EINVAL;
		}
	}
	dev_pm_opp_put(opp);

	ret = dev_pm_opp_set_rate(core->dev, opp_freq);
	if (ret) {
		dev_err(core->dev, "failed to set rate\n");
		return ret;
	}

	return ret;
}

static int iris_init_bus(struct iris_core *core)
{
	const struct bus_info *bus_tbl;
	struct bus_info *binfo = NULL;
	u32 i = 0;

	bus_tbl = core->platform_data->bus_tbl;

	core->bus_count = core->platform_data->bus_tbl_size;
	core->bus_tbl = devm_kzalloc(core->dev,
				     sizeof(struct bus_info) * core->bus_count,
				     GFP_KERNEL);
	if (!core->bus_tbl)
		return -ENOMEM;

	for (i = 0; i < core->bus_count; i++) {
		binfo = &core->bus_tbl[i];
		binfo->name = bus_tbl[i].name;
		binfo->bw_min_kbps = bus_tbl[i].bw_min_kbps;
		binfo->bw_max_kbps = bus_tbl[i].bw_max_kbps;
		binfo->icc = devm_of_icc_get(core->dev, binfo->name);
		if (IS_ERR(binfo->icc)) {
			dev_err(core->dev,
				"%s: failed to get bus: %s\n", __func__, binfo->name);
			return PTR_ERR(binfo->icc);
		}
	}

	return 0;
}

static int iris_init_power_domains(struct iris_core *core)
{
	struct device **opp_vdevs = NULL;
	const char * const *opp_pd_tbl;
	unsigned int pmdomains_cnt;
	u32 opp_pd_cnt, i;
	int ret;

	pmdomains_cnt = core->platform_data->pmdomains_count;
	core->pmdomains = devm_kzalloc(core->dev,
				       sizeof(struct dev_pm_domain_list) * pmdomains_cnt,
				       GFP_KERNEL);
	if (!core->pmdomains)
		return -ENOMEM;

	ret = iris_pd_get(core);
	if (ret)
		return ret;

	opp_pd_tbl = core->platform_data->opp_pd_tbl;
	opp_pd_cnt = core->platform_data->opp_pd_tbl_size;

	ret = devm_pm_opp_attach_genpd(core->dev, opp_pd_tbl, &opp_vdevs);
	if (ret)
		return ret;

	for (i = 0; i < (opp_pd_cnt - 1) ; i++) {
		ret = iris_opp_dl_get(core->dev, opp_vdevs[i]);
		if (ret) {
			dev_err(core->dev, "%s: failed to create dl: %s\n",
				__func__, dev_name(opp_vdevs[i]));
			return ret;
		}
	}

	ret = devm_pm_opp_set_clkname(core->dev, core->platform_data->clks[2]);
	if (ret)
		return ret;

	ret = devm_pm_opp_of_add_table(core->dev);
	if (ret) {
		dev_err(core->dev, "%s: failed to add opp table\n", __func__);
		return ret;
	}

	return ret;
}

int iris_enable_power_domains(struct iris_core *core, struct device *pd_dev)
{
	int ret;

	ret = iris_opp_set_rate(core, ULONG_MAX);
	if (ret)
		return ret;

	ret = pm_runtime_get_sync(pd_dev);
	if (ret < 0)
		return ret;

	ret = iris_opp_set_rate(core, ULONG_MAX);
	if (ret)
		return ret;

	return ret;
}

int iris_disable_power_domains(struct iris_core *core, struct device *pd_dev)
{
	int ret;

	ret = iris_opp_set_rate(core, 0);
	if (ret)
		return ret;

	ret = pm_runtime_put_sync(pd_dev);
	if (ret)
		return ret;

	return ret;
}

static int iris_init_clocks(struct iris_core *core)
{
	u32 ret;

	ret = devm_clk_bulk_get_all(core->dev, &core->clock_tbl);
	if (ret < 0) {
		dev_err(core->dev, "failed to get bulk clock\n");
		return ret;
	}

	core->clk_count = ret;

	return 0;
}

static int iris_init_reset_clocks(struct iris_core *core)
{
	struct reset_info *rinfo = NULL;
	const char * const *rst_tbl;
	u32 i = 0;

	rst_tbl = core->platform_data->clk_rst_tbl;

	core->reset_count = core->platform_data->clk_rst_tbl_size;
	core->reset_tbl = devm_kzalloc(core->dev,
				       sizeof(struct reset_info) * core->reset_count,
				       GFP_KERNEL);
	if (!core->reset_tbl)
		return -ENOMEM;

	for (i = 0; i < (core->reset_count - 1); i++) {
		rinfo = &core->reset_tbl[i];
		rinfo->name = rst_tbl[i];
		rinfo->rst = devm_reset_control_get(core->dev, rinfo->name);
		if (IS_ERR(rinfo->rst)) {
			dev_err(core->dev,
				"%s: failed to get reset clock: %s\n", __func__, rinfo->name);
			return PTR_ERR(rinfo->rst);
		}
	}

	return 0;
}

int iris_unset_bus_bw(struct iris_core *core)
{
	struct bus_info *bus = NULL;
	int ret = 0;
	u32 i;

	core->power.bus_bw = 0;
	core->bus_count = core->platform_data->bus_tbl_size;

	for (i = 0; i < core->bus_count; i++) {
		bus = &core->bus_tbl[i];
		if (!bus->icc)
			return -EINVAL;

		ret = icc_set_bw(bus->icc, 0, 0);
		if (ret)
			return ret;
	}

	return ret;
}

int iris_set_bus_bw(struct iris_core *core, unsigned long bus_bw)
{
	unsigned long bw_kbps = 0, bw_prev = 0;
	struct bus_info *bus = NULL;
	int ret = 0;
	u32 i;

	core->bus_count = core->platform_data->bus_tbl_size;

	for (i = 0; i < core->bus_count; i++) {
		bus = &core->bus_tbl[i];
		if (bus && bus->icc) {
			if (!strcmp(bus->name, core->platform_data->bus_tbl[1].name)) {
				bw_kbps = bus_bw;
				bw_prev = core->power.bus_bw;
			} else {
				bw_kbps = bus->bw_max_kbps;
				bw_prev = core->power.bus_bw ?
						bw_kbps : 0;
			}

			bw_kbps = clamp_t(typeof(bw_kbps), bw_kbps,
					  bus->bw_min_kbps, bus->bw_max_kbps);

			if (abs(bw_kbps - bw_prev) < BW_THRESHOLD && bw_prev)
				continue;

			ret = icc_set_bw(bus->icc, bw_kbps, 0);
			if (ret)
				return ret;

			if (!strcmp(bus->name, core->platform_data->bus_tbl[1].name))
				core->power.bus_bw = bw_kbps;
		}
	}

	return ret;
}

static int iris_deassert_reset_control(struct iris_core *core)
{
	struct reset_info *rcinfo = NULL;
	int ret = 0;
	u32 i;

	core->reset_count = core->platform_data->clk_rst_tbl_size;

	for (i = 0; i < (core->reset_count - 1); i++) {
		rcinfo = &core->reset_tbl[i];
		ret = reset_control_deassert(rcinfo->rst);
		if (ret) {
			dev_err(core->dev, "deassert reset control failed. ret = %d\n", ret);
			continue;
		}
	}

	return ret;
}

static int iris_assert_reset_control(struct iris_core *core)
{
	struct reset_info *rcinfo = NULL;
	int ret = 0, cnt = 0;
	u32 i;

	core->reset_count = core->platform_data->clk_rst_tbl_size;

	for (i = 0; i < (core->reset_count - 1); i++) {
		rcinfo = &core->reset_tbl[i];
		if (!rcinfo->rst)
			return -EINVAL;

		ret = reset_control_assert(rcinfo->rst);
		if (ret) {
			dev_err(core->dev, "failed to assert reset control %s, ret = %d\n",
				rcinfo->name, ret);
			goto deassert_reset_control;
		}
		cnt++;

		usleep_range(1000, 1100);
	}

	return ret;
deassert_reset_control:
	for (i = 0; i < cnt; i++) {
		rcinfo = &core->reset_tbl[i];
		reset_control_deassert(rcinfo->rst);
	}

	return ret;
}

int iris_reset_ahb2axi_bridge(struct iris_core *core)
{
	int ret;

	ret = iris_assert_reset_control(core);
	if (ret)
		return ret;

	ret = iris_deassert_reset_control(core);

	return ret;
}

static struct clk *iris_get_clk_by_name(struct clk_bulk_data *clks, int count,
					const char *id)
{
	int i;

	for (i = 0; clks && i < count; i++)
		if (!strcmp(clks[i].id, id))
			return clks[i].clk;

	return NULL;
}

int iris_disable_unprepare_clock(struct iris_core *core, const char *clk_name)
{
	struct clk *clock;

	clock = iris_get_clk_by_name(core->clock_tbl, core->clk_count, clk_name);
	if (!clock) {
		dev_err(core->dev, "failed to get clk: %s\n", clk_name);
		return -EINVAL;
	}

	clk_disable_unprepare(clock);

	return 0;
}

int iris_prepare_enable_clock(struct iris_core *core, const char *clk_name)
{
	struct clk *clock;
	int ret = 0;

	clock = iris_get_clk_by_name(core->clock_tbl, core->clk_count, clk_name);
	if (!clock) {
		dev_err(core->dev, "failed to get clk: %s\n", clk_name);
		return -EINVAL;
	}

	ret = clk_prepare_enable(clock);
	if (ret) {
		dev_err(core->dev, "failed to enable clock %s\n", clk_name);
		return ret;
	}

	if (!__clk_is_enabled(clock)) {
		clk_disable_unprepare(clock);
		return -EINVAL;
	}

	return ret;
}

int iris_init_resources(struct iris_core *core)
{
	int ret;

	ret = iris_init_bus(core);
	if (ret)
		return ret;

	ret = iris_init_power_domains(core);
	if (ret)
		return ret;

	ret = iris_init_clocks(core);
	if (ret)
		return ret;

	ret = iris_init_reset_clocks(core);

	return ret;
}
