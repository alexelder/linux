// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/iopoll.h>

#include "iris_core.h"
#include "iris_common.h"
#include "iris_vpu_common.h"

int iris_vpu_set_preset_registers(struct iris_core *core)
{
	const struct reg_preset_info *reg_prst;
	unsigned int prst_count;
	int cnt;

	reg_prst = core->platform_data->reg_prst_tbl;
	prst_count = core->platform_data->reg_prst_tbl_size;

	if (!reg_prst || !prst_count)
		return 0;

	for (cnt = 0; cnt < prst_count; cnt++)
		writel(reg_prst[cnt].value, core->reg_base + reg_prst[cnt].reg);

	return 0;
}

static void iris_vpu_interrupt_init(struct iris_core *core)
{
	u32 mask_val;

	mask_val = readl(core->reg_base + WRAPPER_INTR_MASK);
	mask_val &= ~(WRAPPER_INTR_MASK_A2HWD_BMSK |
		      WRAPPER_INTR_MASK_A2HCPU_BMSK);
	writel(mask_val, core->reg_base + WRAPPER_INTR_MASK);
}

static void iris_vpu_setup_ucregion_memory_map(struct iris_core *core)
{
	u32 value;

	value = (u32)core->iface_q_table.device_addr;
	writel(value, core->reg_base + UC_REGION_ADDR);

	value = SHARED_QSIZE;
	writel(value, core->reg_base + UC_REGION_SIZE);

	value = (u32)core->iface_q_table.device_addr;
	writel(value, core->reg_base + QTBL_ADDR);

	writel(0x01, core->reg_base + QTBL_INFO);

	if (core->sfr.device_addr) {
		value = (u32)core->sfr.device_addr + core->cap[CORE_ARCH].value;
		writel(value, core->reg_base + SFR_ADDR);
	}
}

int iris_vpu_boot_firmware(struct iris_core *core)
{
	u32 ctrl_init = 0, ctrl_status = 0, count = 0, max_tries = 1000;

	iris_vpu_setup_ucregion_memory_map(core);

	ctrl_init = BIT(0);

	writel(ctrl_init, core->reg_base + CTRL_INIT);
	writel(0x1, core->reg_base + CPU_CS_SCIACMDARG3);

	while (!ctrl_status && count < max_tries) {
		ctrl_status = readl(core->reg_base + CTRL_STATUS);
		if ((ctrl_status & CTRL_ERROR_STATUS__M) == 0x4) {
			dev_err(core->dev, "invalid setting for uc_region\n");
			break;
		}

		usleep_range(50, 100);
		count++;
	}

	if (count >= max_tries) {
		dev_err(core->dev, "error booting up iris firmware\n");
		return -ETIME;
	}

	writel(0x1, core->reg_base + CPU_CS_H2XSOFTINTEN);
	writel(0x0, core->reg_base + CPU_CS_X2RPMH);

	return 0;
}

void iris_vpu_raise_interrupt(struct iris_core *core)
{
	writel(1 << CPU_IC_SOFTINT_H2A_SHFT, core->reg_base + CPU_IC_SOFTINT);
}

void iris_vpu_clear_interrupt(struct iris_core *core)
{
	u32 intr_status = 0, mask = 0;

	intr_status = readl(core->reg_base + WRAPPER_INTR_STATUS);
	mask = (WRAPPER_INTR_STATUS_A2H_BMSK |
		WRAPPER_INTR_STATUS_A2HWD_BMSK |
		CTRL_INIT_IDLE_MSG_BMSK);

	if (intr_status & mask)
		core->intr_status |= intr_status;

	writel(1, core->reg_base + CPU_CS_A2HSOFTINTCLR);
}

int iris_vpu_watchdog(struct iris_core *core, u32 intr_status)
{
	if (intr_status & WRAPPER_INTR_STATUS_A2HWD_BMSK) {
		dev_err(core->dev, "%s: received interrupt\n", __func__);
		return -ETIME;
	}

	return 0;
}

int iris_vpu_prepare_pc(struct iris_core *core)
{
	u32 wfi_status = 0, idle_status = 0, pc_ready = 0;
	u32 ctrl_status = 0;
	int val = 0;
	int ret;

	ctrl_status = readl(core->reg_base + CTRL_STATUS);
	pc_ready = ctrl_status & CTRL_STATUS_PC_READY;
	idle_status = ctrl_status & BIT(30);
	if (pc_ready)
		return 0;

	wfi_status = readl(core->reg_base + WRAPPER_TZ_CPU_STATUS);
	wfi_status &= BIT(0);
	if (!wfi_status || !idle_status)
		goto skip_power_off;

	ret = core->hfi_ops->sys_pc_prep(core);
	if (ret) {
		dev_err(core->dev, "failed to prepare iris for power off\n");
		goto skip_power_off;
	}

	ret = readl_poll_timeout(core->reg_base + CTRL_STATUS, val,
				 val & CTRL_STATUS_PC_READY, 250, 2500);
	if (ret)
		goto skip_power_off;

	ret = readl_poll_timeout(core->reg_base + WRAPPER_TZ_CPU_STATUS,
				 val, val & BIT(0), 250, 2500);
	if (ret)
		goto skip_power_off;

	return ret;

skip_power_off:
	ctrl_status = readl(core->reg_base + CTRL_STATUS);
	wfi_status = readl(core->reg_base + WRAPPER_TZ_CPU_STATUS);
	wfi_status &= BIT(0);
	dev_err(core->dev, "skip power collapse, wfi=%#x, idle=%#x, pcr=%#x, ctrl=%#x)\n",
		wfi_status, idle_status, pc_ready, ctrl_status);

	return -EAGAIN;
}

static int iris_vpu_power_off_controller(struct iris_core *core)
{
	int val = 0;
	int ret;

	writel(0x3, core->reg_base + CPU_CS_X2RPMH);

	writel(0x1, core->reg_base + AON_WRAPPER_MVP_NOC_LPI_CONTROL);

	ret = readl_poll_timeout(core->reg_base + AON_WRAPPER_MVP_NOC_LPI_STATUS,
				 val, val & BIT(0), 200, 2000);
	if (ret)
		goto disable_power;

	writel(0x1, core->reg_base + WRAPPER_IRIS_CPU_NOC_LPI_CONTROL);

	ret = readl_poll_timeout(core->reg_base + WRAPPER_IRIS_CPU_NOC_LPI_STATUS,
				 val, val & BIT(0), 200, 2000);
	if (ret)
		goto disable_power;

	writel(0x0, core->reg_base + WRAPPER_DEBUG_BRIDGE_LPI_CONTROL);

	ret = readl_poll_timeout(core->reg_base + WRAPPER_DEBUG_BRIDGE_LPI_STATUS,
				 val, val == 0, 200, 2000);
	if (ret)
		goto disable_power;

	writel(0x3, core->reg_base + WRAPPER_TZ_CTL_AXI_CLOCK_CONFIG);
	writel(0x1, core->reg_base + WRAPPER_TZ_QNS4PDXFIFO_RESET);
	writel(0x0, core->reg_base + WRAPPER_TZ_QNS4PDXFIFO_RESET);
	writel(0x0, core->reg_base + WRAPPER_TZ_CTL_AXI_CLOCK_CONFIG);

disable_power:
	iris_disable_unprepare_clock(core, core->platform_data->clks[1]);
	iris_disable_unprepare_clock(core, core->platform_data->clks[0]);
	iris_disable_power_domains(core, core->pmdomains->pd_devs[0]);

	return 0;
}

void iris_vpu_power_off_hw(struct iris_core *core)
{
	iris_disable_power_domains(core, core->pmdomains->pd_devs[1]);
	iris_disable_unprepare_clock(core, core->platform_data->clks[2]);
}

void iris_vpu_power_off(struct iris_core *core)
{
	if (!core->power_enabled)
		return;

	iris_opp_set_rate(core, 0);
	call_vpu_op(core, power_off_hw, core);
	iris_vpu_power_off_controller(core);
	iris_unset_bus_bw(core);

	if (!iris_vpu_watchdog(core, core->intr_status))
		disable_irq_nosync(core->irq);

	core->power_enabled = false;
}

static int iris_vpu_power_on_controller(struct iris_core *core)
{
	int ret;

	ret = iris_enable_power_domains(core, core->pmdomains->pd_devs[0]);
	if (ret)
		return ret;

	ret = iris_reset_ahb2axi_bridge(core);
	if (ret)
		goto err_disable_power;

	ret = iris_prepare_enable_clock(core, core->platform_data->clks[0]);
	if (ret)
		goto err_disable_power;

	ret = iris_prepare_enable_clock(core, core->platform_data->clks[1]);
	if (ret)
		goto err_disable_clock;

	return ret;

err_disable_clock:
	iris_disable_unprepare_clock(core, core->platform_data->clks[0]);
err_disable_power:
	iris_disable_power_domains(core, core->pmdomains->pd_devs[0]);

	return ret;
}

static int iris_vpu_switch_vcodec_gdsc_mode(struct iris_core *core, bool sw_mode)
{
	void __iomem *base_addr;
	u32 val = 0;
	int ret;

	base_addr = core->reg_base;

	if (sw_mode) {
		writel_relaxed(0, base_addr + WRAPPER_CORE_POWER_CONTROL);
		ret = readl_relaxed_poll_timeout(base_addr + WRAPPER_CORE_POWER_STATUS, val,
						 val & BIT(1), 1, 200);
		if (ret)
			return ret;
	} else {
		writel_relaxed(1, base_addr + WRAPPER_CORE_POWER_CONTROL);
		ret = readl_relaxed_poll_timeout(base_addr + WRAPPER_CORE_POWER_STATUS, val,
						 !(val & BIT(1)), 1, 200);
		if (ret)
			return ret;
	}

	return 0;
}

static int iris_vpu_power_on_hw(struct iris_core *core)
{
	int ret;

	ret = iris_enable_power_domains(core, core->pmdomains->pd_devs[1]);
	if (ret)
		return ret;

	ret = iris_vpu_switch_vcodec_gdsc_mode(core, true);
	if (ret)
		goto err_disable_power;

	ret = iris_prepare_enable_clock(core, core->platform_data->clks[2]);
	if (ret)
		goto err_gdsc_switch;

	ret = iris_vpu_switch_vcodec_gdsc_mode(core, false);
	if (ret)
		goto err_disable_clock;

	return ret;

err_disable_clock:
	iris_disable_unprepare_clock(core, core->platform_data->clks[2]);
err_gdsc_switch:
	iris_vpu_switch_vcodec_gdsc_mode(core, false);
err_disable_power:
	iris_disable_power_domains(core, core->pmdomains->pd_devs[1]);

	return ret;
}

int iris_vpu_power_on(struct iris_core *core)
{
	u32 freq = 0;
	int ret;

	if (core->power_enabled)
		return 0;

	if (core->state != IRIS_CORE_INIT)
		return -EINVAL;

	ret = iris_set_bus_bw(core, INT_MAX);
	if (ret)
		goto err;

	ret = iris_vpu_power_on_controller(core);
	if (ret)
		goto err_unvote_bus;

	ret = iris_vpu_power_on_hw(core);
	if (ret)
		goto err_power_off_ctrl;

	core->power_enabled = true;

	freq = core->power.clk_freq ? core->power.clk_freq :
				      (u32)ULONG_MAX;

	iris_opp_set_rate(core, freq);

	iris_vpu_set_preset_registers(core);

	iris_vpu_interrupt_init(core);
	core->intr_status = 0;
	enable_irq(core->irq);

	return ret;

err_power_off_ctrl:
	dev_err(core->dev, "power on failed\n");
	iris_vpu_power_off_controller(core);
err_unvote_bus:
	iris_unset_bus_bw(core);
err:
	core->power_enabled = false;

	return ret;
}
