// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2026 by RISCstar Solutions Corporation.  All rights reserved.
 */

#include <linux/bits.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/device-id/of.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/string_choices.h>

#include <dt-bindings/clock/toshiba,tc9564.h>

#define CLK_CTRL0_OFFSET	0x1004
#define CLK_CTRL1_OFFSET	0x100c

struct tc9564_clock_init {
	const char *name;	/* NULL means unused entry */
	bool critical;
	u16 offset;
	u32 mask;
};

struct tc9564_clock {
	struct clk_hw hw;
	u32 offset;		/* CLK_CTRL0_OFFSET or CLK_CTRL1_OFFSET */
	u32 mask;		/* Zero means undefined clock */
};

struct tc9564_clocks {
	size_t clock_count;
	struct tc9564_clock clocks[] __counted_by(clock_count);
};

#define TC9564_CLOCK_INIT0(_name, _bit)				\
	__TC9564_CLOCK_INIT(_name, 0, _bit, false)
#define TC9564_CLOCK_INIT0_CRITICAL(_name, _bit)		\
	__TC9564_CLOCK_INIT(_name, 0, _bit, true)
#define TC9564_CLOCK_INIT1(_name, _bit)				\
	__TC9564_CLOCK_INIT(_name, 1, _bit, false)

#define __TC9564_CLOCK_INIT(_name, _reg, _bit, _critical)	\
	[CLOCK_##_name] = {					\
		.name		= #_name,			\
		.offset		= CLK_CTRL ## _reg ## _OFFSET,	\
		.mask		= BIT(_bit),			\
		.critical	= _critical,			\
	}

/*
 * The PCIe and I2C clocks are controllable, but we depend on PCIe
 * and that relies on I2C, so we don't allow them to be disabled.
 */
static const struct tc9564_clock_init tc9564_clock_init[] = {
	TC9564_CLOCK_INIT0(MCU, 0),
	TC9564_CLOCK_INIT0(INTC, 4),
	TC9564_CLOCK_INIT0_CRITICAL(PCIE, 9),
	TC9564_CLOCK_INIT0_CRITICAL(I2C, 12),
	TC9564_CLOCK_INIT0(SRAM, 13),
	TC9564_CLOCK_INIT0(UART, 16),
	TC9564_CLOCK_INIT0(MSIGEN, 18),
	TC9564_CLOCK_INIT0(PLL, 24),
	TC9564_CLOCK_INIT0(SGMII, 25),
	TC9564_CLOCK_INIT0(REFCLKO, 26),

	TC9564_CLOCK_INIT0(MAC0_TX, 7),
	TC9564_CLOCK_INIT0(MAC0_RX, 14),
	TC9564_CLOCK_INIT0(MAC0_125M, 29),
	TC9564_CLOCK_INIT0(MAC0_312_5M, 30),
	TC9564_CLOCK_INIT0(MAC0_ALL, 31),

	TC9564_CLOCK_INIT1(MAC1_TX, 7),
	TC9564_CLOCK_INIT1(MAC1_RX, 14),
	TC9564_CLOCK_INIT1(MAC1_RMII, 15),
	TC9564_CLOCK_INIT1(MAC1_125M, 29),
	TC9564_CLOCK_INIT1(MAC1_312_5M, 30),
	TC9564_CLOCK_INIT1(MAC1_ALL, 31),
};
#define TC9564_CLOCK_COUNT	ARRAY_SIZE(tc9564_clock_init)

static const struct tc9564_clock *hw_to_tc9564_clock(struct clk_hw *hw)
{
	return container_of_const(hw, struct tc9564_clock, hw);
}

static int tc9564_clk_manage(struct clk_hw *hw, bool enable)
{
	const struct tc9564_clock *clock = hw_to_tc9564_clock(hw);
	struct device *dev = clk_hw_get_dev(hw);
	u32 offset = clock->offset;
	u32 mask = clock->mask;
	struct regmap *regmap;

	regmap = dev_get_drvdata(dev);

	return regmap_update_bits(regmap, offset, mask, enable ? mask : 0);
}

static int tc9564_clk_enable(struct clk_hw *hw)
{
	return tc9564_clk_manage(hw, true);
}

static void tc9564_clk_disable(struct clk_hw *hw)
{
	(void)tc9564_clk_manage(hw, false);
}

static int tc9564_clk_is_enabled(struct clk_hw *hw)
{
	const struct tc9564_clock *clock = hw_to_tc9564_clock(hw);
	struct device *dev = clk_hw_get_dev(hw);
	u32 offset = clock->offset;
	u32 mask = clock->mask;
	struct regmap *regmap;
	u32 val;

	regmap = dev_get_drvdata(dev);

	regmap_read(regmap, offset, &val);

	return val & mask ? 1 : 0;
}

static const struct clk_ops tc9564_clk_ops = {
	.enable = tc9564_clk_enable,
	.disable = tc9564_clk_disable,
	.is_enabled = tc9564_clk_is_enabled,
};

static struct clk_hw *tc9564_clk_hw_get(struct of_phandle_args *clkspec,
					void *data)
{
	struct tc9564_clocks *clocks = data;

	return &clocks->clocks[clkspec->args[0]].hw;
}

static int tc9564_clk_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *parent_np;
	struct tc9564_clocks *clocks;
	struct regmap *regmap;
	size_t clocks_size;
	int ret;

	parent_np = dev_of_node(dev->parent);
	if (!parent_np)
		return dev_err_probe(dev, -EINVAL, "no devicetree node\n");

	regmap = device_node_to_regmap(parent_np);
	if (IS_ERR(regmap))
		return dev_err_probe(dev, PTR_ERR(regmap),
				     "failed to get config regmap\n");
	dev_set_drvdata(dev, regmap);

	clocks_size = struct_size(clocks, clocks, TC9564_CLOCK_COUNT);
	clocks = devm_kzalloc(dev, clocks_size, GFP_KERNEL);
	if (!clocks)
		return -ENOMEM;

	clocks->clock_count = TC9564_CLOCK_COUNT;

	for (u32 i = 0; i < clocks->clock_count; i++) {
		const struct tc9564_clock_init *clock_init;
		struct clk_init_data init = { };
		struct tc9564_clock *clock;

		clock_init = &tc9564_clock_init[i];
		if (!clock_init->name)
			continue;

		init.name = clock_init->name;
		init.flags = clock_init->critical ? CLK_IS_CRITICAL : 0;
		init.ops = &tc9564_clk_ops;

		clock = &clocks->clocks[i];
		clock->hw.init = &init;
		clock->offset = clock_init->offset;
		clock->mask = clock_init->mask;

		ret = devm_clk_hw_register(dev, &clock->hw);
		if (ret)
			return dev_err_probe(dev, ret,
					     "failed to register clock %s\n",
					     init.name);
	}

	ret = devm_of_clk_add_hw_provider(dev, tc9564_clk_hw_get, clocks);
	if (ret)
		return dev_err_probe(dev, ret,
				     "failed to add clock provider\n");

	return 0;
}

static struct platform_driver tc9564_clk_driver = {
	.probe = tc9564_clk_probe,
	.driver = {
		.name = "toshiba-tc9564-clock",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(tc9564_clk_driver);

MODULE_DESCRIPTION("Toshiba TC9564 Clock Driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:toshiba-tc9564-clock");
