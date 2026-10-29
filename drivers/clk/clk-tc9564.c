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

/* Two registers control whether gate clocks are enabled */
#define CLK_CTRL0_OFFSET	0x1004	/* Common and MAC0 gate clocks */
#define CLK_CTRL1_OFFSET	0x100c	/* MAC1 gate clocks */

/*
 * A 25 MHz oscillator supplies the TC9564 chip, and it drives an internal
 * PLL running at 1250 MHz.  A set of fixed rate clocks are derived from
 * the PLL.  All remaining clocks are simple gate clocks, each running at
 * the same rate its parent.
 */
enum {
	CLOCK_FIXED_50M,
	CLOCK_FIXED_62_5M,
	CLOCK_FIXED_125M,
	CLOCK_FIXED_250M,
	CLOCK_FIXED_312_5M,
	CLOCK_FIXED_625M,
};

/*
 * All clocks are named with a prefix "tc9564" followed by a single
 * character ('a', 'b', etc.) that differs for each chip/device number.
 * Each clock's "suffix" defines the unique portion of the clock name.
 */
#define NAME_SIZE	24	/* Enough for formatted name including suffix */
#define SUFFIX_SIZE	12
#define FORMAT_NAME(_name, _id, _suffix)			\
	snprintf(_name, NAME_SIZE, "tc9564%c_%.*s",		\
		'a' + (_id), SUFFIX_SIZE, _suffix)

struct fixed_init {
	const char suffix[SUFFIX_SIZE];
	u32 div;	/* Fixed divider */
};

static const struct fixed_init fixed_init[] = {
	[CLOCK_FIXED_50M] = {
		.suffix = "50_mhz",
		.div = 25,
	},
	[CLOCK_FIXED_62_5M] = {
		.suffix = "62_5_mhz",
		.div = 20,
	},
	[CLOCK_FIXED_125M] = {
		.suffix = "125_mhz",
		.div = 10,
	},
	[CLOCK_FIXED_250M] = {
		.suffix = "250_mhz",
		.div = 5,
	},
	[CLOCK_FIXED_312_5M] = {
		.suffix = "312_5_mhz",
		.div = 4,
	},
	[CLOCK_FIXED_625M] = {
		.suffix = "625_mhz",
		.div = 2,
	},
};
#define FIXED_COUNT	ARRAY_SIZE(fixed_init)

/* Input oscillator runs at 25 MHz; PLL runs at 1250 MHz */
static struct clk_hw *tc9564_pll_register(struct device *dev)
{
	char name[NAME_SIZE];
	struct clk_hw *hw;

	FORMAT_NAME(name, dev->id, "pll");

	hw = devm_clk_hw_register_fixed_factor_index(dev, name, 0, 0, 500, 1);
	if (IS_ERR(hw))
		dev_err(dev, "failed to register PLL\n");

	return hw;
}

static struct clk_hw *tc9564_fixed_register(struct device *dev,
					    struct clk_hw *pll_hw,
					    const struct fixed_init *init)
{
	char name[NAME_SIZE];
	struct clk_hw *hw;

	FORMAT_NAME(name, dev->id, init->suffix);

	hw = devm_clk_hw_register_fixed_factor_parent_hw(dev, name, pll_hw, 0,
							 1, init->div);
	if (IS_ERR(hw))
		dev_err(dev, "failed to register %s\n", name);

	return hw;
}

static int tc9564_fixed_clock_init(struct device *dev)
{
	struct clk_hw_onecell_data *clk_data;
	struct clk_hw *pll_hw;
	int ret;

	/* The PLL is the parent of all the fixed rate clocks */
	pll_hw = tc9564_pll_register(dev);
	if (IS_ERR(pll_hw))
		return PTR_ERR(pll_hw);

	clk_data = devm_kzalloc_flex(dev, *clk_data, hws, FIXED_COUNT);
	if (!clk_data)
		return -ENOMEM;

	for (u32 i = 0; i < clk_data->num; i++) {
		struct clk_hw *hw;

		hw = tc9564_fixed_register(dev, pll_hw, &fixed_init[i]);
		if (IS_ERR(hw))
			return PTR_ERR(hw);

		clk_data->hws[i] = hw;
	}

	ret = devm_of_clk_add_hw_provider(dev, of_clk_hw_onecell_get, clk_data);
	if (ret)
		dev_err(dev, "failed to add fixed clock provider\n");

	return ret;
}

struct gate_init {
	const char suffix[SUFFIX_SIZE];
	bool critical;
	bool reg0;		/* Controlled by CLK_CTRL0_OFFSET? */
	u32 mask;
};

struct gate_clock {
	struct clk_hw hw;
	const struct gate_init *init;
};

#define TC9564_CLOCK_INIT0(_suffix, _bit)			\
	__TC9564_CLOCK_INIT(_suffix, true, _bit, false)
#define TC9564_CLOCK_INIT0_CRITICAL(_suffix, _bit)		\
	__TC9564_CLOCK_INIT(_suffix, true, _bit, true)
#define TC9564_CLOCK_INIT1(_suffix, _bit)			\
	__TC9564_CLOCK_INIT(_suffix, false, _bit, false)

#define __TC9564_CLOCK_INIT(_suffix, _reg0, _bit, _critical)	\
	[CLOCK_##_suffix] = {					\
		.suffix = #_suffix,				\
		.reg0 = _reg0,					\
		.mask = BIT(_bit),				\
		.critical = _critical,				\
	}

/*
 * The PCIe and I2C clocks are controllable, but we depend on PCIe
 * and that relies on I2C, so we don't allow them to be disabled.
 */
static const struct gate_init gate_init[] = {
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
#define GATE_COUNT	ARRAY_SIZE(gate_init)

static const struct gate_clock *hw_to_gate_clock(struct clk_hw *hw)
{
	return container_of_const(hw, struct gate_clock, hw);
}

static void tc9564_clk_manage(struct clk_hw *hw, bool enable)
{
	struct regmap *regmap = dev_get_drvdata(clk_hw_get_dev(hw));
	const struct gate_clock *clock = hw_to_gate_clock(hw);
	u32 mask = clock->init->mask;
	u32 offset;

	offset = clock->init->reg0 ? CLK_CTRL0_OFFSET : CLK_CTRL1_OFFSET;

	regmap_update_bits(regmap, offset, mask, enable ? mask : 0);
}

static int tc9564_clk_enable(struct clk_hw *hw)
{
	tc9564_clk_manage(hw, true);

	return 0;
}

static void tc9564_clk_disable(struct clk_hw *hw)
{
	tc9564_clk_manage(hw, false);
}

static int tc9564_clk_is_enabled(struct clk_hw *hw)
{
	struct regmap *regmap = dev_get_drvdata(clk_hw_get_dev(hw));
	const struct gate_clock *clock = hw_to_gate_clock(hw);
	u32 offset;
	u32 val;

	offset = clock->init->reg0 ? CLK_CTRL0_OFFSET : CLK_CTRL1_OFFSET;

	regmap_read(regmap, offset, &val);

	return val & clock->init->mask ? 1 : 0;
}

static const struct clk_ops tc9564_clk_ops = {
	.enable = tc9564_clk_enable,
	.disable = tc9564_clk_disable,
	.is_enabled = tc9564_clk_is_enabled,
};

static struct clk_hw *tc9564_gate_register(struct device *dev,
					   struct gate_clock *clock,
					   const struct gate_init *init)
{
	struct clk_init_data clk_init = { };
	char name[NAME_SIZE];
	int ret;

	FORMAT_NAME(name, dev->id, init->suffix);

	clk_init.name = name;
	clk_init.flags = init->critical ? CLK_IS_CRITICAL : 0;
	clk_init.ops = &tc9564_clk_ops;

	clock->hw.init = &clk_init;
	clock->init = init;

	ret = devm_clk_hw_register(dev, &clock->hw);
	if (ret) {
		dev_err(dev, "failed to register gate clock %s\n", name);
		return ERR_PTR(ret);
	}

	return &clock->hw;
}

static int tc9564_gate_clock_init(struct device *dev)
{
	struct clk_hw_onecell_data *clk_data;
	struct gate_clock *clocks;
	int ret;

	clocks = devm_kzalloc_objs(dev, *clocks, GATE_COUNT);
	if (!clocks)
		return -ENOMEM;

	clk_data = devm_kzalloc_flex(dev, *clk_data, hws, GATE_COUNT);
	if (!clk_data)
		return -ENOMEM;

	for (u32 i = 0; i < clk_data->num; i++) {
		const struct gate_init *init = &gate_init[i];
		struct gate_clock *clock = &clocks[i];
		struct clk_hw *hw;

		hw = tc9564_gate_register(dev, clock, init);
		if (IS_ERR(hw))
			return PTR_ERR(hw);

		clk_data->hws[i] = hw;
	}

	ret = devm_of_clk_add_hw_provider(dev, of_clk_hw_onecell_get, clk_data);
	if (ret)
		dev_err(dev, "failed to add gate clock provider\n");

	return ret;
}

static int tc9564_clk_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *parent_np;
	struct regmap *regmap;
	int ret;

	parent_np = dev_of_node(dev->parent);
	if (!parent_np)
		return dev_err_probe(dev, -EINVAL, "no devicetree node\n");

	/* Note: MMIO regmap (no error checking needed when used) */
	regmap = device_node_to_regmap(parent_np);
	if (IS_ERR(regmap))
		return dev_err_probe(dev, PTR_ERR(regmap),
				     "failed to get config regmap\n");
	dev_set_drvdata(dev, regmap);

	ret = tc9564_fixed_clock_init(dev);
	if (ret)
		return dev_err_probe(dev, ret,
				     "failed to initialize fixed clocks\n");

	ret = tc9564_gate_clock_init(dev);
	if (ret)
		return dev_err_probe(dev, ret,
				     "failed to initialize gate clocks\n");

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
