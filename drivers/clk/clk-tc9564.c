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
 * The full name of every clock has a prefix "tc9564" followed by a single
 * character ('a', 'b', etc.) that differs for each chip/device number.
 * Each clock's "name" defines the unique portion of the clock's full name.
 */
#define FULL_NAME_SIZE	24	/* Enough for formatted name */
#define NAME_SIZE	12	/* Unique portion of the clock name */
#define FORMAT_FULL_NAME(_full_name, _id, _name)		\
	snprintf(_full_name, FULL_NAME_SIZE, "tc9564%c_%.*s",	\
		'a' + (_id), NAME_SIZE, _name)

enum clock_type { PLL, FIXED, GATE };

struct clock_init {
	const char name[NAME_SIZE];
	enum clock_type type;
	union {
		u32 mult;	/* PLL rate multiplier */

		u32 div;	/* Fixed rate clock divider */

		struct {	/* Gate clock */
			bool reg0;	/* Controlled by CLK_CTRL0_OFFSET? */
			u16 parent;	/* Parent clock ID, e.g. CLOCK_50M */
			u32 mask;
		};
	};
};

struct gate_clock {
	struct clk_hw hw;
	const struct clock_init *init;
};

struct tc9564_clock {
	struct regmap *regmap;
	struct clk_hw_onecell_data *clk_data;
};

/* There is only one PLL */
#define PLL_INIT(_name, _mult)					\
	[CLOCK_##_name] = {					\
		.name = #_name,					\
		.type = PLL,					\
		.mult = (_mult),				\
	}

/* The PLL is the parent of all the fixed rate clocks */
#define FIXED_INIT(_name, _div)					\
	[CLOCK_##_name] = {					\
		.name = #_name,					\
		.type = FIXED,					\
		.div = (_div),					\
	}

#define GATE_INIT0(_name, _bit, _pname)				\
	__GATE_INIT(_name, _bit, _pname, true)
#define GATE_INIT1(_name, _bit, _pname)				\
	__GATE_INIT(_name, _bit, _pname, false)

#define __GATE_INIT(_name, _bit, _pname, _reg0)			\
	[CLOCK_##_name] = {					\
		.name = #_name,					\
		.type = GATE,					\
		.reg0 = _reg0,					\
		.parent = CLOCK_##_pname,			\
		.mask = BIT(_bit),				\
	}

/*
 * Clocks are initialized and registered in the order of their IDs.
 * Parent clocks must be registered before their children.
 */
static const struct clock_init clock_init[] = {
	PLL_INIT(PLL, 50),		/* Parent is XO input clock */

	FIXED_INIT(62_5M, 20),		/* Parent of all fixed clocks is PLL */
	FIXED_INIT(125M, 10),
	FIXED_INIT(250M, 5),
	FIXED_INIT(312_5M, 4),

	GATE_INIT0(MSIGEN, 18, 62_5M),		/* ??? */

	GATE_INIT0(MAC0_TX, 7, 250M),		/* ??? */
	GATE_INIT0(MAC0_RX, 14, 250M),		/* ??? */
	GATE_INIT0(MAC0_125M, 29, 125M),
	GATE_INIT0(MAC0_312_5M, 30, 312_5M),
	GATE_INIT0(MAC0_ALL, 31, 250M),		/* XXX */

	GATE_INIT1(MAC1_TX, 7, 250M),		/* ??? */
	GATE_INIT1(MAC1_RX, 14, 250M),		/* ??? */
	GATE_INIT1(MAC1_125M, 29, 125M),
	GATE_INIT1(MAC1_312_5M, 30, 312_5M),
	GATE_INIT1(MAC1_ALL, 31, 250M),		/* XXX */
	GATE_INIT1(MAC1_RMII, 15, 125M),
};
#define CLOCK_COUNT	ARRAY_SIZE(clock_init)

static const struct gate_clock *hw_to_gate_clock(struct clk_hw *hw)
{
	return container_of_const(hw, struct gate_clock, hw);
}

static void gate_clk_manage(struct clk_hw *hw, bool enable)
{
	const struct gate_clock *clock = hw_to_gate_clock(hw);
	struct device *dev = clk_hw_get_dev(hw);
	struct tc9564_clock *tc9564_clock;
	u32 mask = clock->init->mask;
	struct regmap *regmap;
	u32 offset;

	tc9564_clock = dev_get_drvdata(dev);
	regmap = tc9564_clock->regmap;

	offset = clock->init->reg0 ? CLK_CTRL0_OFFSET : CLK_CTRL1_OFFSET;

	regmap_update_bits(regmap, offset, mask, enable ? mask : 0);
}

static int gate_clk_enable(struct clk_hw *hw)
{
	gate_clk_manage(hw, true);

	return 0;
}

static void gate_clk_disable(struct clk_hw *hw)
{
	gate_clk_manage(hw, false);
}

static int gate_clk_is_enabled(struct clk_hw *hw)
{
	const struct gate_clock *clock = hw_to_gate_clock(hw);
	struct device *dev = clk_hw_get_dev(hw);
	struct tc9564_clock *tc9564_clock;
	struct regmap *regmap;
	u32 offset;
	u32 val;

	tc9564_clock = dev_get_drvdata(dev);
	regmap = tc9564_clock->regmap;

	offset = clock->init->reg0 ? CLK_CTRL0_OFFSET : CLK_CTRL1_OFFSET;

	regmap_read(regmap, offset, &val);

	return val & clock->init->mask ? 1 : 0;
}

static const struct clk_ops gate_clk_ops = {
	.enable = gate_clk_enable,
	.disable = gate_clk_disable,
	.is_enabled = gate_clk_is_enabled,
};

/* Input oscillator runs at 25 MHz; PLL runs at 1250 MHz */
static struct clk_hw *tc9564_pll_register(struct device *dev,
					  const struct clock_init *init)
{
	char full_name[FULL_NAME_SIZE];
	struct clk_hw *hw;

	FORMAT_FULL_NAME(full_name, dev->id, init->name);

	hw = devm_clk_hw_register_fixed_factor_index(dev, full_name, 0, 0,
						     init->mult, 1);
	if (IS_ERR(hw))
		dev_err(dev, "failed to register PLL\n");

	return hw;
}

static struct clk_hw *tc9564_fixed_register(struct device *dev,
					    const struct clock_init *init)
{
	struct tc9564_clock *tc9564_clock = dev_get_drvdata(dev);
	char full_name[FULL_NAME_SIZE];
	struct clk_hw *pll_hw;
	struct clk_hw *hw;

	FORMAT_FULL_NAME(full_name, dev->id, init->name);

	pll_hw = tc9564_clock->clk_data->hws[CLOCK_PLL];
	hw = devm_clk_hw_register_fixed_factor_parent_hw(dev, full_name,
							 pll_hw, 0,
							 1, init->div);
	if (IS_ERR(hw))
		dev_err(dev, "failed to register %s\n", full_name);

	return hw;
}

static struct clk_hw *tc9564_gate_register(struct device *dev,
					   const struct clock_init *init)
{
	struct tc9564_clock *tc9564_clock = dev_get_drvdata(dev);
	struct clk_init_data clk_init = { };
	const struct clk_hw *parent_hw;
	char full_name[FULL_NAME_SIZE];
	struct gate_clock *clock;
	int ret;

	clock = devm_kzalloc_obj(dev, *clock);
	if (!clock)
		return ERR_PTR(-ENOMEM);

	FORMAT_FULL_NAME(full_name, dev->id, init->name);

	parent_hw = tc9564_clock->clk_data->hws[init->parent];

	clk_init.name = full_name;
	clk_init.ops = &gate_clk_ops;
	clk_init.parent_hws = &parent_hw;
	clk_init.num_parents = 1;

	clock->hw.init = &clk_init;
	clock->init = init;

	ret = devm_clk_hw_register(dev, &clock->hw);
	if (ret) {
		dev_err(dev, "failed to register gate clock %s\n", full_name);
		return ERR_PTR(ret);
	}

	return &clock->hw;
}

static int tc9564_clock_init(struct device *dev)
{
	struct tc9564_clock *tc9564_clock = dev_get_drvdata(dev);
	struct clk_hw_onecell_data *clk_data;
	int ret;

	clk_data = tc9564_clock->clk_data;

	for (u32 i = 0; i < clk_data->num; i++) {
		const struct clock_init *init = &clock_init[i];
		struct clk_hw *hw;

		if (init->type == PLL)
			hw = tc9564_pll_register(dev, init);
		else if (init->type == FIXED)
			hw = tc9564_fixed_register(dev, init);
		else
			hw = tc9564_gate_register(dev, init);
		if (IS_ERR(hw))
			return PTR_ERR(hw);

		clk_data->hws[i] = hw;
	}

	ret = devm_of_clk_add_hw_provider(dev, of_clk_hw_onecell_get, clk_data);
	if (ret)
		dev_err(dev, "failed to add clock provider\n");

	return ret;
}

static int tc9564_clk_probe(struct platform_device *pdev)
{
	struct tc9564_clock *tc9564_clock;
	struct device *dev = &pdev->dev;
	struct device_node *parent_np;
	int ret;

	parent_np = dev_of_node(dev->parent);
	if (!parent_np)
		return dev_err_probe(dev, -EINVAL, "no devicetree node\n");

	tc9564_clock = devm_kzalloc_obj(dev, *tc9564_clock);
	if (!tc9564_clock)
		return -ENOMEM;

	/* Note: MMIO regmap (no error checking needed when used) */
	tc9564_clock->regmap = device_node_to_regmap(parent_np);
	if (IS_ERR(tc9564_clock->regmap))
		return dev_err_probe(dev, PTR_ERR(tc9564_clock->regmap),
				     "failed to get config regmap\n");

	tc9564_clock->clk_data = devm_kzalloc_flex(dev, *tc9564_clock->clk_data,
						   hws, CLOCK_COUNT);
	if (!tc9564_clock->clk_data)
		return -ENOMEM;

	dev_set_drvdata(dev, tc9564_clock);

	ret = tc9564_clock_init(dev);
	if (ret)
		return dev_err_probe(dev, ret, "failed to initialize clocks\n");

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
