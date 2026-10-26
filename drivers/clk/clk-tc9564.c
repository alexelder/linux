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
	u32 offset;
	u32 mask;
};

struct tc9564_clock {
	struct clk_hw hw;
	u32 which;
	u32 offset;		/* CLK_CTRL0_OFFSET or CLK_CTRL1_OFFSET */
	u32 mask;		/* Zero means undefined clock */
};

struct tc9564_clocks {
	struct device *dev;
	struct regmap *regmap;
	size_t clock_count;
	struct tc9564_clock clocks[] __counted_by(clock_count);
};

#define TC9564_CLOCK_INIT0(_name, _bit)	__TC9564_CLOCK_INIT(_name, 0, _bit)
#define TC9564_CLOCK_INIT1(_name, _bit)	__TC9564_CLOCK_INIT(_name, 1, _bit)

#define __TC9564_CLOCK_INIT(_name, _reg, _bit)		\
	[CLOCK_##_name] = {				\
		.name	= #_name,			\
		.offset	= CLK_CTRL ## _reg ## _OFFSET,	\
		.mask	= BIT(_bit),			\
	}

/*
 * The PCIe and I2C clocks are controllable, but we depend on PCIe
 * and that relies on I2C, so we don't allow them to be disabled.
 */
static const struct tc9564_clock_init tc9564_clock_init[] = {
	TC9564_CLOCK_INIT0(MCU, 0),
	TC9564_CLOCK_INIT0(INTC, 4),
	/* TC9564_CLOCK_INIT0(PCIE, 9), */
	/* TC9564_CLOCK_INIT0(I2C, 12), */
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

static const struct tc9564_clocks *
tc9564_clock_to_clocks(const struct tc9564_clock *clock)
{
	u32 which = clock->which;

	if (which >= TC9564_CLOCK_COUNT)
		return ERR_PTR(-ENXIO);

	return container_of_const(clock, struct tc9564_clocks, clocks[which]);
}

static int tc9564_clk_manage(struct clk_hw *hw, bool enable)
{
	const struct tc9564_clock *clock = hw_to_tc9564_clock(hw);
	const struct tc9564_clocks *clocks;
	u32 offset = clock->offset;
	u32 mask = clock->mask;

	clocks = tc9564_clock_to_clocks(clock);
	if (IS_ERR(clocks) || !mask) {
		dev_err(clocks->dev, "invalid clock (%s id %u)\n",
			str_enable_disable(enable), clock->which);
		return -ENXIO;
	}

	return regmap_update_bits(clocks->regmap, offset, mask,
				  enable ? mask : 0);
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
	const struct tc9564_clocks *clocks;
	u32 offset = clock->offset;
	u32 mask = clock->mask;
	u32 val;

	clocks = tc9564_clock_to_clocks(clock);
	if (IS_ERR(clocks) || !mask) {
		dev_err(clocks->dev, "invalid clock (id %u)\n", clock->which);
		return -ENXIO;
	}

	regmap_read(clocks->regmap, offset, &val);

	return val & mask ? 1 : 0;
}

static const struct clk_ops tc9564_clk_ops = {
	.enable = tc9564_clk_enable,
	.disable = tc9564_clk_disable,
	.is_enabled = tc9564_clk_is_enabled,
};

static void tc9564_clock_disable_all(struct tc9564_clocks *clocks)
{
	for (u32 i = 0; i < clocks->clock_count; i++) {
		const struct tc9564_clock *clock = &clocks->clocks[i];

		if (clock->mask)
			regmap_update_bits(clocks->regmap, clock->offset,
					   clock->mask, 0);
	}
}

static struct clk_hw *tc9564_clk_hw_get(struct of_phandle_args *clkspec,
					void *data)
{
	struct tc9564_clocks *clocks = data;
	u32 i = clkspec->args[0];

	if (i < clocks->clock_count)
		return &clocks->clocks[i].hw;

	dev_err(clocks->dev, "invalid index %u\n", i);

	return ERR_PTR(-EINVAL);
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

	clocks_size = struct_size(clocks, clocks, TC9564_CLOCK_COUNT);
	clocks = devm_kzalloc(dev, clocks_size, GFP_KERNEL);
	if (!clocks)
		return -ENOMEM;

	clocks->dev = dev;
	clocks->regmap = regmap;
	clocks->clock_count = TC9564_CLOCK_COUNT;

	for (u32 i = 0; i < TC9564_CLOCK_COUNT; i++) {
		const struct tc9564_clock_init *clock_init;
		struct clk_init_data init = { };
		struct tc9564_clock *clock;

		clock_init = &tc9564_clock_init[i];
		if (!clock_init->name)
			continue;

		init.name = clock_init->name;
		init.ops = &tc9564_clk_ops;

		clock = &clocks->clocks[i];
		clock->hw.init = &init;
		clock->which = i;
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

	/* Force all clocks to be initially disabled */
	tc9564_clock_disable_all(clocks);

	platform_set_drvdata(pdev, clocks);

	return 0;
}

static void tc9564_clk_remove(struct platform_device *pdev)
{
	struct tc9564_clocks *clocks = platform_get_drvdata(pdev);

	/* Leave all clocks disabled when done */
	tc9564_clock_disable_all(clocks);
}

static struct platform_driver tc9564_clk_driver = {
	.probe = tc9564_clk_probe,
	.remove = tc9564_clk_remove,
	.driver = {
		.name = "toshiba-tc9564-clock",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(tc9564_clk_driver);

MODULE_DESCRIPTION("Toshiba TC9564 Clock Driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:toshiba-tc9564-clock");
