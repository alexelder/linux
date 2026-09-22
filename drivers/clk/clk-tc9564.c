// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2026 by RISCstar Solutions Corporation.  All rights reserved.
 */

#include <linux/bits.h>
#include <linux/clk-provider.h>
#include <linux/device-id/of.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/reset-controller.h>

#include <dt-bindings/clock/toshiba,tc9564.h>

#define CLK_CTRL0_OFFSET	0x1004
#define RST_CTRL0_OFFSET	0x1008
#define CLK_CTRL1_OFFSET	0x100c
#define RST_CTRL1_OFFSET	0x1010

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

struct tc9564_reset {
	u32 offset;		/* RST_CTRL0_OFFSET or RST_CTRL1_OFFSET */
	u32 mask;		/* Zero means undefined reset */
};

struct tc9564_clocks {
	struct device *dev;
	struct regmap *regmap;
	struct reset_controller_dev rcdev;
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

#define TC9564_RESET_INIT0(_name, _bit)	__TC9564_RESET_INIT(_name, 0, _bit)
#define TC9564_RESET_INIT1(_name, _bit)	__TC9564_RESET_INIT(_name, 1, _bit)

#define __TC9564_RESET_INIT(_name, _reg, _bit)		\
	[RESET_##_name] = {				\
		.offset	= RST_CTRL ## _reg ## _OFFSET,	\
		.mask = BIT(_bit),			\
	}

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

static const struct tc9564_reset tc9564_reset[] = {
	TC9564_RESET_INIT0(MCU, 0),
	TC9564_RESET_INIT0(MCU1, 1),
	TC9564_RESET_INIT0(INTC, 4),
	/* TC9564_RESET_INIT0(PCIE, 9), */
	/* TC9564_RESET_INIT0(I2C, 12), */
	TC9564_RESET_INIT0(UART, 16),
	TC9564_RESET_INIT0(MSIGEN, 18),

	TC9564_RESET_INIT0(MAC0_MAC, 7),
	TC9564_RESET_INIT0(MAC0_PMA, 30),
	TC9564_RESET_INIT0(MAC0_XPCS, 31),

	TC9564_RESET_INIT1(MAC1_MAC, 7),
	TC9564_RESET_INIT1(MAC1_PMA, 30),
	TC9564_RESET_INIT1(MAC1_XPCS, 31),
};
#define TC9564_RESET_COUNT	ARRAY_SIZE(tc9564_reset)

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
		dev_err(clk_hw_get_dev(hw), "invalid clock (%s id %u)\n",
			enable ? "enable" : "disable", clock->which);
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

static const struct clk_ops tc9564_clk_ops = {
	.enable = tc9564_clk_enable,
	.disable = tc9564_clk_disable,
};

static void tc9564_clock_disable_all(struct tc9564_clocks *clocks)
{
	for (int i = 0; i < clocks->clock_count; i++) {
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
	unsigned int i = clkspec->args[0];

	if (i < clocks->clock_count)
		return &clocks->clocks[i].hw;

	dev_err(clocks->dev, "invalid index %u\n", i);

	return ERR_PTR(-EINVAL);
}

static struct tc9564_clocks *tc9564_clk_init(struct device *dev)
{
	struct tc9564_clocks *clocks;
	size_t clocks_size;
	int ret;

	clocks_size = struct_size(clocks, clocks, TC9564_CLOCK_COUNT);
	clocks = devm_kzalloc(dev, clocks_size, GFP_KERNEL);
	if (!clocks)
		return ERR_PTR(-ENOMEM);

	clocks->dev = dev;
	clocks->clock_count = TC9564_CLOCK_COUNT;

	clocks->regmap = syscon_node_to_regmap(dev_of_node(dev->parent));
	if (IS_ERR(clocks->regmap)) {
		dev_err(dev, "failed to get config regmap\n");
		return ERR_CAST(clocks->regmap);
	}

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

		ret = devm_clk_hw_register(dev, &clock->hw);
		if (ret) {
			dev_err(dev, "failed to register clock \"%s\"\n",
				init.name);
			return ERR_PTR(ret);
		}

		clock->which = i;
		clock->offset = clock_init->offset;
		clock->mask = clock_init->mask;
	}

	ret = devm_of_clk_add_hw_provider(dev, tc9564_clk_hw_get, clocks);
	if (ret) {
		dev_err(dev, "failed to add clock hardware provider\n");
		return ERR_PTR(ret);
	}

	return clocks;
}

static const struct tc9564_clocks *
rcdev_to_tc9564_clocks(struct reset_controller_dev *rcdev)
{
	return container_of_const(rcdev, struct tc9564_clocks, rcdev);
}

static int tc9564_reset_manage(struct reset_controller_dev *rcdev,
			       unsigned long id, bool assert)
{
	const struct tc9564_clocks *clocks = rcdev_to_tc9564_clocks(rcdev);

	if (id < rcdev->nr_resets) {
		const struct tc9564_reset *reset = &tc9564_reset[id];
		u32 mask = reset->mask;

		if (mask)
			return regmap_update_bits(clocks->regmap,
						  reset->offset, mask,
						  assert ? mask : 0);
	}

	dev_err(clocks->dev, "invalid reset (%sassert id %lu)\n",
		assert ? "" : "de", id);

	return -ENXIO;
}

static int tc9564_reset_assert(struct reset_controller_dev *rcdev,
			       unsigned long id)
{
	return tc9564_reset_manage(rcdev, id, true);
}

static int tc9564_reset_deassert(struct reset_controller_dev *rcdev,
				 unsigned long id)
{
	return tc9564_reset_manage(rcdev, id, false);
}

static const struct reset_control_ops tc9564_reset_control_ops = {
	.assert		= tc9564_reset_assert,
	.deassert	= tc9564_reset_deassert,
};

static void tc9564_reset_assert_all(struct tc9564_clocks *clocks)
{
	for (u32 id = 0; id < TC9564_RESET_COUNT; id++)
		if (tc9564_reset[id].mask)
			tc9564_reset_manage(&clocks->rcdev, id, true);
}

static int tc9564_reset_init(struct tc9564_clocks *clocks)
{
	struct reset_controller_dev *rcdev = &clocks->rcdev;

	rcdev->ops = &tc9564_reset_control_ops;
	rcdev->owner = THIS_MODULE;
	rcdev->dev = clocks->dev;
	rcdev->of_node = dev_of_node(clocks->dev);
	rcdev->nr_resets = TC9564_RESET_COUNT;

	return devm_reset_controller_register(clocks->dev, rcdev);
}

static int tc9564_clk_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct tc9564_clocks *clocks;
	int ret;

	if (!dev_of_node(dev))
		return dev_err_probe(dev, -EINVAL, "no devicetree node\n");

	clocks = tc9564_clk_init(dev);
	if (IS_ERR(clocks))
		return dev_err_probe(dev, PTR_ERR(clocks),
				     "failed to initialize clocks\n");

	ret = tc9564_reset_init(clocks);
	if (ret)
		return dev_err_probe(dev, ret, "failed to initialize resets\n");

	/* Force all resets to be initially asserted */
	tc9564_reset_assert_all(clocks);

	/* Force all clocks to be initially disabled */
	tc9564_clock_disable_all(clocks);

	platform_set_drvdata(pdev, clocks);

	return 0;
}

static void tc9564_clk_remove(struct platform_device *pdev)
{
	struct tc9564_clocks *clocks = platform_get_drvdata(pdev);

	/* Leave all resets to be deasserted when done */
	tc9564_reset_assert_all(clocks);

	/* Leave all clocks disabled when done */
	tc9564_clock_disable_all(clocks);
}

static const struct of_device_id tc9564_clk_ids[] = {
	{ .compatible = "toshiba,tc9564-clock" },
	{ }
};
MODULE_DEVICE_TABLE(of, tc9564_clk_ids);

static struct platform_driver tc9564_clk_driver = {
	.probe	= tc9564_clk_probe,
	.remove	= tc9564_clk_remove,
	.driver	= {
		.name		= KBUILD_MODNAME,
		.of_match_table = tc9564_clk_ids,
		.probe_type	= PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(tc9564_clk_driver);

MODULE_DESCRIPTION("Toshiba TC9564 Clock and Reset Driver");
MODULE_LICENSE("GPL");
