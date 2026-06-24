// SPDX-License-Identifier: GPL-2.0
//

/*
 * Copyright (C) 2026 by RISCstar Solutions Corporation.  All rights reserved.
 */

#include <linux/bits.h>
#include <linux/clk-provider.h>
#include <linux/mfd/syscon.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>

#include <dt-bindings/clock/toshiba,tc9564.h>

#define DRIVER_NAME		"tc956x-clk"

/*
 * Clock register offsets used to enable/disable clocks.  These offsets
 * are relative to the base of the chip configuration space mapped by the
 * system controller referred to by the "toshiba,config-syscon" property.
 */
#define CLKCTRL0_OFFSET			0x1004
#define CLKCTRL1_OFFSET			0x100c

struct tc956x_clock_init {
	const char *name;		/* NULL means unused entry */
	u32 offset;
	u32 mask;
};

struct tc956x_clock {
	struct clk_hw hw;
	u16 which;
	u16 offset;
	u32 mask;			/* Zero means undefined clock */
};

struct tc956x_clocks {
	struct regmap *regmap;
	size_t clock_count;
	struct tc956x_clock clocks[] __counted_by(clock_count);
};

#define TC956X_CLOCK_INIT(_name, _zero_one, _bit)		\
	[CLOCK_ ## _name] = {					\
		.name	= #_name,				\
		.offset	= CLKCTRL ## _zero_one ## _OFFSET,	\
		.mask	= BIT(_bit),				\
	}

static const struct tc956x_clock_init tc9564_clock_init[] = {
	TC956X_CLOCK_INIT(MCU, 0, 0),
	TC956X_CLOCK_INIT(INTC, 0, 4),
	/* TC956X_CLOCK_INIT(PCIE, 0, 9), */
	/* TC956X_CLOCK_INIT(I2C, 0, 12), */
	TC956X_CLOCK_INIT(SRAM, 0, 13),
	TC956X_CLOCK_INIT(UART, 0, 16),
	TC956X_CLOCK_INIT(MSIGEN, 0, 18),
	TC956X_CLOCK_INIT(PLL, 0, 24),
	TC956X_CLOCK_INIT(SGMII, 0, 25),
	TC956X_CLOCK_INIT(REFCLKO, 0, 26),

	TC956X_CLOCK_INIT(MAC0_TX, 0, 7),
	TC956X_CLOCK_INIT(MAC0_RX, 0, 14),
	TC956X_CLOCK_INIT(MAC0_125M, 0, 29),
	TC956X_CLOCK_INIT(MAC0_312_5M, 0, 30),
	TC956X_CLOCK_INIT(MAC0_ALL, 0, 31),

	TC956X_CLOCK_INIT(MAC1_TX, 1, 7),
	TC956X_CLOCK_INIT(MAC1_RX, 1, 14),
	TC956X_CLOCK_INIT(MAC1_RMII, 1, 15),
	TC956X_CLOCK_INIT(MAC1_125M, 1, 29),
	TC956X_CLOCK_INIT(MAC1_312_5M, 1, 30),
	TC956X_CLOCK_INIT(MAC1_ALL, 1, 31),
};

static struct tc956x_clock *hw_to_tc956x_clock(struct clk_hw *hw)
{
	return container_of(hw, struct tc956x_clock, hw);
}

static struct tc956x_clocks *tc956x_clock_to_clocks(struct tc956x_clock *clock)
{
	return container_of(clock, struct tc956x_clocks, clocks[clock->which]);
}

static void tc956x_clk_manage(struct tc956x_clock *clock, bool enable)
{
	struct tc956x_clocks *clocks = tc956x_clock_to_clocks(clock);

	/* No errors returned for MMIO regmap */
	regmap_update_bits(clocks->regmap, clock->offset, clock->mask,
			   enable ? clock->mask : 0);
}

/* Prepare also includes enable */
static int tc956x_clk_prepare(struct clk_hw *hw)
{
	struct tc956x_clock *clock = hw_to_tc956x_clock(hw);

	if (clock->mask)
		tc956x_clk_manage(hw_to_tc956x_clock(hw), true);
	else
		pr_warn("invalid clock (prepare)!\n");

	return 0;
}

/* Unprepare also includes disable */
static void tc956x_clk_unprepare(struct clk_hw *hw)
{
	struct tc956x_clock *clock = hw_to_tc956x_clock(hw);

	if (clock->mask)
		tc956x_clk_manage(hw_to_tc956x_clock(hw), false);
	else
		pr_warn("invalid clock! (unprepare)\n");
}

static struct clk_ops tc956x_clk_ops = {
	.prepare	= tc956x_clk_prepare,
	.unprepare	= tc956x_clk_unprepare,
};

static int tc956x_clk_probe(struct platform_device *pdev)
{
	const struct tc956x_clock_init *clock_init;
	struct device *dev = &pdev->dev;
	struct tc956x_clocks *clocks;
	struct tc956x_clock *clock;
	struct regmap *regmap;
	struct clk_hw *hw;
	int ret;
	u32 i;

	dev_info(dev, " === %s starting\n", __func__);

	regmap = syscon_regmap_lookup_by_phandle(dev_of_node(dev),
						 "toshiba,config-syscon");
	if (IS_ERR(regmap))
		return dev_err_probe(dev, PTR_ERR(regmap),
				     "failed to get config regmap\n");

	clocks = kzalloc_flex(*clocks, clocks, ARRAY_SIZE(tc9564_clock_init));
	if (!clocks)
		return dev_err_probe(dev, -ENOMEM,
				     "failed to allocate clocks\n");
	clocks->regmap = regmap;

	clock = &clocks->clocks[0];
	clock_init = &tc9564_clock_init[0];
	for (i = 0; i < clocks->clock_count && clock_init->name; i++) {
		struct clk_init_data init = { };

		init.name = clock_init->name;
		init.ops = &tc956x_clk_ops;

		hw = &clock->hw;
		hw->init = &init;

		ret = clk_hw_register(dev, hw);
		if (ret)
			goto unwind;

		clock->which = i;
		clock->offset = clock_init->offset;
		clock->mask = clock_init->mask;

		clock++;
		clock_init++;
	}

	dev_info(dev, " === %s successful\n", __func__);

	return 0;
unwind:
	while (--i)
		clk_hw_unregister(--hw);

	return dev_err_probe(dev, -ENOMEM, "failed to register \"%s\" clock\n",
			     clock_init->name);
}

static void tc956x_clk_remove(struct platform_device *pdev)
{
	/* Nothing to do for now */
}

static const struct of_device_id tc956x_clk_ids[] = {
	{ .compatible = "toshiba,tc956x-clocks" },
	{ },
};
MODULE_DEVICE_TABLE(of, tc956x_clk_ids);

static struct platform_driver tc956x_clk_driver = {
	.probe	= tc956x_clk_probe,
	.remove	= tc956x_clk_remove,
	.driver	= {
		.name		= DRIVER_NAME,
		.of_match_table = tc956x_clk_ids,
		.owner		= THIS_MODULE,
		// .probe_type	= PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(tc956x_clk_driver);

MODULE_DESCRIPTION("Toshiba TC956X Clock Driver");
MODULE_LICENSE("GPL");
