// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2026 by RISCstar Solutions Corporation.  All rights reserved.
 */

#include <linux/bits.h>
#include <linux/clk-provider.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/reset-controller.h>
#include <linux/slab.h>

#include <dt-bindings/clock/toshiba,tc9564.h>

/*
 * Two registers implement clock enable/disable bits for all gated clocks.
 * And two registers implement reset assertion bits for all resets.
 * These offsets are relative to the address space defined in devicetree.
 */
#define CLOCK0_OFFSET	0x0
#define CLOCK1_OFFSET	0x8
#define RESET0_OFFSET	0x4
#define RESET1_OFFSET	0xc

struct tc9564_clock {
	void __iomem *ioaddr;		/* Mapped clock/reset registers */
	struct clk_hw_onecell_data *clk_data;
	struct reset_controller_dev rcdev;
};

struct gate_clock {
	const struct clock_init *init;
	struct clk_hw hw;
};

enum clock_type { PLL, FIXED, GATE, CRITICAL_GATE };

struct clock_init {
	const char *name;
	enum clock_type type;
	union {
		u32 mult;	/* PLL rate multiplier */

		struct {	/* Fixed rate clock; parent is PLL */
			u32 numerator;	/* 0 is treated as 1 */
			u32 denominator;
		};

		struct {	/* Gated clock; parent is a fixed rate clock */
			u16 parent;	/* Parent clock ID, e.g. CLOCK_100M */
			u16 offset;	/* Register offset */
			u32 mask;	/* Value is 2^n (only one bit set) */
		};
	};
};

struct reset_init {
	u32 offset;	/* Register offset */
	u32 mask;	/* Value is 2^n (only one bit set) */
};

/*
 * Clocks are initialized and registered in the order of their IDs.
 * There is one PLL, and it is initialized first.  Fixed clocks are
 * initialized after that, and the gated clocks are initialized last
 * (after their parent clocks have been registered).
 */
static const struct clock_init clock_init[] = {
	[CLOCK_PLL] = {
		.name = "pll",
		.type = PLL,
		.mult = 50,
	},

	[CLOCK_62_5M] = {
		.name = "62.5MHz",
		.type = FIXED,
		.denominator = 20,
	},
	[CLOCK_100M] = {
		.name = "100MHz",
		.type = FIXED,
		.numerator = 2,
		.denominator = 25,
	},
	[CLOCK_125M] = {
		.name = "125MHz",
		.type = FIXED,
		.denominator = 10,
	},
	[CLOCK_250M] = {
		.name = "250MHz",
		.type = FIXED,
		.denominator = 5,
	},
	[CLOCK_312_5M] = {
		.name = "312.5MHz",
		.type = FIXED,
		.denominator = 4,
	},

	[CLOCK_I2C] = {
		.name = "i2c",
		.type = CRITICAL_GATE,
		.parent = CLOCK_100M,
		.offset = CLOCK0_OFFSET,
		.mask = BIT(12),
	},
	[CLOCK_PCIE] = {
		.name = "PCIe",
		.type = CRITICAL_GATE,
		.parent = CLOCK_100M,
		.offset = CLOCK0_OFFSET,
		.mask = BIT(9),
	},
	[CLOCK_MSIGEN] = {
		.name = "msigen",
		.type = GATE,
		.parent = CLOCK_62_5M,
		.offset = CLOCK0_OFFSET,
		.mask = BIT(18),
	},

	[CLOCK_MAC0_TX] = {
		.name = "MAC0-TX",
		.type = GATE,
		.parent = CLOCK_250M,
		.offset = CLOCK0_OFFSET,
		.mask = BIT(7),
	},
	[CLOCK_MAC0_RX] = {
		.name = "MAC0-RX",
		.type = GATE,
		.parent = CLOCK_250M,
		.offset = CLOCK0_OFFSET,
		.mask = BIT(14),
	},
	[CLOCK_MAC0_125M] = {
		.name = "MAC0-125MHz",
		.type = GATE,
		.parent = CLOCK_125M,
		.offset = CLOCK0_OFFSET,
		.mask = BIT(29),
	},
	[CLOCK_MAC0_312_5M] = {
		.name = "MAC0-312.5MHz",
		.type = GATE,
		.parent = CLOCK_312_5M,
		.offset = CLOCK0_OFFSET,
		.mask = BIT(30),
	},
	[CLOCK_MAC0_ALL] = {
		.name = "MAC0-ALL",
		.type = GATE,
		.parent = CLOCK_250M,
		.offset = CLOCK0_OFFSET,
		.mask = BIT(31),
	},

	[CLOCK_MAC1_TX] = {
		.name = "MAC1-TX",
		.type = GATE,
		.parent = CLOCK_250M,
		.offset = CLOCK1_OFFSET,
		.mask = BIT(7),
	},
	[CLOCK_MAC1_RX] = {
		.name = "MAC1-RX",
		.type = GATE,
		.parent = CLOCK_250M,
		.offset = CLOCK1_OFFSET,
		.mask = BIT(14),
	},
	[CLOCK_MAC1_125M] = {
		.name = "MAC1-125MHz",
		.type = GATE,
		.parent = CLOCK_125M,
		.offset = CLOCK1_OFFSET,
		.mask = BIT(29),
	},
	[CLOCK_MAC1_312_5M] = {
		.name = "MAC1-312.5MHz",
		.type = GATE,
		.parent = CLOCK_312_5M,
		.offset = CLOCK1_OFFSET,
		.mask = BIT(30),
	},
	[CLOCK_MAC1_ALL] = {
		.name = "MAC1-ALL",
		.type = GATE,
		.parent = CLOCK_250M,
		.offset = CLOCK1_OFFSET,
		.mask = BIT(31),
	},
};
#define CLOCK_COUNT	ARRAY_SIZE(clock_init)

static const struct reset_init reset_init[] = {
	[RESET_I2C] = {
		.offset = RESET0_OFFSET,
		.mask = BIT(12),
	},
	[RESET_PCIE] = {
		.offset = RESET0_OFFSET,
		.mask = BIT(9),
	},
	[RESET_MSIGEN] = {
		.offset = RESET0_OFFSET,
		.mask = BIT(18),
	},

	[RESET_MAC0_MAC] = {
		.offset = RESET0_OFFSET,
		.mask = BIT(7),
	},
	[RESET_MAC0_PMA] = {
		.offset = RESET0_OFFSET,
		.mask = BIT(30),
	},
	[RESET_MAC0_XPCS] = {
		.offset = RESET0_OFFSET,
		.mask = BIT(31),
	},

	[RESET_MAC1_MAC] = {
		.offset = RESET1_OFFSET,
		.mask = BIT(7),
	},
	[RESET_MAC1_PMA] = {
		.offset = RESET1_OFFSET,
		.mask = BIT(30),
	},
	[RESET_MAC1_XPCS] = {
		.offset = RESET1_OFFSET,
		.mask = BIT(31),
	},
};
#define RESET_COUNT	ARRAY_SIZE(reset_init)

/* Parent is the input oscillator running at 25 MHz; PLL runs at 1250 MHz */
static struct clk_hw *pll_register(struct device *dev, const char *name,
				   const struct clock_init *init)
{
	return devm_clk_hw_register_fixed_factor_index(dev, name, 0, 0,
						       init->mult, 1);
}

/* The PLL is the parent of all fixed clocks */
static struct clk_hw *fixed_register(struct device *dev, const char *name,
				     const struct clock_init *init)
{
	struct tc9564_clock *tc9564_clock = dev_get_drvdata(dev);
	u32 numerator = init->numerator ? : 1;
	struct clk_hw *pll_hw;

	pll_hw = tc9564_clock->clk_data->hws[CLOCK_PLL];

	return devm_clk_hw_register_fixed_factor_parent_hw(dev, name, pll_hw,
							   0, numerator,
							   init->denominator);
}

static const struct gate_clock *hw_to_gate_clock(struct clk_hw *hw)
{
	return container_of_const(hw, struct gate_clock, hw);
}

static int gate_clk_manage(struct clk_hw *hw, bool enable)
{
	struct tc9564_clock *tc9564_clock = dev_get_drvdata(clk_hw_get_dev(hw));
	const struct gate_clock *clock = hw_to_gate_clock(hw);
	u32 mask = clock->init->mask;
	void __iomem *ioaddr;
	u32 val;

	ioaddr = tc9564_clock->ioaddr + clock->init->offset;

	val = readl(ioaddr);
	if (enable)
		val |= mask;
	else
		val &= ~mask;
	writel(val, ioaddr);

	return 0;
}

static int gate_clk_enable(struct clk_hw *hw)
{
	return gate_clk_manage(hw, true);
}

static void gate_clk_disable(struct clk_hw *hw)
{
	(void)gate_clk_manage(hw, false);
}

static int gate_clk_is_enabled(struct clk_hw *hw)
{
	struct tc9564_clock *tc9564_clock = dev_get_drvdata(clk_hw_get_dev(hw));
	const struct gate_clock *clock = hw_to_gate_clock(hw);
	void __iomem *ioaddr;

	ioaddr = tc9564_clock->ioaddr + clock->init->offset;

	return readl(ioaddr) & clock->init->mask ? 1 : 0;
}

static const struct clk_ops gate_clk_ops = {
	.enable = gate_clk_enable,
	.disable = gate_clk_disable,
	.is_enabled = gate_clk_is_enabled,
};

static struct clk_hw *gate_register(struct device *dev, const char *name,
				    const struct clock_init *init)
{
	struct tc9564_clock *tc9564_clock = dev_get_drvdata(dev);
	struct clk_init_data clk_init = { };
	const struct clk_hw *parent_hw;
	struct gate_clock *clock;
	int ret;

	clock = devm_kzalloc_obj(dev, *clock);
	if (!clock)
		return ERR_PTR(-ENOMEM);

	parent_hw = tc9564_clock->clk_data->hws[init->parent];

	clk_init.name = name;
	clk_init.ops = &gate_clk_ops;
	clk_init.parent_hws = &parent_hw;
	clk_init.num_parents = 1;
	if (init->type == CRITICAL_GATE)
		clk_init.flags = CLK_IS_CRITICAL;

	clock->hw.init = &clk_init;
	clock->init = init;

	ret = devm_clk_hw_register(dev, &clock->hw);
	if (ret)
		return ERR_PTR(ret);

	return &clock->hw;
}

/* Warn on requests to assert or deassert critical resets */
static bool reset_is_critical(unsigned long id)
{
	return WARN_ON(id == RESET_I2C) || WARN_ON(id == RESET_PCIE);
}

static int reset_manage(struct reset_controller_dev *rcdev,
			unsigned long id, bool assert)
{
	struct tc9564_clock *tc9564_clock = dev_get_drvdata(rcdev->dev);
	const struct reset_init *reset = &reset_init[id];
	u32 mask = reset->mask;
	void __iomem *ioaddr;
	u32 val;

	if (reset_is_critical(id))
		return 0;		/* Just ignore the request */

	ioaddr = tc9564_clock->ioaddr + reset->offset;

	val = readl(ioaddr);
	if (assert)
		val |= mask;
	else
		val &= ~mask;
	writel(val, ioaddr);

	return 0;
}

static int reset_assert(struct reset_controller_dev *rcdev, unsigned long id)
{
	return reset_manage(rcdev, id, true);
}

static int reset_deassert(struct reset_controller_dev *rcdev, unsigned long id)
{
	return reset_manage(rcdev, id, false);
}

static int reset_status(struct reset_controller_dev *rcdev, unsigned long id)
{
	struct tc9564_clock *tc9564_clock = dev_get_drvdata(rcdev->dev);
	const struct reset_init *reset = &reset_init[id];
	void __iomem *ioaddr;

	ioaddr = tc9564_clock->ioaddr + reset->offset;

	return readl(ioaddr) & reset->mask ? 1 : 0;
}

static const struct reset_control_ops reset_control_ops = {
	.assert = reset_assert,
	.deassert = reset_deassert,
	.status = reset_status,
};

static int tc9564_clk_probe(struct platform_device *pdev)
{
	struct clk_hw_onecell_data *clk_data;
	struct reset_controller_dev *rcdev;
	struct tc9564_clock *tc9564_clock;
	struct device *dev = &pdev->dev;
	struct device_node *np;
	int ret;

	np = dev_of_node(dev);
	if (!np)
		return dev_err_probe(dev, -EINVAL, "no devicetree node\n");

	tc9564_clock = devm_kzalloc_obj(dev, *tc9564_clock);
	if (!tc9564_clock)
		return -ENOMEM;

	tc9564_clock->ioaddr = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(tc9564_clock->ioaddr))
		return dev_err_probe(dev, PTR_ERR(tc9564_clock->ioaddr),
				     "failed to map registers\n");

	clk_data = devm_kzalloc_flex(dev, *tc9564_clock->clk_data, hws,
				     CLOCK_COUNT);
	if (!clk_data)
		return -ENOMEM;
	clk_data->num = CLOCK_COUNT;

	tc9564_clock->clk_data = clk_data;

	/* Record the driver data pointer before we register anything */
	dev_set_drvdata(dev, tc9564_clock);

	/* Initialize all the clocks, then register the provider */
	for (u32 i = 0; i < clk_data->num; i++) {
		const struct clock_init *init = &clock_init[i];
		struct clk_hw *hw;
		char *name;

		name = kasprintf(GFP_KERNEL, "%s-%s", dev_name(dev), init->name);
		if (!name)
			return -ENOMEM;

		if (init->type == PLL)
			hw = pll_register(dev, name, init);
		else if (init->type == FIXED)
			hw = fixed_register(dev, name, init);
		else
			hw = gate_register(dev, name, init);
		kfree(name);

		if (IS_ERR(hw))
			return dev_err_probe(dev, PTR_ERR(hw),
					     "failed to register %s\n",
					     init->name);
		clk_data->hws[i] = hw;
	}

	ret = devm_of_clk_add_hw_provider(dev, of_clk_hw_onecell_get, clk_data);
	if (ret)
		return dev_err_probe(dev, ret, "failed to add clock provider\n");

	/* Set up and register the reset controller */
	rcdev = &tc9564_clock->rcdev;
	rcdev->ops = &reset_control_ops;
	rcdev->owner = THIS_MODULE;
	rcdev->dev = dev;
	rcdev->of_node = np;
	rcdev->nr_resets = RESET_COUNT;

	ret = devm_reset_controller_register(dev, rcdev);
	if (ret)
		return dev_err_probe(dev, ret,
				     "failed to register reset controller\n");

	return 0;
}

static const struct of_device_id tc9564_clock_match[] = {
	{ .compatible = "toshiba,tc9564-clock", },
	{ }
};
MODULE_DEVICE_TABLE(of, tc9564_clock_match);

static struct platform_driver tc9564_clk_driver = {
	.probe = tc9564_clk_probe,
	.driver = {
		.name = KBUILD_MODNAME,
		.of_match_table = tc9564_clock_match,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(tc9564_clk_driver);

MODULE_DESCRIPTION("Toshiba TC9564 Clock Driver");
MODULE_LICENSE("GPL");
