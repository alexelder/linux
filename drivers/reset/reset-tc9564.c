// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2026 by RISCstar Solutions Corporation.  All rights reserved.
 */

#include <linux/bits.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/reset-controller.h>

#include <dt-bindings/reset/toshiba,tc9564.h>

#define RST_CTRL0_OFFSET	0x1008
#define RST_CTRL1_OFFSET	0x1010

struct tc9564_reset {
	u32 offset;		/* RST_CTRL0_OFFSET or RST_CTRL1_OFFSET */
	u32 mask;		/* Zero means undefined reset */
};

struct tc9564_resets {
	struct regmap *regmap;
	struct reset_controller_dev rcdev;
};

#define TC9564_RESET_INIT0(_name, _bit)	__TC9564_RESET_INIT(_name, 0, _bit)
#define TC9564_RESET_INIT1(_name, _bit)	__TC9564_RESET_INIT(_name, 1, _bit)

#define __TC9564_RESET_INIT(_name, _reg, _bit)		\
	[RESET_##_name] = {				\
		.offset	= RST_CTRL ## _reg ## _OFFSET,	\
		.mask = BIT(_bit),			\
	}

/*
 * The PCIe and I2C resets are controllable, but we depend on PCIe
 * and that relies on I2C, so we don't allow them to be asserted.
 */
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

static const struct tc9564_resets *
rcdev_to_tc9564_resets(struct reset_controller_dev *rcdev)
{
	return container_of_const(rcdev, struct tc9564_resets, rcdev);
}

static void tc9564_reset_manage(struct reset_controller_dev *rcdev,
				unsigned long id, bool assert)
{
	const struct tc9564_resets *resets = rcdev_to_tc9564_resets(rcdev);
	const struct tc9564_reset *reset = &tc9564_reset[id];
	u32 mask = reset->mask;

	regmap_update_bits(resets->regmap, reset->offset, mask,
			  assert ? mask : 0);
}

static int tc9564_reset_assert(struct reset_controller_dev *rcdev,
			       unsigned long id)
{
	tc9564_reset_manage(rcdev, id, true);

	return 0;
}

static int tc9564_reset_deassert(struct reset_controller_dev *rcdev,
				 unsigned long id)
{
	tc9564_reset_manage(rcdev, id, false);

	return 0;
}

static int tc9564_reset_status(struct reset_controller_dev *rcdev,
			       unsigned long id)
{
	const struct tc9564_resets *resets = rcdev_to_tc9564_resets(rcdev);
	const struct tc9564_reset *reset = &tc9564_reset[id];
	u32 val;

	regmap_read(resets->regmap, reset->offset, &val);

	return val & reset->mask ? 1 : 0;
}

static const struct reset_control_ops tc9564_reset_control_ops = {
	.assert = tc9564_reset_assert,
	.deassert = tc9564_reset_deassert,
	.status = tc9564_reset_status,
};

static int tc9564_reset_probe(struct platform_device *pdev)
{
	struct reset_controller_dev *rcdev;
	struct device *dev = &pdev->dev;
	struct device_node *parent_np;
	struct tc9564_resets *resets;
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

	resets = devm_kzalloc(dev, sizeof(*resets), GFP_KERNEL);
	if (!resets)
		return -ENOMEM;
	resets->regmap = regmap;

	rcdev = &resets->rcdev;
	rcdev->ops = &tc9564_reset_control_ops;
	rcdev->owner = THIS_MODULE;
	rcdev->dev = dev;
	rcdev->of_node = parent_np;
	rcdev->nr_resets = TC9564_RESET_COUNT;

	ret = devm_reset_controller_register(dev, rcdev);
	if (ret)
		return dev_err_probe(dev, ret,
				     "failed to register reset controller\n");

	return 0;
}

static struct platform_driver tc9564_reset_driver = {
	.probe = tc9564_reset_probe,
	.driver = {
		.name = "toshiba-tc9564-reset",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(tc9564_reset_driver);

MODULE_DESCRIPTION("Toshiba TC9564 Reset Driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:toshiba-tc9564-reset");
