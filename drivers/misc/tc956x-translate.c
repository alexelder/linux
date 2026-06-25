// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2026 by RISCstar Solutions Corporation.  All rights reserved.
 */

/*
 * The Toshiba TC956X implements a PCIe Gen 3 switch that connects an
 * upstream x4 port to three downstream PCIe ports--two external ones
 * and an internal one which implements an internal PCIe endpoint.  The
 * endpoint implements two PCIe functions, each having a Synopsys XGMAC
 * Ethernet interface.
 *
 * The XGMACs access the PCIe bus via an AXI bus.  The AXI bus uses
 * addresses above 64 GB (2^36), and an address translation unit
 * translates between this AXI bus space and PCIe bus space.
 */

#include <linux/device.h>
#include <linux/io.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>

#include <soc/toshiba/tc956x-dwmac.h>

#define DRIVER_NAME			"tc956x_translate"

/*
 * The bus translation function has four AXI translation table entries
 * each with eight 4-byte registers.  These entries translate between
 * an internal AXI bus address space and "external" PCIe address space.
 * The Ethernet MACs access the PCIe subsystem via this bus.  Currently
 * we only use the first translation table entry.
 */
#define ATR_AXI4_SLV0_OFFSET		0x0800
#define AXI4_TABLE_ENTRY_COUNT		4
#define AXI4_ENTRY_BASE(id)		((id) * AXI4_TABLE_STRIDE)
#define AXI4_TABLE_STRIDE               0x20

/*
 * Address translation space parameters used for entry 0.
 *
 * The size value determines the the size (2^(size+1)) of the AXI bus
 * address space, which begins at TC956X_SLV00_SRC_ADDR.  It defines a
 * mask that extracts the lower bits from the AXI space to determine
 * the bus-relative offset.  That address is added (actually, OR'd) to
 * SLV00_TRSL_ADDR to produce a PCIe bus space address.
 */
#define SLV00_ATR_SIZE			35	/* 2^36 (64 gigabytes) */
/* TC956X_SLV00_SRC_ADDR is the source address, defined in the common header */
#define SLV00_TRSL_ADDR			0x0000000000000000ULL
/* XXX Can we just *say* this address is 0? */

/* Translation entry registers, fields, and values used */
#define SRC_ADDR_LO_OFFSET		0x0000
#define ATR_IMPL			BIT(0)		/* 1 = enabled */
#define ATR_SIZE_MASK			GENMASK(6, 1)	/* 2^(SIZE+1) */
#define SRC_ADDR_HI_OFFSET		0x0004
#define TRSL_ADDR_LO_OFFSET		0x0008
#define TRSL_ADDR_HI_OFFSET		0x000c
#define TRSL_PARAM_OFFSET		0x0010
#define TRSL_ID_MASK			GENMASK(3, 0)
#define TRSL_ID_PCIE_TX_RX		0
#define TRSL_PARAM_MASK			GENMASK(27, 16)

/**
 * tc956x_translate_config() - Configure the translation unit registers
 * @regmap:	Regmap used to configure the translation table entries
 *
 * Define the translation between AXI bus accesses and PCI TLPs.
 * TC956X_SLV00_SRC_ADDR defines the base address of the AXI address
 * range.  AXI addresses are translated to the PCIe address range,
 * whose base address is defined by SLV00_TRSL_ADDR (which is 0x0).
 */
static void tc956x_translate_config(struct regmap *regmap)
{
	u32 trsl_param_val;
	u32 atr_size_val;
	u32 entry_offset;
	u32 val;
	u32 i;

	/*
	 * The lower bits of the source address must be zero, because the
	 * SRC_ADDR_LO register encodes the address translation space size
	 * and "implmented" bit there.  The size field defines the size of
	 * the translation space (2^(ATR_SIZE + 1)).  The minimum size is
	 * 4096 bytes, so ATR_SIZE value must be 11 or more.
	 */
	/* XXX Make these static asserts in place */
	BUILD_BUG_ON(!!u32_get_bits(lower_32_bits(TC956X_SLV00_SRC_ADDR),
						  ATR_SIZE_MASK));
	BUILD_BUG_ON(TC956X_SLV00_SRC_ADDR & ATR_IMPL);
	BUILD_BUG_ON(SLV00_ATR_SIZE < 11);

	/*
	 * We only use the first AXI4 slave TAMAC table:
	 *	EDMA address region:	0x10 0000 0000 - 0x1f ffff ffff
	 *	is translated to:	0x00 0000 0000 - 0x0f ffff ffff
	 */
	entry_offset = ATR_AXI4_SLV0_OFFSET + AXI4_ENTRY_BASE(0);

	atr_size_val = u32_encode_bits(SLV00_ATR_SIZE, ATR_SIZE_MASK);
	atr_size_val |= ATR_IMPL;
	val = lower_32_bits(TC956X_SLV00_SRC_ADDR) | atr_size_val;
	/* No errors returned for MMIO regmap */
	regmap_write(regmap, entry_offset + SRC_ADDR_LO_OFFSET, val);

	val = upper_32_bits(TC956X_SLV00_SRC_ADDR);
	regmap_write(regmap, entry_offset + SRC_ADDR_HI_OFFSET, val);

	val = lower_32_bits(SLV00_TRSL_ADDR);
	regmap_write(regmap, entry_offset + TRSL_ADDR_LO_OFFSET, val);

	val = upper_32_bits(SLV00_TRSL_ADDR);
	regmap_write(regmap, entry_offset + TRSL_ADDR_HI_OFFSET, val);

	/* This TRSL_PARAM value is assigned for all four TAMAC tables */
	trsl_param_val = u32_encode_bits(TRSL_ID_PCIE_TX_RX, TRSL_ID_MASK);
	regmap_write(regmap, entry_offset + TRSL_PARAM_OFFSET, trsl_param_val);

	/* Set all other unused entries to default values (no translation) */
	for (i = 1; i < AXI4_TABLE_ENTRY_COUNT; i++) {
		entry_offset = ATR_AXI4_SLV0_OFFSET + AXI4_ENTRY_BASE(i);

		regmap_write(regmap, entry_offset + SRC_ADDR_LO_OFFSET, 0);
		regmap_write(regmap, entry_offset + SRC_ADDR_HI_OFFSET, 0);
		regmap_write(regmap, entry_offset + TRSL_ADDR_LO_OFFSET, 0);
		regmap_write(regmap, entry_offset + TRSL_ADDR_HI_OFFSET, 0);
		regmap_write(regmap, entry_offset + TRSL_PARAM_OFFSET,
			     trsl_param_val);
	}
}

static int tc956x_translate_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np;
	struct regmap *regmap;

	dev_info(dev, " === %s starting\n", __func__);

	np = dev_of_node(dev);
	if (!np)
		return dev_err_probe(dev, -EINVAL, "no devicetree node\n");
	regmap = syscon_regmap_lookup_by_phandle(np, "toshiba,bridge-syscon");
	if (IS_ERR(regmap))
		return dev_err_probe(dev, PTR_ERR(regmap),
				    "failed to get bridge regmap\n");

	dev->platform_data = regmap;

	/* Do the initial configuraiton */

	tc956x_translate_config(regmap);

	dev_info(dev, " === %s successful\n", __func__);

	return 0;
}

static void tc956x_translate_remove(struct platform_device *pdev)
{
	/* Nothing to do at this point */
}

static int tc956x_translate_suspend_noirq(struct device *dev)
{
	return 0;
}

/* We need to reconfigure address translation when we resume */
static int tc956x_translate_resume_noirq(struct device *dev)
{
	struct regmap *regmap = dev->platform_data;

	tc956x_translate_config(regmap);

	return 0;
}

static DEFINE_NOIRQ_DEV_PM_OPS(tc956x_translate_pm_ops,
			       tc956x_translate_suspend_noirq,
			       tc956x_translate_resume_noirq);

static const struct of_device_id tc956x_translate_match[] = {
	{ .compatible	= "toshiba,tc956x-translate", },
	{ },
};
MODULE_DEVICE_TABLE(of, tc956x_translate_match);

static struct platform_driver tc956x_translate_driver = {
	.probe		= tc956x_translate_probe,
	.remove		= tc956x_translate_remove,
	.driver		= {
		.name		= DRIVER_NAME,
		.of_match_table	= of_match_ptr(tc956x_translate_match),
		.pm		= pm_sleep_ptr(&tc956x_translate_pm_ops),
	},
};

module_platform_driver(tc956x_translate_driver);

MODULE_DESCRIPTION("Toshiba TC956X Configuration Driver");
MODULE_LICENSE("GPL");
