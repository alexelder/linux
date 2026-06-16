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
 * The XGMACs use a 64 MB (2^36) internal address space for accessing
 * PCI resources.  An address translation unit in the TC956X translates
 * between AXI bus addresses received and the internal PCI address space.
 * Up to four ranges can be programed for translation; currently only one
 * is used.
 */

#include <linux/device.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#if 0
#include <linux/bitfield.h>
#include <linux/compiler_types.h>
#include <linux/device.h>
#include <linux/dev_printk.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/pci.h>
#include <linux/property.h>
#include <linux/regmap.h>
#include <linux/types.h>
#endif

#include <soc/toshiba/tc956x-dwmac.h>

#define DRIVER_NAME			"tc956x_config"

/*
 * The TAMAP function has four AXI translation tables each with eight
 * 4-byte registers.  The Ethernet MAC accesses PCI resources through
 * addressses based at TC956X_SLV00_SRC_ADDR, and the first translation
 * table converts those to PCIe address space starting based at 0x0.
 * We don't use the other three available TAMAC tables.
 */
#define ATR_AXI4_SLV0_OFFSET		0x0800
#define AXI4_TABLE_ENTRY_COUNT		4
#define AXI4_ENTRY_BASE(id)		((id) * AXI4_TABLE_STRIDE)
#define AXI4_TABLE_STRIDE               0x20

/* Address translation space parameters used for entry 0 */
#define SLV00_ATR_SIZE			35	/* 2^36 (64 gigabytes) */
/* TC956X_SLV00_SRC_ADDR is the source address, defined in the common header */
#define SLV00_TRSL_ADDR			0x0000000000000000ULL

/* Translation entry registers, fields, and values used */
#define SRC_ADDR_LO_OFFSET		0x0000
#define ATR_IMPL			BIT(0)		/* 1 = enabled */
#define ATR_SIZE_MASK			GENMASK(6, 1)	/* size 2^(ATR + 1) */
#define SRC_ADDR_HI_OFFSET		0x0004
#define TRSL_ADDR_LO_OFFSET		0x0008
#define TRSL_ADDR_HI_OFFSET		0x000c
#define TRSL_PARAM_OFFSET		0x0010
#define TRSL_ID_MASK			GENMASK(3, 0)
#define TRSL_ID_PCIE_TX_RX		0
#define TRSL_PARAM_MASK			GENMASK(27, 16)

/*
 * struct tc956x_config - Common configuration information
 * @base:		Mapped configuration memory region
 */
struct tc956x_config {
	void __iomem *base;
};

/**
 * tc956x_config_tamac() - Configure the table address map registers
 * @config:	Pointer to the TC956X config structure
 *
 * Populate the registers used to translate AXI bus accesses to PCI TLPs.
 * TC956X_SLV00_SRC_ADDR defines the base address of the AXI address range.
 * AXI addresses are translated to the PCIe address range, whose base address
 * is defined by SLV00_TRSL_ADDR (which is 0x0).
 */
static void tc956x_config_tamac(struct tc956x_config *config)
{
	void __iomem *table_base = config->base + ATR_AXI4_SLV0_OFFSET;
	void __iomem *entry_base;
	u32 trsl_param_val;
	u32 atr_size_val;
	u32 val;
	u32 i;

	/*
	 * The lower bits of the source address must be zero, because the
	 * SRC_ADDR_LO register encodes the address translation space size
	 * and "implmented" bit there.  The size field defines the size of
	 * the translation space (2^(ATR_SIZE + 1)).  The minimum size is
	 * 4096 bytes, so ATR_SIZE value must be 11 or more.
	 */
	BUILD_BUG_ON(!!u32_get_bits(lower_32_bits(TC956X_SLV00_SRC_ADDR),
						  ATR_SIZE_MASK));
	BUILD_BUG_ON(TC956X_SLV00_SRC_ADDR & ATR_IMPL);
	BUILD_BUG_ON(SLV00_ATR_SIZE < 11);

	/*
	 * We only use the first AXI4 slave TAMAC table:
	 *	EDMA address region:	0x10 0000 0000 - 0x1f ffff ffff
	 *	is translated to:	0x00 0000 0000 - 0x0f ffff ffff
	 */
	entry_base = table_base + AXI4_ENTRY_BASE(0);

	atr_size_val = u32_encode_bits(SLV00_ATR_SIZE, ATR_SIZE_MASK);
	atr_size_val |= ATR_IMPL;
	val = lower_32_bits(TC956X_SLV00_SRC_ADDR) | atr_size_val;
	writel(val, entry_base + SRC_ADDR_LO_OFFSET);

	val = upper_32_bits(TC956X_SLV00_SRC_ADDR);
	writel(val, entry_base + SRC_ADDR_HI_OFFSET);

	val = lower_32_bits(SLV00_TRSL_ADDR);
	writel(val, entry_base + TRSL_ADDR_LO_OFFSET);

	val = upper_32_bits(SLV00_TRSL_ADDR);
	writel(val, entry_base + TRSL_ADDR_HI_OFFSET);

	/* This TRSL_PARAM value is assigned for all four TAMAC tables */
	trsl_param_val = u32_encode_bits(TRSL_ID_PCIE_TX_RX, TRSL_ID_MASK);

	writel(trsl_param_val, entry_base + TRSL_PARAM_OFFSET);

	/* Set all other unused entries to default values (no translation) */
	for (i = 1; i < AXI4_TABLE_ENTRY_COUNT; i++) {
		entry_base = table_base + AXI4_ENTRY_BASE(i);

		writel(0x0, entry_base + SRC_ADDR_LO_OFFSET);
		writel(0x0, entry_base + SRC_ADDR_HI_OFFSET);
		writel(0x0, entry_base + TRSL_ADDR_LO_OFFSET);
		writel(0x0, entry_base + TRSL_ADDR_HI_OFFSET);
		writel(trsl_param_val, entry_base + TRSL_PARAM_OFFSET);
	}
}

static int tc956x_config_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct tc956x_config *config;
	resource_size_t size;
	void __iomem *base;

	if (!dev_of_node(dev))
		return dev_err_probe(dev, -EINVAL, "no devicetree node\n");

	config = devm_kzalloc(dev, sizeof(*config), GFP_KERNEL);
	if (!config)
		return -ENOMEM;

	config->base = devm_of_iomap(dev, dev->of_node, 0, &size);
	if (IS_ERR(base) || !size)
		return dev_err_probe(dev, PTR_ERR(base), "mapping error\n");

	/* Do the initial configuraiton */

	tc956x_config_tamac(config);

	dev->platform_data = config;

	return 0;
}

static void tc956x_config_remove(struct platform_device *pdev)
{
	/* Nothing to do at this point */
}

static int tc956x_config_suspend_noirq(struct device *dev)
{
	return 0;
}

/* We need to reconfigure address translation when we resume */
static int tc956x_config_resume_noirq(struct device *dev)
{
	tc956x_config_tamac(dev->platform_data);

	return 0;
}

static DEFINE_NOIRQ_DEV_PM_OPS(tc956x_config_pm_ops,
			       tc956x_config_suspend_noirq,
			       tc956x_config_resume_noirq);

static const struct of_device_id tc956x_config_match[] = {
	{ .compatible	= "toshiba,tc956x-config", },
	{ },
};
MODULE_DEVICE_TABLE(of, tc956x_config_match);

static struct platform_driver tc956x_config_driver = {
	.probe		= tc956x_config_probe,
	.remove		= tc956x_config_remove,
	.driver		= {
		.name		= DRIVER_NAME,
		.of_match_table	= of_match_ptr(tc956x_config_match),
		.pm		= pm_sleep_ptr(&tc956x_config_pm_ops),
	},
};

module_platform_driver(tc956x_config_driver);

MODULE_DESCRIPTION("Toshiba TC956X Configuration Driver");
MODULE_LICENSE("GPL");
