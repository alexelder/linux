// SPDX-License-Identifier: GPL-2.0-only

/*
 * Toshiba TC956x DWC Ethernet driver
 *
 * Copyright (C) 2026 by RISCstar Solutions Corporation.  All rights reserved.
 */

#include <linux/module.h>
#include <linux/of_irq.h>
#include <linux/stmmac.h>

#include "stmmac.h"
#include "stmmac_libpci.h"
#include "stmmac_platform.h"

#define DRIVER_NAME	"toshiba-tc956x-dwmac"

/* XXX TC9564? Also, this is a physical function; virtual is 0x0221 */
#define PCI_DEVICE_ID_TOSHIBA_TC956X		0x0220

struct tc956x_priv {
};

/* Based generally on stmmac_get_platform_resources() */
static int
tc956x_get_resources(struct pci_dev *pci_dev, struct stmmac_resources *res)
{
	struct device *dev = &pci_dev->dev;
	struct device_node *np;

	np = dev_of_node(dev);
	if (!np)
		return -ENODEV;

	memset(res, 0, sizeof(*res));

	/* The PCI device IRQ is the MAC IRQ */
	res->irq = pci_dev->irq;

	/* Use the MAC IRQ if a wake-up IRQ is not defined */
	res->wol_irq = of_irq_get_byname(np, "eth_wake_irq");
	if (res->wol_irq <= 0) {
		if (res->wol_irq == -EPROBE_DEFER)
			return -EPROBE_DEFER;
		res->wol_irq = res->irq;
	}

	/* The low-power idle IRQ is optional, but report if it's missing */
	res->lpi_irq = of_irq_get_byname(np, "eth_lpi");
	if (res->lpi_irq <= 0) {
		if (res->lpi_irq == -EPROBE_DEFER)
			return -EPROBE_DEFER;
		dev_info(dev, "\"eth_lpi\" IRQ not found\n");
	}

	/* The safety IRQ is optional, but report if it's missing */
	res->sfty_irq = of_irq_get_byname(np, "sfty");
	if (res->sfty_irq <= 0) {
		if (res->sfty_irq == -EPROBE_DEFER)
			return -EPROBE_DEFER;
		dev_info(dev, "\"sfty\" IRQ not found\n");
	}

	res->addr = pcim_iomap_region(pci_dev, 4, DRIVER_NAME);
	if (IS_ERR(res->addr))
		return PTR_ERR(res->addr);

	return 0;
}

static int
tc956x_pci_probe(struct pci_dev *pci_dev, const struct pci_device_id *id)
{
	struct plat_stmmacenet_data *plat;
	struct device *dev = &pci_dev->dev;
	struct stmmac_resources res;
	struct tc956x_priv *tc956x;
	int ret;

	ret = tc956x_get_resources(pci_dev, &res);
	if (ret)
		return dev_err_probe(dev, ret, "failed to get resources\n");

	plat = devm_stmmac_probe_config_dt(dev, res.mac);
	if (IS_ERR(plat))
		return dev_err_probe(dev, PTR_ERR(plat),
				     "failed devicetree lookup\n");

	plat->suspend = stmmac_pci_plat_suspend;
	plat->resume = stmmac_pci_plat_resume;

	tc956x = devm_kzalloc(dev, sizeof(*tc956x), GFP_KERNEL);
	if (!tc956x)
		return -ENOMEM;

	return -EINVAL;
//	return stmmac_dvr_probe(dev, plat, &res);
}

static void tc956x_pci_remove(struct pci_dev *pci_dev)
{
//	stmmac_dvr_remove(&pci_dev->dev);
}

static const struct pci_device_id tc956x_id_table[] = {
	{ PCI_DEVICE_DATA(TOSHIBA, TC956X, NULL), },
	{ },
};

MODULE_DEVICE_TABLE(pci, tc956x_id_table);

static struct pci_driver tc956x_pci_driver = {
	.name		= DRIVER_NAME,
	.id_table	= tc956x_id_table,
	.probe		= tc956x_pci_probe,
	.remove		= tc956x_pci_remove,
	.driver         = {
		.pm     = &stmmac_simple_pm_ops,
	},
};

module_pci_driver(tc956x_pci_driver);

MODULE_DESCRIPTION("Toshiba TC956x DWC Ethernet driver");
MODULE_LICENSE("GPL");
