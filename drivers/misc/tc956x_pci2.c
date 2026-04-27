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
 * The TC956X implements other functionality, including an embedded
 * MCU, a UART, a GPIO controller, internal resets and clocks, and
 * interrupt handling.  These features are separate from (and in some
 * cases used by) both Ethernet XGMACs.  Each Ethernet MAC must be
 * attached to a working PHY for it to be functional, and for this
 * reason either of them (or both!) might not be usable/used.
 *
 * This PCI driver binds to the Toshiba TC956X (physical) PCI function
 * (VID 0x1179, DID 0x0220).  There are two of these present on the
 * TC956X SoC.
 */

#include <linux/device.h>
#include <linux/irqdomain.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/pci.h>

#define DRIVER_NAME "tc956x_pci2"

static int
tc956x_function_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct device_node *np;
	int ret;

	/* Despite being a PCI device, we require devicetree */
	np = dev_of_node(dev);
	if (!np)
		return dev_err_probe(dev, -EINVAL, "no devicetree node\n");

	ret = pcim_enable_device(pdev);
	if (ret)
		return ret;

	pci_set_master(pdev);

	/* Not-embedded devices would need to apply a DT overlay here! */

	ret = of_platform_default_populate(np, NULL, dev);
	if (ret) {
		pci_clear_master(pdev);
		return dev_err_probe(dev, ret, "failed to populate platform bus\n");
	}

	return 0;
}

static void tc956x_function_remove(struct pci_dev *pdev)
{
	of_platform_depopulate(&pdev->dev);
	pci_clear_master(pdev);
}

static const struct pci_device_id tc956x_function_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_TOSHIBA, 0x0220), },
	{ },
};
MODULE_DEVICE_TABLE(pci, tc956x_function_id_table);

static struct pci_driver tc956x_function_driver = {
	.name		= DRIVER_NAME,
	.id_table	= tc956x_function_id_table,
	.probe		= tc956x_function_probe,
	.remove		= tc956x_function_remove,
	.driver		= {
		.name		= DRIVER_NAME,
		.owner		= THIS_MODULE,
	},
};

module_pci_driver(tc956x_function_driver);

MODULE_DESCRIPTION("Toshiba TC956X PCIe Embedded Function Driver");
MODULE_LICENSE("GPL");
