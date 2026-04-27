// SPDX-License-Identifier: GPL-2.0

#include <linux/clk.h>
#include <linux/irqdomain.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/reset.h>

/**
 * struct tc956x_msigen - Context for MSIGEN IRQ domain
 * @ioaddr:		Pointer to mapped MSIGEN memory
 * @irq:		IRQ number for MSIGEN
 */
struct tc956x_msigen {
	void __iomem *ioaddr;
	unsigned int irq;
};

#define HWIRQ_COUNT			25

#define MSI_OUT_EN_OFFSET		0x0000
#define MSI_MASK_CLR_OFFSET		0x000c
#define MSI_MASK_VALUE			BIT(0)
#define MSI_INT_STS_OFFSET		0x0010

static void tc956x_msigen_irq_handler(struct irq_desc *desc)
{
	struct irq_domain *irq_domain = irq_desc_get_handler_data(desc);
	struct irq_chip *chip = irq_desc_get_chip(desc);
	struct irq_chip_generic *gc;
	unsigned long status;
	unsigned int hwirq;

	gc = irq_get_domain_generic_chip(irq_domain, 0);

	chained_irq_enter(chip, desc);

	status = irq_reg_readl(gc, MSI_INT_STS_OFFSET);
	for_each_set_bit(hwirq, &status, HWIRQ_COUNT)
		generic_handle_domain_irq(irq_domain, hwirq);

	/*
	 * Clear the MSI flag. Most interrupts within TC956X are level-high
	 * type. If any interrupts are still asserted then clearing this flag
	 * will cause the (edge-triggered) MSI to be regenerated.
	 */
	irq_reg_writel(gc, MSI_MASK_VALUE, MSI_MASK_CLR_OFFSET);

	chained_irq_exit(chip, desc);
}

static int tc956x_msigen_irq_chip_init(struct irq_chip_generic *gc)
{
	struct tc956x_msigen *msigen = gc->domain->host_data;

	gc->reg_base = msigen->ioaddr;
	gc->chip_types[0].regs.mask = MSI_OUT_EN_OFFSET;
	gc->chip_types[0].chip.irq_mask = irq_gc_mask_clr_bit;
	gc->chip_types[0].chip.irq_unmask = irq_gc_mask_set_bit;

	/* Disable all interrupts */
	irq_reg_writel(gc, 0, MSI_OUT_EN_OFFSET);
	return 0;
}

static void tc956x_msigen_irq_chip_exit(struct irq_chip_generic *gc)
{
	irq_reg_writel(gc, 0, MSI_OUT_EN_OFFSET);
}

static int tc956x_msigen_irq_domain_init(struct irq_domain *irq_domain)
{
	struct tc956x_msigen *msigen = irq_domain->host_data;

	irq_set_chained_handler_and_data(msigen->irq, tc956x_msigen_irq_handler,
					 irq_domain);
	return 0;
}

static void tc956x_msigen_irq_domain_exit(struct irq_domain *irq_domain)
{
	struct tc956x_msigen *msigen = irq_domain->host_data;

	irq_set_chained_handler_and_data(msigen->irq, NULL, NULL);
}

static struct pci_dev *tc956x_msigen_find_pci_dev(struct device *dev)
{
	struct device *ancestor;

	for (ancestor = dev->parent; ancestor; ancestor = ancestor->parent) {
		if (dev_is_pci(ancestor)) {
			if (!dev_is_pf(ancestor))
				return ERR_PTR(-EINVAL);

			return to_pci_dev(ancestor);
		}
	}

	return ERR_PTR(-ENXIO);
}

static void tc956x_msigen_free_irq_vectors(void *pci_dev)
{
	pci_free_irq_vectors(pci_dev);
}

static int tc956x_msigen_probe(struct platform_device *pdev)
{
	struct irq_domain_chip_generic_info dgc_info;
	struct device *dev = &pdev->dev;
	struct irq_domain *irq_domain;
	struct tc956x_msigen *msigen;
	struct irq_domain_info info;
	struct reset_control *reset;
	struct pci_dev *pci_dev;
	struct clk *clk;
	int ret;

	msigen = devm_kzalloc(dev, sizeof(*msigen), GFP_KERNEL);
	if (!msigen)
		return -ENOMEM;

	msigen->ioaddr = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(msigen->ioaddr))
		return dev_err_probe(dev, PTR_ERR(msigen->ioaddr),
				     "failed to map MSIGEN registers\n");

	clk = devm_clk_get_enabled(dev, "toshiba,tc9564-msigen-clock");
	if (IS_ERR(clk))
		return dev_err_probe(dev, PTR_ERR(clk), "failed to get/enable MSIGEN clock\n");

	reset = devm_reset_control_get_shared_deasserted(dev, "toshiba,tc9564-msigen-reset");
	if (IS_ERR(reset))
		return dev_err_probe(dev, PTR_ERR(reset), "failed to get MSIGEN reset\n");

	pci_dev = tc956x_msigen_find_pci_dev(dev);
	if (IS_ERR(pci_dev))
		return dev_err_probe(dev, PTR_ERR(pci_dev), "cannot find PCI dev\n");

	ret = pci_alloc_irq_vectors(pci_dev, 1, 1, PCI_IRQ_MSI);
	if (ret < 0)
		return dev_err_probe(dev, ret, "failed to alloc irq vector\n");
	ret = devm_add_action_or_reset(dev, tc956x_msigen_free_irq_vectors, pci_dev);
	if (ret)
		return ret;

	msigen->irq = pci_irq_vector(pci_dev, 0);

	dgc_info.name = "tc956x-msigen";
	dgc_info.handler = handle_level_irq;
	dgc_info.irqs_per_chip = HWIRQ_COUNT;
	dgc_info.num_ct = 1;
	dgc_info.init = tc956x_msigen_irq_chip_init;
	dgc_info.exit = tc956x_msigen_irq_chip_exit;

	info.fwnode = of_fwnode_handle(dev->of_node);
	info.domain_flags = IRQ_DOMAIN_FLAG_DESTROY_GC;
	info.size = HWIRQ_COUNT;
	info.hwirq_max = HWIRQ_COUNT;
	info.ops = &irq_generic_chip_ops;
	info.host_data = msigen;
	info.dgc_info = &dgc_info;
	info.init = tc956x_msigen_irq_domain_init;
	info.exit = tc956x_msigen_irq_domain_exit;

	irq_domain = devm_irq_domain_instantiate(dev, &info);
	if (IS_ERR(irq_domain))
		return dev_err_probe(dev, PTR_ERR(irq_domain),
				     "failed to instantiate IRQ domain\n");

	return 0;
}

static const struct of_device_id tc956x_msigen_of_match[] = {
	{ .compatible = "toshiba,tc9564-msigen" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, tc956x_msigen_of_match);

static struct platform_driver tc956x_msigen_driver = {
	.probe = tc956x_msigen_probe,
	.driver = {
		.name = "tc956x-msigen",
		.of_match_table = tc956x_msigen_of_match,
	},
};
module_platform_driver(tc956x_msigen_driver);

MODULE_AUTHOR("Daniel Thompson <danielt@kernel.org>");
MODULE_DESCRIPTION("TC956X MSIGEN IRQ controller driver");
MODULE_LICENSE("GPL");
