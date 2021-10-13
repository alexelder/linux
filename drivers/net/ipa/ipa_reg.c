// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2019-2020 Linaro Ltd.
 */

#include <linux/io.h>

#include "ipa.h"
#include "ipa_reg.h"
#include "gsi_reg.h"

void ipa_reg_dump(struct ipa *ipa)
{
	enum ipa_version version = ipa->version;
	struct device *dev = &ipa->pdev->dev;
	u32 enabled;
	u32 offset;

	/* Channel ring read and write pointers for each active AP endpoint */
	enabled = ipa->enabled;
	while (enabled) {
		u32 endpoint_id = __ffs(enabled);
		u32 channel_id;

		enabled ^= BIT(endpoint_id);

		channel_id = ipa->endpoint[endpoint_id].channel_id;
		offset = GSI_CH_C_CNTXT_4_OFFSET(channel_id);
		dev_err(dev, "ERROR: AP GSI CHANNEL %u RP = 0x%08x\n",
			ioread32(ipa->gsi.virt + offset));
		offset = GSI_CH_C_CNTXT_6_OFFSET(channel_id);
		dev_err(dev, "ERROR: AP GSI CHANNEL %u WP = 0x%08x\n",
			ioread32(ipa->gsi.virt + offset));
	}

	offset = ipa_reg_state_offset(version);
	dev_err(dev, "ERROR: IPA STATE = 0x%08x\n",
		ioread32(ipa->reg_virt + offset));
	offset = ipa_reg_state_rx_active_offset(version);
	dev_err(dev, "ERROR: IPA RX_ACTIVE = 0x%08x\n",
		ioread32(ipa->reg_virt + offset));

	if (version < IPA_VERSION_4_0)
		return;

	dev_err(dev, "ERROR: IPA STATE_TX0 = 0x%08x\n",
		ioread32(ipa->reg_virt + IPA_REG_STATE_TX0_OFFSET));
	dev_err(dev, "ERROR: IPA STATE_TX1 = 0x%08x\n",
		ioread32(ipa->reg_virt + IPA_REG_STATE_TX1_OFFSET));
}

int ipa_reg_init(struct ipa *ipa)
{
	struct device *dev = &ipa->pdev->dev;
	struct resource *res;

	/* Setup IPA register memory  */
	res = platform_get_resource_byname(ipa->pdev, IORESOURCE_MEM,
					   "ipa-reg");
	if (!res) {
		dev_err(dev, "DT error getting \"ipa-reg\" memory property\n");
		return -ENODEV;
	}

	ipa->reg_virt = ioremap(res->start, resource_size(res));
	if (!ipa->reg_virt) {
		dev_err(dev, "unable to remap \"ipa-reg\" memory\n");
		return -ENOMEM;
	}
	ipa->reg_addr = res->start;

	return 0;
}

void ipa_reg_exit(struct ipa *ipa)
{
	iounmap(ipa->reg_virt);
}
