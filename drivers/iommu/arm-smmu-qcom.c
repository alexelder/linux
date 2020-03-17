// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2019, The Linux Foundation. All rights reserved.
 */

#include <linux/of_device.h>
#include <linux/qcom_scm.h>

#include "arm-smmu.h"

struct qcom_smmu {
	struct arm_smmu_device smmu;
};

static const struct arm_smmu_client_match_data qcom_adreno = {
	.direct_mapping = true,
};

static const struct arm_smmu_client_match_data qcom_mdss = {
	.direct_mapping = true,
};

static const struct arm_smmu_client_match_data qcom_mss = {
	.direct_mapping = true,
};

static const struct of_device_id qcom_smmu_client_of_match[] = {
	{ .compatible = "qcom,adreno", .data = &qcom_adreno },
	{ .compatible = "qcom,mdp4", .data = &qcom_mdss },
	{ .compatible = "qcom,mdss", .data = &qcom_mdss },
	{ .compatible = "qcom,sc7180-mdss", .data = &qcom_mdss },
	{ .compatible = "qcom,sc7180-mss-pil", .data = &qcom_mss },
	{ .compatible = "qcom,sdm845-mdss", .data = &qcom_mdss },
	{ .compatible = "qcom,sdm845-mss-pil", .data = &qcom_mss },
	{},
};

static const struct arm_smmu_client_match_data *
qcom_smmu_client_data(struct device *dev)
{
	const struct of_device_id *match =
		of_match_device(qcom_smmu_client_of_match, dev);

	return match ? match->data : NULL;
}

static int qcom_smmu_request_domain(struct device *dev)
{
	const struct arm_smmu_client_match_data *client;

	client = qcom_smmu_client_data(dev);
	if (client && client->direct_mapping)
		iommu_request_dm_for_dev(dev);

	return 0;
}

static int qcom_sdm845_smmu500_reset(struct arm_smmu_device *smmu)
{
	int ret;

	arm_mmu500_reset(smmu);

	/*
	 * To address performance degradation in non-real time clients,
	 * such as USB and UFS, turn off wait-for-safe on sdm845 based boards,
	 * such as MTP and db845, whose firmwares implement secure monitor
	 * call handlers to turn on/off the wait-for-safe logic.
	 */
	ret = qcom_scm_qsmmu500_wait_safe_toggle(0);
	if (ret)
		dev_warn(smmu->dev, "Failed to turn off SAFE logic\n");

	return ret;
}

static const struct arm_smmu_impl qcom_smmu_impl = {
	.req_domain = qcom_smmu_request_domain,
	.reset = qcom_sdm845_smmu500_reset,
};

struct arm_smmu_device *qcom_smmu_impl_init(struct arm_smmu_device *smmu)
{
	struct qcom_smmu *qsmmu;

	qsmmu = devm_kzalloc(smmu->dev, sizeof(*qsmmu), GFP_KERNEL);
	if (!qsmmu)
		return ERR_PTR(-ENOMEM);

	qsmmu->smmu = *smmu;

	qsmmu->smmu.impl = &qcom_smmu_impl;
	devm_kfree(smmu->dev, smmu);

	return &qsmmu->smmu;
}
