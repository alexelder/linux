/* SPDX-License-Identifier: GPL-2.0 */

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2019-2020 Linaro Ltd.
 */
#ifndef _IPA_GSI_TRANS_H_
#define _IPA_GSI_TRANS_H_

#include <linux/types.h>

struct gsi;
struct gsi_trans;
struct ipa_gsi_endpoint_data;

/**
 * ipa_gsi_trans_complete() - GSI transaction completion callback
 * @trans:	Transaction that has completed
 *
 * This called from the GSI layer to notify the IPA layer that a
 * transaction has completed.
 */
void ipa_gsi_trans_complete(struct gsi_trans *trans);

/**
 * ipa_gsi_trans_release() - GSI transaction release callback
 * @trans:	Transaction whose resources should be freed
 *
 * This called from the GSI layer to notify the IPA layer that a
 * transaction is about to be freed, so any resources associated
 * with it should be released.
 */
void ipa_gsi_trans_release(struct gsi_trans *trans);

/* ipa_gsi_endpoint_data_empty() - Empty endpoint config data test
 * @data:	endpoint configuration data
 *
 * Determines whether an endpoint configuration data entry is empty,
 * meaning it contains no valid configuration information and should
 * be ignored.
 *
 * Return:	true if empty; false otherwise
 */
bool ipa_gsi_endpoint_data_empty(const struct ipa_gsi_endpoint_data *data);

#endif /* _IPA_GSI_TRANS_H_ */
