/* SPDX-License-Identifier: GPL-2.0 */

/* Copyright (C) 2022 Linaro Ltd.  */

#ifndef _IPA_MONITOR_H_
#define _IPA_MONITOR_H_

#include <linux/types.h>

struct page;

struct ipa;
struct ipa_endpoint;

int ipa_monitor_open(struct ipa *ipa);
void ipa_monitor_close(struct ipa *ipa);

void ipa_monitor_suspend(struct ipa *ipa);
void ipa_monitor_resume(struct ipa *ipa);

bool ipa_monitor_receive(struct ipa_endpoint *endpoint,
			 struct page *page, u32 len);

int ipa_monitor_init(struct ipa *ipa);
void ipa_monitor_exit(struct ipa *ipa);

#endif /* _IPA_MONITOR_H_ */
