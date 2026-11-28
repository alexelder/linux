/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */

/*
 * Copyright (C) 2026 by RISCstar Solutions Corporation.  All rights reserved.
 */

#ifndef __CLOCK_TOSHIBA_TC9564_H__
#define __CLOCK_TOSHIBA_TC9564_H__

/* Clock IDs */

#define TC9564_CLK_I2C		0	/* critical */
#define TC9564_CLK_PCIE		1	/* critical */
#define TC9564_CLK_MSIGEN	2

#define TC9564_CLK_MAC0_TX	3
#define TC9564_CLK_MAC0_RX	4
#define TC9564_CLK_MAC0_125M	5
#define TC9564_CLK_MAC0_ALL	6

#define TC9564_CLK_MAC1_TX	7
#define TC9564_CLK_MAC1_RX	8
#define TC9564_CLK_MAC1_125M	9
#define TC9564_CLK_MAC1_ALL	10

#endif /* __CLOCK_TOSHIBA_TC9564_H__ */
