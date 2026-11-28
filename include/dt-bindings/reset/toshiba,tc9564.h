/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */

/*
 * Copyright (C) 2026 by RISCstar Solutions Corporation.  All rights reserved.
 */

#ifndef __RESET_TOSHIBA_TC9564_H__
#define __RESET_TOSHIBA_TC9564_H__

/* Reset IDs */

#define TC9564_RST_I2C		0	/* critical */
#define TC9564_RST_PCIE		1	/* critical */
#define TC9564_RST_MSIGEN	2

#define TC9564_RST_MAC0_MAC	3
#define TC9564_RST_MAC0_PMA	4
#define TC9564_RST_MAC0_XPCS	5

#define TC9564_RST_MAC1_MAC	6
#define TC9564_RST_MAC1_PMA	7
#define TC9564_RST_MAC1_XPCS	8

#endif /* __RESET_TOSHIBA_TC9564_H__ */
