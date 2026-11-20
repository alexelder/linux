/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */

/*
 * Copyright (C) 2026 by RISCstar Solutions Corporation.  All rights reserved.
 */

#ifndef __CLOCK_TOSHIBA_TC9564_H__
#define __CLOCK_TOSHIBA_TC9564_H__

/* Clock IDs */

#define CLOCK_PLL		0

#define CLOCK_62_5M		1
#define CLOCK_100M		2
#define CLOCK_125M		3
#define CLOCK_250M		4
#define CLOCK_312_5M		5

#define CLOCK_I2C		6	/* critical */
#define CLOCK_PCIE		7	/* critical */
#define CLOCK_MSIGEN		8

#define CLOCK_MAC0_TX		9
#define CLOCK_MAC0_RX		10
#define CLOCK_MAC0_125M		11
#define CLOCK_MAC0_312_5M	12
#define CLOCK_MAC0_ALL		13

#define CLOCK_MAC1_TX		14
#define CLOCK_MAC1_RX		15
#define CLOCK_MAC1_125M		16
#define CLOCK_MAC1_312_5M	17
#define CLOCK_MAC1_ALL		18

/* Reset IDs */

#define RESET_I2C		0	/* critical */
#define RESET_PCIE		1	/* critical */
#define RESET_MSIGEN		2

#define RESET_MAC0_MAC		3
#define RESET_MAC0_PMA		4
#define RESET_MAC0_XPCS		5

#define RESET_MAC1_MAC		6
#define RESET_MAC1_PMA		7
#define RESET_MAC1_XPCS		8

#endif /* __CLOCK_TOSHIBA_TC9564_H__*/
