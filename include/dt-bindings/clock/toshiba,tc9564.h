/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */

/*
 * Copyright (C) 2026 by RISCstar Solutions Corporation.  All rights reserved.
 */

#ifndef __ClOCK_TOSHIBA_TC9564_H__
#define __ClOCK_TOSHIBA_TC9564_H__

/* Clock IDs */

#define CLOCK_MCU		0
#define CLOCK_INTC		1
/* #define CLOCK_PCIE		2 */
/* #define CLOCK_I2C		3 */
#define CLOCK_SRAM		4
#define CLOCK_UART		5
#define CLOCK_MSIGEN		6
#define CLOCK_PLL		7
#define CLOCK_SGMII		8
#define CLOCK_REFCLKO		9

#define CLOCK_MAC0_TX		10
#define CLOCK_MAC0_RX		11
#define CLOCK_MAC0_125M		12
#define CLOCK_MAC0_312_5M	13
#define CLOCK_MAC0_ALL		14

#define CLOCK_MAC1_TX		15
#define CLOCK_MAC1_RX		16
#define CLOCK_MAC1_RMII		17
#define CLOCK_MAC1_125M		18
#define CLOCK_MAC1_312_5M	19
#define CLOCK_MAC1_ALL		20

/* Reset IDs */

#define RESET_MCU		0
#define RESET_MCU1		1
#define RESET_MSIGEN		2
#define RESET_INTC		3
#define RESET_UART		4
/* #define RESET_I2C		5 */
/* #define RESET_PCIE		6 */

#define RESET_MAC0_MAC		7
#define RESET_MAC0_PMA		8
#define RESET_MAC0_XPCS		9

#define RESET_MAC1_MAC		10
#define RESET_MAC1_PMA		11
#define RESET_MAC1_XPCS		12

#endif /* __ClOCK_TOSHIBA_TC9564_H__*/
