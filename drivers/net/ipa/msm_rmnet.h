/* SPDX-License-Identifier: GPL-2.0 */

/* Copyright (c) 2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018-2020 Linaro Ltd.
 */
#ifndef _MSM_RMNET_H_
#define _MSM_RMNET_H_

/* IOCTL commands
 * Values chosen to not conflict with other drivers in the ecosystem
 */

#define RMNET_IOCTL_SET_LLP_ETHERNET		0x000089f1
#define RMNET_IOCTL_SET_LLP_IP			0x000089f2
#define RMNET_IOCTL_GET_LLP			0x000089f3
#define RMNET_IOCTL_SET_QOS_ENABLE		0x000089f4
#define RMNET_IOCTL_SET_QOS_DISABLE		0x000089f5
#define RMNET_IOCTL_GET_QOS			0x000089f6
#define RMNET_IOCTL_GET_OPMODE			0x000089f7
#define RMNET_IOCTL_OPEN			0x000089f8
#define RMNET_IOCTL_CLOSE			0x000089f9
#define RMNET_IOCTL_FLOW_ENABLE			0x000089fa
#define RMNET_IOCTL_FLOW_DISABLE		0x000089fb
#define RMNET_IOCTL_FLOW_SET_HANDLE		0x000089fb
#define RMNET_IOCTL_EXTENDED			0x000089fd

/* RmNet Data extended IOCTLs */
#define RMNET_IOCTL_GET_SUPPORTED_FEATURES	0x00000000
#define RMNET_IOCTL_SET_MRU			0x00000001
#define RMNET_IOCTL_GET_EPID			0x00000003
#define RMNET_IOCTL_ADD_MUX_CHANNEL		0x00000005
#define RMNET_IOCTL_SET_EGRESS_DATA_FORMAT	0x00000006
#define RMNET_IOCTL_SET_INGRESS_DATA_FORMAT	0x00000007
#define RMNET_IOCTL_GET_EP_PAIR			0x00000010

/* Return values for the RMNET_IOCTL_GET_SUPPORTED_FEATURES IOCTL */
#define RMNET_IOCTL_FEAT_NOTIFY_MUX_CHANNEL		BIT(0)
#define RMNET_IOCTL_FEAT_SET_EGRESS_DATA_FORMAT		BIT(1)
#define RMNET_IOCTL_FEAT_SET_INGRESS_DATA_FORMAT	BIT(2)

/* Input values for the RMNET_IOCTL_SET_EGRESS_DATA_FORMAT IOCTL  */
#define RMNET_IOCTL_EGRESS_FORMAT_MAP			BIT(1)
#define RMNET_IOCTL_EGRESS_FORMAT_AGGREGATION		BIT(2)
#define RMNET_IOCTL_EGRESS_FORMAT_MUXING		BIT(3)
#define RMNET_IOCTL_EGRESS_FORMAT_CHECKSUM		BIT(4)
#define RMNET_IOCTL_EGRESS_FORMAT_IP_ROUTE		BIT(5)
#define RMNET_IOCTL_EGRESS_FORMAT_ALL			GENMASK(5, 1)

/* Input values for the RMNET_IOCTL_SET_INGRESS_DATA_FORMAT IOCTL */
#define RMNET_IOCTL_INGRESS_FORMAT_MAP			BIT(1)
#define RMNET_IOCTL_INGRESS_FORMAT_DEAGGREGATION	BIT(2)
#define RMNET_IOCTL_INGRESS_FORMAT_DEMUXING		BIT(3)
#define RMNET_IOCTL_INGRESS_FORMAT_CHECKSUM		BIT(4)
#define RMNET_IOCTL_INGRESS_FORMAT_AGG_DATA		BIT(5)
#define RMNET_IOCTL_INGRESS_FORMAT_IP_ROUTE		BIT(6)
#define RMNET_IOCTL_INGRESS_FORMAT_ALL			GENMASK(6, 1)

/* Return types for RMNET_IOCTL_EXTENDED requests */
struct rmnet_ioctl_extended_s {
	u32	extended_ioctl;
	union {
		u32	data; /* Generic data field for most extended IOCTLs */

		struct {
			u32	mux_id;
			char	name[IFNAMSIZ];
		} add_mux_channel;

		/* Return values for RMNET_IOCTL_GET_EP_PAIR */
		struct {
			u32	consumer_pipe_num;
			u32	producer_pipe_num;
		} ipa_endpoint_pair;

		struct {
			u32	__data; /* Placeholder for legacy data*/
			u32	agg_size;
			u32	agg_count;
		} ingress_format;
	} u;
};

#endif /* _MSM_RMNET_H_ */
