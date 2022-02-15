/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef _UAPI_LINUX_QCOM_IPA_MONITOR_H
#define _UAPI_LINUX_QCOM_IPA_MONITOR_H

/**
 * DOC: IPA monitor
 *
 * The IPA "monitor" device presents a stream of entries, each consisting
 * of a fixed size header and a block of packet data the header describes.
 * The packet data in each entry is a replica of a packet that entered the
 * IPA hardware through one of its endpoints.  Large packets are truncated,
 * but still provide the IP header and UDP or TCP header (including options
 * and extensions), up to a fixed size limit.  Each entry begins with a "DPL"
 * (for Data Protocol Logging) header, which includes a packet length field
 * describing the length of the (truncated) packet.  The exact format of the
 * DPL header depends on the IPA hardware in use.  The supported DPL version
 * can be determined from IPA sysfs device attributes.
 */

/**
 * struct qcom_dplv2_header - DPLv2 header for IPA monitor data
 * @flags0:	First flags field; contains opcode (0x10)
 * @pkt_len:	Length of the packet data that follows the header
 * @flags1:	Flags field; contains source endpoint index
 * @metadata:	Out-of-band metadata value supplied with the packet
 * @flags2:	Flags field; contains the time of day counter
 * @flags3:	Last flags field; contains an 8 bit sequence number
 *
 * For DPLv2, the IPA status header structure is reused to describe
 * the packet data that follows.  Some data present in received
 * headers is meaningful, but n
 */
struct qcom_dplv2_header {
	__le32 flags0;
	__le16 pkt_len;
	__le16 flags1;
	__le32 metadata;
	u8 reserved[4];
	__le64 flags2;
	__le64 flags3;
};

/* Field masks for fields in dplv2_header->flags0 */
#define IPA_DPLv2_FLAGS0_OPCODE_FMASK		GENMASK(7, 0)

/* Field masks for fields in dplv2_header->flags1 */
#define IPA_DPLv2_FLAGS1_SRC_IDX_FMASK		GENMASK(4, 0)

/* Field masks for fields in dplv2_header->flags2 */
#define IPA_DPLv2_FLAGS2_DPL_TOD_FMASK		GENMASK_ULL(63, 15)

/* Field masks for fields in dplv2_header->flags3 */
#define IPA_DPLv2_FLAGS3_SEQ_NUM_FMASK		GENMASK_ULL(7, 0)

/**
 * struct qcom_dplv3_header - DPLv3 header for IPA monitor data
 * @opcode:	DPL opcode (0x10)
 * @seq_num:	8 bit sequence number
 * @flags0:	First flags field; contains source endpoint index
 * @pkt_len:	Length of the packet data that follows the header
 * @metadata:	Out-of-band metadata value supplied with the packet
 * @flags1:	Flags field; contains packet length and time of day counter
 */
struct qcom_dplv3_header {
	u8 opcode;		/* Expected to be 0x10 */
	u8 seq_num;
	__le16 flags0;
	__le32 metadata;
	__le64 flags1;
};

/* Field masks for fields in dplv3_header->flags0 */
#define IPA_DPLv3_FLAGS0_SRC_IDX_FMASK		GENMASK(4, 0)

/* Field masks for fields in dplv3_header->flags1 */
#define IPA_DPLv3_FLAGS1_DPL_TOD_FMASK		GENMASK_ULL(47, 0)
#define IPA_DPLv3_FLAGS1_PKT_LEN_FMASK		GENMASK_ULL(63, 48)

#endif /* _UAPI_LINUX_QCOM_IPA_MONITOR_H */
