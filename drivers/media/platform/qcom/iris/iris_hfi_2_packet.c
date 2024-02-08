// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include "iris_hfi_2_defines.h"
#include "iris_hfi_2_packet.h"
#include "iris_instance.h"

u32 iris_hfi_2_buf_type_to_driver(enum hfi_buffer_type buf_type)
{
	switch (buf_type) {
	case HFI_BUFFER_BITSTREAM:
		return BUF_INPUT;
	case HFI_BUFFER_RAW:
		return BUF_OUTPUT;
	case HFI_BUFFER_BIN:
		return BUF_BIN;
	case HFI_BUFFER_ARP:
		return BUF_ARP;
	case HFI_BUFFER_COMV:
		return BUF_COMV;
	case HFI_BUFFER_NON_COMV:
		return BUF_NON_COMV;
	case HFI_BUFFER_LINE:
		return BUF_LINE;
	case HFI_BUFFER_DPB:
		return BUF_DPB;
	case HFI_BUFFER_PERSIST:
		return BUF_PERSIST;
	case HFI_BUFFER_VPSS:
		return BUF_VPSS;
	default:
		return 0;
	}
}

u32 iris_hfi_2_get_color_primaries(u32 primaries)
{
	u32 hfi_primaries = HFI_PRIMARIES_RESERVED;

	switch (primaries) {
	case V4L2_COLORSPACE_DEFAULT:
		hfi_primaries = HFI_PRIMARIES_RESERVED;
		break;
	case V4L2_COLORSPACE_REC709:
		hfi_primaries = HFI_PRIMARIES_BT709;
		break;
	case V4L2_COLORSPACE_470_SYSTEM_M:
		hfi_primaries = HFI_PRIMARIES_BT470_SYSTEM_M;
		break;
	case V4L2_COLORSPACE_470_SYSTEM_BG:
		hfi_primaries = HFI_PRIMARIES_BT470_SYSTEM_BG;
		break;
	case V4L2_COLORSPACE_SMPTE170M:
		hfi_primaries = HFI_PRIMARIES_BT601_525;
		break;
	case V4L2_COLORSPACE_SMPTE240M:
		hfi_primaries = HFI_PRIMARIES_SMPTE_ST240M;
		break;
	case V4L2_COLORSPACE_BT2020:
		hfi_primaries = HFI_PRIMARIES_BT2020;
		break;
	case V4L2_COLORSPACE_DCI_P3:
		hfi_primaries = HFI_PRIMARIES_SMPTE_RP431_2;
		break;
	default:
		break;
	}

	return hfi_primaries;
}

u32 iris_hfi_2_get_transfer_char(u32 characterstics)
{
	u32 hfi_characterstics = HFI_TRANSFER_RESERVED;

	switch (characterstics) {
	case V4L2_XFER_FUNC_DEFAULT:
		hfi_characterstics = HFI_TRANSFER_RESERVED;
		break;
	case V4L2_XFER_FUNC_709:
		hfi_characterstics = HFI_TRANSFER_BT709;
		break;
	case V4L2_XFER_FUNC_SMPTE240M:
		hfi_characterstics = HFI_TRANSFER_SMPTE_ST240M;
		break;
	case V4L2_XFER_FUNC_SRGB:
		hfi_characterstics = HFI_TRANSFER_SRGB_SYCC;
		break;
	case V4L2_XFER_FUNC_SMPTE2084:
		hfi_characterstics = HFI_TRANSFER_SMPTE_ST2084_PQ;
		break;
	default:
		break;
	}

	return hfi_characterstics;
}

u32 iris_hfi_2_get_matrix_coefficients(u32 coefficients)
{
	u32 hfi_coefficients = HFI_MATRIX_COEFF_RESERVED;

	switch (coefficients) {
	case V4L2_YCBCR_ENC_DEFAULT:
		hfi_coefficients = HFI_MATRIX_COEFF_RESERVED;
		break;
	case V4L2_YCBCR_ENC_709:
		hfi_coefficients = HFI_MATRIX_COEFF_BT709;
		break;
	case V4L2_YCBCR_ENC_XV709:
		hfi_coefficients = HFI_MATRIX_COEFF_BT709;
		break;
	case V4L2_YCBCR_ENC_XV601:
		hfi_coefficients = HFI_MATRIX_COEFF_BT470_SYS_BG_OR_BT601_625;
		break;
	case V4L2_YCBCR_ENC_601:
		hfi_coefficients = HFI_MATRIX_COEFF_BT601_525_BT1358_525_OR_625;
		break;
	case V4L2_YCBCR_ENC_SMPTE240M:
		hfi_coefficients = HFI_MATRIX_COEFF_SMPTE_ST240;
		break;
	case V4L2_YCBCR_ENC_BT2020:
		hfi_coefficients = HFI_MATRIX_COEFF_BT2020_NON_CONSTANT;
		break;
	case V4L2_YCBCR_ENC_BT2020_CONST_LUM:
		hfi_coefficients = HFI_MATRIX_COEFF_BT2020_CONSTANT;
		break;
	default:
		break;
	}

	return hfi_coefficients;
}

static int iris_hfi_2_create_header(u8 *packet, u32 packet_size, u32 session_id,
				    u32 header_id)
{
	struct iris_hfi_header *hdr = (struct iris_hfi_header *)packet;

	if (!packet || packet_size < sizeof(*hdr))
		return -EINVAL;

	memset(hdr, 0, sizeof(*hdr));

	hdr->size = sizeof(*hdr);
	hdr->session_id = session_id;
	hdr->header_id = header_id;
	hdr->num_packets = 0;

	return 0;
}

static int iris_hfi_2_create_packet(u8 *packet, u32 packet_size, u32 pkt_type,
				    u32 pkt_flags, u32 payload_type, u32 port,
				    u32 packet_id, void *payload, u32 payload_size)
{
	struct iris_hfi_header *hdr;
	struct iris_hfi_packet *pkt;
	u32 pkt_size;

	if (!packet)
		return -EINVAL;

	hdr = (struct iris_hfi_header *)packet;
	if (hdr->size < sizeof(*hdr))
		return -EINVAL;

	pkt = (struct iris_hfi_packet *)(packet + hdr->size);
	pkt_size = sizeof(*pkt) + payload_size;
	if (packet_size < hdr->size  + pkt_size)
		return -EINVAL;

	memset(pkt, 0, pkt_size);
	pkt->size = pkt_size;
	pkt->type = pkt_type;
	pkt->flags = pkt_flags;
	pkt->payload_info = payload_type;
	pkt->port = port;
	pkt->packet_id = packet_id;
	if (payload_size)
		memcpy((u8 *)pkt + sizeof(*pkt),
		       payload, payload_size);

	hdr->num_packets++;
	hdr->size += pkt->size;

	return 0;
}

int iris_hfi_2_packet_sys_init(struct iris_core *core, u8 *pkt, u32 pkt_size)
{
	u32 payload = 0;
	int ret;

	ret = iris_hfi_2_create_header(pkt, pkt_size,
				       0,
				       core->header_id++);
	if (ret)
		goto error;

	payload = HFI_VIDEO_ARCH_LX;
	ret = iris_hfi_2_create_packet(pkt, pkt_size,
				       HFI_CMD_INIT,
				       (HFI_HOST_FLAGS_RESPONSE_REQUIRED |
				       HFI_HOST_FLAGS_INTR_REQUIRED |
				       HFI_HOST_FLAGS_NON_DISCARDABLE),
				       HFI_PAYLOAD_U32,
				       HFI_PORT_NONE,
				       core->packet_id++,
				       &payload,
				       sizeof(u32));
	if (ret)
		goto error;

	payload = core->platform_data->ubwc_config->max_channels;
	ret = iris_hfi_2_create_packet(pkt, pkt_size,
				       HFI_PROP_UBWC_MAX_CHANNELS,
				       HFI_HOST_FLAGS_NONE,
				       HFI_PAYLOAD_U32,
				       HFI_PORT_NONE,
				       core->packet_id++,
				       &payload,
				       sizeof(u32));
	if (ret)
		goto error;

	payload = core->platform_data->ubwc_config->mal_length;
	ret = iris_hfi_2_create_packet(pkt, pkt_size,
				       HFI_PROP_UBWC_MAL_LENGTH,
				       HFI_HOST_FLAGS_NONE,
				       HFI_PAYLOAD_U32,
				       HFI_PORT_NONE,
				       core->packet_id++,
				       &payload,
				       sizeof(u32));
	if (ret)
		goto error;

	payload = core->platform_data->ubwc_config->highest_bank_bit;
	ret = iris_hfi_2_create_packet(pkt, pkt_size,
				       HFI_PROP_UBWC_HBB,
				       HFI_HOST_FLAGS_NONE,
				       HFI_PAYLOAD_U32,
				       HFI_PORT_NONE,
				       core->packet_id++,
				       &payload,
				       sizeof(u32));
	if (ret)
		goto error;

	payload = core->platform_data->ubwc_config->bank_swzl_level;
	ret = iris_hfi_2_create_packet(pkt, pkt_size,
				       HFI_PROP_UBWC_BANK_SWZL_LEVEL1,
				       HFI_HOST_FLAGS_NONE,
				       HFI_PAYLOAD_U32,
				       HFI_PORT_NONE,
				       core->packet_id++,
				       &payload,
				       sizeof(u32));
	if (ret)
		goto error;

	payload = core->platform_data->ubwc_config->bank_swz2_level;
	ret = iris_hfi_2_create_packet(pkt, pkt_size,
				       HFI_PROP_UBWC_BANK_SWZL_LEVEL2,
				       HFI_HOST_FLAGS_NONE,
				       HFI_PAYLOAD_U32,
				       HFI_PORT_NONE,
				       core->packet_id++,
				       &payload,
				       sizeof(u32));
	if (ret)
		goto error;

	payload = core->platform_data->ubwc_config->bank_swz3_level;
	ret = iris_hfi_2_create_packet(pkt, pkt_size,
				       HFI_PROP_UBWC_BANK_SWZL_LEVEL3,
				       HFI_HOST_FLAGS_NONE,
				       HFI_PAYLOAD_U32,
				       HFI_PORT_NONE,
				       core->packet_id++,
				       &payload,
				       sizeof(u32));
	if (ret)
		goto error;

	payload = core->platform_data->ubwc_config->bank_spreading;
	ret = iris_hfi_2_create_packet(pkt, pkt_size,
				       HFI_PROP_UBWC_BANK_SPREADING,
				       HFI_HOST_FLAGS_NONE,
				       HFI_PAYLOAD_U32,
				       HFI_PORT_NONE,
				       core->packet_id++,
				       &payload,
				       sizeof(u32));
	if (ret)
		goto error;

	return ret;

error:
	dev_err(core->dev, "%s: create sys init packet failed\n", __func__);

	return ret;
}

int iris_hfi_2_packet_image_version(struct iris_core *core, u8 *pkt, u32 pkt_size)
{
	int ret;

	ret = iris_hfi_2_create_header(pkt, pkt_size,
				       0,
				       core->header_id++);
	if (ret)
		goto error;

	ret = iris_hfi_2_create_packet(pkt, pkt_size,
				       HFI_PROP_IMAGE_VERSION,
				       (HFI_HOST_FLAGS_RESPONSE_REQUIRED |
				       HFI_HOST_FLAGS_INTR_REQUIRED |
				       HFI_HOST_FLAGS_GET_PROPERTY),
				       HFI_PAYLOAD_NONE,
				       HFI_PORT_NONE,
				       core->packet_id++,
				       NULL, 0);
	if (ret)
		goto error;

	return ret;

error:
	dev_err(core->dev, "%s: create image version packet failed\n", __func__);

	return ret;
}

int iris_hfi_2_packet_session_command(struct iris_inst *inst, u32 pkt_type,
				      u32 flags, u32 port, u32 session_id,
				      u32 payload_type, void *payload,
				      u32 payload_size)
{
	struct iris_core *core;
	int ret;

	if (!inst->packet)
		return -EINVAL;

	core = inst->core;

	ret = iris_hfi_2_create_header(inst->packet, inst->packet_size,
				       session_id, core->header_id++);
	if (ret)
		return ret;

	ret = iris_hfi_2_create_packet(inst->packet,
				       inst->packet_size,
				       pkt_type,
				       flags,
				       payload_type,
				       port,
				       core->packet_id++,
				       payload,
				       payload_size);

	return ret;
}

int iris_hfi_2_packet_session_property(struct iris_inst *inst,
				       u32 pkt_type, u32 flags, u32 port,
				       u32 payload_type, void *payload, u32 payload_size)
{
	struct iris_core *core;
	int ret;

	core = inst->core;

	ret = iris_hfi_2_create_header(inst->packet, inst->packet_size,
				       inst->session_id, core->header_id++);
	if (ret)
		return ret;

	ret = iris_hfi_2_create_packet(inst->packet, inst->packet_size,
				       pkt_type,
				       flags,
				       payload_type,
				       port,
				       core->packet_id++,
				       payload,
				       payload_size);

	return ret;
}

int iris_hfi_2_packet_sys_interframe_powercollapse(struct iris_core *core,
						   u8 *pkt, u32 pkt_size)
{
	u32 payload = 0;
	int ret;

	ret = iris_hfi_2_create_header(pkt, pkt_size,
				       0 /*session_id*/,
				       core->header_id++);
	if (ret)
		return ret;

	payload = HFI_TRUE;

	ret = iris_hfi_2_create_packet(pkt, pkt_size,
				       HFI_PROP_INTRA_FRAME_POWER_COLLAPSE,
				       HFI_HOST_FLAGS_NONE,
				       HFI_PAYLOAD_U32,
				       HFI_PORT_NONE,
				       core->packet_id++,
				       &payload,
				       sizeof(u32));

	return ret;
}

int iris_hfi_2_packet_sys_pc_prep(struct iris_core *core, u8 *pkt, u32 pkt_size)
{
	int ret;

	ret = iris_hfi_2_create_header(pkt, pkt_size,
				       0 /*session_id*/,
				       core->header_id++);
	if (ret)
		return ret;

	ret = iris_hfi_2_create_packet(pkt, pkt_size,
				       HFI_CMD_POWER_COLLAPSE,
				       HFI_HOST_FLAGS_NONE,
				       HFI_PAYLOAD_NONE,
				       HFI_PORT_NONE,
				       core->packet_id++,
				       NULL, 0);

	return ret;
}
