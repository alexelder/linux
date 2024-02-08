// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */
#include <media/v4l2-mem2mem.h>

#include "iris_buffer_helpers.h"
#include "iris_hfi_2_defines.h"
#include "iris_hfi_2_packet.h"
#include "iris_hfi_2_response.h"
#include "iris_instance.h"
#include "iris_vdec.h"
#include "iris_vpu_buffer.h"
#include "iris_vpu_common.h"

struct iris_hfi_2_core_hfi_range {
	u32 begin;
	u32 end;
	int (*handle)(struct iris_core *core, struct iris_hfi_packet *pkt);
};

struct iris_hfi_2_inst_hfi_range {
	u32 begin;
	u32 end;
	int (*handle)(struct iris_inst *inst, struct iris_hfi_packet *pkt);
};

struct iris_hfi_2_packet_handle {
	enum hfi_buffer_type type;
	int (*handle)(struct iris_inst *inst, struct iris_hfi_packet *pkt);
};

static bool iris_hfi_2_is_valid_hfi_buffer_type(u32 buffer_type)
{
	if (buffer_type != HFI_BUFFER_BITSTREAM &&
	    buffer_type != HFI_BUFFER_RAW &&
	    buffer_type != HFI_BUFFER_BIN &&
	    buffer_type != HFI_BUFFER_ARP &&
	    buffer_type != HFI_BUFFER_COMV &&
	    buffer_type != HFI_BUFFER_NON_COMV &&
	    buffer_type != HFI_BUFFER_LINE &&
	    buffer_type != HFI_BUFFER_DPB &&
	    buffer_type != HFI_BUFFER_PERSIST &&
	    buffer_type != HFI_BUFFER_VPSS) {
		return false;
	}

	return true;
}

static bool iris_hfi_2_is_valid_hfi_port(u32 port, u32 buffer_type)
{
	if (port == HFI_PORT_NONE &&
	    buffer_type != HFI_BUFFER_PERSIST)
		return false;

	if (port != HFI_PORT_BITSTREAM && port != HFI_PORT_RAW)
		return false;

	return true;
}

static int iris_hfi_2_get_driver_buffer_flags(struct iris_inst *inst, u32 hfi_flags)
{
	u32 driver_flags = 0;

	if (inst->hfi_frame_info.picture_type & HFI_PICTURE_IDR)
		driver_flags |= V4L2_BUF_FLAG_KEYFRAME;
	else if (inst->hfi_frame_info.picture_type & HFI_PICTURE_P)
		driver_flags |= V4L2_BUF_FLAG_PFRAME;
	else if (inst->hfi_frame_info.picture_type & HFI_PICTURE_B)
		driver_flags |= V4L2_BUF_FLAG_BFRAME;
	else if (inst->hfi_frame_info.picture_type & HFI_PICTURE_I)
		driver_flags |= V4L2_BUF_FLAG_KEYFRAME;
	else if (inst->hfi_frame_info.picture_type & HFI_PICTURE_CRA)
		driver_flags |= V4L2_BUF_FLAG_KEYFRAME;
	else if (inst->hfi_frame_info.picture_type & HFI_PICTURE_BLA)
		driver_flags |= V4L2_BUF_FLAG_KEYFRAME;

	if (inst->hfi_frame_info.data_corrupt)
		driver_flags |= V4L2_BUF_FLAG_ERROR;

	if (inst->hfi_frame_info.overflow)
		driver_flags |= V4L2_BUF_FLAG_ERROR;

	if (hfi_flags & HFI_BUF_FW_FLAG_LAST ||
	    hfi_flags & HFI_BUF_FW_FLAG_PSC_LAST)
		driver_flags |= V4L2_BUF_FLAG_LAST;

	return driver_flags;
}

static bool iris_hfi_2_validate_packet_payload(struct iris_hfi_packet *pkt)
{
	u32 payload_size = 0;

	switch (pkt->payload_info) {
	case HFI_PAYLOAD_U32:
	case HFI_PAYLOAD_S32:
	case HFI_PAYLOAD_Q16:
	case HFI_PAYLOAD_U32_ENUM:
	case HFI_PAYLOAD_32_PACKED:
		payload_size = 4;
		break;
	case HFI_PAYLOAD_U64:
	case HFI_PAYLOAD_S64:
	case HFI_PAYLOAD_64_PACKED:
		payload_size = 8;
		break;
	case HFI_PAYLOAD_STRUCTURE:
		if (pkt->type == HFI_CMD_BUFFER)
			payload_size = sizeof(struct iris_hfi_buffer);
		break;
	default:
		payload_size = 0;
		break;
	}

	if (pkt->size < sizeof(struct iris_hfi_packet) + payload_size)
		return false;

	return true;
}

static int iris_hfi_2_validate_packet(u8 *response_pkt, u8 *core_resp_pkt, u32 core_resp_pkt_size)
{
	u32 response_pkt_size = 0;
	u8 *response_limit;

	if (!response_pkt || !core_resp_pkt || !core_resp_pkt_size)
		return -EINVAL;

	response_limit = core_resp_pkt + core_resp_pkt_size;

	if (response_pkt < core_resp_pkt || response_pkt > response_limit)
		return -EINVAL;

	response_pkt_size = *(u32 *)response_pkt;
	if (!response_pkt_size)
		return -EINVAL;

	if (response_pkt_size < sizeof(struct iris_hfi_packet))
		return -EINVAL;

	if (response_pkt + response_pkt_size > response_limit)
		return -EINVAL;

	return 0;
}

static int iris_hfi_2_validate_hdr_packet(struct iris_core *core, struct iris_hfi_header *hdr)
{
	struct iris_hfi_packet *packet;
	int i, ret = 0;
	u8 *pkt;

	if (hdr->size < sizeof(*hdr) + sizeof(*packet))
		return -EINVAL;

	pkt = (u8 *)((u8 *)hdr + sizeof(*hdr));

	for (i = 0; i < hdr->num_packets; i++) {
		packet = (struct iris_hfi_packet *)pkt;
		ret = iris_hfi_2_validate_packet(pkt, core->response_packet, core->packet_size);
		if (ret)
			return ret;

		pkt += packet->size;
	}

	return ret;
}

static int iris_hfi_2_handle_session_info(struct iris_inst *inst,
					  struct iris_hfi_packet *pkt)
{
	struct iris_core *core;
	int ret = 0;
	char *info;

	core = inst->core;

	switch (pkt->type) {
	case HFI_INFO_UNSUPPORTED:
		info = "unsupported";
		break;
	case HFI_INFO_DATA_CORRUPT:
		info = "data corrupt";
		inst->hfi_frame_info.data_corrupt = 1;
		break;
	case HFI_INFO_BUFFER_OVERFLOW:
		info = "buffer overflow";
		inst->hfi_frame_info.overflow = 1;
		break;
	case HFI_INFO_HFI_FLAG_DRAIN_LAST:
		info = "drain last flag";
		ret = iris_inst_sub_state_change_drain_last(inst);
		break;
	case HFI_INFO_HFI_FLAG_PSC_LAST:
		info = "drc last flag";
		ret = iris_inst_sub_state_change_drc_last(inst);
		break;
	default:
		info = "unknown";
		break;
	}

	dev_dbg(core->dev, "session info received %#x: %s\n",
		pkt->type, info);

	return ret;
}

static int iris_hfi_2_handle_session_error(struct iris_inst *inst,
					   struct iris_hfi_packet *pkt)
{
	struct iris_core *core;
	char *error;

	core = inst->core;

	switch (pkt->type) {
	case HFI_ERROR_MAX_SESSIONS:
		error = "exceeded max sessions";
		break;
	case HFI_ERROR_UNKNOWN_SESSION:
		error = "unknown session id";
		break;
	case HFI_ERROR_INVALID_STATE:
		error = "invalid operation for current state";
		break;
	case HFI_ERROR_INSUFFICIENT_RESOURCES:
		error = "insufficient resources";
		break;
	case HFI_ERROR_BUFFER_NOT_SET:
		error = "internal buffers not set";
		break;
	case HFI_ERROR_FATAL:
		error = "fatal error";
		break;
	default:
		error = "unknown";
		break;
	}

	dev_err(core->dev, "session error received %#x: %s\n",
		pkt->type, error);
	iris_vb2_queue_error(inst);
	iris_inst_change_state(inst, IRIS_INST_ERROR);

	return 0;
}

static int iris_hfi_2_handle_system_error(struct iris_core *core,
					  struct iris_hfi_packet *pkt)
{
	dev_err(core->dev, "received system error of type %#x\n", pkt->type);

	iris_change_core_state(core, IRIS_CORE_ERROR);
	schedule_delayed_work(&core->sys_error_handler, msecs_to_jiffies(10));

	return 0;
}

static int iris_hfi_2_handle_system_init(struct iris_core *core,
					 struct iris_hfi_packet *pkt)
{
	if (!(pkt->flags & HFI_FW_FLAGS_SUCCESS)) {
		iris_change_core_state(core, IRIS_CORE_ERROR);
		return 0;
	}

	iris_change_core_state(core, IRIS_CORE_INIT);
	complete(&core->core_init_done);

	return 0;
}

static int iris_hfi_2_handle_session_close(struct iris_inst *inst,
					   struct iris_hfi_packet *pkt)
{
	if (!(pkt->flags & HFI_FW_FLAGS_SUCCESS)) {
		iris_inst_change_state(inst, IRIS_INST_ERROR);
		return 0;
	}

	complete(&inst->completion);

	return 0;
}

static int iris_hfi_2_handle_input_buffer(struct iris_inst *inst,
					  struct iris_hfi_buffer *buffer)
{
	struct v4l2_m2m_ctx *m2m_ctx = inst->m2m_ctx;
	struct v4l2_m2m_buffer *m2m_buffer, *n;
	struct iris_buffer *buf = NULL;
	bool found;

	v4l2_m2m_for_each_src_buf_safe(m2m_ctx, m2m_buffer, n) {
		buf = to_iris_buffer(&m2m_buffer->vb);
		if (buf->index == buffer->index) {
			found = true;
			break;
		}
	}
	if (!found)
		return -EINVAL;

	if (!(buf->attr & BUF_ATTR_QUEUED))
		return 0;

	buf->data_size = buffer->data_size;
	buf->attr &= ~BUF_ATTR_QUEUED;
	buf->attr |= BUF_ATTR_DEQUEUED;

	buf->flags = iris_hfi_2_get_driver_buffer_flags(inst, buffer->flags);

	return 0;
}

static int iris_hfi_2_handle_output_buffer(struct iris_inst *inst,
					   struct iris_hfi_buffer *hfi_buffer)
{
	struct v4l2_m2m_ctx *m2m_ctx = inst->m2m_ctx;
	struct v4l2_m2m_buffer *m2m_buffer, *n;
	struct iris_buffer *buf = NULL;
	int ret = 0;
	bool found;

	if (hfi_buffer->flags & HFI_BUF_FW_FLAG_LAST) {
		ret = iris_inst_sub_state_change_drain_last(inst);
		if (ret)
			return ret;
	}

	if (hfi_buffer->flags & HFI_BUF_FW_FLAG_PSC_LAST) {
		ret = iris_inst_sub_state_change_drc_last(inst);
		if (ret)
			return ret;
	}

	v4l2_m2m_for_each_dst_buf_safe(m2m_ctx, m2m_buffer, n) {
		buf = to_iris_buffer(&m2m_buffer->vb);
		if (!(buf->attr & BUF_ATTR_QUEUED))
			continue;

		found = (buf->index == hfi_buffer->index &&
				buf->device_addr == hfi_buffer->base_address &&
				buf->data_offset == hfi_buffer->data_offset);

		if (found)
			break;
	}
	if (!found)
		return 0;

	buf->data_offset = hfi_buffer->data_offset;
	buf->data_size = hfi_buffer->data_size;
	buf->timestamp = hfi_buffer->timestamp;

	buf->attr &= ~BUF_ATTR_QUEUED;
	buf->attr |= BUF_ATTR_DEQUEUED;

	buf->flags = iris_hfi_2_get_driver_buffer_flags(inst, hfi_buffer->flags);

	return ret;
}

static int iris_hfi_2_handle_dequeue_buffers(struct iris_inst *inst)
{
	struct v4l2_m2m_ctx *m2m_ctx = inst->m2m_ctx;
	struct v4l2_m2m_buffer *buffer, *n;
	struct iris_buffer *buf = NULL;
	int ret = 0;

	v4l2_m2m_for_each_src_buf_safe(m2m_ctx, buffer, n) {
		buf = to_iris_buffer(&buffer->vb);
		if (buf->attr & BUF_ATTR_DEQUEUED) {
			buf->attr &= ~BUF_ATTR_DEQUEUED;
			if (!(buf->attr & BUF_ATTR_BUFFER_DONE)) {
				buf->attr |= BUF_ATTR_BUFFER_DONE;
				ret = iris_vb2_buffer_done(inst, buf);
				if (ret)
					ret = 0;
			}
		}
	}

	v4l2_m2m_for_each_dst_buf_safe(m2m_ctx, buffer, n) {
		buf = to_iris_buffer(&buffer->vb);
		if (buf->attr & BUF_ATTR_DEQUEUED) {
			buf->attr &= ~BUF_ATTR_DEQUEUED;
			if (!(buf->attr & BUF_ATTR_BUFFER_DONE)) {
				buf->attr |= BUF_ATTR_BUFFER_DONE;
				ret = iris_vb2_buffer_done(inst, buf);
				if (ret)
					ret = 0;
			}
		}
	}

	return ret;
}

static int iris_hfi_2_handle_release_internal_buffer(struct iris_inst *inst,
						     struct iris_hfi_buffer *buffer)
{
	struct iris_buffer *buf, *iter;
	struct iris_buffers *buffers;
	int ret = 0;
	bool found;

	buffers = iris_get_buffer_list(inst, iris_hfi_2_buf_type_to_driver(buffer->type));
	if (!buffers)
		return -EINVAL;

	found = false;
	list_for_each_entry(iter, &buffers->list, list) {
		if (iter->device_addr == buffer->base_address) {
			found = true;
			buf = iter;
			break;
		}
	}
	if (!found)
		return -EINVAL;

	buf->attr &= ~BUF_ATTR_QUEUED;

	if (buf->attr & BUF_ATTR_PENDING_RELEASE)
		ret = iris_destroy_internal_buffer(inst, buf);

	return ret;
}

static int iris_hfi_2_handle_session_stop(struct iris_inst *inst,
					  struct iris_hfi_packet *pkt)
{
	int ret = 0;

	if (pkt->port == HFI_PORT_RAW)
		ret = iris_inst_sub_state_change_pause(inst, V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE);
	else if (pkt->port == HFI_PORT_BITSTREAM)
		ret = iris_inst_sub_state_change_pause(inst, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE);

	complete(&inst->completion);

	return ret;
}

static int iris_hfi_2_handle_session_buffer(struct iris_inst *inst,
					    struct iris_hfi_packet *pkt)
{
	struct iris_hfi_buffer *buffer;

	if (pkt->payload_info == HFI_PAYLOAD_NONE)
		return 0;

	if (!iris_hfi_2_validate_packet_payload(pkt)) {
		iris_inst_change_state(inst, IRIS_INST_ERROR);
		return 0;
	}

	buffer = (struct iris_hfi_buffer *)((u8 *)pkt + sizeof(*pkt));
	if (!iris_hfi_2_is_valid_hfi_buffer_type(buffer->type))
		return 0;

	if (!iris_hfi_2_is_valid_hfi_port(pkt->port, buffer->type))
		return 0;

	if (buffer->type == HFI_BUFFER_BITSTREAM)
		return iris_hfi_2_handle_input_buffer(inst, buffer);
	else if (buffer->type == HFI_BUFFER_RAW)
		return iris_hfi_2_handle_output_buffer(inst, buffer);
	else
		return iris_hfi_2_handle_release_internal_buffer(inst, buffer);
}

static int iris_hfi_2_handle_session_drain(struct iris_inst *inst,
					   struct iris_hfi_packet *pkt)
{
	int ret = 0;

	if (!(pkt->flags & HFI_FW_FLAGS_SUCCESS)) {
		iris_inst_change_state(inst, IRIS_INST_ERROR);
		return 0;
	}

	if (inst->sub_state & IRIS_INST_SUB_DRAIN)
		ret = iris_inst_change_sub_state(inst, 0, IRIS_INST_SUB_INPUT_PAUSE);

	return ret;
}

static void iris_hfi_2_read_input_subcr_params(struct iris_inst *inst)
{
	struct v4l2_pix_format_mplane *pixmp_ip, *pixmp_op;
	u32 primaries, matrix_coeff, transfer_char;
	struct hfi_subscription_params subsc_params;
	u32 colour_description_present_flag = 0;
	u32 video_signal_type_present_flag = 0;
	struct iris_core *core;
	u32 full_range = 0;
	u32 width, height;

	core = inst->core;
	subsc_params = inst->src_subcr_params;
	pixmp_ip = &inst->fmt_src->fmt.pix_mp;
	pixmp_op = &inst->fmt_dst->fmt.pix_mp;
	width = (subsc_params.bitstream_resolution &
		HFI_BITMASK_BITSTREAM_WIDTH) >> 16;
	height = subsc_params.bitstream_resolution &
		HFI_BITMASK_BITSTREAM_HEIGHT;

	pixmp_ip->width = width;
	pixmp_ip->height = height;

	pixmp_op->width = ALIGN(width, 128);
	pixmp_op->height = ALIGN(height, 32);
	pixmp_op->plane_fmt[0].bytesperline = ALIGN(width, 128);
	pixmp_op->plane_fmt[0].sizeimage = iris_get_buffer_size(inst, BUF_OUTPUT);

	matrix_coeff = subsc_params.color_info & 0xFF;
	transfer_char = (subsc_params.color_info & 0xFF00) >> 8;
	primaries = (subsc_params.color_info & 0xFF0000) >> 16;
	colour_description_present_flag =
		(subsc_params.color_info & 0x1000000) >> 24;
	full_range = (subsc_params.color_info & 0x2000000) >> 25;
	video_signal_type_present_flag =
		(subsc_params.color_info & 0x20000000) >> 29;

	pixmp_op->colorspace = V4L2_COLORSPACE_DEFAULT;
	pixmp_op->xfer_func = V4L2_XFER_FUNC_DEFAULT;
	pixmp_op->ycbcr_enc = V4L2_YCBCR_ENC_DEFAULT;
	pixmp_op->quantization = V4L2_QUANTIZATION_DEFAULT;

	if (video_signal_type_present_flag) {
		pixmp_op->quantization =
			full_range ?
			V4L2_QUANTIZATION_FULL_RANGE :
			V4L2_QUANTIZATION_LIM_RANGE;
		if (colour_description_present_flag) {
			pixmp_op->colorspace =
				iris_hfi_get_v4l2_color_primaries(primaries);
			pixmp_op->xfer_func =
				iris_hfi_get_v4l2_transfer_char(transfer_char);
			pixmp_op->ycbcr_enc =
				iris_hfi_get_v4l2_matrix_coefficients(matrix_coeff);
		}
	}

	pixmp_ip->colorspace = pixmp_op->colorspace;
	pixmp_ip->xfer_func = pixmp_op->xfer_func;
	pixmp_ip->ycbcr_enc = pixmp_op->ycbcr_enc;
	pixmp_ip->quantization = pixmp_op->quantization;

	inst->crop.top = subsc_params.crop_offsets[0] & 0xFFFF;
	inst->crop.left = (subsc_params.crop_offsets[0] >> 16) & 0xFFFF;
	inst->crop.height = pixmp_ip->height -
		(subsc_params.crop_offsets[1] & 0xFFFF) - inst->crop.top;
	inst->crop.width = pixmp_ip->width -
		((subsc_params.crop_offsets[1] >> 16) & 0xFFFF) - inst->crop.left;

	inst->cap[PROFILE].value = subsc_params.profile;
	inst->cap[LEVEL].value = subsc_params.level;
	inst->cap[POC].value = subsc_params.pic_order_cnt;

	if (subsc_params.bit_depth != BIT_DEPTH_8 ||
	    !(subsc_params.coded_frames & HFI_BITMASK_FRAME_MBS_ONLY_FLAG)) {
		dev_err(core->dev, "unsupported content, bit depth: %x, pic_struct = %x\n",
			subsc_params.bit_depth, subsc_params.coded_frames);
		iris_inst_change_state(inst, IRIS_INST_ERROR);
	}

	inst->fw_min_count = subsc_params.fw_min_count;
	inst->buffers.output.min_count = iris_vpu_buf_count(inst, BUF_OUTPUT);
}

static int iris_hfi_2_handle_src_change(struct iris_inst *inst,
					struct iris_hfi_packet *pkt)
{
	int ret;

	if (pkt->port != HFI_PORT_BITSTREAM)
		return 0;

	ret = iris_inst_sub_state_change_drc(inst);
	if (ret)
		return ret;

	iris_hfi_2_read_input_subcr_params(inst);
	iris_vdec_src_change(inst);

	return 0;
}

static int iris_hfi_2_handle_session_command(struct iris_inst *inst,
					     struct iris_hfi_packet *pkt)
{
	int i, ret = 0;
	static const struct iris_hfi_2_packet_handle hfi_pkt_handle[] = {
		{HFI_CMD_OPEN,              NULL                              },
		{HFI_CMD_CLOSE,             iris_hfi_2_handle_session_close   },
		{HFI_CMD_START,             NULL                              },
		{HFI_CMD_STOP,              iris_hfi_2_handle_session_stop    },
		{HFI_CMD_DRAIN,             iris_hfi_2_handle_session_drain   },
		{HFI_CMD_BUFFER,            iris_hfi_2_handle_session_buffer  },
		{HFI_CMD_SETTINGS_CHANGE,   iris_hfi_2_handle_src_change      },
		{HFI_CMD_SUBSCRIBE_MODE,    NULL                              },
		{HFI_CMD_PAUSE,             NULL                              },
		{HFI_CMD_RESUME,            NULL                              },
	};

	for (i = 0; i < ARRAY_SIZE(hfi_pkt_handle); i++) {
		if (hfi_pkt_handle[i].type == pkt->type) {
			if (hfi_pkt_handle[i].handle) {
				ret = hfi_pkt_handle[i].handle(inst, pkt);
				if (ret)
					return ret;
			}
			break;
		}
	}

	if (i == ARRAY_SIZE(hfi_pkt_handle))
		return -EINVAL;

	return ret;
}

static int iris_hfi_2_handle_session_property(struct iris_inst *inst,
					      struct iris_hfi_packet *pkt)
{
	u32 *payload_ptr = NULL;
	int ret = 0;

	if (pkt->port != HFI_PORT_BITSTREAM)
		return 0;

	if (pkt->flags & HFI_FW_FLAGS_INFORMATION)
		return 0;

	payload_ptr = (u32 *)((u8 *)pkt + sizeof(*pkt));
	if (!payload_ptr)
		return -EINVAL;

	switch (pkt->type) {
	case HFI_PROP_BITSTREAM_RESOLUTION:
		inst->src_subcr_params.bitstream_resolution = payload_ptr[0];
		break;
	case HFI_PROP_CROP_OFFSETS:
		inst->src_subcr_params.crop_offsets[0] = payload_ptr[0];
		inst->src_subcr_params.crop_offsets[1] = payload_ptr[1];
		break;
	case HFI_PROP_CODED_FRAMES:
		inst->src_subcr_params.coded_frames = payload_ptr[0];
		break;
	case HFI_PROP_BUFFER_FW_MIN_OUTPUT_COUNT:
		inst->src_subcr_params.fw_min_count = payload_ptr[0];
		break;
	case HFI_PROP_PIC_ORDER_CNT_TYPE:
		inst->src_subcr_params.pic_order_cnt = payload_ptr[0];
		break;
	case HFI_PROP_SIGNAL_COLOR_INFO:
		inst->src_subcr_params.color_info = payload_ptr[0];
		break;
	case HFI_PROP_PROFILE:
		inst->src_subcr_params.profile = payload_ptr[0];
		break;
	case HFI_PROP_LEVEL:
		inst->src_subcr_params.level = payload_ptr[0];
		break;
	case HFI_PROP_PICTURE_TYPE:
		inst->hfi_frame_info.picture_type = payload_ptr[0];
		break;
	case HFI_PROP_NO_OUTPUT:
		inst->hfi_frame_info.no_output = 1;
		break;
	case HFI_PROP_QUALITY_MODE:
	case HFI_PROP_STAGE:
	case HFI_PROP_PIPE:
		break;
	default:
		break;
	}

	return ret;
}

static int iris_hfi_2_handle_image_version_property(struct iris_core *core,
						    struct iris_hfi_packet *pkt)
{
	u8 *str_image_version;
	u32 req_bytes;
	u32 i = 0;

	req_bytes = pkt->size - sizeof(*pkt);
	if (req_bytes < IRIS_FW_VERSION_LENGTH - 1)
		return -EINVAL;

	str_image_version = (u8 *)pkt + sizeof(*pkt);

	for (i = 0; i < IRIS_FW_VERSION_LENGTH - 1; i++) {
		if (str_image_version[i] != '\0')
			core->fw_version[i] = str_image_version[i];
		else
			core->fw_version[i] = ' ';
	}
	core->fw_version[i] = '\0';

	return 0;
}

static int iris_hfi_2_handle_system_property(struct iris_core *core,
					     struct iris_hfi_packet *pkt)
{
	int ret = 0;

	switch (pkt->type) {
	case HFI_PROP_IMAGE_VERSION:
		ret = iris_hfi_2_handle_image_version_property(core, pkt);
		break;
	default:
		break;
	}

	return ret;
}

static int iris_hfi_2_handle_system_response(struct iris_core *core,
					     struct iris_hfi_header *hdr)
{
	struct iris_hfi_packet *packet;
	u8 *pkt, *start_pkt;
	int ret = 0;
	int i, j;
	static const struct iris_hfi_2_core_hfi_range range[] = {
		{HFI_SYSTEM_ERROR_BEGIN, HFI_SYSTEM_ERROR_END, iris_hfi_2_handle_system_error   },
		{HFI_PROP_BEGIN,         HFI_PROP_END,         iris_hfi_2_handle_system_property},
		{HFI_CMD_BEGIN,          HFI_CMD_END,          iris_hfi_2_handle_system_init    },
	};

	start_pkt = (u8 *)((u8 *)hdr + sizeof(*hdr));
	for (i = 0; i < ARRAY_SIZE(range); i++) {
		pkt = start_pkt;
		for (j = 0; j < hdr->num_packets; j++) {
			packet = (struct iris_hfi_packet *)pkt;
			if (packet->flags & HFI_FW_FLAGS_SYSTEM_ERROR) {
				ret = iris_hfi_2_handle_system_error(core, packet);
				return ret;
			}

			if (packet->type > range[i].begin && packet->type < range[i].end) {
				ret = range[i].handle(core, packet);
				if (ret)
					return ret;

				if (packet->type >  HFI_SYSTEM_ERROR_BEGIN &&
				    packet->type < HFI_SYSTEM_ERROR_END)
					return 0;
			}
			pkt += packet->size;
		}
	}

	return ret;
}

static void iris_hfi_2_init_src_change_param(struct iris_inst *inst)
{
	u32 left_offset, top_offset, right_offset, bottom_offset;
	struct v4l2_pix_format_mplane *pixmp_ip, *pixmp_op;
	u32 primaries, matrix_coeff, transfer_char;
	struct hfi_subscription_params *subsc_params;
	u32 colour_description_present_flag = 0;
	u32 video_signal_type_present_flag = 0;
	u32 full_range = 0, video_format = 0;

	subsc_params = &inst->src_subcr_params;
	pixmp_ip = &inst->fmt_src->fmt.pix_mp;
	pixmp_op = &inst->fmt_dst->fmt.pix_mp;

	subsc_params->bitstream_resolution =
		pixmp_ip->width << 16 | pixmp_ip->height;

	left_offset = inst->crop.left;
	top_offset = inst->crop.top;
	right_offset = (pixmp_ip->width - inst->crop.width);
	bottom_offset = (pixmp_ip->height - inst->crop.height);
	subsc_params->crop_offsets[0] =
			left_offset << 16 | top_offset;
	subsc_params->crop_offsets[1] =
			right_offset << 16 | bottom_offset;

	subsc_params->fw_min_count = inst->buffers.output.min_count;

	primaries = iris_hfi_2_get_color_primaries(pixmp_op->colorspace);
	matrix_coeff = iris_hfi_2_get_matrix_coefficients(pixmp_op->ycbcr_enc);
	transfer_char = iris_hfi_2_get_transfer_char(pixmp_op->xfer_func);
	full_range = pixmp_op->quantization == V4L2_QUANTIZATION_FULL_RANGE ? 1 : 0;
	subsc_params->color_info =
		(matrix_coeff & 0xFF) |
		((transfer_char << 8) & 0xFF00) |
		((primaries << 16) & 0xFF0000) |
		((colour_description_present_flag << 24) & 0x1000000) |
		((full_range << 25) & 0x2000000) |
		((video_format << 26) & 0x1C000000) |
		((video_signal_type_present_flag << 29) & 0x20000000);

	subsc_params->profile = inst->cap[PROFILE].value;
	subsc_params->level = inst->cap[LEVEL].value;
	subsc_params->pic_order_cnt = inst->cap[POC].value;
	subsc_params->bit_depth = inst->cap[BIT_DEPTH].value;
	if (inst->cap[CODED_FRAMES].value ==
			CODED_FRAMES_PROGRESSIVE)
		subsc_params->coded_frames = HFI_BITMASK_FRAME_MBS_ONLY_FLAG;
	else
		subsc_params->coded_frames = 0;
}

static int iris_hfi_2_handle_session_response(struct iris_core *core,
					      struct iris_hfi_header *hdr)
{
	struct iris_hfi_packet *packet;
	struct iris_inst *inst;
	bool dequeue = false;
	u8 *pkt, *start_pkt;
	int ret = 0;
	int i, j;
	static const struct iris_hfi_2_inst_hfi_range range[] = {
		{HFI_SESSION_ERROR_BEGIN, HFI_SESSION_ERROR_END,
		 iris_hfi_2_handle_session_error},
		{HFI_INFORMATION_BEGIN, HFI_INFORMATION_END,
		 iris_hfi_2_handle_session_info},
		{HFI_PROP_BEGIN, HFI_PROP_END,
		 iris_hfi_2_handle_session_property},
		{HFI_CMD_BEGIN, HFI_CMD_END,
		 iris_hfi_2_handle_session_command },
	};

	inst = iris_get_instance(core, hdr->session_id);
	if (!inst)
		return -EINVAL;

	mutex_lock(&inst->lock);
	memset(&inst->hfi_frame_info, 0, sizeof(struct iris_hfi_frame_info));

	pkt = (u8 *)((u8 *)hdr + sizeof(*hdr));
	for (i = 0; i < hdr->num_packets; i++) {
		packet = (struct iris_hfi_packet *)pkt;
		if (packet->type == HFI_CMD_SETTINGS_CHANGE) {
			if (packet->port == HFI_PORT_BITSTREAM) {
				iris_hfi_2_init_src_change_param(inst);
				break;
			}
		}
		pkt += packet->size;
	}

	start_pkt = (u8 *)((u8 *)hdr + sizeof(*hdr));
	for (i = 0; i < ARRAY_SIZE(range); i++) {
		pkt = start_pkt;
		for (j = 0; j < hdr->num_packets; j++) {
			packet = (struct iris_hfi_packet *)pkt;
			if (packet->flags & HFI_FW_FLAGS_SESSION_ERROR)
				iris_hfi_2_handle_session_error(inst, packet);

			if (packet->type > range[i].begin && packet->type < range[i].end) {
				dequeue |= (packet->type == HFI_CMD_BUFFER);
				ret = range[i].handle(inst, packet);
				if (ret)
					iris_inst_change_state(inst, IRIS_INST_ERROR);
			}
			pkt += packet->size;
		}
	}

	if (dequeue) {
		ret = iris_hfi_2_handle_dequeue_buffers(inst);
		if (ret)
			goto unlock;
	}

	memset(&inst->hfi_frame_info, 0, sizeof(struct iris_hfi_frame_info));

unlock:
	mutex_unlock(&inst->lock);

	return ret;
}

static int iris_hfi_2_handle_response(struct iris_core *core, void *response)
{
	struct iris_hfi_header *hdr;
	int ret;

	hdr = (struct iris_hfi_header *)response;
	ret = iris_hfi_2_validate_hdr_packet(core, hdr);
	if (ret)
		return iris_hfi_2_handle_system_error(core, NULL);

	if (!hdr->session_id)
		return iris_hfi_2_handle_system_response(core, hdr);
	else
		return iris_hfi_2_handle_session_response(core, hdr);
}

static void iris_hfi_2_flush_debug_queue(struct iris_core *core,
					 u8 *packet, u32 packet_size)
{
	struct hfi_debug_header *pkt;
	bool local_packet = false;
	u8 *log;

	if (!packet || !packet_size) {
		packet = kzalloc(IFACEQ_CORE_PKT_SIZE, GFP_KERNEL);
		if (!packet)
			return;

		packet_size = IFACEQ_CORE_PKT_SIZE;

		local_packet = true;
	}

	while (!iris_hfi_queue_dbg_read(core, packet)) {
		pkt = (struct hfi_debug_header *)packet;

		if (pkt->size < sizeof(*pkt))
			continue;

		if (pkt->size >= packet_size)
			continue;

		packet[pkt->size] = '\0';
		log = (u8 *)packet + sizeof(*pkt) + 1;
		dev_dbg(core->dev, "%s", log);
	}

	if (local_packet)
		kfree(packet);
}

static void iris_hfi_2_response_handler(struct iris_core *core)
{
	if (iris_vpu_watchdog(core, core->intr_status)) {
		struct iris_hfi_packet pkt = {.type = HFI_SYS_ERROR_WD_TIMEOUT};

		dev_err(core->dev, "%s: cpu watchdog error received\n", __func__);
		iris_change_core_state(core, IRIS_CORE_ERROR);
		iris_hfi_2_handle_system_error(core, &pkt);

		return;
	}

	memset(core->response_packet, 0, sizeof(struct iris_hfi_header));
	while (!iris_hfi_queue_msg_read(core, core->response_packet)) {
		iris_hfi_2_handle_response(core, core->response_packet);
		if (core->state != IRIS_CORE_INIT)
			break;
		memset(core->response_packet, 0, sizeof(struct iris_hfi_header));
	}

	iris_hfi_2_flush_debug_queue(core, core->response_packet, core->packet_size);
}

static const struct iris_hfi_response_ops iris_hfi_2_response_ops = {
	.hfi_response_handler = iris_hfi_2_response_handler,
};

void iris_hfi_2_response_ops_init(struct iris_core *core)
{
	core->hfi_response_ops = &iris_hfi_2_response_ops;
}
