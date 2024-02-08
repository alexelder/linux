// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */
#include <linux/types.h>
#include <media/v4l2-mem2mem.h>

#include "iris_buffer_helpers.h"
#include "iris_hfi_1.h"
#include "iris_hfi_1_defines.h"
#include "iris_hfi_1_response.h"
#include "iris_instance.h"
#include "iris_vdec.h"
#include "iris_vpu_buffer.h"

static void iris_hfi_1_read_changed_params(struct iris_inst *inst,
					   struct hfi_msg_event_notify_pkt *pkt)
{
	struct v4l2_pix_format_mplane *pixmp_ip, *pixmp_op;
	u32 primaries, matrix_coeff, transfer_char;
	struct hfi_profile_level *profile_level;
	u32 colour_description_present_flag = 0;
	struct hfi_buffer_requirements *bufreq;
	u32 video_signal_type_present_flag = 0;
	struct hfi_extradata_input_crop *crop;
	struct hfi_colour_space *colour_info;
	struct hfi_event_data event = {0};
	struct hfi_bit_depth *pixel_depth;
	struct hfi_pic_struct *pic_struct;
	struct hfi_dpb_counts *iris_vpu_dpb_count;
	struct hfi_framesize *frame_sz;
	int num_properties_changed;
	struct iris_core *core;
	u32 full_range = 0;
	u8 *data_ptr;
	u32 ptype;

	pixmp_ip = &inst->fmt_src->fmt.pix_mp;
	pixmp_op = &inst->fmt_dst->fmt.pix_mp;
	num_properties_changed = pkt->event_data2;

	core = inst->core;

	data_ptr = (u8 *)&pkt->ext_event_data[0];
	do {
		ptype = *((u32 *)data_ptr);
		switch (ptype) {
		case HFI_PROPERTY_PARAM_FRAME_SIZE:
			data_ptr += sizeof(u32);
			frame_sz = (struct hfi_framesize *)data_ptr;
			event.width = frame_sz->width;
			event.height = frame_sz->height;
			data_ptr += sizeof(*frame_sz);
			break;
		case HFI_PROPERTY_PARAM_PROFILE_LEVEL_CURRENT:
			data_ptr += sizeof(u32);
			profile_level = (struct hfi_profile_level *)data_ptr;
			event.profile = profile_level->profile;
			event.level = profile_level->level;
			data_ptr += sizeof(*profile_level);
			break;
		case HFI_PROPERTY_PARAM_VDEC_PIXEL_BITDEPTH:
			data_ptr += sizeof(u32);
			pixel_depth = (struct hfi_bit_depth *)data_ptr;
			event.bit_depth = pixel_depth->bit_depth;
			data_ptr += sizeof(*pixel_depth);
			break;
		case HFI_PROPERTY_PARAM_VDEC_PIC_STRUCT:
			data_ptr += sizeof(u32);
			pic_struct = (struct hfi_pic_struct *)data_ptr;
			event.pic_struct = pic_struct->progressive_only;
			data_ptr += sizeof(*pic_struct);
			break;
		case HFI_PROPERTY_PARAM_VDEC_COLOUR_SPACE:
			data_ptr += sizeof(u32);
			colour_info = (struct hfi_colour_space *)data_ptr;
			event.colour_space = colour_info->colour_space;
			data_ptr += sizeof(*colour_info);
			break;
		case HFI_PROPERTY_CONFIG_VDEC_ENTROPY:
			data_ptr += sizeof(u32);
			event.entropy_mode = *(u32 *)data_ptr;
			data_ptr += sizeof(u32);
			break;
		case HFI_PROPERTY_CONFIG_BUFFER_REQUIREMENTS:
			data_ptr += sizeof(u32);
			bufreq = (struct hfi_buffer_requirements *)data_ptr;
			event.buf_count = bufreq->count_min;
			data_ptr += sizeof(*bufreq);
			break;
		case HFI_INDEX_EXTRADATA_INPUT_CROP:
			data_ptr += sizeof(u32);
			crop = (struct hfi_extradata_input_crop *)data_ptr;
			event.input_crop.left = crop->left;
			event.input_crop.top = crop->top;
			event.input_crop.width = crop->width;
			event.input_crop.height = crop->height;
			data_ptr += sizeof(*crop);
			break;
		case HFI_PROPERTY_PARAM_VDEC_DPB_COUNTS:
			data_ptr += sizeof(u32);
			iris_vpu_dpb_count = (struct hfi_dpb_counts *)data_ptr;
			event.buf_count = iris_vpu_dpb_count->fw_min_count;
			data_ptr += sizeof(*iris_vpu_dpb_count);
			break;
		default:
			break;
		}
		num_properties_changed--;
	} while (num_properties_changed > 0);

	pixmp_ip->width = event.width;
	pixmp_ip->height = event.height;

	pixmp_op->width = ALIGN(event.width, 128);
	pixmp_op->height = ALIGN(event.height, 32);
	pixmp_op->plane_fmt[0].bytesperline = ALIGN(event.width, 128);
	pixmp_op->plane_fmt[0].sizeimage = iris_get_buffer_size(inst, BUF_OUTPUT);

	matrix_coeff = event.colour_space & 0xFF;
	transfer_char = (event.colour_space & 0xFF00) >> 8;
	primaries = (event.colour_space & 0xFF0000) >> 16;
	colour_description_present_flag =
		(event.colour_space & 0x1000000) >> 24;
	full_range = (event.colour_space & 0x2000000) >> 25;
	video_signal_type_present_flag =
		(event.colour_space & 0x20000000) >> 29;

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

	if (event.input_crop.width > 0 && event.input_crop.height > 0) {
		inst->crop.left = event.input_crop.left;
		inst->crop.top = event.input_crop.top;
		inst->crop.width = event.input_crop.width;
		inst->crop.height = event.input_crop.height;
	} else {
		inst->crop.left = 0;
		inst->crop.top = 0;
		inst->crop.width = event.width;
		inst->crop.height = event.height;
	}

	inst->fw_min_count = event.buf_count;
	inst->buffers.output.min_count = iris_vpu_buf_count(inst, BUF_OUTPUT);

	if (event.bit_depth || !event.pic_struct) {
		dev_err(core->dev, "unsupported content, bit depth: %x, pic_struct = %x\n",
			event.bit_depth, event.pic_struct);
		iris_inst_change_state(inst, IRIS_INST_ERROR);
	}
}

static int iris_hfi_1_event_seq_changed(struct iris_inst *inst,
					struct hfi_msg_event_notify_pkt *pkt)
{
	struct hfi_session_flush_pkt flush_pkt;
	int num_properties_changed;
	int ret;

	ret = iris_inst_sub_state_change_drc(inst);
	if (ret)
		return ret;

	switch (pkt->event_data1) {
	case HFI_EVENT_DATA_SEQUENCE_CHANGED_SUFFICIENT_BUF_RESOURCES:
	case HFI_EVENT_DATA_SEQUENCE_CHANGED_INSUFFICIENT_BUF_RESOURCES:
		break;
	default:
		iris_inst_change_state(inst, IRIS_INST_ERROR);
		return HFI_ERR_SESSION_INVALID_PARAMETER;
	}

	num_properties_changed = pkt->event_data2;
	if (!num_properties_changed) {
		iris_inst_change_state(inst, IRIS_INST_ERROR);
		return HFI_ERR_SESSION_INSUFFICIENT_RESOURCES;
	}

	iris_hfi_1_read_changed_params(inst, pkt);

	reinit_completion(&inst->flush_completion);

	flush_pkt.shdr.hdr.size = sizeof(struct hfi_session_flush_pkt);
	flush_pkt.shdr.hdr.pkt_type = HFI_CMD_SESSION_FLUSH;
	flush_pkt.shdr.session_id = inst->session_id;
	flush_pkt.flush_type = HFI_FLUSH_OUTPUT;
	iris_hfi_queue_cmd_write(inst->core, &flush_pkt, flush_pkt.shdr.hdr.size);

	iris_vdec_src_change(inst);

	return iris_inst_sub_state_change_drc_last(inst);
}

static void
iris_hfi_1_sys_event_notify(struct iris_core *core, void *packet)
{
	struct hfi_msg_event_notify_pkt *pkt = packet;

	if (pkt->event_id == HFI_EVENT_SYS_ERROR)
		dev_err(core->dev, "sys error (type: %x, session id:%x, data1:%x, data2:%x)\n",
			pkt->event_id, pkt->shdr.session_id, pkt->event_data1,
			pkt->event_data2);

	iris_change_core_state(core, IRIS_CORE_ERROR);
	schedule_delayed_work(&core->sys_error_handler, msecs_to_jiffies(10));
}

static void
iris_hfi_1_event_session_error(struct iris_inst *inst, struct hfi_msg_event_notify_pkt *pkt)
{
	switch (pkt->event_data1) {
	/* non fatal session errors */
	case HFI_ERR_SESSION_INVALID_SCALE_FACTOR:
	case HFI_ERR_SESSION_UNSUPPORT_BUFFERTYPE:
	case HFI_ERR_SESSION_UNSUPPORTED_SETTING:
	case HFI_ERR_SESSION_UPSCALE_NOT_SUPPORTED:
		dev_dbg(inst->core->dev, "session error: event id:%x, session id:%x\n",
			pkt->event_data1, pkt->shdr.session_id);
		break;
	default:
		dev_err(inst->core->dev, "session error: event id:%x (%x), session id:%x\n",
			pkt->event_data1, pkt->event_data2,
			pkt->shdr.session_id);
		iris_vb2_queue_error(inst);
		iris_inst_change_state(inst, IRIS_INST_ERROR);
		break;
	}
}

static void iris_hfi_1_event_release_buffer_ref(struct hfi_msg_event_notify_pkt *pkt)
{
	struct hfi_msg_iris_hfi_1_event_release_buffer_ref_pkt *data;
	struct hfi_event_data event = {0};

	data = (struct hfi_msg_iris_hfi_1_event_release_buffer_ref_pkt *)
		pkt->ext_event_data;

	event.event_type = HFI_EVENT_RELEASE_BUFFER_REFERENCE;
	event.packet_buffer = data->packet_buffer;
	event.extradata_buffer = data->extradata_buffer;
	event.tag = data->output_tag;
}

static void iris_hfi_1_session_event_notify(struct iris_inst *inst, void *packet)
{
	struct hfi_msg_event_notify_pkt *pkt = packet;

	if (!packet)
		return;

	switch (pkt->event_id) {
	case HFI_EVENT_SESSION_ERROR:
		iris_hfi_1_event_session_error(inst, pkt);
		break;
	case HFI_EVENT_SESSION_SEQUENCE_CHANGED:
		iris_hfi_1_event_seq_changed(inst, pkt);
		break;
	case HFI_EVENT_RELEASE_BUFFER_REFERENCE:
		iris_hfi_1_event_release_buffer_ref(pkt);
		break;
	case HFI_EVENT_SESSION_PROPERTY_CHANGED:
		break;
	default:
		break;
	}
}

static void iris_hfi_1_sys_init_done(struct iris_core *core, void *packet)
{
	struct hfi_msg_sys_init_done_pkt *pkt = packet;

	if (pkt->error_type != HFI_ERR_NONE) {
		iris_change_core_state(core, IRIS_CORE_ERROR);
		return;
	}

	iris_change_core_state(core, IRIS_CORE_INIT);
	complete(&core->core_init_done);
}

static void
iris_hfi_1_sys_get_prop_image_version(struct iris_core *core,
				      struct hfi_msg_sys_property_info_pkt *pkt)
{
	int req_bytes;
	u8 *img_ver;
	u32 i;

	req_bytes = pkt->hdr.size - sizeof(*pkt);

	if (req_bytes < IRIS_FW_VERSION_LENGTH - 1 || !pkt->data[0] || pkt->num_properties > 1)
		/* bad packet */
		return;

	img_ver = pkt->data;
	if (!img_ver)
		return;

	for (i = 0; i < IRIS_FW_VERSION_LENGTH - 1; i++) {
		if (img_ver[i] != '\0')
			core->fw_version[i] = img_ver[i];
		else
			core->fw_version[i] = ' ';
	}
	core->fw_version[i] = '\0';

	dev_dbg(core->dev, "F/W version: %s\n", img_ver);
}

static void iris_hfi_1_sys_property_info(struct iris_core *core, void *packet)
{
	struct hfi_msg_sys_property_info_pkt *pkt = packet;

	if (!pkt->num_properties) {
		dev_dbg(core->dev, "no properties\n");
		return;
	}

	switch (pkt->property) {
	case HFI_PROPERTY_SYS_IMAGE_VERSION:
		iris_hfi_1_sys_get_prop_image_version(core, pkt);
		break;
	default:
		dev_dbg(core->dev, "unknown property data\n");
		break;
	}
}

static void iris_hfi_1_session_init_done(struct iris_inst *inst, void *packet)
{
	struct hfi_msg_session_init_done_pkt *pkt = packet;

	if (pkt->error_type != HFI_ERR_NONE)
		iris_inst_change_state(inst, IRIS_INST_ERROR);

	complete(&inst->completion);
}

static void iris_hfi_1_session_load_res_done(struct iris_inst *inst, void *packet)
{
	struct hfi_msg_session_load_resources_done_pkt *pkt = packet;

	if (pkt->error_type != HFI_ERR_NONE)
		iris_inst_change_state(inst, IRIS_INST_ERROR);

	complete(&inst->completion);
}

static void iris_hfi_1_session_flush_done(struct iris_inst *inst, void *packet)
{
	struct hfi_msg_session_flush_done_pkt *pkt = packet;

	if (pkt->error_type != HFI_ERR_NONE)
		iris_inst_change_state(inst, IRIS_INST_ERROR);

	complete(&inst->flush_completion);
}

static void iris_hfi_1_session_etb_done(struct iris_inst *inst, void *packet)
{
	struct hfi_msg_session_empty_buffer_done_pkt *pkt = packet;
	struct v4l2_m2m_ctx *m2m_ctx = inst->m2m_ctx;
	struct v4l2_m2m_buffer *m2m_buffer, *n;
	struct iris_buffer *buf = NULL;
	bool found;

	v4l2_m2m_for_each_src_buf_safe(m2m_ctx, m2m_buffer, n) {
		buf = to_iris_buffer(&m2m_buffer->vb);
		if (buf->index == pkt->input_tag) {
			found = true;
			break;
		}
	}
	if (!found)
		goto error;

	if (!(buf->attr & BUF_ATTR_QUEUED))
		return;

	buf->data_size = pkt->filled_len;
	buf->attr &= ~BUF_ATTR_QUEUED;

	if (!(buf->attr & BUF_ATTR_BUFFER_DONE)) {
		buf->attr |= BUF_ATTR_BUFFER_DONE;
		iris_vb2_buffer_done(inst, buf);
	}

	return;

error:
	iris_inst_change_state(inst, IRIS_INST_ERROR);
	dev_err(inst->core->dev, "%s: error in etb done\n", __func__);
}

static void iris_hfi_1_session_ftb_done(struct iris_inst *inst, void *packet)
{
	struct hfi_msg_session_fbd_uncompressed_plane0_pkt *pkt = packet;
	u32 flags = 0, hfi_flags = 0, offset = 0, filled_len = 0;
	struct v4l2_m2m_ctx *m2m_ctx = inst->m2m_ctx;
	struct v4l2_m2m_buffer *m2m_buffer, *n;
	u32 timestamp_hi = 0, timestamp_lo = 0;
	struct hfi_session_flush_pkt flush_pkt;
	struct iris_buffer *buf = NULL, *iter;
	u32 pic_type = 0, output_tag = -1;
	struct iris_buffers *buffers;
	struct iris_core *core;
	u64 timestamp_us = 0;
	bool found;

	core = inst->core;

	timestamp_hi = pkt->time_stamp_hi;
	timestamp_lo = pkt->time_stamp_lo;
	hfi_flags = pkt->flags;
	offset = pkt->offset;
	filled_len = pkt->filled_len;
	pic_type = pkt->picture_type;
	output_tag = pkt->output_tag;

	if ((hfi_flags & HFI_BUFFERFLAG_EOS) && !filled_len) {
		reinit_completion(&inst->flush_completion);

		flush_pkt.shdr.hdr.size = sizeof(struct hfi_session_flush_pkt);
		flush_pkt.shdr.hdr.pkt_type = HFI_CMD_SESSION_FLUSH;
		flush_pkt.shdr.session_id = inst->session_id;
		flush_pkt.flush_type = HFI_FLUSH_OUTPUT;
		iris_hfi_queue_cmd_write(core, &flush_pkt, flush_pkt.shdr.hdr.size);
		iris_inst_sub_state_change_drain_last(inst);

		return;
	}

	if (iris_split_mode_enabled(inst) && pkt->stream_id == 0) {
		buffers = iris_get_buffer_list(inst, BUF_DPB);
		if (!buffers)
			goto error;

		found = false;
		list_for_each_entry(iter, &buffers->list, list) {
			if (!(iter->attr & BUF_ATTR_QUEUED))
				continue;

			found = (iter->index == output_tag &&
				iter->data_offset == offset);

			if (found) {
				buf = iter;
				break;
			}
		}
	} else {
		v4l2_m2m_for_each_dst_buf_safe(m2m_ctx, m2m_buffer, n) {
			buf = to_iris_buffer(&m2m_buffer->vb);
			if (!(buf->attr & BUF_ATTR_QUEUED))
				continue;

			found = (buf->index == output_tag &&
				 buf->data_offset == offset);

			if (found)
				break;
		}
	}
	if (!found)
		goto error;

	buf->data_offset = offset;
	buf->data_size = filled_len;

	if (!(hfi_flags & HFI_BUFFERFLAG_TIMESTAMPINVALID) && filled_len) {
		timestamp_us = timestamp_hi;
		timestamp_us = (timestamp_us << 32) | timestamp_lo;
	}
	buf->timestamp = timestamp_us;

	switch (pic_type) {
	case HFI_PICTURE_IDR:
	case HFI_PICTURE_I:
		flags |= V4L2_BUF_FLAG_KEYFRAME;
		break;
	case HFI_PICTURE_P:
		flags |= V4L2_BUF_FLAG_PFRAME;
		break;
	case HFI_PICTURE_B:
		flags |= V4L2_BUF_FLAG_BFRAME;
		break;
	case HFI_FRAME_NOTCODED:
	case HFI_UNUSED_PICT:
	case HFI_FRAME_YUV:
	default:
		break;
	}

	buf->attr &= ~BUF_ATTR_QUEUED;
	buf->attr |= BUF_ATTR_DEQUEUED;
	buf->attr |= BUF_ATTR_BUFFER_DONE;

	buf->flags = flags;

	iris_vb2_buffer_done(inst, buf);

	return;

error:
	iris_inst_change_state(inst, IRIS_INST_ERROR);
	dev_err(core->dev, "%s: error in ftb done\n", __func__);
}

static void iris_hfi_1_session_start_done(struct iris_inst *inst, void *packet)
{
	struct hfi_msg_session_start_done_pkt *pkt = packet;

	if (pkt->error_type != HFI_ERR_NONE)
		iris_inst_change_state(inst, IRIS_INST_ERROR);

	complete(&inst->completion);
}

static void iris_hfi_1_session_stop_done(struct iris_inst *inst, void *packet)
{
	struct hfi_msg_session_stop_done_pkt *pkt = packet;

	if (pkt->error_type != HFI_ERR_NONE)
		iris_inst_change_state(inst, IRIS_INST_ERROR);

	complete(&inst->completion);
}

static void iris_hfi_1_session_rel_res_done(struct iris_inst *inst, void *packet)
{
	struct hfi_msg_session_release_resources_done_pkt *pkt = packet;

	if (pkt->error_type != HFI_ERR_NONE)
		iris_inst_change_state(inst, IRIS_INST_ERROR);

	complete(&inst->completion);
}

static void iris_hfi_1_session_rel_buf_done(struct iris_inst *inst, void *packet)
{
	struct hfi_msg_session_release_buffers_done_pkt *pkt = packet;

	if (pkt->error_type != HFI_ERR_NONE)
		iris_inst_change_state(inst, IRIS_INST_ERROR);

	complete(&inst->completion);
}

static void iris_hfi_1_session_end_done(struct iris_inst *inst, void *packet)
{
	struct hfi_msg_session_end_done_pkt *pkt = packet;

	if (pkt->error_type != HFI_ERR_NONE)
		iris_inst_change_state(inst, IRIS_INST_ERROR);

	complete(&inst->completion);
}

static void iris_hfi_1_session_abort_done(struct iris_inst *inst, void *packet)
{
	struct hfi_msg_sys_session_abort_done_pkt *pkt = packet;

	if (pkt->error_type != HFI_ERR_NONE)
		iris_inst_change_state(inst, IRIS_INST_ERROR);

	complete(&inst->completion);
}

static void iris_hfi_1_session_get_seq_hdr_done(struct iris_inst *inst, void *packet)
{
	struct hfi_msg_session_get_sequence_hdr_done_pkt *pkt = packet;

	if (pkt->error_type != HFI_ERR_NONE)
		iris_inst_change_state(inst, IRIS_INST_ERROR);

	complete(&inst->completion);
}

struct iris_hfi_1_done_handler {
	u32 pkt;
	u32 pkt_sz;
	void (*session_done)(struct iris_inst *inst, void *packet);
	void (*sys_done)(struct iris_core *core, void *packet);
};

static const struct iris_hfi_1_done_handler handlers[] = {
	{.pkt = HFI_MSG_EVENT_NOTIFY,
	 .pkt_sz = sizeof(struct hfi_msg_event_notify_pkt),
	 .session_done = iris_hfi_1_session_event_notify,
	 .sys_done = iris_hfi_1_sys_event_notify,
	},
	{.pkt = HFI_MSG_SYS_INIT,
	 .pkt_sz = sizeof(struct hfi_msg_sys_init_done_pkt),
	 .session_done = NULL,
	 .sys_done = iris_hfi_1_sys_init_done,
	},
	{.pkt = HFI_MSG_SYS_PROPERTY_INFO,
	 .pkt_sz = sizeof(struct hfi_msg_sys_property_info_pkt),
	 .session_done = NULL,
	 .sys_done = iris_hfi_1_sys_property_info,
	},
	{.pkt = HFI_MSG_SYS_SESSION_INIT,
	 .pkt_sz = sizeof(struct hfi_msg_session_init_done_pkt),
	 .session_done = iris_hfi_1_session_init_done,
	 .sys_done = NULL,
	},
	{.pkt = HFI_MSG_SYS_SESSION_END,
	 .pkt_sz = sizeof(struct hfi_msg_session_end_done_pkt),
	 .session_done = iris_hfi_1_session_end_done,
	 .sys_done = NULL,
	},
	{.pkt = HFI_MSG_SESSION_LOAD_RESOURCES,
	 .pkt_sz = sizeof(struct hfi_msg_session_load_resources_done_pkt),
	 .session_done = iris_hfi_1_session_load_res_done,
	 .sys_done = NULL,
	},
	{.pkt = HFI_MSG_SESSION_START,
	 .pkt_sz = sizeof(struct hfi_msg_session_start_done_pkt),
	 .session_done = iris_hfi_1_session_start_done,
	 .sys_done = NULL,
	},
	{.pkt = HFI_MSG_SESSION_STOP,
	 .pkt_sz = sizeof(struct hfi_msg_session_stop_done_pkt),
	 .session_done = iris_hfi_1_session_stop_done,
	 .sys_done = NULL,
	},
	{.pkt = HFI_MSG_SYS_SESSION_ABORT,
	 .pkt_sz = sizeof(struct hfi_msg_sys_session_abort_done_pkt),
	 .session_done = iris_hfi_1_session_abort_done,
	 .sys_done = NULL,
	},
	{.pkt = HFI_MSG_SESSION_EMPTY_BUFFER,
	 .pkt_sz = sizeof(struct hfi_msg_session_empty_buffer_done_pkt),
	 .session_done = iris_hfi_1_session_etb_done,
	 .sys_done = NULL,
	},
	{.pkt = HFI_MSG_SESSION_FILL_BUFFER,
	 .pkt_sz = sizeof(struct hfi_msg_session_fbd_uncompressed_plane0_pkt),
	 .session_done = iris_hfi_1_session_ftb_done,
	 .sys_done = NULL,
	},
	{.pkt = HFI_MSG_SESSION_FLUSH,
	 .pkt_sz = sizeof(struct hfi_msg_session_flush_done_pkt),
	 .session_done = iris_hfi_1_session_flush_done,
	 .sys_done = NULL,
	},
	{.pkt = HFI_MSG_SESSION_RELEASE_RESOURCES,
	 .pkt_sz = sizeof(struct hfi_msg_session_release_resources_done_pkt),
	 .session_done = iris_hfi_1_session_rel_res_done,
	 .sys_done = NULL,
	},
	{.pkt = HFI_MSG_SESSION_GET_SEQUENCE_HEADER,
	 .pkt_sz = sizeof(struct hfi_msg_session_get_sequence_hdr_done_pkt),
	 .session_done = iris_hfi_1_session_get_seq_hdr_done,
	 .sys_done = NULL,
	},
	{.pkt = HFI_MSG_SESSION_RELEASE_BUFFERS,
	 .pkt_sz = sizeof(struct hfi_msg_session_release_buffers_done_pkt),
	 .session_done = iris_hfi_1_session_rel_buf_done,
	 .sys_done = NULL,
	},
};

static u32 iris_hfi_1_handle_response(struct iris_core *core, void *response)
{
	const struct iris_hfi_1_done_handler *handler;
	struct device *dev = core->dev;
	struct hfi_pkt_hdr *hdr;
	struct iris_inst *inst;
	bool found = false;
	unsigned int i;

	hdr = (struct hfi_pkt_hdr *)response;

	for (i = 0; i < ARRAY_SIZE(handlers); i++) {
		handler = &handlers[i];
		if (handler->pkt != hdr->pkt_type)
			continue;
		found = true;
		break;
	}

	if (!found || (hdr->size && hdr->size < handler->pkt_sz)) {
		dev_err(dev, "bad packet size (%d should be %d, pkt type:%x, found %d)\n",
			hdr->size, handler->pkt_sz, hdr->pkt_type, found);

		return hdr->pkt_type;
	}

	if (hdr->pkt_type == HFI_MSG_EVENT_NOTIFY) {
		struct hfi_session_pkt *pkt;

		pkt = (struct hfi_session_pkt *)hdr;
		inst = iris_get_instance(core, pkt->shdr.session_id);
		if (inst) {
			mutex_lock(&inst->lock);
			handler->session_done(inst, hdr);
			mutex_unlock(&inst->lock);
		} else {
			handler->sys_done(core, hdr);
		}

		return hdr->pkt_type;
	}

	if (handler->sys_done) {
		handler->sys_done(core, hdr);
	} else if (handler->session_done) {
		struct hfi_session_pkt *pkt;

		pkt = (struct hfi_session_pkt *)hdr;
		inst = iris_get_instance(core, pkt->shdr.session_id);
		if (!inst) {
			dev_warn(dev, "no valid instance(pkt session_id:%x, pkt:%x)\n",
				 pkt->shdr.session_id,
				 handler ? handler->pkt : 0);
			goto invalid_session;
		}

		/*
		 * Event of type HFI_EVENT_SYS_ERROR will not have any session
		 * associated with it
		 */
		if (!inst && hdr->pkt_type != HFI_MSG_EVENT_NOTIFY) {
			dev_err(dev, "got invalid session id:%x\n",
				pkt->shdr.session_id);
			goto invalid_session;
		}

		mutex_lock(&inst->lock);
		handler->session_done(inst, hdr);
		mutex_unlock(&inst->lock);
	}

invalid_session:
	return hdr->pkt_type;
}

static void iris_hfi_1_flush_debug_queue(struct iris_core *core,
					 u8 *packet, u32 packet_size)
{
	struct hfi_msg_sys_coverage_pkt *pkt;
	bool local_packet = false;

	if (!packet || !packet_size) {
		packet = kzalloc(IFACEQ_CORE_PKT_SIZE, GFP_KERNEL);
		if (!packet)
			return;

		packet_size = IFACEQ_CORE_PKT_SIZE;

		local_packet = true;
	}

	while (!iris_hfi_queue_dbg_read(core, packet)) {
		pkt = (struct hfi_msg_sys_coverage_pkt *)packet;

		if (pkt->hdr.pkt_type != HFI_MSG_SYS_COV) {
			struct hfi_msg_sys_debug_pkt *pkt =
				(struct hfi_msg_sys_debug_pkt *)packet;

			dev_dbg(core->dev, "%s", pkt->msg_data);
		}
	}

	if (local_packet)
		kfree(packet);
}

static void iris_hfi_1_response_handler(struct iris_core *core)
{
	memset(core->response_packet, 0, sizeof(struct hfi_pkt_hdr));
	while (!iris_hfi_queue_msg_read(core, core->response_packet)) {
		iris_hfi_1_handle_response(core, core->response_packet);
		if (core->state != IRIS_CORE_INIT)
			break;

		memset(core->response_packet, 0, sizeof(struct hfi_pkt_hdr));
	}

	iris_hfi_1_flush_debug_queue(core, core->packet, core->packet_size);
}

static const struct iris_hfi_response_ops iris_hfi_1_response_ops = {
	.hfi_response_handler = iris_hfi_1_response_handler,
};

void iris_hfi_1_response_ops_init(struct iris_core *core)
{
	core->hfi_response_ops = &iris_hfi_1_response_ops;
}
