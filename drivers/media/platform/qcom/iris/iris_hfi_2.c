// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include "iris_hfi_2.h"
#include "iris_hfi_2_defines.h"
#include "iris_hfi_2_packet.h"
#include "iris_instance.h"

#define UNSPECIFIED_COLOR_FORMAT 5

static int iris_hfi_2_sys_init(struct iris_core *core)
{
	int ret;

	ret = iris_hfi_2_packet_sys_init(core, core->packet, core->packet_size);
	if (ret)
		return ret;

	return iris_hfi_queue_cmd_write_locked(core, core->packet,
					       ((struct iris_hfi_header *)
					       core->packet)->size);
}

static int iris_hfi_2_sys_image_version(struct iris_core *core)
{
	int ret;

	ret = iris_hfi_2_packet_image_version(core, core->packet, core->packet_size);
	if (ret)
		return ret;

	return iris_hfi_queue_cmd_write_locked(core, core->packet,
					       ((struct iris_hfi_header *)
					       core->packet)->size);
}

static int iris_hfi_2_sys_interframe_powercollapse(struct iris_core *core)
{
	int ret;

	ret = iris_hfi_2_packet_sys_interframe_powercollapse(core, core->packet,
							     core->packet_size);
	if (ret)
		return ret;

	return iris_hfi_queue_cmd_write_locked(core, core->packet,
					       ((struct iris_hfi_header *)
					       core->packet)->size);
}

static int iris_hfi_2_sys_pc_prep(struct iris_core *core)
{
	int ret;

	ret = iris_hfi_2_packet_sys_pc_prep(core, core->packet, core->packet_size);
	if (ret)
		return ret;

	return iris_hfi_queue_cmd_write_locked(core, core->packet,
					       ((struct iris_hfi_header *)
					       core->packet)->size);
}

static u32 iris_hfi_2_get_port(u32 plane)
{
	u32 hfi_port = HFI_PORT_NONE;

	switch (plane) {
	case V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE:
		hfi_port = HFI_PORT_BITSTREAM;
		break;
	case V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE:
		hfi_port = HFI_PORT_RAW;
		break;
	default:
		break;
	}

	return hfi_port;
}

static u32 iris_hfi_2_get_port_from_buf_type(enum iris_buffer_type buffer_type)
{
	u32 hfi_port = HFI_PORT_NONE;

	switch (buffer_type) {
	case BUF_INPUT:
	case BUF_BIN:
	case BUF_COMV:
	case BUF_NON_COMV:
	case BUF_LINE:
		hfi_port = HFI_PORT_BITSTREAM;
		break;
	case BUF_OUTPUT:
	case BUF_DPB:
		hfi_port = HFI_PORT_RAW;
		break;
	case BUF_PERSIST:
		hfi_port = HFI_PORT_NONE;
		break;
	default:
		break;
	}

	return hfi_port;
}

static int iris_hfi_2_session_set_property(struct iris_inst *inst,
					   u32 packet_type, u32 flag, u32 plane, u32 payload_type,
					   void *payload, u32 payload_size)
{
	int ret = 0;

	ret = iris_hfi_2_packet_session_property(inst,
						 packet_type,
						 flag,
						 plane,
						 payload_type,
						 payload,
						 payload_size);
	if (ret)
		return ret;

	return iris_hfi_queue_cmd_write(inst->core, inst->packet,
					((struct iris_hfi_header *)inst->packet)->size);
}

static int iris_hfi_2_set_bitstream_resolution(struct iris_inst *inst)
{
	u32 resolution;
	int ret;

	resolution = inst->fmt_src->fmt.pix_mp.width << 16 |
		inst->fmt_src->fmt.pix_mp.height;
	inst->src_subcr_params.bitstream_resolution = resolution;

	ret =
	iris_hfi_2_session_set_property(inst,
					HFI_PROP_BITSTREAM_RESOLUTION,
					HFI_HOST_FLAGS_NONE,
					iris_hfi_2_get_port(V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE),
					HFI_PAYLOAD_U32,
					&resolution,
					sizeof(u32));
	return ret;
}

static int iris_hfi_2_set_crop_offsets(struct iris_inst *inst)
{
	u32 left_offset, top_offset, right_offset, bottom_offset;
	u32 payload[2] = {0};

	left_offset = inst->crop.left;
	top_offset = inst->crop.top;
	right_offset = (inst->fmt_src->fmt.pix_mp.width -
		inst->crop.width);
	bottom_offset = (inst->fmt_src->fmt.pix_mp.height -
		inst->crop.height);

	payload[0] = left_offset << 16 | top_offset;
	payload[1] = right_offset << 16 | bottom_offset;
	inst->src_subcr_params.crop_offsets[0] = payload[0];
	inst->src_subcr_params.crop_offsets[1] = payload[1];

	return
	iris_hfi_2_session_set_property(inst,
					HFI_PROP_CROP_OFFSETS,
					HFI_HOST_FLAGS_NONE,
					iris_hfi_2_get_port(V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE),
					HFI_PAYLOAD_64_PACKED,
					&payload,
					sizeof(u64));
}

static int iris_hfi_2_set_bit_dpeth(struct iris_inst *inst)
{
	u32 bitdepth = BIT_DEPTH_8;

	inst->src_subcr_params.bit_depth = bitdepth;

	return
	iris_hfi_2_session_set_property(inst,
					HFI_PROP_LUMA_CHROMA_BIT_DEPTH,
					HFI_HOST_FLAGS_NONE,
					iris_hfi_2_get_port(V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE),
					HFI_PAYLOAD_U32,
					&bitdepth,
					sizeof(u32));
}

static int iris_hfi_2_set_coded_frames(struct iris_inst *inst)
{
	u32 coded_frames = 0;

	if (inst->cap[CODED_FRAMES].value == CODED_FRAMES_PROGRESSIVE)
		coded_frames = HFI_BITMASK_FRAME_MBS_ONLY_FLAG;
	inst->src_subcr_params.coded_frames = coded_frames;

	return
	iris_hfi_2_session_set_property(inst,
					HFI_PROP_CODED_FRAMES,
					HFI_HOST_FLAGS_NONE,
					iris_hfi_2_get_port(V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE),
					HFI_PAYLOAD_U32,
					&coded_frames,
					sizeof(u32));
}

static int iris_hfi_2_set_min_output_count(struct iris_inst *inst)
{
	u32 min_output;

	min_output = inst->buffers.output.min_count;
	inst->src_subcr_params.fw_min_count = min_output;

	return
	iris_hfi_2_session_set_property(inst,
					HFI_PROP_BUFFER_FW_MIN_OUTPUT_COUNT,
					HFI_HOST_FLAGS_NONE,
					iris_hfi_2_get_port(V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE),
					HFI_PAYLOAD_U32,
					&min_output,
					sizeof(u32));
}

static int iris_hfi_2_set_picture_order_count(struct iris_inst *inst)
{
	u32 poc = 0;

	inst->src_subcr_params.pic_order_cnt = poc;

	return
	iris_hfi_2_session_set_property(inst,
					HFI_PROP_PIC_ORDER_CNT_TYPE,
					HFI_HOST_FLAGS_NONE,
					iris_hfi_2_get_port(V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE),
					HFI_PAYLOAD_U32,
					&poc,
					sizeof(u32));
}

static int iris_hfi_2_set_colorspace(struct iris_inst *inst)
{
	u32 video_signal_type_present_flag = 0, color_info = 0;
	u32 matrix_coeff = HFI_MATRIX_COEFF_RESERVED;
	u32 video_format = UNSPECIFIED_COLOR_FORMAT;
	struct v4l2_pix_format_mplane *pixmp = NULL;
	u32 full_range = V4L2_QUANTIZATION_DEFAULT;
	u32 transfer_char = HFI_TRANSFER_RESERVED;
	u32 colour_description_present_flag = 0;
	u32 primaries = HFI_PRIMARIES_RESERVED;
	int ret;

	pixmp = &inst->fmt_src->fmt.pix_mp;
	if (pixmp->colorspace != V4L2_COLORSPACE_DEFAULT ||
	    pixmp->ycbcr_enc != V4L2_YCBCR_ENC_DEFAULT ||
	    pixmp->xfer_func != V4L2_XFER_FUNC_DEFAULT) {
		colour_description_present_flag = 1;
		video_signal_type_present_flag = 1;
		primaries = iris_hfi_2_get_color_primaries(pixmp->colorspace);
		matrix_coeff = iris_hfi_2_get_matrix_coefficients(pixmp->ycbcr_enc);
		transfer_char = iris_hfi_2_get_transfer_char(pixmp->xfer_func);
	}

	if (pixmp->quantization != V4L2_QUANTIZATION_DEFAULT) {
		video_signal_type_present_flag = 1;
		full_range = pixmp->quantization ==
			V4L2_QUANTIZATION_FULL_RANGE ? 1 : 0;
	}

	color_info = (matrix_coeff & 0xFF) |
		((transfer_char << 8) & 0xFF00) |
		((primaries << 16) & 0xFF0000) |
		((colour_description_present_flag << 24) & 0x1000000) |
		((full_range << 25) & 0x2000000) |
		((video_format << 26) & 0x1C000000) |
		((video_signal_type_present_flag << 29) & 0x20000000);

	inst->src_subcr_params.color_info = color_info;

	return
	iris_hfi_2_session_set_property(inst,
					HFI_PROP_SIGNAL_COLOR_INFO,
					HFI_HOST_FLAGS_NONE,
					iris_hfi_2_get_port(V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE),
					HFI_PAYLOAD_32_PACKED,
					&color_info,
					sizeof(u32));

	return ret;
}

static int iris_hfi_2_set_profile(struct iris_inst *inst)
{
	u32 profile;

	profile = inst->cap[PROFILE].value;
	inst->src_subcr_params.profile = profile;

	return
	iris_hfi_2_session_set_property(inst,
					HFI_PROP_PROFILE,
					HFI_HOST_FLAGS_NONE,
					iris_hfi_2_get_port(V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE),
					HFI_PAYLOAD_U32_ENUM,
					&profile,
					sizeof(u32));
}

static int iris_hfi_2_set_level(struct iris_inst *inst)
{
	u32 level;

	level = inst->cap[LEVEL].value;
	inst->src_subcr_params.level = level;

	return
	iris_hfi_2_session_set_property(inst,
					HFI_PROP_LEVEL,
					HFI_HOST_FLAGS_NONE,
					iris_hfi_2_get_port(V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE),
					HFI_PAYLOAD_U32_ENUM,
					&level,
					sizeof(u32));
}

static int iris_hfi_2_set_colorformat(struct iris_inst *inst)
{
	u32 hfi_colorformat;
	u32 pixelformat;

	pixelformat = inst->fmt_dst->fmt.pix_mp.pixelformat;
	hfi_colorformat = pixelformat == V4L2_PIX_FMT_NV12 ? HFI_COLOR_FMT_NV12 : 0;

	return
	iris_hfi_2_session_set_property(inst,
					HFI_PROP_COLOR_FORMAT,
					HFI_HOST_FLAGS_NONE,
					iris_hfi_2_get_port(V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE),
					HFI_PAYLOAD_U32,
					&hfi_colorformat,
					sizeof(u32));
}

static int iris_hfi_2_set_linear_stride_scanline(struct iris_inst *inst)
{
	u32 stride_y, scanline_y, stride_uv, scanline_uv;
	u32 pixelformat;
	u32 payload[2];

	pixelformat = inst->fmt_dst->fmt.pix_mp.pixelformat;

	if (pixelformat != V4L2_PIX_FMT_NV12)
		return 0;

	stride_y = inst->fmt_dst->fmt.pix_mp.width;
	scanline_y = inst->fmt_dst->fmt.pix_mp.height;
	stride_uv = stride_y;
	scanline_uv = scanline_y / 2;

	payload[0] = stride_y << 16 | scanline_y;
	payload[1] = stride_uv << 16 | scanline_uv;

	return
	iris_hfi_2_session_set_property(inst,
					HFI_PROP_LINEAR_STRIDE_SCANLINE,
					HFI_HOST_FLAGS_NONE,
					iris_hfi_2_get_port(V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE),
					HFI_PAYLOAD_U64,
					&payload,
					sizeof(u64));
}

static int iris_hfi_2_session_set_config_params(struct iris_inst *inst, u32 plane)
{
	const u32 *config_params;
	u32 config_params_size;
	struct iris_core *core;
	int ret;
	u32 i, j;

	static const struct iris_hfi_prop_type_handle prop_type_handle_arr[] = {
		{HFI_PROP_BITSTREAM_RESOLUTION,          iris_hfi_2_set_bitstream_resolution   },
		{HFI_PROP_CROP_OFFSETS,                  iris_hfi_2_set_crop_offsets           },
		{HFI_PROP_CODED_FRAMES,                  iris_hfi_2_set_coded_frames           },
		{HFI_PROP_LUMA_CHROMA_BIT_DEPTH,         iris_hfi_2_set_bit_dpeth              },
		{HFI_PROP_BUFFER_FW_MIN_OUTPUT_COUNT,    iris_hfi_2_set_min_output_count       },
		{HFI_PROP_PIC_ORDER_CNT_TYPE,            iris_hfi_2_set_picture_order_count    },
		{HFI_PROP_SIGNAL_COLOR_INFO,             iris_hfi_2_set_colorspace             },
		{HFI_PROP_PROFILE,                       iris_hfi_2_set_profile                },
		{HFI_PROP_LEVEL,                         iris_hfi_2_set_level                  },
		{HFI_PROP_COLOR_FORMAT,                  iris_hfi_2_set_colorformat            },
		{HFI_PROP_LINEAR_STRIDE_SCANLINE,        iris_hfi_2_set_linear_stride_scanline },
	};

	core = inst->core;

	if (V4L2_TYPE_IS_OUTPUT(plane)) {
		config_params = core->platform_data->input_config_params;
		config_params_size = core->platform_data->input_config_params_size;
	} else {
		config_params = core->platform_data->output_config_params;
		config_params_size = core->platform_data->output_config_params_size;
	}

	if (!config_params || !config_params_size)
		return -EINVAL;

	for (i = 0; i < config_params_size; i++) {
		for (j = 0; j < ARRAY_SIZE(prop_type_handle_arr); j++) {
			if (prop_type_handle_arr[j].type == config_params[i]) {
				ret = prop_type_handle_arr[j].handle(inst);
				if (ret)
					return ret;
				break;
			}
		}
	}

	return ret;
}

static int iris_hfi_2_session_set_codec(struct iris_inst *inst)
{
	u32 codec;
	int ret;

	if (!inst->packet)
		return -EINVAL;

	codec = HFI_CODEC_DECODE_AVC;
	ret = iris_hfi_2_packet_session_property(inst,
						 HFI_PROP_CODEC,
						 HFI_HOST_FLAGS_NONE,
						 HFI_PORT_NONE,
						 HFI_PAYLOAD_U32_ENUM,
						 &codec,
						 sizeof(u32));
	if (ret)
		return ret;

	return iris_hfi_queue_cmd_write(inst->core, inst->packet,
					((struct iris_hfi_header *)inst->packet)->size);
}

static int iris_hfi_2_session_set_default_header(struct iris_inst *inst)
{
	u32 default_header = false;
	int ret;

	if (!inst->packet)
		return -EINVAL;

	default_header = inst->cap[DEFAULT_HEADER].value;
	ret = iris_hfi_2_packet_session_property(inst,
						 HFI_PROP_DEC_DEFAULT_HEADER,
						 HFI_HOST_FLAGS_NONE,
						 HFI_PORT_BITSTREAM,
						 HFI_PAYLOAD_U32,
						 &default_header,
						 sizeof(u32));
	if (ret)
		return ret;

	return iris_hfi_queue_cmd_write(inst->core, inst->packet,
					((struct iris_hfi_header *)inst->packet)->size);
}

static int iris_hfi_2_session_open(struct iris_inst *inst, u32 codec)
{
	int ret;

	inst->packet_size = 4096;
	inst->packet = kzalloc(inst->packet_size, GFP_KERNEL);

	if (inst->state != IRIS_INST_DEINIT)
		return -EALREADY;

	ret = iris_hfi_2_packet_session_command(inst,
						HFI_CMD_OPEN,
						HFI_HOST_FLAGS_RESPONSE_REQUIRED |
						HFI_HOST_FLAGS_INTR_REQUIRED,
						HFI_PORT_NONE,
						0,
						HFI_PAYLOAD_U32,
						&inst->session_id,
						sizeof(u32));
	if (ret)
		goto fail_free_packet;

	ret = iris_hfi_queue_cmd_write(inst->core, inst->packet,
				       ((struct iris_hfi_header *)inst->packet)->size);
	if (ret)
		goto fail_free_packet;

	ret = iris_hfi_2_session_set_codec(inst);
	if (ret)
		goto fail_free_packet;

	ret = iris_hfi_2_session_set_default_header(inst);
	if (ret)
		goto fail_free_packet;

	return ret;

fail_free_packet:
	kfree(inst->packet);
	inst->packet = NULL;

	return ret;
}

static int iris_hfi_2_session_close(struct iris_inst *inst)
{
	int ret;

	ret = iris_hfi_2_packet_session_command(inst,
						HFI_CMD_CLOSE,
						(HFI_HOST_FLAGS_RESPONSE_REQUIRED |
						HFI_HOST_FLAGS_INTR_REQUIRED |
						HFI_HOST_FLAGS_NON_DISCARDABLE),
						HFI_PORT_NONE,
						inst->session_id,
						HFI_PAYLOAD_NONE,
						NULL,
						0);
	if (ret)
		return ret;

	return iris_hfi_queue_cmd_write(inst->core, inst->packet,
					((struct iris_hfi_header *)inst->packet)->size);
}

static int iris_hfi_2_session_subscribe_mode(struct iris_inst *inst,
					     u32 cmd, u32 plane, u32 payload_type,
					     void *payload, u32 payload_size)
{
	int ret;

	ret = iris_hfi_2_packet_session_command(inst,
						cmd,
						(HFI_HOST_FLAGS_RESPONSE_REQUIRED |
						HFI_HOST_FLAGS_INTR_REQUIRED),
						iris_hfi_2_get_port(plane),
						inst->session_id,
						payload_type,
						payload,
						payload_size);
	if (ret)
		return ret;

	return iris_hfi_queue_cmd_write(inst->core, inst->packet,
					((struct iris_hfi_header *)inst->packet)->size);
}

static int iris_hfi_2_subscribe_change_param(struct iris_inst *inst, u32 plane)
{
	u32 prop_type, payload_size, payload_type;
	struct hfi_subscription_params subsc_params;
	const u32 *change_param = NULL;
	u32 change_param_size = 0;
	struct iris_core *core;
	u32 payload[32] = {0};
	u32 hfi_port = 0;
	int ret;
	u32 i;

	core = inst->core;

	if ((V4L2_TYPE_IS_OUTPUT(plane) && inst->ipsc_properties_set) ||
	    (V4L2_TYPE_IS_CAPTURE(plane) && inst->opsc_properties_set)) {
		dev_err(core->dev, "%s: invalid plane\n", __func__);
		return 0;
	}

	change_param = core->platform_data->input_config_params;
	change_param_size = core->platform_data->input_config_params_size;

	if (!change_param || !change_param_size)
		return -EINVAL;

	payload[0] = HFI_MODE_PORT_SETTINGS_CHANGE;

	for (i = 0; i < change_param_size; i++)
		payload[i + 1] = change_param[i];

	ret = iris_hfi_2_session_subscribe_mode(inst,
						HFI_CMD_SUBSCRIBE_MODE,
						plane,
						HFI_PAYLOAD_U32_ARRAY,
						&payload[0],
						((change_param_size + 1) * sizeof(u32)));
	if (ret)
		return ret;

	if (V4L2_TYPE_IS_OUTPUT(plane)) {
		inst->ipsc_properties_set = true;
	} else {
		hfi_port = iris_hfi_2_get_port(V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE);
		memcpy(&inst->dst_subcr_params,
		       &inst->src_subcr_params,
		       sizeof(inst->src_subcr_params));
		subsc_params = inst->dst_subcr_params;
		for (i = 0; i < change_param_size; i++) {
			payload[0] = 0;
			payload[1] = 0;
			payload_size = 0;
			payload_type = 0;
			prop_type = change_param[i];
			switch (prop_type) {
			case HFI_PROP_BITSTREAM_RESOLUTION:
				payload[0] = subsc_params.bitstream_resolution;
				payload_size = sizeof(u32);
				payload_type = HFI_PAYLOAD_U32;
				break;
			case HFI_PROP_CROP_OFFSETS:
				payload[0] = subsc_params.crop_offsets[0];
				payload[1] = subsc_params.crop_offsets[1];
				payload_size = sizeof(u64);
				payload_type = HFI_PAYLOAD_64_PACKED;
				break;
			case HFI_PROP_CODED_FRAMES:
				payload[0] = subsc_params.coded_frames;
				payload_size = sizeof(u32);
				payload_type = HFI_PAYLOAD_U32;
				break;
			case HFI_PROP_BUFFER_FW_MIN_OUTPUT_COUNT:
				payload[0] = subsc_params.fw_min_count;
				payload_size = sizeof(u32);
				payload_type = HFI_PAYLOAD_U32;
				break;
			case HFI_PROP_PIC_ORDER_CNT_TYPE:
				payload[0] = subsc_params.pic_order_cnt;
				payload_size = sizeof(u32);
				payload_type = HFI_PAYLOAD_U32;
				break;
			case HFI_PROP_SIGNAL_COLOR_INFO:
				payload[0] = subsc_params.color_info;
				payload_size = sizeof(u32);
				payload_type = HFI_PAYLOAD_U32;
				break;
			case HFI_PROP_PROFILE:
				payload[0] = subsc_params.profile;
				payload_size = sizeof(u32);
				payload_type = HFI_PAYLOAD_U32;
				break;
			case HFI_PROP_LEVEL:
				payload[0] = subsc_params.level;
				payload_size = sizeof(u32);
				payload_type = HFI_PAYLOAD_U32;
				break;
			default:
				prop_type = 0;
				ret = -EINVAL;
				break;
			}
			if (prop_type) {
				ret = iris_hfi_2_session_set_property(inst,
								      prop_type,
								      HFI_HOST_FLAGS_NONE,
								      hfi_port,
								      payload_type,
								      &payload,
								      payload_size);
				if (ret)
					return ret;
			}
		}
		inst->opsc_properties_set = true;
	}

	return ret;
}

static int iris_hfi_2_subscribe_property(struct iris_inst *inst, u32 plane)
{
	const u32 *subcribe_prop = NULL;
	u32 subscribe_prop_size = 0;
	struct iris_core *core;
	u32 payload[32] = {0};
	u32 i;

	core = inst->core;

	payload[0] = HFI_MODE_PROPERTY;

	if (V4L2_TYPE_IS_OUTPUT(plane)) {
		subscribe_prop_size = core->platform_data->dec_input_prop_size;
		subcribe_prop = core->platform_data->dec_input_prop;
	} else {
		subscribe_prop_size = core->platform_data->dec_output_prop_size;
		subcribe_prop = core->platform_data->dec_output_prop;
	}

	for (i = 0; i < subscribe_prop_size; i++)
		payload[i + 1] = subcribe_prop[i];

	return iris_hfi_2_session_subscribe_mode(inst,
						 HFI_CMD_SUBSCRIBE_MODE,
						 plane,
						 HFI_PAYLOAD_U32_ARRAY,
						 &payload[0],
						 (subscribe_prop_size + 1) * sizeof(u32));
}

static int iris_hfi_2_session_start(struct iris_inst *inst, u32 plane)
{
	int ret = 0;

	ret = iris_hfi_2_subscribe_change_param(inst, plane);
	if (ret)
		return ret;

	ret = iris_hfi_2_subscribe_property(inst, plane);
	if (ret)
		return ret;

	ret = iris_hfi_2_packet_session_command(inst,
						HFI_CMD_START,
						(HFI_HOST_FLAGS_RESPONSE_REQUIRED |
						HFI_HOST_FLAGS_INTR_REQUIRED),
						iris_hfi_2_get_port(plane),
						inst->session_id,
						HFI_PAYLOAD_NONE,
						NULL,
						0);
	if (ret)
		return ret;

	return iris_hfi_queue_cmd_write(inst->core, inst->packet,
					((struct iris_hfi_header *)inst->packet)->size);
}

static int iris_hfi_2_session_stop(struct iris_inst *inst, u32 plane)
{
	int ret = 0;

	reinit_completion(&inst->completion);

	ret = iris_hfi_2_packet_session_command(inst,
						HFI_CMD_STOP,
						(HFI_HOST_FLAGS_RESPONSE_REQUIRED |
						HFI_HOST_FLAGS_INTR_REQUIRED |
						HFI_HOST_FLAGS_NON_DISCARDABLE),
						iris_hfi_2_get_port(plane),
						inst->session_id,
						HFI_PAYLOAD_NONE,
						NULL,
						0);
	if (ret)
		return ret;

	ret = iris_hfi_queue_cmd_write(inst->core, inst->packet,
				       ((struct iris_hfi_header *)inst->packet)->size);
	if (ret)
		return ret;

	return iris_wait_for_session_response(inst, false);
}

static int iris_hfi_2_session_pause(struct iris_inst *inst, u32 plane)
{
	int ret = 0;

	ret = iris_hfi_2_packet_session_command(inst,
						HFI_CMD_PAUSE,
						(HFI_HOST_FLAGS_RESPONSE_REQUIRED |
						HFI_HOST_FLAGS_INTR_REQUIRED),
						iris_hfi_2_get_port(plane),
						inst->session_id,
						HFI_PAYLOAD_NONE,
						NULL,
						0);
	if (ret)
		return ret;

	return iris_hfi_queue_cmd_write(inst->core, inst->packet,
					((struct iris_hfi_header *)inst->packet)->size);
}

static int iris_hfi_2_session_resume(struct iris_inst *inst, u32 plane, u32 payload)
{
	int ret = 0;

	ret = iris_hfi_2_packet_session_command(inst,
						HFI_CMD_RESUME,
						(HFI_HOST_FLAGS_RESPONSE_REQUIRED |
						HFI_HOST_FLAGS_INTR_REQUIRED),
						iris_hfi_2_get_port(plane),
						inst->session_id,
						HFI_PAYLOAD_U32,
						&payload,
						sizeof(u32));
	if (ret)
		return ret;

	ret = iris_hfi_queue_cmd_write(inst->core, inst->packet,
				       ((struct iris_hfi_header *)inst->packet)->size);
	if (ret)
		return ret;

	return ret;
}

static int iris_hfi_2_session_drain(struct iris_inst *inst, u32 plane)
{
	int ret = 0;

	if (!V4L2_TYPE_IS_OUTPUT(plane))
		return ret;

	ret = iris_hfi_2_packet_session_command(inst,
						HFI_CMD_DRAIN,
						(HFI_HOST_FLAGS_RESPONSE_REQUIRED |
						HFI_HOST_FLAGS_INTR_REQUIRED |
						HFI_HOST_FLAGS_NON_DISCARDABLE),
						iris_hfi_2_get_port(plane),
						inst->session_id,
						HFI_PAYLOAD_NONE,
						NULL,
						0);
	if (ret)
		return ret;

	return iris_hfi_queue_cmd_write(inst->core, inst->packet,
					((struct iris_hfi_header *)inst->packet)->size);
}

static u32 iris_hfi_2_buf_type_from_driver(enum iris_buffer_type buffer_type)
{
	switch (buffer_type) {
	case BUF_INPUT:
		return HFI_BUFFER_BITSTREAM;
	case BUF_OUTPUT:
		return HFI_BUFFER_RAW;
	case BUF_BIN:
		return HFI_BUFFER_BIN;
	case BUF_COMV:
		return HFI_BUFFER_COMV;
	case BUF_NON_COMV:
		return HFI_BUFFER_NON_COMV;
	case BUF_LINE:
		return HFI_BUFFER_LINE;
	case BUF_DPB:
		return HFI_BUFFER_DPB;
	case BUF_PERSIST:
		return HFI_BUFFER_PERSIST;
	default:
		return 0;
	}
}

static void iris_hfi_2_get_buffer(struct iris_buffer *buffer, struct iris_hfi_buffer *buf)
{
	memset(buf, 0, sizeof(*buf));
	buf->type = iris_hfi_2_buf_type_from_driver(buffer->type);
	buf->index = buffer->index;
	buf->base_address = buffer->device_addr;
	buf->addr_offset = 0;
	buf->buffer_size = buffer->buffer_size;
	/*
	 * for decoder input buffers, firmware (BSE HW) needs 256 aligned
	 * buffer size otherwise it will truncate or ignore the data after 256
	 * aligned size which may lead to error concealment
	 */
	if (buffer->type == BUF_INPUT)
		buf->buffer_size = ALIGN(buffer->buffer_size, 256);
	buf->data_offset = buffer->data_offset;
	buf->data_size = buffer->data_size;
	if (buffer->attr & BUF_ATTR_PENDING_RELEASE)
		buf->flags |= HFI_BUF_HOST_FLAG_RELEASE;
	buf->flags |= HFI_BUF_HOST_FLAGS_CB_NON_SECURE;
	buf->timestamp = buffer->timestamp;
}

static int iris_hfi_2_session_queue_buffer(struct iris_inst *inst, struct iris_buffer *buffer)
{
	struct iris_hfi_buffer hfi_buffer;
	int ret;

	iris_hfi_2_get_buffer(buffer, &hfi_buffer);
	ret = iris_hfi_2_packet_session_command(inst,
						HFI_CMD_BUFFER,
						HFI_HOST_FLAGS_INTR_REQUIRED,
						iris_hfi_2_get_port_from_buf_type(buffer->type),
						inst->session_id,
						HFI_PAYLOAD_STRUCTURE,
						&hfi_buffer,
						sizeof(hfi_buffer));
	if (ret)
		return ret;

	return iris_hfi_queue_cmd_write(inst->core, inst->packet,
					((struct iris_hfi_header *)inst->packet)->size);
}

static int iris_hfi_2_session_release_buffer(struct iris_inst *inst, struct iris_buffer *buffer)
{
	struct iris_hfi_buffer hfi_buffer;
	int ret;

	iris_hfi_2_get_buffer(buffer, &hfi_buffer);
	hfi_buffer.flags |= HFI_BUF_HOST_FLAG_RELEASE;

	ret = iris_hfi_2_packet_session_command(inst,
						HFI_CMD_BUFFER,
						(HFI_HOST_FLAGS_RESPONSE_REQUIRED |
						HFI_HOST_FLAGS_INTR_REQUIRED),
						iris_hfi_2_get_port_from_buf_type(buffer->type),
						inst->session_id,
						HFI_PAYLOAD_STRUCTURE,
						&hfi_buffer,
						sizeof(hfi_buffer));
	if (ret)
		return ret;

	return iris_hfi_queue_cmd_write(inst->core, inst->packet,
					((struct iris_hfi_header *)inst->packet)->size);
}

static const struct iris_hfi_ops iris_hfi_2_ops = {
	.sys_init = iris_hfi_2_sys_init,
	.sys_image_version = iris_hfi_2_sys_image_version,
	.sys_pc_prep = iris_hfi_2_sys_pc_prep,
	.sys_interframe_powercollapse = iris_hfi_2_sys_interframe_powercollapse,
	.session_open = iris_hfi_2_session_open,
	.session_set_config_params = iris_hfi_2_session_set_config_params,
	.session_set_property = iris_hfi_2_session_set_property,
	.session_start = iris_hfi_2_session_start,
	.session_queue_buf = iris_hfi_2_session_queue_buffer,
	.session_release_buf = iris_hfi_2_session_release_buffer,
	.session_pause = iris_hfi_2_session_pause,
	.session_resume = iris_hfi_2_session_resume,
	.session_stop = iris_hfi_2_session_stop,
	.session_drain = iris_hfi_2_session_drain,
	.session_close = iris_hfi_2_session_close,
};

void iris_hfi_2_ops_init(struct iris_core *core)
{
	core->hfi_ops = &iris_hfi_2_ops;
}
