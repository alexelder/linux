/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _IRIS_VPU_BUFFER_H_
#define _IRIS_VPU_BUFFER_H_

#include <linux/types.h>
#include <linux/minmax.h>
#include <linux/align.h>

struct iris_inst;

#define MIN_BUFFERS  4
#define INTERAL_BUF_COUNT 1

#define DMA_ALIGNMENT 256

#define BUFFER_ALIGNMENT_512_BYTES 512
#define BUFFER_ALIGNMENT_64_BYTES 64
#define BUFFER_ALIGNMENT_32_BYTES 32
#define BUFFER_ALIGNMENT_16_BYTES 16

#define NUM_HW_PIC_BUF 32
#define SIZE_HW_PIC(size_per_buf) (NUM_HW_PIC_BUF * (size_per_buf))

#define MAX_TILE_COLUMNS 32

#define BIN_BUFFER_THRESHOLD (1280 * 736)

#define VPP_CMD_MAX_SIZE (BIT(20))

#define H264D_MAX_SLICE 1800

#define SIZE_H264D_BUFTAB_T (256)
#define SIZE_H264D_BSE_CMD_PER_BUF (32 * 4)
#define SIZE_H264D_VPP_CMD_PER_BUF (512)

#define NUM_SLIST_BUF_H264 (256 + 32)
#define SIZE_SLIST_BUF_H264 (512)
#define H264_DISPLAY_BUF_SIZE (3328)
#define H264_NUM_FRM_INFO (66)

#define SIZE_SEI_USERDATA (4096)

#define H264_CABAC_HDR_RATIO_HD_TOT 1
#define H264_CABAC_RES_RATIO_HD_TOT 3

#define MAX_FE_NBR_CTRL_LCU64_LINE_BUFFER_SIZE 64

#define MAX_SE_NBR_CTRL_LCU64_LINE_BUFFER_SIZE (128 / 8)

#define MAX_PE_NBR_DATA_LCU64_LINE_BUFFER_SIZE (64 * 2 * 3)
#define MAX_FE_NBR_DATA_LUMA_LINE_BUFFER_SIZE 640

#define SIZE_H264D_HW_PIC_T (BIT(11))

static inline u32 size_h264d_lb_fe_top_data(u32 frame_width, u32 frame_height)
{
	return MAX_FE_NBR_DATA_LUMA_LINE_BUFFER_SIZE * ALIGN(frame_width, 16) * 3;
}

static inline u32 size_h264d_lb_fe_top_ctrl(u32 frame_width, u32 frame_height)
{
	return MAX_FE_NBR_CTRL_LCU64_LINE_BUFFER_SIZE * ((frame_width + 15) >> 4);
}

static inline u32 size_h264d_lb_fe_left_ctrl(u32 frame_width, u32 frame_height)
{
	return MAX_FE_NBR_CTRL_LCU64_LINE_BUFFER_SIZE * ((frame_height + 15) >> 4);
}

static inline u32 size_h264d_lb_se_top_ctrl(u32 frame_width, u32 frame_height)
{
	return MAX_SE_NBR_CTRL_LCU64_LINE_BUFFER_SIZE * ((frame_width + 15) >> 4);
}

static inline u32 size_h264d_lb_se_left_ctrl(u32 frame_width, u32 frame_height)
{
	return MAX_SE_NBR_CTRL_LCU64_LINE_BUFFER_SIZE * ((frame_height + 15) >> 4);
}

static inline u32 size_h264d_lb_pe_top_data(u32 frame_width, u32 frame_height)
{
	return MAX_PE_NBR_DATA_LCU64_LINE_BUFFER_SIZE *  ((frame_width + 15) >> 4);
}

static inline u32 size_h264d_lb_vsp_top(u32 frame_width, u32 frame_height)
{
	return (((frame_width + 15) >> 4) << 7);
}

static inline u32 size_h264d_lb_recon_dma_metadata_wr(u32 frame_width, u32 frame_height)
{
	return ALIGN(frame_height, 16) * 32;
}

static inline u32 size_h264d_qp(u32 frame_width, u32 frame_height)
{
	return ((frame_width + 63) >> 6) * ((frame_height + 63) >> 6) * 128;
}

static inline
u32 size_h264d_hw_bin_buffer(u32 frame_width, u32 frame_height,
			     u32 num_vpp_pipes)
{
	u32 size_yuv, size_bin_hdr, size_bin_res;

	size_yuv = ((frame_width * frame_height) <= BIN_BUFFER_THRESHOLD) ?
			((BIN_BUFFER_THRESHOLD * 3) >> 1) :
			((frame_width * frame_height * 3) >> 1);
	size_bin_hdr = size_yuv * H264_CABAC_HDR_RATIO_HD_TOT;
	size_bin_res = size_yuv * H264_CABAC_RES_RATIO_HD_TOT;
	size_bin_hdr = ALIGN(size_bin_hdr / num_vpp_pipes,
			     DMA_ALIGNMENT) * num_vpp_pipes;
	size_bin_res = ALIGN(size_bin_res / num_vpp_pipes,
			     DMA_ALIGNMENT) * num_vpp_pipes;

	return size_bin_hdr + size_bin_res;
}

static inline
u32 hfi_buffer_bin_h264d(u32 frame_width, u32 frame_height,
			 u32 num_vpp_pipes)
{
	u32 n_aligned_w, n_aligned_h;

	n_aligned_w = ALIGN(frame_width, BUFFER_ALIGNMENT_16_BYTES);
	n_aligned_h = ALIGN(frame_height, BUFFER_ALIGNMENT_16_BYTES);

	return size_h264d_hw_bin_buffer(n_aligned_w, n_aligned_h,
					num_vpp_pipes);
}

static inline
u32 hfi_buffer_comv_h264d(u32 frame_width, u32 frame_height,
			  u32 _comv_bufcount)
{
	u32 frame_width_in_mbs = ((frame_width + 15) >> 4);
	u32 frame_height_in_mbs = ((frame_height + 15) >> 4);
	u32 col_mv_aligned_width = (frame_width_in_mbs << 7);
	u32 col_zero_aligned_width = (frame_width_in_mbs << 2);
	u32 col_zero_size = 0, size_colloc = 0;

	col_mv_aligned_width =
		ALIGN(col_mv_aligned_width, BUFFER_ALIGNMENT_16_BYTES);
	col_zero_aligned_width =
		ALIGN(col_zero_aligned_width, BUFFER_ALIGNMENT_16_BYTES);
	col_zero_size = col_zero_aligned_width *
			((frame_height_in_mbs + 1) >> 1);
	col_zero_size = ALIGN(col_zero_size, BUFFER_ALIGNMENT_64_BYTES);
	col_zero_size <<= 1;
	col_zero_size = ALIGN(col_zero_size, BUFFER_ALIGNMENT_512_BYTES);
	size_colloc = col_mv_aligned_width * ((frame_height_in_mbs + 1) >> 1);
	size_colloc = ALIGN(size_colloc, BUFFER_ALIGNMENT_64_BYTES);
	size_colloc <<= 1;
	size_colloc = ALIGN(size_colloc, BUFFER_ALIGNMENT_512_BYTES);
	size_colloc += (col_zero_size + SIZE_H264D_BUFTAB_T * 2);

	return (size_colloc * (_comv_bufcount)) +
		BUFFER_ALIGNMENT_512_BYTES;
}

static inline
u32 size_h264d_bse_cmd_buf(u32 frame_height)
{
	u32 height = ALIGN(frame_height,
			    BUFFER_ALIGNMENT_32_BYTES);
	return min_t(u32, (((height + 15) >> 4) * 48), H264D_MAX_SLICE) *
		SIZE_H264D_BSE_CMD_PER_BUF;
}

static inline
u32 size_h264d_vpp_cmd_buf(u32 frame_height)
{
	u32 size, height;

	height = ALIGN(frame_height, BUFFER_ALIGNMENT_32_BYTES);
	size = min_t(u32, (((height + 15) >> 4) * 48), H264D_MAX_SLICE) *
			SIZE_H264D_VPP_CMD_PER_BUF;

	if (size > VPP_CMD_MAX_SIZE)
		size = VPP_CMD_MAX_SIZE;

	return size;
}

static inline u32 hfi_buffer_persist_h264d(void)
{
	return ALIGN(SIZE_SLIST_BUF_H264 * NUM_SLIST_BUF_H264 +
		    H264_DISPLAY_BUF_SIZE * H264_NUM_FRM_INFO +
		    NUM_HW_PIC_BUF * SIZE_SEI_USERDATA,
		    DMA_ALIGNMENT);
}

static inline
u32 hfi_buffer_non_comv_h264d(u32 frame_width, u32 frame_height,
			      u32 num_vpp_pipes)
{
	u32 size_bse, size_vpp, size;

	size_bse = size_h264d_bse_cmd_buf(frame_height);
	size_vpp = size_h264d_vpp_cmd_buf(frame_height);
	size = ALIGN(size_bse, DMA_ALIGNMENT) +
		ALIGN(size_vpp, DMA_ALIGNMENT) +
		ALIGN(SIZE_HW_PIC(SIZE_H264D_HW_PIC_T), DMA_ALIGNMENT);

	return ALIGN(size, DMA_ALIGNMENT);
}

static inline
u32 size_vpss_lb(u32 frame_width, u32 frame_height, u32 num_vpp_pipes)
{
	u32 vpss_4tap_left_buffer_size = 0, vpss_div2_left_buffer_size = 0;
	u32 vpss_4tap_top_buffer_size = 0, vpss_div2_top_buffer_size = 0;
	u32 opb_lb_wr_llb_y_buffer_size, opb_lb_wr_llb_uv_buffer_size;
	u32 opb_wr_top_line_chroma_buffer_size;
	u32 opb_wr_top_line_luma_buffer_size;
	u32 macrotiling_size = 32, size;

	opb_wr_top_line_luma_buffer_size =
		ALIGN(frame_width, macrotiling_size) /
		macrotiling_size * 256;
	opb_wr_top_line_luma_buffer_size =
		ALIGN(opb_wr_top_line_luma_buffer_size, DMA_ALIGNMENT) +
		(MAX_TILE_COLUMNS - 1) * 256;
	opb_wr_top_line_luma_buffer_size =
		max_t(u32, opb_wr_top_line_luma_buffer_size,
		      (32 * ALIGN(frame_height, 8)));
	opb_wr_top_line_chroma_buffer_size =
		opb_wr_top_line_luma_buffer_size;
	opb_lb_wr_llb_uv_buffer_size =
		ALIGN((ALIGN(frame_height, 8) / (4 / 2)) * 64,
		      BUFFER_ALIGNMENT_32_BYTES);
	opb_lb_wr_llb_y_buffer_size =
		ALIGN((ALIGN(frame_height, 8) / (4 / 2)) * 64,
		      BUFFER_ALIGNMENT_32_BYTES);
	size = num_vpp_pipes * 2 *
		(vpss_4tap_top_buffer_size + vpss_div2_top_buffer_size) +
		2 * (vpss_4tap_left_buffer_size + vpss_div2_left_buffer_size) +
		opb_wr_top_line_luma_buffer_size +
		opb_wr_top_line_chroma_buffer_size +
		opb_lb_wr_llb_uv_buffer_size +
		opb_lb_wr_llb_y_buffer_size;

	return size;
}

static inline
u32 hfi_buffer_line_h264d(u32 frame_width, u32 frame_height,
			  bool is_opb, u32 num_vpp_pipes)
{
	u32 vpss_lb_size = 0;
	u32 size;

	size = ALIGN(size_h264d_lb_fe_top_data(frame_width, frame_height),
		     DMA_ALIGNMENT) +
		ALIGN(size_h264d_lb_fe_top_ctrl(frame_width, frame_height),
		      DMA_ALIGNMENT) +
		ALIGN(size_h264d_lb_fe_left_ctrl(frame_width, frame_height),
		      DMA_ALIGNMENT) * num_vpp_pipes +
		ALIGN(size_h264d_lb_se_top_ctrl(frame_width, frame_height),
		      DMA_ALIGNMENT) +
		ALIGN(size_h264d_lb_se_left_ctrl(frame_width, frame_height),
		      DMA_ALIGNMENT) * num_vpp_pipes +
		ALIGN(size_h264d_lb_pe_top_data(frame_width, frame_height),
		      DMA_ALIGNMENT) +
		ALIGN(size_h264d_lb_vsp_top(frame_width, frame_height),
		      DMA_ALIGNMENT) +
		ALIGN(size_h264d_lb_recon_dma_metadata_wr(frame_width, frame_height),
		      DMA_ALIGNMENT) * 2 +
		ALIGN(size_h264d_qp(frame_width, frame_height),
		      DMA_ALIGNMENT);
	size = ALIGN(size, DMA_ALIGNMENT);
	if (is_opb)
		vpss_lb_size = size_vpss_lb(frame_width, frame_height,
					    num_vpp_pipes);

	size = ALIGN((size + vpss_lb_size), DMA_ALIGNMENT);

	return size;
}

int iris_vpu_buf_size(struct iris_inst *inst, enum iris_buffer_type buffer_type);
int iris_vpu_buf_count(struct iris_inst *inst, enum iris_buffer_type buffer_type);

#endif
