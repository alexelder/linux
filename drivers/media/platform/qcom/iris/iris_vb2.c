// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */
#include <media/videobuf2-dma-contig.h>
#include <media/v4l2-mem2mem.h>

#include "iris_buffer_helpers.h"
#include "iris_ctrls.h"
#include "iris_instance.h"
#include "iris_vb2.h"
#include "iris_vdec.h"
#include "iris_power.h"
#include "iris_vpu_buffer.h"

static int iris_check_core_mbpf(struct iris_inst *inst)
{
	struct iris_inst *instance;
	struct iris_core *core;
	u32 total_mbpf = 0;

	core = inst->core;

	mutex_lock(&core->lock);
	list_for_each_entry(instance, &core->instances, list)
		total_mbpf += iris_get_mbpf(instance);
	mutex_unlock(&core->lock);

	if (total_mbpf > core->cap[MAX_MBPF].value)
		return -ENOMEM;

	return 0;
}

static int iris_check_inst_mbpf(struct iris_inst *inst)
{
	u32 mbpf = 0, max_mbpf = 0;

	max_mbpf = inst->cap[MBPF].max;
	mbpf = iris_get_mbpf(inst);
	if (mbpf > max_mbpf)
		return -ENOMEM;

	return 0;
}

static int iris_check_resolution_supported(struct iris_inst *inst)
{
	u32 width = 0, height = 0, min_width, min_height,
		max_width, max_height;

	width = inst->fmt_src->fmt.pix_mp.width;
	height = inst->fmt_src->fmt.pix_mp.height;

	min_width = inst->cap[FRAME_WIDTH].min;
	max_width = inst->cap[FRAME_WIDTH].max;
	min_height = inst->cap[FRAME_HEIGHT].min;
	max_height = inst->cap[FRAME_HEIGHT].max;

	if (!(min_width <= width && width <= max_width) ||
	    !(min_height <= height && height <= max_height))
		return -EINVAL;

	return 0;
}

static int iris_check_max_sessions(struct iris_inst *inst)
{
	struct iris_core *core;
	u32 num_sessions = 0;
	struct iris_inst *i;

	core = inst->core;
	mutex_lock(&core->lock);
	list_for_each_entry(i, &core->instances, list) {
		num_sessions++;
	}
	mutex_unlock(&core->lock);

	if (num_sessions > core->cap[MAX_SESSION_COUNT].value)
		return -ENOMEM;

	return 0;
}

static int iris_check_session_supported(struct iris_inst *inst)
{
	int ret;

	ret = iris_check_core_mbpf(inst);
	if (ret)
		goto exit;

	ret = iris_check_inst_mbpf(inst);
	if (ret)
		goto exit;

	ret = iris_check_resolution_supported(inst);
	if (ret)
		goto exit;

	ret = iris_check_max_sessions(inst);
	if (ret)
		goto exit;

	return ret;
exit:
	dev_err(inst->core->dev, "current session not supported(%d)\n", ret);

	return ret;
}

int iris_vb2_buf_init(struct vb2_buffer *vb2)
{
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb2);
	struct iris_buffer *buf = NULL;

	buf = container_of(vbuf, struct iris_buffer, vb2);
	if (!buf)
		return -EINVAL;

	buf->device_addr = vb2_dma_contig_plane_dma_addr(vb2, 0);

	return 0;
}

int iris_vb2_queue_setup(struct vb2_queue *q,
			 unsigned int *num_buffers, unsigned int *num_planes,
			 unsigned int sizes[], struct device *alloc_devs[])
{
	enum iris_buffer_type buffer_type = 0;
	struct iris_buffers *buffers;
	struct iris_inst *inst;
	struct iris_core *core;
	struct v4l2_format *f;
	int ret;

	if (!q || !num_buffers || !num_planes || !sizes)
		return -EINVAL;

	inst = vb2_get_drv_priv(q);
	if (!inst || !inst->core)
		return -EINVAL;

	mutex_lock(&inst->lock);
	if (IS_SESSION_ERROR(inst)) {
		ret = -EBUSY;
		goto unlock;
	}

	if (!iris_allow_reqbufs(inst, q->type)) {
		ret = -EBUSY;
		goto unlock;
	}

	core = inst->core;
	if (V4L2_TYPE_IS_OUTPUT(q->type))
		f = inst->fmt_src;
	else
		f = inst->fmt_dst;

	if (inst->state == IRIS_INST_STREAMING) {
		ret = -EINVAL;
		goto unlock;
	}

	if (*num_planes) {
		if (*num_planes != f->fmt.pix_mp.num_planes ||
		    sizes[0] < f->fmt.pix_mp.plane_fmt[0].sizeimage) {
			ret = -EINVAL;
			goto unlock;
		}
	}

	buffer_type = iris_v4l2_type_to_driver(q->type);
	if (!buffer_type) {
		ret = -EINVAL;
		goto unlock;
	}

	ret = iris_check_session_supported(inst);
	if (ret)
		goto unlock;

	if (!inst->once_per_session_set) {
		inst->once_per_session_set = true;

		mutex_lock(&core->lock);
		if (core->state == IRIS_CORE_ERROR) {
			mutex_unlock(&core->lock);
			ret = -EIO;
			goto unlock;
		}
		mutex_unlock(&core->lock);

		ret = core->hfi_ops->session_open(inst, inst->codec);
		if (ret) {
			dev_err(core->dev, "%s: session open failed\n", __func__);
			goto unlock;
		}

		ret = iris_inst_change_state(inst, IRIS_INST_INIT);
		if (ret)
			goto unlock;
	}

	buffers = iris_get_buffer_list(inst, buffer_type);
	if (!buffers) {
		ret = -EINVAL;
		goto unlock;
	}

	buffers->min_count = iris_vpu_buf_count(inst, buffer_type);
	if (*num_buffers < buffers->min_count)
		*num_buffers = buffers->min_count;
	buffers->actual_count = *num_buffers;
	*num_planes = 1;

	buffers->size = iris_get_buffer_size(inst, buffer_type);

	f->fmt.pix_mp.plane_fmt[0].sizeimage = buffers->size;
	sizes[0] = f->fmt.pix_mp.plane_fmt[0].sizeimage;

	q->dev = core->dev;

unlock:
	mutex_unlock(&inst->lock);
	return ret;
}

static void iris_helper_buffers_done(struct iris_inst *inst, unsigned int type,
				     enum vb2_buffer_state state)
{
	struct v4l2_m2m_ctx *m2m_ctx = inst->m2m_ctx;
	struct vb2_v4l2_buffer *buf;

	if (V4L2_TYPE_IS_OUTPUT(type)) {
		while ((buf = v4l2_m2m_src_buf_remove(m2m_ctx)))
			v4l2_m2m_buf_done(buf, state);
	} else if (V4L2_TYPE_IS_CAPTURE(type)) {
		while ((buf = v4l2_m2m_dst_buf_remove(m2m_ctx)))
			v4l2_m2m_buf_done(buf, state);
	}
}

int iris_vb2_start_streaming(struct vb2_queue *q, unsigned int count)
{
	enum iris_buffer_type buf_type;
	struct iris_inst *inst;
	int ret = 0;

	if (!q)
		return -EINVAL;

	inst = vb2_get_drv_priv(q);
	if (!inst || !inst->core)
		return -EINVAL;

	mutex_lock(&inst->lock);
	if (IS_SESSION_ERROR(inst)) {
		ret = -EBUSY;
		goto error;
	}

	if (!iris_allow_streamon(inst, q->type)) {
		ret = -EBUSY;
		goto error;
	}

	if (!V4L2_TYPE_IS_OUTPUT(q->type) &&
	    !V4L2_TYPE_IS_CAPTURE(q->type)) {
		ret = -EINVAL;
		goto error;
	}

	iris_scale_power(inst);

	ret = iris_check_session_supported(inst);
	if (ret)
		goto error;

	if (V4L2_TYPE_IS_OUTPUT(q->type))
		ret = iris_vdec_streamon_input(inst);
	else if (V4L2_TYPE_IS_CAPTURE(q->type))
		ret = iris_vdec_streamon_output(inst);
	if (ret)
		goto error;

	buf_type = iris_v4l2_type_to_driver(q->type);
	if (!buf_type) {
		ret = -EINVAL;
		goto error;
	}

	ret = iris_queue_deferred_buffers(inst, buf_type);
	if (ret)
		goto error;

	mutex_unlock(&inst->lock);

	return ret;

error:
	iris_helper_buffers_done(inst, q->type, VB2_BUF_STATE_QUEUED);
	iris_inst_change_state(inst, IRIS_INST_ERROR);
	mutex_unlock(&inst->lock);

	return ret;
}

void iris_vb2_stop_streaming(struct vb2_queue *q)
{
	struct iris_inst *inst;
	int ret = 0;

	if (!q)
		return;

	inst = vb2_get_drv_priv(q);
	if (!inst)
		return;

	mutex_lock(&inst->lock);
	if (IS_SESSION_ERROR(inst)) {
		ret = -EBUSY;
		goto error;
	}

	if (!iris_allow_streamoff(inst, q->type)) {
		ret = -EBUSY;
		goto error;
	}

	if (!V4L2_TYPE_IS_OUTPUT(q->type) &&
	    !V4L2_TYPE_IS_CAPTURE(q->type))
		goto error;

	ret = iris_vdec_session_streamoff(inst, q->type);
	if (ret)
		goto error;

	iris_helper_buffers_done(inst, q->type, VB2_BUF_STATE_ERROR);
	mutex_unlock(&inst->lock);

	return;

error:
	iris_inst_change_state(inst, IRIS_INST_ERROR);
	mutex_unlock(&inst->lock);
}

void iris_vb2_buf_queue(struct vb2_buffer *vb2)
{
	static const struct v4l2_event eos = { .type = V4L2_EVENT_EOS };
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb2);
	struct v4l2_m2m_ctx *m2m_ctx;
	struct iris_core *core;
	struct iris_inst *inst;
	int ret = 0;

	inst = vb2_get_drv_priv(vb2->vb2_queue);
	if (!inst || !inst->core)
		return;

	mutex_lock(&inst->lock);
	if (IS_SESSION_ERROR(inst)) {
		ret = -EBUSY;
		goto exit;
	}

	core = inst->core;
	m2m_ctx = inst->m2m_ctx;

	if (!vb2->planes[0].bytesused && V4L2_TYPE_IS_OUTPUT(vb2->type)) {
		ret = -EINVAL;
		goto exit;
	}

	if (V4L2_TYPE_IS_CAPTURE(vb2->vb2_queue->type)) {
		if ((inst->sub_state & IRIS_INST_SUB_DRC &&
		     inst->sub_state & IRIS_INST_SUB_DRC_LAST) ||
		    (inst->sub_state & IRIS_INST_SUB_DRAIN &&
		     inst->sub_state & IRIS_INST_SUB_DRAIN_LAST)) {
			vbuf->flags |= V4L2_BUF_FLAG_LAST;
			vbuf->field = V4L2_FIELD_NONE;
			vb2_set_plane_payload(vb2, 0, 0);
			v4l2_m2m_buf_done(vbuf, VB2_BUF_STATE_DONE);
			if (inst->subscriptions & V4L2_EVENT_EOS)
				v4l2_event_queue_fh(&inst->fh, &eos);
			goto exit;
		}
	}

	v4l2_m2m_buf_queue(m2m_ctx, vbuf);

	dev_dbg(inst->core->dev, "vdec qbuf ret %d", ret);
	ret = iris_vdec_qbuf(inst, vbuf);

exit:
	if (ret) {
		iris_inst_change_state(inst, IRIS_INST_ERROR);
		v4l2_m2m_buf_done(vbuf, VB2_BUF_STATE_ERROR);
	}
	mutex_unlock(&inst->lock);
}
