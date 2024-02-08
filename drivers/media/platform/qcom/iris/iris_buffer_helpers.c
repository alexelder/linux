// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */
#include <media/v4l2-mem2mem.h>

#include "iris_buffer_helpers.h"
#include "iris_instance.h"
#include "iris_power.h"

int iris_queue_buffer(struct iris_inst *inst, struct iris_buffer *buf)
{
	struct iris_core *core;
	int ret;

	core = inst->core;

	ret = core->hfi_ops->session_queue_buf(inst, buf);
	if (ret)
		return ret;

	buf->attr &= ~BUF_ATTR_DEFERRED;
	buf->attr |= BUF_ATTR_QUEUED;

	return ret;
}

int iris_queue_deferred_buffers(struct iris_inst *inst, enum iris_buffer_type buf_type)
{
	struct v4l2_m2m_ctx *m2m_ctx = inst->m2m_ctx;
	struct v4l2_m2m_buffer *buffer, *n;
	struct iris_buffer *buf = NULL;
	int ret;

	iris_scale_power(inst);

	if (buf_type == BUF_INPUT) {
		v4l2_m2m_for_each_src_buf_safe(m2m_ctx, buffer, n) {
			buf = to_iris_buffer(&buffer->vb);
			if (!(buf->attr & BUF_ATTR_DEFERRED))
				continue;
			ret = iris_queue_buffer(inst, buf);
			if (ret)
				return ret;
		}
	} else {
		v4l2_m2m_for_each_dst_buf_safe(m2m_ctx, buffer, n) {
			buf = to_iris_buffer(&buffer->vb);
			if (!(buf->attr & BUF_ATTR_DEFERRED))
				continue;
			ret = iris_queue_buffer(inst, buf);
			if (ret)
				return ret;
		}
	}

	return 0;
}

void iris_vb2_queue_error(struct iris_inst *inst)
{
	struct v4l2_m2m_ctx *m2m_ctx = inst->m2m_ctx;
	struct vb2_queue *q;

	q = v4l2_m2m_get_src_vq(m2m_ctx);
	vb2_queue_error(q);
	q = v4l2_m2m_get_dst_vq(m2m_ctx);
	vb2_queue_error(q);
}

static struct vb2_v4l2_buffer *
iris_helper_find_buf(struct iris_inst *inst, unsigned int type, u32 idx)
{
	struct v4l2_m2m_ctx *m2m_ctx = inst->m2m_ctx;
	struct vb2_queue *src_q, *dst_q;

	src_q = v4l2_m2m_get_src_vq(m2m_ctx);
	dst_q = v4l2_m2m_get_dst_vq(m2m_ctx);

	if (!vb2_is_streaming(src_q) || !vb2_is_streaming(dst_q))
		return NULL;

	if (V4L2_TYPE_IS_OUTPUT(type))
		return v4l2_m2m_src_buf_remove_by_idx(m2m_ctx, idx);
	else
		return v4l2_m2m_dst_buf_remove_by_idx(m2m_ctx, idx);
}

int iris_vb2_buffer_done(struct iris_inst *inst,
			 struct iris_buffer *buf)
{
	struct vb2_v4l2_buffer *vbuf;
	struct vb2_buffer *vb2;
	int type, state;

	type = iris_v4l2_type_from_driver(buf->type);
	if (!type)
		return -EINVAL;

	vbuf = iris_helper_find_buf(inst, type, buf->index);
	if (!vbuf)
		return -EINVAL;

	vb2 = &vbuf->vb2_buf;

	if (buf->flags & V4L2_BUF_FLAG_ERROR)
		state = VB2_BUF_STATE_ERROR;
	else
		state = VB2_BUF_STATE_DONE;

	vbuf->flags = buf->flags;

	if (vbuf->flags & V4L2_BUF_FLAG_LAST) {
		if (inst->subscriptions & V4L2_EVENT_EOS) {
			const struct v4l2_event ev = { .type = V4L2_EVENT_EOS };

			v4l2_event_queue_fh(&inst->fh, &ev);
		}
	}
	vb2->timestamp = buf->timestamp;
	vb2->planes[0].bytesused = buf->data_size + vb2->planes[0].data_offset;
	v4l2_m2m_buf_done(vbuf, state);

	return 0;
}
