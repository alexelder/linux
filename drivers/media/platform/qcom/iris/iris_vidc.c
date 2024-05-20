// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/videodev2.h>
#include <media/v4l2-event.h>
#include <media/v4l2-ioctl.h>
#include <media/v4l2-mem2mem.h>
#include <media/videobuf2-dma-contig.h>

#include "iris_vidc.h"
#include "iris_buffer_helpers.h"
#include "iris_ctrls.h"
#include "iris_instance.h"
#include "iris_power.h"
#include "iris_vdec.h"
#include "iris_vb2.h"
#include "iris_platform_common.h"

#define IRIS_DRV_NAME "iris_driver"
#define IRIS_BUS_NAME "platform:iris_bus"

static int iris_v4l2_fh_init(struct iris_inst *inst)
{
	struct iris_core *core;

	core = inst->core;

	if (inst->fh.vdev)
		return -EINVAL;

	v4l2_fh_init(&inst->fh, core->vdev_dec);
	inst->fh.ctrl_handler = &inst->ctrl_handler;
	v4l2_fh_add(&inst->fh);

	return 0;
}

static void iris_v4l2_fh_deinit(struct iris_inst *inst)
{
	if (!inst->fh.vdev)
		return;

	v4l2_fh_del(&inst->fh);
	inst->fh.ctrl_handler = NULL;
	v4l2_fh_exit(&inst->fh);
}

static int iris_add_session(struct iris_inst *inst)
{
	struct iris_core *core;
	struct iris_inst *i;
	u32 count = 0;
	int ret = 0;

	core = inst->core;

	mutex_lock(&core->lock);
	if (core->state != IRIS_CORE_INIT) {
		ret = -EINVAL;
		goto unlock;
	}
	list_for_each_entry(i, &core->instances, list)
		count++;

	if (count < core->cap[MAX_SESSION_COUNT].value)
		list_add_tail(&inst->list, &core->instances);
	else
		ret = -EAGAIN;
unlock:
	mutex_unlock(&core->lock);

	return ret;
}

static void iris_remove_session(struct iris_inst *inst)
{
	struct iris_inst *i, *temp;
	struct iris_core *core;

	core = inst->core;

	mutex_lock(&core->lock);
	list_for_each_entry_safe(i, temp, &core->instances, list) {
		if (i->session_id == inst->session_id) {
			list_del_init(&i->list);
			break;
		}
	}
	mutex_unlock(&core->lock);
}

static struct iris_inst *iris_get_inst(struct file *filp, void *fh)
{
	if (!filp || !filp->private_data)
		return NULL;

	return container_of(filp->private_data,
					struct iris_inst, fh);
}

static void iris_m2m_device_run(void *priv)
{
}

static void iris_m2m_job_abort(void *priv)
{
	struct iris_inst *inst = priv;
	struct v4l2_m2m_ctx *m2m_ctx = inst->m2m_ctx;

	v4l2_m2m_job_finish(inst->m2m_dev, m2m_ctx);
}

static const struct v4l2_m2m_ops iris_m2m_ops = {
	.device_run = iris_m2m_device_run,
	.job_abort = iris_m2m_job_abort,
};

static int
iris_m2m_queue_init(void *priv, struct vb2_queue *src_vq, struct vb2_queue *dst_vq)
{
	struct iris_inst *inst = priv;
	int ret;

	src_vq->type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	src_vq->io_modes = VB2_MMAP | VB2_DMABUF;
	src_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	src_vq->ops = inst->core->iris_vb2_ops;
	src_vq->mem_ops = &vb2_dma_contig_memops;
	src_vq->drv_priv = inst;
	src_vq->buf_struct_size = sizeof(struct iris_buffer);
	src_vq->allow_zero_bytesused = 1;
	src_vq->dev = inst->core->dev;
	src_vq->lock = &inst->ctx_q_lock;
	ret = vb2_queue_init(src_vq);
	if (ret)
		return ret;

	dst_vq->type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	dst_vq->io_modes = VB2_MMAP | VB2_DMABUF;
	dst_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	dst_vq->ops = inst->core->iris_vb2_ops;
	dst_vq->mem_ops = &vb2_dma_contig_memops;
	dst_vq->drv_priv = inst;
	dst_vq->buf_struct_size = sizeof(struct iris_buffer);
	dst_vq->allow_zero_bytesused = 1;
	dst_vq->dev = inst->core->dev;
	dst_vq->lock = &inst->ctx_q_lock;
	return vb2_queue_init(dst_vq);
}

int iris_open(struct file *filp)
{
	struct iris_core *core = video_drvdata(filp);
	struct iris_inst *inst = NULL;
	int ret;

	inst = kzalloc(sizeof(*inst), GFP_KERNEL);
	if (!inst)
		return -ENOMEM;

	inst->core = core;
	inst->session_id = hash32_ptr(inst);
	inst->ipsc_properties_set = false;
	inst->opsc_properties_set = false;
	inst->state = IRIS_INST_DEINIT;

	ret = iris_add_session(inst);
	if (ret)
		goto fail_free_inst;

	mutex_init(&inst->lock);
	mutex_init(&inst->ctx_q_lock);

	INIT_LIST_HEAD(&inst->buffers.bin.list);
	INIT_LIST_HEAD(&inst->buffers.arp.list);
	INIT_LIST_HEAD(&inst->buffers.comv.list);
	INIT_LIST_HEAD(&inst->buffers.non_comv.list);
	INIT_LIST_HEAD(&inst->buffers.line.list);
	INIT_LIST_HEAD(&inst->buffers.dpb.list);
	INIT_LIST_HEAD(&inst->buffers.persist.list);
	INIT_LIST_HEAD(&inst->buffers.vpss.list);
	INIT_LIST_HEAD(&inst->buffers.scratch.list);
	INIT_LIST_HEAD(&inst->buffers.scratch1.list);
	INIT_LIST_HEAD(&inst->caps_list);
	init_completion(&inst->completion);
	init_completion(&inst->flush_completion);

	ret = iris_v4l2_fh_init(inst);
	if (ret)
		goto fail_remove_session;

	inst->m2m_dev = v4l2_m2m_init(&iris_m2m_ops);
	if (IS_ERR_OR_NULL(inst->m2m_dev)) {
		ret = -EINVAL;
		goto fail_inst_deinit;
	}

	inst->m2m_ctx = v4l2_m2m_ctx_init(inst->m2m_dev, inst, iris_m2m_queue_init);
	if (IS_ERR_OR_NULL(inst->m2m_ctx)) {
		ret = -EINVAL;
		goto fail_m2m_release;
	}

	iris_vdec_inst_init(inst);
	if (ret)
		goto fail_m2m_ctx_release;

	inst->fh.m2m_ctx = inst->m2m_ctx;
	filp->private_data = &inst->fh;

	return 0;

fail_m2m_ctx_release:
	v4l2_m2m_ctx_release(inst->m2m_ctx);
fail_m2m_release:
	v4l2_m2m_release(inst->m2m_dev);
fail_inst_deinit:
	v4l2_ctrl_handler_free(&inst->ctrl_handler);
	iris_vdec_inst_deinit(inst);
	iris_v4l2_fh_deinit(inst);
fail_remove_session:
	mutex_destroy(&inst->ctx_q_lock);
	mutex_destroy(&inst->lock);
	iris_remove_session(inst);
fail_free_inst:
	kfree(inst);

	return ret;
}

int iris_close(struct file *filp)
{
	struct iris_inst *inst;
	struct iris_core *core;

	inst = iris_get_inst(filp, NULL);
	if (!inst)
		return -EINVAL;

	core = inst->core;

	v4l2_ctrl_handler_free(&inst->ctrl_handler);
	iris_vdec_inst_deinit(inst);
	mutex_lock(&inst->lock);
	iris_session_close(inst);
	iris_inst_change_state(inst, IRIS_INST_DEINIT);
	v4l2_m2m_ctx_release(inst->m2m_ctx);
	v4l2_m2m_release(inst->m2m_dev);
	iris_v4l2_fh_deinit(inst);
	iris_destroy_internal_buffers(inst, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE);
	iris_destroy_internal_buffers(inst, V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE);
	iris_remove_session(inst);
	mutex_unlock(&inst->lock);
	mutex_destroy(&inst->ctx_q_lock);
	mutex_destroy(&inst->lock);
	kfree(inst);
	filp->private_data = NULL;

	return 0;
}

static int iris_enum_fmt(struct file *filp, void *fh, struct v4l2_fmtdesc *f)
{
	struct iris_inst *inst;
	int ret;

	inst = iris_get_inst(filp, fh);
	if (!inst)
		return -EINVAL;

	mutex_lock(&inst->lock);
	if (IS_SESSION_ERROR(inst)) {
		ret = -EBUSY;
		goto unlock;
	}

	ret = iris_vdec_enum_fmt(inst, f);

unlock:
	mutex_unlock(&inst->lock);

	return ret;
}

static int iris_try_fmt(struct file *filp, void *fh, struct v4l2_format *f)
{
	struct iris_inst *inst;
	int ret;

	inst = iris_get_inst(filp, fh);
	if (!inst)
		return -EINVAL;

	mutex_lock(&inst->lock);
	if (IS_SESSION_ERROR(inst)) {
		ret = -EBUSY;
		goto unlock;
	}

	if (!iris_allow_s_fmt(inst, f->type)) {
		ret = -EBUSY;
		goto unlock;
	}

	ret = iris_vdec_try_fmt(inst, f);

unlock:
	mutex_unlock(&inst->lock);

	return ret;
}

static int iris_s_fmt(struct file *filp, void *fh, struct v4l2_format *f)
{
	struct iris_inst *inst;
	int ret;

	inst = iris_get_inst(filp, fh);
	if (!inst)
		return -EINVAL;

	mutex_lock(&inst->lock);
	if (IS_SESSION_ERROR(inst)) {
		ret = -EBUSY;
		goto unlock;
	}

	if (!iris_allow_s_fmt(inst, f->type)) {
		ret = -EBUSY;
		goto unlock;
	}

	ret = iris_vdec_s_fmt(inst, f);

unlock:
	mutex_unlock(&inst->lock);

	return ret;
}

static int iris_g_fmt(struct file *filp, void *fh, struct v4l2_format *f)
{
	struct iris_inst *inst;
	int ret = 0;

	inst = iris_get_inst(filp, fh);
	if (!inst)
		return -EINVAL;

	mutex_lock(&inst->lock);
	if (IS_SESSION_ERROR(inst)) {
		ret = -EBUSY;
		goto unlock;
	}

	if (V4L2_TYPE_IS_OUTPUT(f->type))
		memcpy(f, inst->fmt_src, sizeof(*f));
	else if (V4L2_TYPE_IS_CAPTURE(f->type))
		memcpy(f, inst->fmt_dst, sizeof(*f));
	else
		ret = -EINVAL;

unlock:
	mutex_unlock(&inst->lock);

	return ret;
}

static int iris_enum_framesizes(struct file *filp, void *fh,
				struct v4l2_frmsizeenum *fsize)
{
	struct iris_inst *inst;
	int ret = 0;

	inst = iris_get_inst(filp, fh);
	if (!inst || !fsize)
		return -EINVAL;

	if (fsize->index)
		return -EINVAL;

	mutex_lock(&inst->lock);
	if (IS_SESSION_ERROR(inst)) {
		ret = -EBUSY;
		goto unlock;
	}

	if (fsize->pixel_format != V4L2_PIX_FMT_H264 &&
	    fsize->pixel_format != V4L2_PIX_FMT_NV12) {
		ret = -EINVAL;
		goto unlock;
	}

	fsize->type = V4L2_FRMSIZE_TYPE_STEPWISE;
	fsize->stepwise.min_width = inst->cap[FRAME_WIDTH].min;
	fsize->stepwise.max_width = inst->cap[FRAME_WIDTH].max;
	fsize->stepwise.step_width = inst->cap[FRAME_WIDTH].step_or_mask;
	fsize->stepwise.min_height = inst->cap[FRAME_HEIGHT].min;
	fsize->stepwise.max_height = inst->cap[FRAME_HEIGHT].max;
	fsize->stepwise.step_height = inst->cap[FRAME_HEIGHT].step_or_mask;

unlock:
	mutex_unlock(&inst->lock);

	return ret;
}

static int iris_querycap(struct file *filp, void *fh, struct v4l2_capability *cap)
{
	struct iris_inst *inst;
	int ret = 0;

	inst = iris_get_inst(filp, fh);
	if (!inst)
		return -EINVAL;

	mutex_lock(&inst->lock);
	if (IS_SESSION_ERROR(inst)) {
		ret = -EBUSY;
		goto unlock;
	}

	strscpy(cap->driver, IRIS_DRV_NAME, sizeof(cap->driver));
	strscpy(cap->bus_info, IRIS_BUS_NAME, sizeof(cap->bus_info));
	memset(cap->reserved, 0, sizeof(cap->reserved));
	strscpy(cap->card, "iris_decoder", sizeof(cap->card));

unlock:
	mutex_unlock(&inst->lock);

	return ret;
}

static int iris_queryctrl(struct file *filp, void *fh, struct v4l2_queryctrl *q_ctrl)
{
	struct v4l2_ctrl *ctrl;
	struct iris_inst *inst;
	int ret = 0;

	inst = iris_get_inst(filp, fh);
	if (!inst || !q_ctrl)
		return -EINVAL;

	mutex_lock(&inst->lock);
	if (IS_SESSION_ERROR(inst)) {
		ret = -EBUSY;
		goto unlock;
	}

	ctrl = v4l2_ctrl_find(&inst->ctrl_handler, q_ctrl->id);
	if (!ctrl) {
		ret = -EINVAL;
		goto unlock;
	}

	q_ctrl->minimum = ctrl->minimum;
	q_ctrl->maximum = ctrl->maximum;
	q_ctrl->default_value = ctrl->default_value;
	q_ctrl->flags = 0;
	q_ctrl->step = ctrl->step;

unlock:
	mutex_unlock(&inst->lock);

	return ret;
}

static int iris_querymenu(struct file *filp, void *fh, struct v4l2_querymenu *qmenu)
{
	struct v4l2_ctrl *ctrl;
	struct iris_inst *inst;
	int ret = 0;

	inst = iris_get_inst(filp, fh);
	if (!inst || !qmenu)
		return -EINVAL;

	mutex_lock(&inst->lock);
	if (IS_SESSION_ERROR(inst)) {
		ret = -EBUSY;
		goto unlock;
	}

	ctrl = v4l2_ctrl_find(&inst->ctrl_handler, qmenu->id);
	if (!ctrl) {
		ret = -EINVAL;
		goto unlock;
	}

	if (ctrl->type != V4L2_CTRL_TYPE_MENU) {
		ret = -EINVAL;
		goto unlock;
	}

	if (qmenu->index < ctrl->minimum || qmenu->index > ctrl->maximum) {
		ret = -EINVAL;
		goto unlock;
	}

	if (ctrl->menu_skip_mask & (1 << qmenu->index)) {
		ret = -EINVAL;
		goto unlock;
	}

unlock:
	mutex_unlock(&inst->lock);

	return ret;
}

static int iris_subscribe_event(struct v4l2_fh *fh, const struct v4l2_event_subscription *sub)
{
	struct iris_inst *inst;
	int ret;

	inst = container_of(fh, struct iris_inst, fh);

	mutex_lock(&inst->lock);
	if (IS_SESSION_ERROR(inst)) {
		ret = -EBUSY;
		goto unlock;
	}

	ret = iris_vdec_subscribe_event(inst, sub);

unlock:
	mutex_unlock(&inst->lock);

	return ret;
}

static int iris_unsubscribe_event(struct v4l2_fh *fh, const struct v4l2_event_subscription *sub)
{
	struct iris_inst *inst;
	int ret;

	inst = container_of(fh, struct iris_inst, fh);

	mutex_lock(&inst->lock);
	if (IS_SESSION_ERROR(inst)) {
		ret = -EBUSY;
		goto unlock;
	}

	ret = v4l2_event_unsubscribe(&inst->fh, sub);

unlock:
	mutex_unlock(&inst->lock);

	return ret;
}

static int iris_g_selection(struct file *filp, void *fh, struct v4l2_selection *s)
{
	struct iris_inst *inst;
	int ret = 0;

	inst = iris_get_inst(filp, fh);
	if (!inst || !s)
		return -EINVAL;

	mutex_lock(&inst->lock);
	if (IS_SESSION_ERROR(inst)) {
		ret = -EBUSY;
		goto unlock;
	}

	if (!V4L2_TYPE_IS_CAPTURE(s->type)) {
		ret = -EINVAL;
		goto unlock;
	}

	switch (s->target) {
	case V4L2_SEL_TGT_CROP_BOUNDS:
	case V4L2_SEL_TGT_CROP_DEFAULT:
	case V4L2_SEL_TGT_CROP:
	case V4L2_SEL_TGT_COMPOSE_BOUNDS:
	case V4L2_SEL_TGT_COMPOSE_PADDED:
	case V4L2_SEL_TGT_COMPOSE_DEFAULT:
	case V4L2_SEL_TGT_COMPOSE:
		s->r.left = inst->crop.left;
		s->r.top = inst->crop.top;
		s->r.width = inst->crop.width;
		s->r.height = inst->crop.height;
		break;
	default:
		ret = -EINVAL;
	}

unlock:
	mutex_unlock(&inst->lock);

	return ret;
}

static int iris_dec_cmd(struct file *filp, void *fh,
			struct v4l2_decoder_cmd *dec)
{
	struct iris_inst *inst;
	int ret = 0;

	inst = iris_get_inst(filp, fh);
	if (!inst || !dec)
		return -EINVAL;

	mutex_lock(&inst->lock);
	if (IS_SESSION_ERROR(inst)) {
		ret = -EBUSY;
		goto unlock;
	}

	if (inst->state == IRIS_INST_INIT)
		goto unlock;

	if (!iris_allow_cmd(inst, dec->cmd)) {
		ret = -EBUSY;
		goto unlock;
	}

	if (dec->cmd == V4L2_DEC_CMD_START)
		ret = iris_vdec_start_cmd(inst);
	else if (dec->cmd == V4L2_DEC_CMD_STOP)
		ret = iris_vdec_stop_cmd(inst);
	else
		ret = -EINVAL;

unlock:
	mutex_unlock(&inst->lock);

	return ret;
}

static struct v4l2_file_operations iris_v4l2_file_ops = {
	.owner                          = THIS_MODULE,
	.open                           = iris_open,
	.release                        = iris_close,
	.unlocked_ioctl                 = video_ioctl2,
	.poll                           = v4l2_m2m_fop_poll,
	.mmap                           = v4l2_m2m_fop_mmap,
};

static const struct vb2_ops iris_vb2_ops = {
	.buf_init                       = iris_vb2_buf_init,
	.queue_setup                    = iris_vb2_queue_setup,
	.start_streaming                = iris_vb2_start_streaming,
	.stop_streaming                 = iris_vb2_stop_streaming,
	.buf_queue                      = iris_vb2_buf_queue,
};

static const struct v4l2_ioctl_ops iris_v4l2_ioctl_ops = {
	.vidioc_enum_fmt_vid_cap        = iris_enum_fmt,
	.vidioc_enum_fmt_vid_out        = iris_enum_fmt,
	.vidioc_try_fmt_vid_cap_mplane  = iris_try_fmt,
	.vidioc_try_fmt_vid_out_mplane  = iris_try_fmt,
	.vidioc_s_fmt_vid_cap_mplane    = iris_s_fmt,
	.vidioc_s_fmt_vid_out_mplane    = iris_s_fmt,
	.vidioc_g_fmt_vid_cap_mplane    = iris_g_fmt,
	.vidioc_g_fmt_vid_out_mplane    = iris_g_fmt,
	.vidioc_enum_framesizes         = iris_enum_framesizes,
	.vidioc_reqbufs                 = v4l2_m2m_ioctl_reqbufs,
	.vidioc_querybuf                = v4l2_m2m_ioctl_querybuf,
	.vidioc_create_bufs             = v4l2_m2m_ioctl_create_bufs,
	.vidioc_prepare_buf             = v4l2_m2m_ioctl_prepare_buf,
	.vidioc_qbuf                    = v4l2_m2m_ioctl_qbuf,
	.vidioc_dqbuf                   = v4l2_m2m_ioctl_dqbuf,
	.vidioc_streamon                = v4l2_m2m_ioctl_streamon,
	.vidioc_streamoff               = v4l2_m2m_ioctl_streamoff,
	.vidioc_querycap                = iris_querycap,
	.vidioc_queryctrl               = iris_queryctrl,
	.vidioc_querymenu               = iris_querymenu,
	.vidioc_subscribe_event         = iris_subscribe_event,
	.vidioc_unsubscribe_event       = iris_unsubscribe_event,
	.vidioc_g_selection             = iris_g_selection,
	.vidioc_try_decoder_cmd         = v4l2_m2m_ioctl_try_decoder_cmd,
	.vidioc_decoder_cmd             = iris_dec_cmd,
};

void iris_init_ops(struct iris_core *core)
{
	core->iris_v4l2_file_ops = &iris_v4l2_file_ops;
	core->iris_vb2_ops = &iris_vb2_ops;
	core->iris_v4l2_ioctl_ops = &iris_v4l2_ioctl_ops;
}
