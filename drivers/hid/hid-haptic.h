/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  HID Haptic support for Linux
 *
 *  Copyright (c) 2021 Angela Czubak <acz@semihalf.com>
 */

/*
 */


#include <linux/hid.h>

#define HID_HAPTIC_ORDINAL_WAVEFORMNONE 1
#define HID_HAPTIC_ORDINAL_WAVEFORMSTOP 2

#define HID_HAPTIC_PRESS_THRESH 200
#define HID_HAPTIC_RELEASE_THRESH 180

#define HID_HAPTIC_MODE_DEVICE 0
#define HID_HAPTIC_MODE_KERNEL 1

struct hid_haptic_effect {
	u8 *report_buf;
	struct input_dev *input_dev;
	struct work_struct work;
	struct list_head control;
	struct mutex control_mutex;
};

struct hid_haptic_effect_node {
	struct list_head node;
	struct file *file;
};

struct hid_haptic_device {
	struct input_dev *input_dev;
	struct hid_device *hdev;
	struct hid_report *auto_trigger_report;
	struct mutex auto_trigger_mutex;
	struct workqueue_struct *wq;
	struct hid_report *manual_trigger_report;
	struct mutex manual_trigger_mutex;
	size_t manual_trigger_report_len;
	int pressed_state;
	s32 pressure_sum;
	s32 force_logical_minimum;
	s32 force_physical_minimum;
	s32 force_resolution;
	u32 press_threshold;
	u32 release_threshold;
	u32 mode;
	u32 default_auto_trigger;
	u32 vendor_page;
	u32 vendor_id;
	u32 max_waveform_id;
	u32 max_duration_id;
	u16 *hid_usage_map;
	u32 *duration_map;
	u16 press_ordinal_orig;
	u16 press_ordinal_cur;
	u16 release_ordinal_orig;
	u16 release_ordinal_cur;
#define HID_HAPTIC_RELEASE_EFFECT_ID 0
#define HID_HAPTIC_PRESS_EFFECT_ID 1
	struct hid_haptic_effect *effect;
	struct hid_haptic_effect stop_effect;
};

#ifdef CONFIG_MULTITOUCH_HAPTIC
void hid_haptic_feature_mapping(struct hid_device *hdev,
				struct hid_haptic_device *haptic,
				struct hid_field *field, struct hid_usage
				*usage);
bool hid_haptic_check_pressure_unit(struct hid_haptic_device *haptic,
				    struct hid_input *hi, struct hid_field *field);
int hid_haptic_input_mapping(struct hid_device *hdev,
			     struct hid_haptic_device *haptic,
			     struct hid_input *hi,
			     struct hid_field *field, struct hid_usage *usage,
			     unsigned long **bit, int *max);
int hid_haptic_input_configured(struct hid_device *hdev,
				struct hid_haptic_device *haptic,
				struct hid_input *hi);
#else
static inline
void hid_haptic_feature_mapping(struct hid_device *hdev,
				struct hid_haptic_device *haptic,
				struct hid_field *field, struct hid_usage
				*usage)
{}
static inline
bool hid_haptic_check_pressure_unit(struct hid_haptic_device *haptic,
				    struct hid_input *hi, struct hid_field *field)
{
	return false;
}
static inline
int hid_haptic_input_mapping(struct hid_device *hdev,
			     struct hid_haptic_device *haptic,
			     struct hid_input *hi,
			     struct hid_field *field, struct hid_usage *usage,
			     unsigned long **bit, int *max)
{
	return 0;
}
static inline
int hid_haptic_input_configured(struct hid_device *hdev,
				struct hid_haptic_device *haptic,
				struct hid_input *hi)
{
	return 0;
}
#endif
