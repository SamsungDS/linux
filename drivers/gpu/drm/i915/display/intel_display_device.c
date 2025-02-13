// SPDX-License-Identifier: MIT
/*
 * Copyright © 2023 Intel Corporation
 */

#include <drm/i915_pciids.h>
#include <drm/drm_color_mgmt.h>
#include <linux/pci.h>

#include "i915_drv.h"
#include "i915_reg.h"
#include "intel_display_device.h"
#include "intel_display_power.h"
#include "intel_display_reg_defs.h"
#include "intel_fbc.h"

static const struct intel_display_device_info no_display = {};

#define PIPE_A_OFFSET		0x70000
#define PIPE_B_OFFSET		0x71000
#define PIPE_C_OFFSET		0x72000
#define PIPE_D_OFFSET		0x73000
#define CHV_PIPE_C_OFFSET	0x74000
/*
 * There's actually no pipe EDP. Some pipe registers have
 * simply shifted from the pipe to the transcoder, while
 * keeping their original offset. Thus we need PIPE_EDP_OFFSET
 * to access such registers in transcoder EDP.
 */
#define PIPE_EDP_OFFSET	0x7f000

/* ICL DSI 0 and 1 */
#define PIPE_DSI0_OFFSET	0x7b000
#define PIPE_DSI1_OFFSET	0x7b800

#define TRANSCODER_A_OFFSET 0x60000
#define TRANSCODER_B_OFFSET 0x61000
#define TRANSCODER_C_OFFSET 0x62000
#define CHV_TRANSCODER_C_OFFSET 0x63000
#define TRANSCODER_D_OFFSET 0x63000
#define TRANSCODER_EDP_OFFSET 0x6f000
#define TRANSCODER_DSI0_OFFSET	0x6b000
#define TRANSCODER_DSI1_OFFSET	0x6b800

#define CURSOR_A_OFFSET 0x70080
#define CURSOR_B_OFFSET 0x700c0
#define CHV_CURSOR_C_OFFSET 0x700e0
#define IVB_CURSOR_B_OFFSET 0x71080
#define IVB_CURSOR_C_OFFSET 0x72080
#define TGL_CURSOR_D_OFFSET 0x73080

#define I845_PIPE_OFFSETS \
	.pipe_offsets = { \
		[TRANSCODER_A] = PIPE_A_OFFSET,	\
	}, \
	.trans_offsets = { \
		[TRANSCODER_A] = TRANSCODER_A_OFFSET, \
	}

#define I9XX_PIPE_OFFSETS \
	.pipe_offsets = { \
		[TRANSCODER_A] = PIPE_A_OFFSET,	\
		[TRANSCODER_B] = PIPE_B_OFFSET, \
	}, \
	.trans_offsets = { \
		[TRANSCODER_A] = TRANSCODER_A_OFFSET, \
		[TRANSCODER_B] = TRANSCODER_B_OFFSET, \
	}

#define IVB_PIPE_OFFSETS \
	.pipe_offsets = { \
		[TRANSCODER_A] = PIPE_A_OFFSET,	\
		[TRANSCODER_B] = PIPE_B_OFFSET, \
		[TRANSCODER_C] = PIPE_C_OFFSET, \
	}, \
	.trans_offsets = { \
		[TRANSCODER_A] = TRANSCODER_A_OFFSET, \
		[TRANSCODER_B] = TRANSCODER_B_OFFSET, \
		[TRANSCODER_C] = TRANSCODER_C_OFFSET, \
	}

#define HSW_PIPE_OFFSETS \
	.pipe_offsets = { \
		[TRANSCODER_A] = PIPE_A_OFFSET,	\
		[TRANSCODER_B] = PIPE_B_OFFSET, \
		[TRANSCODER_C] = PIPE_C_OFFSET, \
		[TRANSCODER_EDP] = PIPE_EDP_OFFSET, \
	}, \
	.trans_offsets = { \
		[TRANSCODER_A] = TRANSCODER_A_OFFSET, \
		[TRANSCODER_B] = TRANSCODER_B_OFFSET, \
		[TRANSCODER_C] = TRANSCODER_C_OFFSET, \
		[TRANSCODER_EDP] = TRANSCODER_EDP_OFFSET, \
	}

#define CHV_PIPE_OFFSETS \
	.pipe_offsets = { \
		[TRANSCODER_A] = PIPE_A_OFFSET, \
		[TRANSCODER_B] = PIPE_B_OFFSET, \
		[TRANSCODER_C] = CHV_PIPE_C_OFFSET, \
	}, \
	.trans_offsets = { \
		[TRANSCODER_A] = TRANSCODER_A_OFFSET, \
		[TRANSCODER_B] = TRANSCODER_B_OFFSET, \
		[TRANSCODER_C] = CHV_TRANSCODER_C_OFFSET, \
	}

#define I845_CURSOR_OFFSETS \
	.cursor_offsets = { \
		[PIPE_A] = CURSOR_A_OFFSET, \
	}

#define I9XX_CURSOR_OFFSETS \
	.cursor_offsets = { \
		[PIPE_A] = CURSOR_A_OFFSET, \
		[PIPE_B] = CURSOR_B_OFFSET, \
	}

#define CHV_CURSOR_OFFSETS \
	.cursor_offsets = { \
		[PIPE_A] = CURSOR_A_OFFSET, \
		[PIPE_B] = CURSOR_B_OFFSET, \
		[PIPE_C] = CHV_CURSOR_C_OFFSET, \
	}

#define IVB_CURSOR_OFFSETS \
	.cursor_offsets = { \
		[PIPE_A] = CURSOR_A_OFFSET, \
		[PIPE_B] = IVB_CURSOR_B_OFFSET, \
		[PIPE_C] = IVB_CURSOR_C_OFFSET, \
	}

#define TGL_CURSOR_OFFSETS \
	.cursor_offsets = { \
		[PIPE_A] = CURSOR_A_OFFSET, \
		[PIPE_B] = IVB_CURSOR_B_OFFSET, \
		[PIPE_C] = IVB_CURSOR_C_OFFSET, \
		[PIPE_D] = TGL_CURSOR_D_OFFSET, \
	}

#define I845_COLORS \
	.color = { .gamma_lut_size = 256 }
#define I9XX_COLORS \
	.color = { .gamma_lut_size = 129, \
		   .gamma_lut_tests = DRM_COLOR_LUT_NON_DECREASING, \
	}
#define ILK_COLORS \
	.color = { .gamma_lut_size = 1024 }
#define IVB_COLORS \
	.color = { .degamma_lut_size = 1024, .gamma_lut_size = 1024 }
#define CHV_COLORS \
	.color = { \
		.degamma_lut_size = 65, .gamma_lut_size = 257, \
		.degamma_lut_tests = DRM_COLOR_LUT_NON_DECREASING, \
		.gamma_lut_tests = DRM_COLOR_LUT_NON_DECREASING, \
	}
#define GLK_COLORS \
	.color = { \
		.degamma_lut_size = 33, .gamma_lut_size = 1024, \
		.degamma_lut_tests = DRM_COLOR_LUT_NON_DECREASING | \
				     DRM_COLOR_LUT_EQUAL_CHANNELS, \
	}
#define ICL_COLORS \
	.color = { \
		.degamma_lut_size = 33, .gamma_lut_size = 262145, \
		.degamma_lut_tests = DRM_COLOR_LUT_NON_DECREASING | \
				     DRM_COLOR_LUT_EQUAL_CHANNELS, \
		.gamma_lut_tests = DRM_COLOR_LUT_NON_DECREASING, \
	}

#define I830_DISPLAY \
	.has_overlay = 1, \
	.cursor_needs_physical = 1, \
	.overlay_needs_physical = 1, \
	.has_gmch = 1, \
	I9XX_PIPE_OFFSETS, \
	I9XX_CURSOR_OFFSETS, \
	I9XX_COLORS, \
	\
	.__runtime_defaults.ip.ver = 2, \
	.__runtime_defaults.pipe_mask = BIT(PIPE_A) | BIT(PIPE_B), \
	.__runtime_defaults.cpu_transcoder_mask = \
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B)

static const struct intel_display_device_info i830_display = {
	I830_DISPLAY,
};

#define I845_DISPLAY \
	.has_overlay = 1, \
	.overlay_needs_physical = 1, \
	.has_gmch = 1, \
	I845_PIPE_OFFSETS, \
	I845_CURSOR_OFFSETS, \
	I845_COLORS, \
	\
	.__runtime_defaults.ip.ver = 2, \
	.__runtime_defaults.pipe_mask = BIT(PIPE_A), \
	.__runtime_defaults.cpu_transcoder_mask = BIT(TRANSCODER_A)

static const struct intel_display_device_info i845_display = {
	I845_DISPLAY,
};

static const struct intel_display_device_info i85x_display = {
	I830_DISPLAY,

	.__runtime_defaults.fbc_mask = BIT(INTEL_FBC_A),
};

static const struct intel_display_device_info i865g_display = {
	I845_DISPLAY,

	.__runtime_defaults.fbc_mask = BIT(INTEL_FBC_A),
};

#define GEN3_DISPLAY \
	.has_gmch = 1, \
	.has_overlay = 1, \
	I9XX_PIPE_OFFSETS, \
	I9XX_CURSOR_OFFSETS, \
	I9XX_COLORS, \
	\
	.__runtime_defaults.ip.ver = 3, \
	.__runtime_defaults.pipe_mask = BIT(PIPE_A) | BIT(PIPE_B), \
	.__runtime_defaults.cpu_transcoder_mask = \
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B)

static const struct intel_display_device_info i915g_display = {
	GEN3_DISPLAY,
	.cursor_needs_physical = 1,
	.overlay_needs_physical = 1,
};

static const struct intel_display_device_info i915gm_display = {
	GEN3_DISPLAY,
	.cursor_needs_physical = 1,
	.overlay_needs_physical = 1,
	.supports_tv = 1,

	.__runtime_defaults.fbc_mask = BIT(INTEL_FBC_A),
};

static const struct intel_display_device_info i945g_display = {
	GEN3_DISPLAY,
	.has_hotplug = 1,
	.cursor_needs_physical = 1,
	.overlay_needs_physical = 1,
};

static const struct intel_display_device_info i945gm_display = {
	GEN3_DISPLAY,
	.has_hotplug = 1,
	.cursor_needs_physical = 1,
	.overlay_needs_physical = 1,
	.supports_tv = 1,

	.__runtime_defaults.fbc_mask = BIT(INTEL_FBC_A),
};

static const struct intel_display_device_info g33_display = {
	GEN3_DISPLAY,
	.has_hotplug = 1,
};

#define GEN4_DISPLAY \
	.has_hotplug = 1, \
	.has_gmch = 1, \
	I9XX_PIPE_OFFSETS, \
	I9XX_CURSOR_OFFSETS, \
	I9XX_COLORS, \
	\
	.__runtime_defaults.ip.ver = 4, \
	.__runtime_defaults.pipe_mask = BIT(PIPE_A) | BIT(PIPE_B), \
	.__runtime_defaults.cpu_transcoder_mask = \
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B)

static const struct intel_display_device_info i965g_display = {
	GEN4_DISPLAY,
	.has_overlay = 1,
};

static const struct intel_display_device_info i965gm_display = {
	GEN4_DISPLAY,
	.has_overlay = 1,
	.supports_tv = 1,

	.__runtime_defaults.fbc_mask = BIT(INTEL_FBC_A),
};

static const struct intel_display_device_info g45_display = {
	GEN4_DISPLAY,
};

static const struct intel_display_device_info gm45_display = {
	GEN4_DISPLAY,
	.supports_tv = 1,

	.__runtime_defaults.fbc_mask = BIT(INTEL_FBC_A),
};

#define ILK_DISPLAY \
	.has_hotplug = 1, \
	I9XX_PIPE_OFFSETS, \
	I9XX_CURSOR_OFFSETS, \
	ILK_COLORS, \
	\
	.__runtime_defaults.ip.ver = 5, \
	.__runtime_defaults.pipe_mask = BIT(PIPE_A) | BIT(PIPE_B), \
	.__runtime_defaults.cpu_transcoder_mask = \
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B)

static const struct intel_display_device_info ilk_d_display = {
	ILK_DISPLAY,
};

static const struct intel_display_device_info ilk_m_display = {
	ILK_DISPLAY,

	.__runtime_defaults.fbc_mask = BIT(INTEL_FBC_A),
};

static const struct intel_display_device_info snb_display = {
	.has_hotplug = 1,
	I9XX_PIPE_OFFSETS,
	I9XX_CURSOR_OFFSETS,
	ILK_COLORS,

	.__runtime_defaults.ip.ver = 6,
	.__runtime_defaults.pipe_mask = BIT(PIPE_A) | BIT(PIPE_B),
	.__runtime_defaults.cpu_transcoder_mask =
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B),
	.__runtime_defaults.fbc_mask = BIT(INTEL_FBC_A),
};

static const struct intel_display_device_info ivb_display = {
	.has_hotplug = 1,
	IVB_PIPE_OFFSETS,
	IVB_CURSOR_OFFSETS,
	IVB_COLORS,

	.__runtime_defaults.ip.ver = 7,
	.__runtime_defaults.pipe_mask = BIT(PIPE_A) | BIT(PIPE_B) | BIT(PIPE_C),
	.__runtime_defaults.cpu_transcoder_mask =
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B) | BIT(TRANSCODER_C),
	.__runtime_defaults.fbc_mask = BIT(INTEL_FBC_A),
};

static const struct intel_display_device_info vlv_display = {
	.has_gmch = 1,
	.has_hotplug = 1,
	.mmio_offset = VLV_DISPLAY_BASE,
	I9XX_PIPE_OFFSETS,
	I9XX_CURSOR_OFFSETS,
	I9XX_COLORS,

	.__runtime_defaults.ip.ver = 7,
	.__runtime_defaults.pipe_mask = BIT(PIPE_A) | BIT(PIPE_B),
	.__runtime_defaults.cpu_transcoder_mask =
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B),
};

static const struct intel_display_device_info hsw_display = {
	.has_ddi = 1,
	.has_dp_mst = 1,
	.has_fpga_dbg = 1,
	.has_hotplug = 1,
	HSW_PIPE_OFFSETS,
	IVB_CURSOR_OFFSETS,
	IVB_COLORS,

	.__runtime_defaults.ip.ver = 7,
	.__runtime_defaults.pipe_mask = BIT(PIPE_A) | BIT(PIPE_B) | BIT(PIPE_C),
	.__runtime_defaults.cpu_transcoder_mask =
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B) |
		BIT(TRANSCODER_C) | BIT(TRANSCODER_EDP),
	.__runtime_defaults.fbc_mask = BIT(INTEL_FBC_A),
};

static const struct intel_display_device_info bdw_display = {
	.has_ddi = 1,
	.has_dp_mst = 1,
	.has_fpga_dbg = 1,
	.has_hotplug = 1,
	HSW_PIPE_OFFSETS,
	IVB_CURSOR_OFFSETS,
	IVB_COLORS,

	.__runtime_defaults.ip.ver = 8,
	.__runtime_defaults.pipe_mask = BIT(PIPE_A) | BIT(PIPE_B) | BIT(PIPE_C),
	.__runtime_defaults.cpu_transcoder_mask =
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B) |
		BIT(TRANSCODER_C) | BIT(TRANSCODER_EDP),
	.__runtime_defaults.fbc_mask = BIT(INTEL_FBC_A),
};

static const struct intel_display_device_info chv_display = {
	.has_hotplug = 1,
	.has_gmch = 1,
	.mmio_offset = VLV_DISPLAY_BASE,
	CHV_PIPE_OFFSETS,
	CHV_CURSOR_OFFSETS,
	CHV_COLORS,

	.__runtime_defaults.ip.ver = 8,
	.__runtime_defaults.pipe_mask = BIT(PIPE_A) | BIT(PIPE_B) | BIT(PIPE_C),
	.__runtime_defaults.cpu_transcoder_mask =
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B) | BIT(TRANSCODER_C),
};

static const struct intel_display_device_info skl_display = {
	.dbuf.size = 896 - 4, /* 4 blocks for bypass path allocation */
	.dbuf.slice_mask = BIT(DBUF_S1),
	.has_ddi = 1,
	.has_dp_mst = 1,
	.has_fpga_dbg = 1,
	.has_hotplug = 1,
	.has_ipc = 1,
	.has_psr = 1,
	.has_psr_hw_tracking = 1,
	HSW_PIPE_OFFSETS,
	IVB_CURSOR_OFFSETS,
	IVB_COLORS,

	.__runtime_defaults.ip.ver = 9,
	.__runtime_defaults.has_dmc = 1,
	.__runtime_defaults.has_hdcp = 1,
	.__runtime_defaults.pipe_mask = BIT(PIPE_A) | BIT(PIPE_B) | BIT(PIPE_C),
	.__runtime_defaults.cpu_transcoder_mask =
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B) |
		BIT(TRANSCODER_C) | BIT(TRANSCODER_EDP),
	.__runtime_defaults.fbc_mask = BIT(INTEL_FBC_A),
};

#define GEN9_LP_DISPLAY \
	.dbuf.slice_mask = BIT(DBUF_S1), \
	.has_dp_mst = 1, \
	.has_ddi = 1, \
	.has_fpga_dbg = 1, \
	.has_hotplug = 1, \
	.has_ipc = 1, \
	.has_psr = 1, \
	.has_psr_hw_tracking = 1, \
	HSW_PIPE_OFFSETS, \
	IVB_CURSOR_OFFSETS, \
	IVB_COLORS, \
	\
	.__runtime_defaults.has_dmc = 1, \
	.__runtime_defaults.has_hdcp = 1, \
	.__runtime_defaults.fbc_mask = BIT(INTEL_FBC_A), \
	.__runtime_defaults.pipe_mask = BIT(PIPE_A) | BIT(PIPE_B) | BIT(PIPE_C), \
	.__runtime_defaults.cpu_transcoder_mask = \
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B) | \
		BIT(TRANSCODER_C) | BIT(TRANSCODER_EDP) | \
		BIT(TRANSCODER_DSI_A) | BIT(TRANSCODER_DSI_C)

static const struct intel_display_device_info bxt_display = {
	GEN9_LP_DISPLAY,
	.dbuf.size = 512 - 4, /* 4 blocks for bypass path allocation */

	.__runtime_defaults.ip.ver = 9,
};

static const struct intel_display_device_info glk_display = {
	GEN9_LP_DISPLAY,
	.dbuf.size = 1024 - 4, /* 4 blocks for bypass path allocation */
	GLK_COLORS,

	.__runtime_defaults.ip.ver = 10,
};

static const struct intel_display_device_info gen11_display = {
	.abox_mask = BIT(0),
	.dbuf.size = 2048,
	.dbuf.slice_mask = BIT(DBUF_S1) | BIT(DBUF_S2),
	.has_ddi = 1,
	.has_dp_mst = 1,
	.has_fpga_dbg = 1,
	.has_hotplug = 1,
	.has_ipc = 1,
	.has_psr = 1,
	.has_psr_hw_tracking = 1,
	.pipe_offsets = {
		[TRANSCODER_A] = PIPE_A_OFFSET,
		[TRANSCODER_B] = PIPE_B_OFFSET,
		[TRANSCODER_C] = PIPE_C_OFFSET,
		[TRANSCODER_EDP] = PIPE_EDP_OFFSET,
		[TRANSCODER_DSI_0] = PIPE_DSI0_OFFSET,
		[TRANSCODER_DSI_1] = PIPE_DSI1_OFFSET,
	},
	.trans_offsets = {
		[TRANSCODER_A] = TRANSCODER_A_OFFSET,
		[TRANSCODER_B] = TRANSCODER_B_OFFSET,
		[TRANSCODER_C] = TRANSCODER_C_OFFSET,
		[TRANSCODER_EDP] = TRANSCODER_EDP_OFFSET,
		[TRANSCODER_DSI_0] = TRANSCODER_DSI0_OFFSET,
		[TRANSCODER_DSI_1] = TRANSCODER_DSI1_OFFSET,
	},
	IVB_CURSOR_OFFSETS,
	ICL_COLORS,

	.__runtime_defaults.ip.ver = 11,
	.__runtime_defaults.has_dmc = 1,
	.__runtime_defaults.has_dsc = 1,
	.__runtime_defaults.has_hdcp = 1,
	.__runtime_defaults.pipe_mask = BIT(PIPE_A) | BIT(PIPE_B) | BIT(PIPE_C),
	.__runtime_defaults.cpu_transcoder_mask =
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B) |
		BIT(TRANSCODER_C) | BIT(TRANSCODER_EDP) |
		BIT(TRANSCODER_DSI_0) | BIT(TRANSCODER_DSI_1),
	.__runtime_defaults.fbc_mask = BIT(INTEL_FBC_A),
};

#define XE_D_DISPLAY \
	.abox_mask = GENMASK(2, 1), \
	.dbuf.size = 2048, \
	.dbuf.slice_mask = BIT(DBUF_S1) | BIT(DBUF_S2), \
	.has_ddi = 1, \
	.has_dp_mst = 1, \
	.has_dsb = 1, \
	.has_fpga_dbg = 1, \
	.has_hotplug = 1, \
	.has_ipc = 1, \
	.has_psr = 1, \
	.has_psr_hw_tracking = 1, \
	.pipe_offsets = { \
		[TRANSCODER_A] = PIPE_A_OFFSET, \
		[TRANSCODER_B] = PIPE_B_OFFSET, \
		[TRANSCODER_C] = PIPE_C_OFFSET, \
		[TRANSCODER_D] = PIPE_D_OFFSET, \
		[TRANSCODER_DSI_0] = PIPE_DSI0_OFFSET, \
		[TRANSCODER_DSI_1] = PIPE_DSI1_OFFSET, \
	}, \
	.trans_offsets = { \
		[TRANSCODER_A] = TRANSCODER_A_OFFSET, \
		[TRANSCODER_B] = TRANSCODER_B_OFFSET, \
		[TRANSCODER_C] = TRANSCODER_C_OFFSET, \
		[TRANSCODER_D] = TRANSCODER_D_OFFSET, \
		[TRANSCODER_DSI_0] = TRANSCODER_DSI0_OFFSET, \
		[TRANSCODER_DSI_1] = TRANSCODER_DSI1_OFFSET, \
	}, \
	TGL_CURSOR_OFFSETS, \
	ICL_COLORS, \
	\
	.__runtime_defaults.ip.ver = 12, \
	.__runtime_defaults.has_dmc = 1, \
	.__runtime_defaults.has_dsc = 1, \
	.__runtime_defaults.has_hdcp = 1, \
	.__runtime_defaults.pipe_mask = \
		BIT(PIPE_A) | BIT(PIPE_B) | BIT(PIPE_C) | BIT(PIPE_D), \
	.__runtime_defaults.cpu_transcoder_mask = \
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B) | \
		BIT(TRANSCODER_C) | BIT(TRANSCODER_D) | \
		BIT(TRANSCODER_DSI_0) | BIT(TRANSCODER_DSI_1), \
	.__runtime_defaults.fbc_mask = BIT(INTEL_FBC_A)

static const struct intel_display_device_info tgl_display = {
	XE_D_DISPLAY,
};

static const struct intel_display_device_info rkl_display = {
	XE_D_DISPLAY,
	.abox_mask = BIT(0),
	.has_hti = 1,
	.has_psr_hw_tracking = 0,

	.__runtime_defaults.pipe_mask = BIT(PIPE_A) | BIT(PIPE_B) | BIT(PIPE_C),
	.__runtime_defaults.cpu_transcoder_mask =
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B) | BIT(TRANSCODER_C),
};

static const struct intel_display_device_info adl_s_display = {
	XE_D_DISPLAY,
	.has_hti = 1,
	.has_psr_hw_tracking = 0,
};

#define XE_LPD_FEATURES \
	.abox_mask = GENMASK(1, 0),						\
	.color = {								\
		.degamma_lut_size = 129, .gamma_lut_size = 1024,		\
		.degamma_lut_tests = DRM_COLOR_LUT_NON_DECREASING |		\
		DRM_COLOR_LUT_EQUAL_CHANNELS,					\
	},									\
	.dbuf.size = 4096,							\
	.dbuf.slice_mask = BIT(DBUF_S1) | BIT(DBUF_S2) | BIT(DBUF_S3) |		\
		BIT(DBUF_S4),							\
	.has_ddi = 1,								\
	.has_dp_mst = 1,							\
	.has_dsb = 1,								\
	.has_fpga_dbg = 1,							\
	.has_hotplug = 1,							\
	.has_ipc = 1,								\
	.has_psr = 1,								\
	.pipe_offsets = {							\
		[TRANSCODER_A] = PIPE_A_OFFSET,					\
		[TRANSCODER_B] = PIPE_B_OFFSET,					\
		[TRANSCODER_C] = PIPE_C_OFFSET,					\
		[TRANSCODER_D] = PIPE_D_OFFSET,					\
		[TRANSCODER_DSI_0] = PIPE_DSI0_OFFSET,				\
		[TRANSCODER_DSI_1] = PIPE_DSI1_OFFSET,				\
	},									\
	.trans_offsets = {							\
		[TRANSCODER_A] = TRANSCODER_A_OFFSET,				\
		[TRANSCODER_B] = TRANSCODER_B_OFFSET,				\
		[TRANSCODER_C] = TRANSCODER_C_OFFSET,				\
		[TRANSCODER_D] = TRANSCODER_D_OFFSET,				\
		[TRANSCODER_DSI_0] = TRANSCODER_DSI0_OFFSET,			\
		[TRANSCODER_DSI_1] = TRANSCODER_DSI1_OFFSET,			\
	},									\
	TGL_CURSOR_OFFSETS,							\
										\
	.__runtime_defaults.ip.ver = 13,					\
	.__runtime_defaults.has_dmc = 1,					\
	.__runtime_defaults.has_dsc = 1,					\
	.__runtime_defaults.fbc_mask = BIT(INTEL_FBC_A),			\
	.__runtime_defaults.has_hdcp = 1,					\
	.__runtime_defaults.pipe_mask =						\
		BIT(PIPE_A) | BIT(PIPE_B) | BIT(PIPE_C) | BIT(PIPE_D)

static const struct intel_display_device_info xe_lpd_display = {
	XE_LPD_FEATURES,
	.has_cdclk_crawl = 1,
	.has_psr_hw_tracking = 0,

	.__runtime_defaults.cpu_transcoder_mask =
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B) |
		BIT(TRANSCODER_C) | BIT(TRANSCODER_D) |
		BIT(TRANSCODER_DSI_0) | BIT(TRANSCODER_DSI_1),
};

static const struct intel_display_device_info xe_hpd_display = {
	XE_LPD_FEATURES,
	.has_cdclk_squash = 1,

	.__runtime_defaults.cpu_transcoder_mask =
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B) |
		BIT(TRANSCODER_C) | BIT(TRANSCODER_D),
};

static const struct intel_display_device_info xe_lpdp_display = {
	XE_LPD_FEATURES,
	.has_cdclk_crawl = 1,
	.has_cdclk_squash = 1,

	.__runtime_defaults.ip.ver = 14,
	.__runtime_defaults.fbc_mask = BIT(INTEL_FBC_A) | BIT(INTEL_FBC_B),
	.__runtime_defaults.cpu_transcoder_mask =
		BIT(TRANSCODER_A) | BIT(TRANSCODER_B) |
		BIT(TRANSCODER_C) | BIT(TRANSCODER_D),
};

#undef INTEL_VGA_DEVICE
#undef INTEL_QUANTA_VGA_DEVICE
#define INTEL_VGA_DEVICE(id, info) { id, info }
#define INTEL_QUANTA_VGA_DEVICE(info) { 0x16a, info }

static const struct {
	u32 devid;
	const struct intel_display_device_info *info;
} intel_display_ids[] = {
	INTEL_I830_IDS(&i830_display),
	INTEL_I845G_IDS(&i845_display),
	INTEL_I85X_IDS(&i85x_display),
	INTEL_I865G_IDS(&i865g_display),
	INTEL_I915G_IDS(&i915g_display),
	INTEL_I915GM_IDS(&i915gm_display),
	INTEL_I945G_IDS(&i945g_display),
	INTEL_I945GM_IDS(&i945gm_display),
	INTEL_I965G_IDS(&i965g_display),
	INTEL_G33_IDS(&g33_display),
	INTEL_I965GM_IDS(&i965gm_display),
	INTEL_GM45_IDS(&gm45_display),
	INTEL_G45_IDS(&g45_display),
	INTEL_PINEVIEW_G_IDS(&g33_display),
	INTEL_PINEVIEW_M_IDS(&g33_display),
	INTEL_IRONLAKE_D_IDS(&ilk_d_display),
	INTEL_IRONLAKE_M_IDS(&ilk_m_display),
	INTEL_SNB_D_IDS(&snb_display),
	INTEL_SNB_M_IDS(&snb_display),
	INTEL_IVB_Q_IDS(NULL),		/* must be first IVB in list */
	INTEL_IVB_M_IDS(&ivb_display),
	INTEL_IVB_D_IDS(&ivb_display),
	INTEL_HSW_IDS(&hsw_display),
	INTEL_VLV_IDS(&vlv_display),
	INTEL_BDW_IDS(&bdw_display),
	INTEL_CHV_IDS(&chv_display),
	INTEL_SKL_IDS(&skl_display),
	INTEL_BXT_IDS(&bxt_display),
	INTEL_GLK_IDS(&glk_display),
	INTEL_KBL_IDS(&skl_display),
	INTEL_CFL_IDS(&skl_display),
	INTEL_ICL_11_IDS(&gen11_display),
	INTEL_EHL_IDS(&gen11_display),
	INTEL_JSL_IDS(&gen11_display),
	INTEL_TGL_12_IDS(&tgl_display),
	INTEL_DG1_IDS(&tgl_display),
	INTEL_RKL_IDS(&rkl_display),
	INTEL_ADLS_IDS(&adl_s_display),
	INTEL_RPLS_IDS(&adl_s_display),
	INTEL_ADLP_IDS(&xe_lpd_display),
	INTEL_ADLN_IDS(&xe_lpd_display),
	INTEL_RPLP_IDS(&xe_lpd_display),
	INTEL_DG2_IDS(&xe_hpd_display),

	/*
	 * Do not add any GMD_ID-based platforms to this list.  They will
	 * be probed automatically based on the IP version reported by
	 * the hardware.
	 */
};

static const struct {
	u16 ver;
	u16 rel;
	const struct intel_display_device_info *display;
} gmdid_display_map[] = {
	{ 14,  0, &xe_lpdp_display },
};

static const struct intel_display_device_info *
probe_gmdid_display(struct drm_i915_private *i915, u16 *ver, u16 *rel, u16 *step)
{
	struct pci_dev *pdev = to_pci_dev(i915->drm.dev);
	void __iomem *addr;
	u32 val;
	int i;

	addr = pci_iomap_range(pdev, 0, i915_mmio_reg_offset(GMD_ID_DISPLAY), sizeof(u32));
	if (!addr) {
		drm_err(&i915->drm, "Cannot map MMIO BAR to read display GMD_ID\n");
		return &no_display;
	}

	val = ioread32(addr);
	pci_iounmap(pdev, addr);

	if (val == 0)
		/* Platform doesn't have display */
		return &no_display;

	*ver = REG_FIELD_GET(GMD_ID_ARCH_MASK, val);
	*rel = REG_FIELD_GET(GMD_ID_RELEASE_MASK, val);
	*step = REG_FIELD_GET(GMD_ID_STEP, val);

	for (i = 0; i < ARRAY_SIZE(gmdid_display_map); i++)
		if (*ver == gmdid_display_map[i].ver &&
		    *rel == gmdid_display_map[i].rel)
			return gmdid_display_map[i].display;

	drm_err(&i915->drm, "Unrecognized display IP version %d.%02d; disabling display.\n",
		*ver, *rel);
	return &no_display;
}

const struct intel_display_device_info *
intel_display_device_probe(struct drm_i915_private *i915, bool has_gmdid,
			   u16 *gmdid_ver, u16 *gmdid_rel, u16 *gmdid_step)
{
	struct pci_dev *pdev = to_pci_dev(i915->drm.dev);
	int i;

	if (has_gmdid)
		return probe_gmdid_display(i915, gmdid_ver, gmdid_rel, gmdid_step);

	for (i = 0; i < ARRAY_SIZE(intel_display_ids); i++) {
		if (intel_display_ids[i].devid == pdev->device)
			return intel_display_ids[i].info;
	}

	drm_dbg(&i915->drm, "No display ID found for device ID %04x; disabling display.\n",
		pdev->device);

	return &no_display;
}
