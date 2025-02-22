/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * NAU8825 ALSA SoC audio driver
 *
 * Copyright 2015 Google Inc.
 * Author: Anatol Pomozov <anatol.pomozov@chrominium.org>
 */

#ifndef __NAU8825_H__
#define __NAU8825_H__

#define NAU8825_REG_RESET		0x00
#define NAU8825_REG_ENA_CTRL		0x01
#define NAU8825_REG_IIC_ADDR_SET		0x02
#define NAU8825_REG_CLK_DIVIDER		0x03
#define NAU8825_REG_FLL1		0x04
#define NAU8825_REG_FLL2		0x05
#define NAU8825_REG_FLL3		0x06
#define NAU8825_REG_FLL4		0x07
#define NAU8825_REG_FLL5		0x08
#define NAU8825_REG_FLL6		0x09
#define NAU8825_REG_FLL_VCO_RSV		0x0a
#define NAU8825_REG_HSD_CTRL		0x0c
#define NAU8825_REG_JACK_DET_CTRL		0x0d
#define NAU8825_REG_INTERRUPT_MASK		0x0f
#define NAU8825_REG_IRQ_STATUS		0x10
#define NAU8825_REG_INT_CLR_KEY_STATUS		0x11
#define NAU8825_REG_INTERRUPT_DIS_CTRL		0x12
#define NAU8825_REG_SAR_CTRL		0x13
#define NAU8825_REG_KEYDET_CTRL		0x14
#define NAU8825_REG_VDET_THRESHOLD_1		0x15
#define NAU8825_REG_VDET_THRESHOLD_2		0x16
#define NAU8825_REG_VDET_THRESHOLD_3		0x17
#define NAU8825_REG_VDET_THRESHOLD_4		0x18
#define NAU8825_REG_GPIO34_CTRL		0x19
#define NAU8825_REG_GPIO12_CTRL		0x1a
#define NAU8825_REG_TDM_CTRL		0x1b
#define NAU8825_REG_I2S_PCM_CTRL1		0x1c
#define NAU8825_REG_I2S_PCM_CTRL2		0x1d
#define NAU8825_REG_LEFT_TIME_SLOT		0x1e
#define NAU8825_REG_RIGHT_TIME_SLOT		0x1f
#define NAU8825_REG_BIQ_CTRL		0x20
#define NAU8825_REG_BIQ_COF1		0x21
#define NAU8825_REG_BIQ_COF2		0x22
#define NAU8825_REG_BIQ_COF3		0x23
#define NAU8825_REG_BIQ_COF4		0x24
#define NAU8825_REG_BIQ_COF5		0x25
#define NAU8825_REG_BIQ_COF6		0x26
#define NAU8825_REG_BIQ_COF7		0x27
#define NAU8825_REG_BIQ_COF8		0x28
#define NAU8825_REG_BIQ_COF9		0x29
#define NAU8825_REG_BIQ_COF10		0x2a
#define NAU8825_REG_ADC_RATE		0x2b
#define NAU8825_REG_DAC_CTRL1		0x2c
#define NAU8825_REG_DAC_CTRL2		0x2d
#define NAU8825_REG_DAC_DGAIN_CTRL		0x2f
#define NAU8825_REG_ADC_DGAIN_CTRL		0x30
#define NAU8825_REG_MUTE_CTRL		0x31
#define NAU8825_REG_HSVOL_CTRL		0x32
#define NAU8825_REG_DACL_CTRL		0x33
#define NAU8825_REG_DACR_CTRL		0x34
#define NAU8825_REG_ADC_DRC_KNEE_IP12		0x38
#define NAU8825_REG_ADC_DRC_KNEE_IP34		0x39
#define NAU8825_REG_ADC_DRC_SLOPES		0x3a
#define NAU8825_REG_ADC_DRC_ATKDCY		0x3b
#define NAU8825_REG_DAC_DRC_KNEE_IP12		0x45
#define NAU8825_REG_DAC_DRC_KNEE_IP34		0x46
#define NAU8825_REG_DAC_DRC_SLOPES		0x47
#define NAU8825_REG_DAC_DRC_ATKDCY		0x48
#define NAU8825_REG_IMM_MODE_CTRL		0x4c
#define NAU8825_REG_IMM_RMS_L		0x4d
#define NAU8825_REG_IMM_RMS_R		0x4e
#define NAU8825_REG_CLASSG_CTRL		0x50
#define NAU8825_REG_OPT_EFUSE_CTRL		0x51
#define NAU8825_REG_MISC_CTRL		0x55
#define NAU8825_REG_I2C_DEVICE_ID		0x58
#define NAU8825_REG_SARDOUT_RAM_STATUS		0x59
#define NAU8825_REG_BIAS_ADJ		0x66
#define NAU8825_REG_TRIM_SETTINGS		0x68
#define NAU8825_REG_ANALOG_CONTROL_1		0x69
#define NAU8825_REG_ANALOG_CONTROL_2		0x6a
#define NAU8825_REG_ANALOG_ADC_1		0x71
#define NAU8825_REG_ANALOG_ADC_2		0x72
#define NAU8825_REG_RDAC		0x73
#define NAU8825_REG_MIC_BIAS		0x74
#define NAU8825_REG_BOOST		0x76
#define NAU8825_REG_FEPGA		0x77
#define NAU8825_REG_POWER_UP_CONTROL		0x7f
#define NAU8825_REG_CHARGE_PUMP		0x80
#define NAU8825_REG_CHARGE_PUMP_INPUT_READ		0x81
#define NAU8825_REG_GENERAL_STATUS		0x82
#define NAU8825_REG_MAX		NAU8825_REG_GENERAL_STATUS
/* 16-bit control register address, and 16-bits control register data */
#define NAU8825_REG_ADDR_LEN		16
#define NAU8825_REG_DATA_LEN		16

/* ENA_CTRL (0x1) */
#define NAU8825_ENABLE_DACR_SFT	10
#define NAU8825_ENABLE_DACR	(1 << NAU8825_ENABLE_DACR_SFT)
#define NAU8825_ENABLE_DACL_SFT	9
#define NAU8825_ENABLE_DACL		(1 << NAU8825_ENABLE_DACL_SFT)
#define NAU8825_ENABLE_ADC_SFT	8
#define NAU8825_ENABLE_ADC		(1 << NAU8825_ENABLE_ADC_SFT)
#define NAU8825_ENABLE_ADC_CLK_SFT	7
#define NAU8825_ENABLE_ADC_CLK	(1 << NAU8825_ENABLE_ADC_CLK_SFT)
#define NAU8825_ENABLE_DAC_CLK_SFT	6
#define NAU8825_ENABLE_DAC_CLK	(1 << NAU8825_ENABLE_DAC_CLK_SFT)
#define NAU8825_ENABLE_SAR_SFT	1

/* CLK_DIVIDER (0x3) */
#define NAU8825_CLK_SRC_SFT			15
#define NAU8825_CLK_SRC_MASK			(1 << NAU8825_CLK_SRC_SFT)
#define NAU8825_CLK_SRC_VCO			(1 << NAU8825_CLK_SRC_SFT)
#define NAU8825_CLK_SRC_MCLK			(0 << NAU8825_CLK_SRC_SFT)
#define NAU8825_CLK_ADC_SRC_SFT		6
#define NAU8825_CLK_ADC_SRC_MASK		(0x3 << NAU8825_CLK_ADC_SRC_SFT)
#define NAU8825_CLK_DAC_SRC_SFT		4
#define NAU8825_CLK_DAC_SRC_MASK		(0x3 << NAU8825_CLK_DAC_SRC_SFT)
#define NAU8825_CLK_MCLK_SRC_MASK		(0xf << 0)

/* FLL1 (0x04) */
#define NAU8825_ICTRL_LATCH_SFT	10
#define NAU8825_ICTRL_LATCH_MASK	(0x7 << NAU8825_ICTRL_LATCH_SFT)
#define NAU8825_FLL_RATIO_MASK			(0x7f << 0)

/* FLL3 (0x06) */
#define NAU8825_GAIN_ERR_SFT			12
#define NAU8825_GAIN_ERR_MASK			(0xf << NAU8825_GAIN_ERR_SFT)
#define NAU8825_FLL_INTEGER_MASK		(0x3ff << 0)
#define NAU8825_FLL_CLK_SRC_SFT		10
#define NAU8825_FLL_CLK_SRC_MASK		(0x3 << NAU8825_FLL_CLK_SRC_SFT)
#define NAU8825_FLL_CLK_SRC_MCLK		(0 << NAU8825_FLL_CLK_SRC_SFT)
#define NAU8825_FLL_CLK_SRC_BLK		(0x2 << NAU8825_FLL_CLK_SRC_SFT)
#define NAU8825_FLL_CLK_SRC_FS			(0x3 << NAU8825_FLL_CLK_SRC_SFT)

/* FLL4 (0x07) */
#define NAU8825_FLL_REF_DIV_SFT	10
#define NAU8825_FLL_REF_DIV_MASK	(0x3 << NAU8825_FLL_REF_DIV_SFT)

/* FLL5 (0x08) */
#define NAU8825_FLL_PDB_DAC_EN		(0x1 << 15)
#define NAU8825_FLL_LOOP_FTR_EN		(0x1 << 14)
#define NAU8825_FLL_CLK_SW_MASK		(0x1 << 13)
#define NAU8825_FLL_CLK_SW_N2			(0x1 << 13)
#define NAU8825_FLL_CLK_SW_REF		(0x0 << 13)
#define NAU8825_FLL_FTR_SW_MASK		(0x1 << 12)
#define NAU8825_FLL_FTR_SW_ACCU		(0x1 << 12)
#define NAU8825_FLL_FTR_SW_FILTER		(0x0 << 12)

/* FLL6 (0x9) */
#define NAU8825_DCO_EN				(0x1 << 15)
#define NAU8825_SDM_EN				(0x1 << 14)
#define NAU8825_CUTOFF500			(0x1 << 13)

/* HSD_CTRL (0xc) */
#define NAU8825_HSD_AUTO_MODE	(1 << 6)
/* 0 - open, 1 - short to GND */
#define NAU8825_SPKR_ENGND1	(1 << 3)
#define NAU8825_SPKR_ENGND2	(1 << 2)
#define NAU8825_SPKR_DWN1R	(1 << 1)
#define NAU8825_SPKR_DWN1L	(1 << 0)

/* JACK_DET_CTRL (0xd) */
#define NAU8825_JACK_DET_RESTART	(1 << 9)
#define NAU8825_JACK_DET_DB_BYPASS	(1 << 8)
#define NAU8825_JACK_INSERT_DEBOUNCE_SFT	5
#define NAU8825_JACK_INSERT_DEBOUNCE_MASK	(0x7 << NAU8825_JACK_INSERT_DEBOUNCE_SFT)
#define NAU8825_JACK_EJECT_DEBOUNCE_SFT		2
#define NAU8825_JACK_EJECT_DEBOUNCE_MASK	(0x7 << NAU8825_JACK_EJECT_DEBOUNCE_SFT)
#define NAU8825_JACK_POLARITY	(1 << 1) /* 0 - active low, 1 - active high */

/* INTERRUPT_MASK (0xf) */
#define NAU8825_IRQ_PIN_PULLUP (1 << 14)
#define NAU8825_IRQ_PIN_PULL_EN (1 << 13)
#define NAU8825_IRQ_OUTPUT_EN (1 << 11)
#define NAU8825_IRQ_HEADSET_COMPLETE_EN (1 << 10)
#define NAU8825_IRQ_RMS_EN (1 << 8)
#define NAU8825_IRQ_KEY_RELEASE_EN (1 << 7)
#define NAU8825_IRQ_KEY_SHORT_PRESS_EN (1 << 5)
#define NAU8825_IRQ_EJECT_EN (1 << 2)
#define NAU8825_IRQ_INSERT_EN (1 << 0)

/* IRQ_STATUS (0x10) */
#define NAU8825_HEADSET_COMPLETION_IRQ	(1 << 10)
#define NAU8825_SHORT_CIRCUIT_IRQ	(1 << 9)
#define NAU8825_IMPEDANCE_MEAS_IRQ	(1 << 8)
#define NAU8825_KEY_IRQ_MASK	(0x7 << 5)
#define NAU8825_KEY_RELEASE_IRQ	(1 << 7)
#define NAU8825_KEY_LONG_PRESS_IRQ	(1 << 6)
#define NAU8825_KEY_SHORT_PRESS_IRQ	(1 << 5)
#define NAU8825_MIC_DETECTION_IRQ	(1 << 4)
#define NAU8825_JACK_EJECTION_IRQ_MASK	(3 << 2)
#define NAU8825_JACK_EJECTION_DETECTED	(1 << 2)
#define NAU8825_JACK_INSERTION_IRQ_MASK	(3 << 0)
#define NAU8825_JACK_INSERTION_DETECTED	(1 << 0)

/* INTERRUPT_DIS_CTRL (0x12) */
#define NAU8825_IRQ_HEADSET_COMPLETE_DIS (1 << 10)
#define NAU8825_IRQ_KEY_RELEASE_DIS (1 << 7)
#define NAU8825_IRQ_KEY_SHORT_PRESS_DIS (1 << 5)
#define NAU8825_IRQ_EJECT_DIS (1 << 2)
#define NAU8825_IRQ_INSERT_DIS (1 << 0)

/* SAR_CTRL (0x13) */
#define NAU8825_SAR_ADC_EN_SFT	12
#define NAU8825_SAR_ADC_EN	(1 << NAU8825_SAR_ADC_EN_SFT)
#define NAU8825_SAR_INPUT_MASK	(1 << 11)
#define NAU8825_SAR_INPUT_JKSLV	(1 << 11)
#define NAU8825_SAR_INPUT_JKR2	(0 << 11)
#define NAU8825_SAR_TRACKING_GAIN_SFT	8
#define NAU8825_SAR_TRACKING_GAIN_MASK	(0x7 << NAU8825_SAR_TRACKING_GAIN_SFT)
#define NAU8825_SAR_HV_SEL_SFT		7
#define NAU8825_SAR_HV_SEL_MASK		(1 << NAU8825_SAR_HV_SEL_SFT)
#define NAU8825_SAR_HV_SEL_MICBIAS	(0 << NAU8825_SAR_HV_SEL_SFT)
#define NAU8825_SAR_HV_SEL_VDDMIC	(1 << NAU8825_SAR_HV_SEL_SFT)
#define NAU8825_SAR_RES_SEL_SFT		4
#define NAU8825_SAR_RES_SEL_MASK	(0x7 << NAU8825_SAR_RES_SEL_SFT)
#define NAU8825_SAR_RES_SEL_35K		(0 << NAU8825_SAR_RES_SEL_SFT)
#define NAU8825_SAR_RES_SEL_70K		(1 << NAU8825_SAR_RES_SEL_SFT)
#define NAU8825_SAR_RES_SEL_170K	(2 << NAU8825_SAR_RES_SEL_SFT)
#define NAU8825_SAR_RES_SEL_360K	(3 << NAU8825_SAR_RES_SEL_SFT)
#define NAU8825_SAR_RES_SEL_SHORTED	(4 << NAU8825_SAR_RES_SEL_SFT)
#define NAU8825_SAR_COMPARE_TIME_SFT	2
#define NAU8825_SAR_COMPARE_TIME_MASK	(3 << 2)
#define NAU8825_SAR_SAMPLING_TIME_SFT	0
#define NAU8825_SAR_SAMPLING_TIME_MASK	(3 << 0)

/* KEYDET_CTRL (0x14) */
#define NAU8825_KEYDET_SHORTKEY_DEBOUNCE_SFT	12
#define NAU8825_KEYDET_SHORTKEY_DEBOUNCE_MASK	(0x3 << NAU8825_KEYDET_SHORTKEY_DEBOUNCE_SFT)
#define NAU8825_KEYDET_LEVELS_NR_SFT	8
#define NAU8825_KEYDET_LEVELS_NR_MASK	(0x7 << 8)
#define NAU8825_KEYDET_HYSTERESIS_SFT	0
#define NAU8825_KEYDET_HYSTERESIS_MASK	0xf

/* GPIO12_CTRL (0x1a) */
#define NAU8825_JKDET_PULL_UP	(1 << 11) /* 0 - pull down, 1 - pull up */
#define NAU8825_JKDET_PULL_EN	(1 << 9) /* 0 - enable pull, 1 - disable */
#define NAU8825_JKDET_OUTPUT_EN	(1 << 8) /* 0 - enable input, 1 - enable output */

/* TDM_CTRL (0x1b) */
#define NAU8825_TDM_MODE		(0x1 << 15)
#define NAU8825_TDM_OFFSET_EN		(0x1 << 14)
#define NAU8825_TDM_DACL_RX_SFT		6
#define NAU8825_TDM_DACL_RX_MASK	(0x3 << NAU8825_TDM_DACL_RX_SFT)
#define NAU8825_TDM_DACR_RX_SFT		4
#define NAU8825_TDM_DACR_RX_MASK	(0x3 << NAU8825_TDM_DACR_RX_SFT)
#define NAU8825_TDM_TX_MASK		0x3

/* I2S_PCM_CTRL1 (0x1c) */
#define NAU8825_I2S_BP_SFT	7
#define NAU8825_I2S_BP_MASK	(1 << NAU8825_I2S_BP_SFT)
#define NAU8825_I2S_BP_INV	(1 << NAU8825_I2S_BP_SFT)
#define NAU8825_I2S_PCMB_SFT	6
#define NAU8825_I2S_PCMB_MASK	(1 << NAU8825_I2S_PCMB_SFT)
#define NAU8825_I2S_PCMB_EN	(1 << NAU8825_I2S_PCMB_SFT)
#define NAU8825_I2S_DL_SFT	2
#define NAU8825_I2S_DL_MASK	(0x3 << NAU8825_I2S_DL_SFT)
#define NAU8825_I2S_DL_16	(0 << NAU8825_I2S_DL_SFT)
#define NAU8825_I2S_DL_20	(1 << NAU8825_I2S_DL_SFT)
#define NAU8825_I2S_DL_24	(2 << NAU8825_I2S_DL_SFT)
#define NAU8825_I2S_DL_32	(3 << NAU8825_I2S_DL_SFT)
#define NAU8825_I2S_DF_SFT	0
#define NAU8825_I2S_DF_MASK	(0x3 << NAU8825_I2S_DF_SFT)
#define NAU8825_I2S_DF_RIGTH	(0 << NAU8825_I2S_DF_SFT)
#define NAU8825_I2S_DF_LEFT	(1 << NAU8825_I2S_DF_SFT)
#define NAU8825_I2S_DF_I2S	(2 << NAU8825_I2S_DF_SFT)
#define NAU8825_I2S_DF_PCM_AB	(3 << NAU8825_I2S_DF_SFT)

/* I2S_PCM_CTRL2 (0x1d) */
#define NAU8825_I2S_TRISTATE	(1 << 15) /* 0 - normal mode, 1 - Hi-Z output */
#define NAU8825_I2S_LRC_DIV_SFT	12
#define NAU8825_I2S_LRC_DIV_MASK	(0x3 << NAU8825_I2S_LRC_DIV_SFT)
#define NAU8825_I2S_PCM_TS_EN_SFT	10
#define NAU8825_I2S_PCM_TS_EN_MASK	(1 << NAU8825_I2S_PCM_TS_EN_SFT)
#define NAU8825_I2S_PCM_TS_EN		(1 << NAU8825_I2S_PCM_TS_EN_SFT)
#define NAU8825_I2S_MS_SFT	3
#define NAU8825_I2S_MS_MASK	(1 << NAU8825_I2S_MS_SFT)
#define NAU8825_I2S_MS_MASTER	(1 << NAU8825_I2S_MS_SFT)
#define NAU8825_I2S_MS_SLAVE	(0 << NAU8825_I2S_MS_SFT)
#define NAU8825_I2S_BLK_DIV_MASK	0x7

/* LEFT_TIME_SLOT (0x1e) */
#define NAU8825_FS_ERR_CMP_SEL_SFT	14
#define NAU8825_FS_ERR_CMP_SEL_MASK	(0x3 << NAU8825_FS_ERR_CMP_SEL_SFT)
#define NAU8825_DIS_FS_SHORT_DET	(1 << 13)
#define NAU8825_TSLOT_L0_MASK		0x3ff
#define NAU8825_TSLOT_R0_MASK		0x3ff

/* BIQ_CTRL (0x20) */
#define NAU8825_BIQ_WRT_SFT   4
#define NAU8825_BIQ_WRT_EN     (1 << NAU8825_BIQ_WRT_SFT)
#define NAU8825_BIQ_PATH_SFT   0
#define NAU8825_BIQ_PATH_MASK  (1 << NAU8825_BIQ_PATH_SFT)
#define NAU8825_BIQ_PATH_ADC   (0 << NAU8825_BIQ_PATH_SFT)
#define NAU8825_BIQ_PATH_DAC   (1 << NAU8825_BIQ_PATH_SFT)

/* ADC_RATE (0x2b) */
#define NAU8825_ADC_SINC4_SFT		4
#define NAU8825_ADC_SINC4_EN		(1 << NAU8825_ADC_SINC4_SFT)
#define NAU8825_ADC_SYNC_DOWN_SFT	0
#define NAU8825_ADC_SYNC_DOWN_MASK	0x3
#define NAU8825_ADC_SYNC_DOWN_32	0
#define NAU8825_ADC_SYNC_DOWN_64	1
#define NAU8825_ADC_SYNC_DOWN_128	2
#define NAU8825_ADC_SYNC_DOWN_256	3

/* DAC_CTRL1 (0x2c) */
#define NAU8825_DAC_CLIP_OFF	(1 << 7)
#define NAU8825_DAC_OVERSAMPLE_SFT	0
#define NAU8825_DAC_OVERSAMPLE_MASK	0x7
#define NAU8825_DAC_OVERSAMPLE_64	0
#define NAU8825_DAC_OVERSAMPLE_256	1
#define NAU8825_DAC_OVERSAMPLE_128	2
#define NAU8825_DAC_OVERSAMPLE_32	4

/* ADC_DGAIN_CTRL (0x30) */
#define NAU8825_ADC_DIG_VOL_MASK	0xff

/* MUTE_CTRL (0x31) */
#define NAU8825_DAC_ZERO_CROSSING_EN	(1 << 9)
#define NAU8825_DAC_SOFT_MUTE	(1 << 9)

/* HSVOL_CTRL (0x32) */
#define NAU8825_HP_MUTE	(1 << 15)
#define NAU8825_HP_MUTE_AUTO	(1 << 14)
#define NAU8825_HPL_MUTE	(1 << 13)
#define NAU8825_HPR_MUTE	(1 << 12)
#define NAU8825_HPL_VOL_SFT	6
#define NAU8825_HPL_VOL_MASK	(0x3f << NAU8825_HPL_VOL_SFT)
#define NAU8825_HPR_VOL_SFT	0
#define NAU8825_HPR_VOL_MASK	(0x3f << NAU8825_HPR_VOL_SFT)
#define NAU8825_HP_VOL_MIN	0x36

/* DACL_CTRL (0x33) */
#define NAU8825_DACL_CH_SEL_SFT	9
#define NAU8825_DACL_CH_SEL_MASK (0x1 << NAU8825_DACL_CH_SEL_SFT)
#define NAU8825_DACL_CH_SEL_L    (0x0 << NAU8825_DACL_CH_SEL_SFT)
#define NAU8825_DACL_CH_SEL_R    (0x1 << NAU8825_DACL_CH_SEL_SFT)
#define NAU8825_DACL_CH_VOL_MASK	0xff

/* DACR_CTRL (0x34) */
#define NAU8825_DACR_CH_SEL_SFT	9
#define NAU8825_DACR_CH_SEL_MASK (0x1 << NAU8825_DACR_CH_SEL_SFT)
#define NAU8825_DACR_CH_SEL_L    (0x0 << NAU8825_DACR_CH_SEL_SFT)
#define NAU8825_DACR_CH_SEL_R    (0x1 << NAU8825_DACR_CH_SEL_SFT)
#define NAU8825_DACR_CH_VOL_MASK	0xff

/* IMM_MODE_CTRL (0x4C) */
#define NAU8825_IMM_THD_SFT		8
#define NAU8825_IMM_THD_MASK		(0x3f << NAU8825_IMM_THD_SFT)
#define NAU8825_IMM_GEN_VOL_SFT	6
#define NAU8825_IMM_GEN_VOL_MASK	(0x3 << NAU8825_IMM_GEN_VOL_SFT)
#define NAU8825_IMM_GEN_VOL_1_2nd	(0x0 << NAU8825_IMM_GEN_VOL_SFT)
#define NAU8825_IMM_GEN_VOL_1_4th	(0x1 << NAU8825_IMM_GEN_VOL_SFT)
#define NAU8825_IMM_GEN_VOL_1_8th	(0x2 << NAU8825_IMM_GEN_VOL_SFT)
#define NAU8825_IMM_GEN_VOL_1_16th	(0x3 << NAU8825_IMM_GEN_VOL_SFT)

#define NAU8825_IMM_CYC_SFT		4
#define NAU8825_IMM_CYC_MASK		(0x3 << NAU8825_IMM_CYC_SFT)
#define NAU8825_IMM_CYC_1024		(0x0 << NAU8825_IMM_CYC_SFT)
#define NAU8825_IMM_CYC_2048		(0x1 << NAU8825_IMM_CYC_SFT)
#define NAU8825_IMM_CYC_4096		(0x2 << NAU8825_IMM_CYC_SFT)
#define NAU8825_IMM_CYC_8192		(0x3 << NAU8825_IMM_CYC_SFT)
#define NAU8825_IMM_EN			(1 << 3)
#define NAU8825_IMM_DAC_SRC_MASK	0x7
#define NAU8825_IMM_DAC_SRC_BIQ	0x0
#define NAU8825_IMM_DAC_SRC_DRC	0x1
#define NAU8825_IMM_DAC_SRC_MIX	0x2
#define NAU8825_IMM_DAC_SRC_SIN	0x3

/* CLASSG_CTRL (0x50) */
#define NAU8825_CLASSG_TIMER_SFT	8
#define NAU8825_CLASSG_TIMER_MASK	(0x3f << NAU8825_CLASSG_TIMER_SFT)
#define NAU8825_CLASSG_TIMER_1ms	(0x1 << NAU8825_CLASSG_TIMER_SFT)
#define NAU8825_CLASSG_TIMER_2ms	(0x2 << NAU8825_CLASSG_TIMER_SFT)
#define NAU8825_CLASSG_TIMER_8ms	(0x4 << NAU8825_CLASSG_TIMER_SFT)
#define NAU8825_CLASSG_TIMER_16ms	(0x8 << NAU8825_CLASSG_TIMER_SFT)
#define NAU8825_CLASSG_TIMER_32ms	(0x10 << NAU8825_CLASSG_TIMER_SFT)
#define NAU8825_CLASSG_TIMER_64ms	(0x20 << NAU8825_CLASSG_TIMER_SFT)
#define NAU8825_CLASSG_LDAC_EN		(0x1 << 2)
#define NAU8825_CLASSG_RDAC_EN		(0x1 << 1)
#define NAU8825_CLASSG_EN		(1 << 0)

/* I2C_DEVICE_ID (0x58) */
#define NAU8825_GPIO2JD1	(1 << 7)
#define NAU8825_SOFTWARE_ID_MASK	0x3
#define NAU8825_SOFTWARE_ID_NAU8825	0x0

/* BIAS_ADJ (0x66) */
#define NAU8825_BIAS_HPR_IMP		(1 << 15)
#define NAU8825_BIAS_HPL_IMP		(1 << 14)
#define NAU8825_BIAS_TESTDAC_SFT	8
#define NAU8825_BIAS_TESTDAC_EN	(0x3 << NAU8825_BIAS_TESTDAC_SFT)
#define NAU8825_BIAS_TESTDACR_EN	(0x2 << NAU8825_BIAS_TESTDAC_SFT)
#define NAU8825_BIAS_TESTDACL_EN	(0x1 << NAU8825_BIAS_TESTDAC_SFT)
#define NAU8825_BIAS_VMID	(1 << 6)
#define NAU8825_BIAS_VMID_SEL_SFT	4
#define NAU8825_BIAS_VMID_SEL_MASK	(3 << NAU8825_BIAS_VMID_SEL_SFT)

/* ANALOG_CONTROL_1 (0x69) */
#define NAU8825_TESTDACIN_SFT		14
#define NAU8825_TESTDACIN_MASK		(0x3 << NAU8825_TESTDACIN_SFT)
#define NAU8825_TESTDACIN_HIGH		(1 << NAU8825_TESTDACIN_SFT)
#define NAU8825_TESTDACIN_LOW		(2 << NAU8825_TESTDACIN_SFT)
#define NAU8825_TESTDACIN_GND		(3 << NAU8825_TESTDACIN_SFT)

/* ANALOG_CONTROL_2 (0x6a) */
#define NAU8825_HP_NON_CLASSG_CURRENT_2xADJ (1 << 12)
#define NAU8825_DAC_CAPACITOR_MSB (1 << 1)
#define NAU8825_DAC_CAPACITOR_LSB (1 << 0)

/* ANALOG_ADC_2 (0x72) */
#define NAU8825_ADC_VREFSEL_MASK	(0x3 << 8)
#define NAU8825_ADC_VREFSEL_ANALOG	(0 << 8)
#define NAU8825_ADC_VREFSEL_VMID	(1 << 8)
#define NAU8825_ADC_VREFSEL_VMID_PLUS_0_5DB	(2 << 8)
#define NAU8825_ADC_VREFSEL_VMID_PLUS_1DB	(3 << 8)
#define NAU8825_POWERUP_ADCL	(1 << 6)

/* RDAC (0x73) */
#define NAU8825_RDAC_FS_BCLK_ENB	(1 << 15)
#define NAU8825_RDAC_EN_SFT		12
#define NAU8825_RDAC_EN		(0x3 << NAU8825_RDAC_EN_SFT)
#define NAU8825_RDAC_CLK_EN_SFT	8
#define NAU8825_RDAC_CLK_EN		(0x3 << NAU8825_RDAC_CLK_EN_SFT)
#define NAU8825_RDAC_CLK_DELAY_SFT	4
#define NAU8825_RDAC_CLK_DELAY_MASK	(0x7 << NAU8825_RDAC_CLK_DELAY_SFT)
#define NAU8825_RDAC_VREF_SFT	2
#define NAU8825_RDAC_VREF_MASK	(0x3 << NAU8825_RDAC_VREF_SFT)

/* MIC_BIAS (0x74) */
#define NAU8825_MICBIAS_JKSLV	(1 << 14)
#define NAU8825_MICBIAS_JKR2	(1 << 12)
#define NAU8825_MICBIAS_LOWNOISE_SFT	10
#define NAU8825_MICBIAS_LOWNOISE_MASK	(0x1 << NAU8825_MICBIAS_LOWNOISE_SFT)
#define NAU8825_MICBIAS_LOWNOISE_EN	(0x1 << NAU8825_MICBIAS_LOWNOISE_SFT)
#define NAU8825_MICBIAS_POWERUP_SFT	8
#define NAU8825_MICBIAS_VOLTAGE_SFT	0
#define NAU8825_MICBIAS_VOLTAGE_MASK	0x7

/* BOOST (0x76) */
#define NAU8825_PRECHARGE_DIS	(1 << 13)
#define NAU8825_GLOBAL_BIAS_EN	(1 << 12)
#define NAU8825_DISCHRG_EN	(1 << 11)
#define NAU8825_HP_BOOST_DIS		(1 << 9)
#define NAU8825_HP_BOOST_G_DIS	(1 << 8)
#define NAU8825_SHORT_SHUTDOWN_EN	(1 << 6)

/* FEPGA (0x77) */
#define NAU8825_ACDC_CTRL_SFT		14
#define NAU8825_ACDC_CTRL_MASK		(0x3 << NAU8825_ACDC_CTRL_SFT)
#define NAU8825_ACDC_VREF_MICP		(0x1 << NAU8825_ACDC_CTRL_SFT)
#define NAU8825_ACDC_VREF_MICN		(0x2 << NAU8825_ACDC_CTRL_SFT)

/* POWER_UP_CONTROL (0x7f) */
#define NAU8825_POWERUP_INTEGR_R	(1 << 5)
#define NAU8825_POWERUP_INTEGR_L	(1 << 4)
#define NAU8825_POWERUP_DRV_IN_R	(1 << 3)
#define NAU8825_POWERUP_DRV_IN_L	(1 << 2)
#define NAU8825_POWERUP_HP_DRV_R	(1 << 1)
#define NAU8825_POWERUP_HP_DRV_L	(1 << 0)

/* CHARGE_PUMP (0x80) */
#define NAU8825_ADCOUT_DS_SFT	12
#define NAU8825_ADCOUT_DS_MASK	(1 << NAU8825_ADCOUT_DS_SFT)
#define NAU8825_JAMNODCLOW	(1 << 10)
#define NAU8825_POWER_DOWN_DACR	(1 << 9)
#define NAU8825_POWER_DOWN_DACL	(1 << 8)
#define NAU8825_CHANRGE_PUMP_EN	(1 << 5)


/* System Clock Source */
enum {
	NAU8825_CLK_DIS = 0,
	NAU8825_CLK_MCLK,
	NAU8825_CLK_INTERNAL,
	NAU8825_CLK_FLL_MCLK,
	NAU8825_CLK_FLL_BLK,
	NAU8825_CLK_FLL_FS,
};

/* Cross talk detection state */
enum {
	NAU8825_XTALK_PREPARE = 0,
	NAU8825_XTALK_HPR_R2L,
	NAU8825_XTALK_HPL_R2L,
	NAU8825_XTALK_IMM,
	NAU8825_XTALK_DONE,
};

struct nau8825 {
	struct device *dev;
	struct regmap *regmap;
	struct snd_soc_dapm_context *dapm;
	struct snd_soc_jack *jack;
	struct clk *mclk;
	struct work_struct xtalk_work;
	struct semaphore xtalk_sem;
	int irq;
	int mclk_freq; /* 0 - mclk is disabled */
	int button_pressed;
	int micbias_voltage;
	int vref_impedance;
	bool jkdet_enable;
	bool jkdet_pull_enable;
	bool jkdet_pull_up;
	int jkdet_polarity;
	int sar_threshold_num;
	int sar_threshold[8];
	int sar_hysteresis;
	int sar_voltage;
	int sar_compare_time;
	int sar_sampling_time;
	int key_debounce;
	int jack_insert_debounce;
	int jack_eject_debounce;
	int high_imped;
	int xtalk_state;
	int xtalk_event;
	int xtalk_event_mask;
	bool xtalk_protect;
	int imp_rms[NAU8825_XTALK_IMM];
	int xtalk_enable;
	bool xtalk_baktab_initialized; /* True if initialized. */
	bool adcout_ds;
	int adc_delay;
};

int nau8825_enable_jack_detect(struct snd_soc_component *component,
				struct snd_soc_jack *jack);


#endif  /* __NAU8825_H__ */
