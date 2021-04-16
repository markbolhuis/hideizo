#ifndef EIZO_H_FILE
#define EIZO_H_FILE

#define USB_VENDOR_ID_EIZO 0x056d

#define USB_PRODUCT_ID_EIZO_EV2450 0x4001
#define USB_PRODUCT_ID_EIZO_EV2451 0x4026
#define USB_PRODUCT_ID_EIZO_EV2455 0x4002
#define USB_PRODUCT_ID_EIZO_EV2456 0x4027
#define USB_PRODUCT_ID_EIZO_EV2457 0x4044
#define USB_PRODUCT_ID_EIZO_EV2460 0x405B
#define USB_PRODUCT_ID_EIZO_EV2750 0x4014
#define USB_PRODUCT_ID_EIZO_EV2760 0x4059
#define USB_PRODUCT_ID_EIZO_EV2785 0x4036
#define USB_PRODUCT_ID_EIZO_EV2795 0x405f
#define USB_PRODUCT_ID_EIZO_EV3237 0x4000
#define USB_PRODUCT_ID_EIZO_EV3285 0x4037

// #define USB_PRODUCT_ID_EIZO_EV3895 ?
// #define USB_PRODUCT_ID_EIZO_EV2495 ?
// #define USB_PRODUCT_ID_EIZO_EV2780 ?
// #define USB_PRODUCT_ID_EIZO_EV2480 ?
// #define USB_PRODUCT_ID_EIZO_EV2360 ?

/*
 *  Usages
 *  These appear to be 'standard' hid usages where bytes 1 and 2 are the usage page
 *  and bytes 3 and 4 are the usage id.
 *
 *  Some values follow VESA virtual control and consumer usages as indicated by
 *  0x0082 and 0x000c however most are vendor defined.
 *  Despite this it isn't really useful since there are only a few of them and
 *  the message structure in the HID report is vendor defined anyway.
 *
 *  https://www.usb.org/document-library/hid-usage-tables-122
 *  https://www.usb.org/document-library/monitor-control-class-10
 */

/*
 *  Consumer Usage Page
 */
#define EIZO_USAGE_VOLUME          0x00e0000c

/*
 *  VESA Virtual Controls Usage Page
 */

#define EIZO_USAGE_BRIGHTNESS      0x00100082
#define EIZO_USAGE_CONTRAST        0x00120082
#define EIZO_USAGE_GAIN_RED        0x00160082
#define EIZO_USAGE_GAIN_GREEN      0x00180082
#define EIZO_USAGE_GAIN_BLUE       0x001a0082
#define EIZO_USAGE_SETTINGS        0x00B00082

/*
 * Vendor Defined Usage Pages
 * 0xff00 0xff01 0xff02
 */

#define EIZO_USAGE_TEMP            0x0007ff00
#define EIZO_USAGE_IDENTIFY        0x000fff00
#define EIZO_USAGE_PROFILE         0x0015ff00
#define EIZO_USAGE_EEP_DATA        0x0031ff00
#define EIZO_USAGE_USAGE_TIME      0x0037ff00
#define EIZO_USAGE_GAMMA           0x0066ff00
#define EIZO_USAGE_PICTURE_EXP     0x00a5ff00
#define EIZO_USAGE_SATURATION      0x00b3ff00
#define EIZO_USAGE_HUE             0x00b4ff00
#define EIZO_USAGE_POWER           0x00b8ff00
#define EIZO_USAGE_AUTO_ECOVIEW    0x00b9ff00
#define EIZO_USAGE_MODEL           0x00c3ff00
#define EIZO_USAGE_STATE           0x00c9ff00
#define EIZO_USAGE_HORIZONTAL_RES  0x00caff00
#define EIZO_USAGE_VERTICAL_RES    0x00cbff00

#define EIZO_USAGE_ECOVIEW_SENSOR  0x000cff01
#define EIZO_USAGE_BUTTON          0x003dff01
#define EIZO_USAGE_PICBYPIC        0x0040ff01
#define EIZO_USAGE_LOCK_OSD        0x0044ff01
#define EIZO_USAGE_DISABLE_OSD     0x0045ff01
#define EIZO_USAGE_INPUT           0x0048ff01
#define EIZO_USAGE_OVERDRIVE       0x004aff01
#define EIZO_USAGE_POWER_SAVE      0x0054ff01
#define EIZO_USAGE_SUPER_RES       0x005bff01
#define EIZO_USAGE_FACTORY_RESET   0x00a1ff01
#define EIZO_USAGE_ECOVIEW_OPT2    0x00ebff01
#define EIZO_USAGE_SCREEN          0x00f9ff01
#define EIZO_USAGE_STANDBY         0x00feff01
#define EIZO_USAGE_OSD_ROTATION    0x00ffff01
#define EIZO_USAGE_FREQ_DIAGONAL   0x0111ff01

#define EIZO_USAGE_DEBUG_MODE      0x0006ff02
#define EIZO_USAGE_SERIAL          0x0036ff02
#define EIZO_USAGE_MODEL2          0x0100ff02

/*
 *  Values
 */

#define EIZO_VALUE_TEMP_OFF    0x00
#define EIZO_VALUE_TEMP_4000K  0x01
#define EIZO_VALUE_TEMP_4500K  0x02
#define EIZO_VALUE_TEMP_5000K  0x03
#define EIZO_VALUE_TEMP_5500K  0x04
#define EIZO_VALUE_TEMP_6000K  0x05
#define EIZO_VALUE_TEMP_6500K  0x06
#define EIZO_VALUE_TEMP_7000K  0x07
#define EIZO_VALUE_TEMP_7500K  0x08
#define EIZO_VALUE_TEMP_8000K  0x09
#define EIZO_VALUE_TEMP_8500K  0x0a
#define EIZO_VALUE_TEMP_9000K  0x0b
#define EIZO_VALUE_TEMP_9300K  0x0c
#define EIZO_VALUE_TEMP_9500K  0x0d
#define EIZO_VALUE_TEMP_10000K 0x0e

#define EIZO_VALUE_GAMMA_1_8 0x02
#define EIZO_VALUE_GAMMA_2_0 0x03
#define EIZO_VALUE_GAMMA_2_2 0x04
#define EIZO_VALUE_GAMMA_2_4 0x05

#define EIZO_VALUE_INPUT_DVI  0x0200
#define EIZO_VALUE_INPUT_DP1  0x0300
#define EIZO_VALUE_INPUT_DP2  0x0301
#define EIZO_VALUE_INPUT_HDMI 0x0400

#define EIZO_VALUE_PROFILE_MOVIE 0x02
#define EIZO_VALUE_PROFILE_SRGB  0x04
#define EIZO_VALUE_PROFILE_DICOM 0x08
#define EIZO_VALUE_PROFILE_USER1 0x16
#define EIZO_VALUE_PROFILE_USER2 0x17
#define EIZO_VALUE_PROFILE_PAPER 0x22

#define EIZO_VALUE_IDENTIFY_SHOW 0x4000
#define EIZO_VALUE_IDENTIFY_HIDE 0x8000

#define EIZO_VALUE_POWER_OFF 0
#define EIZO_VALUE_POWER_ON 1

#define EIZO_VALUE_SCREEN_1 0
#define EIZO_VALUE_SCREEN_2 1

#define EIZO_VALUE_AUTO_ECOVIEW_OFF 0
#define EIZO_VALUE_AUTO_ECOVIEW_ON 1

#define EIZO_VALUE_ECOVIEW_OPT2_OFF 0
#define EIZO_VALUE_ECOVIEW_OPT2_ON 1

#define EIZO_VALUE_PIC_EXP_DOTBYDOT 0
#define EIZO_VALUE_PIC_EXP_ASPECTRATIO 1
#define EIZO_VALUE_PIC_EXP_FULLSCREEN 2

#define EIZO_VALUE_OVERDRIVE_OFF 0
#define EIZO_VALUE_OVERDRIVE_STANDARD 1
#define EIZO_VALUE_OVERDRIVE_ENHANCED 2

#define EIZO_VALUE_POWER_SAVE_OFF 0
#define EIZO_VALUE_POWER_SAVE_ON 1

#define EIZO_VALUE_OSD_ROTATION_0 0
#define EIZO_VALUE_OSD_ROTATION_90 1
#define EIZO_VALUE_OSD_ROTATION_270 2

#define EIZO_VALUE_PICBYPIC_OFF 0
#define EIZO_VALUE_PICBYPIC_2X1 1

#define EIZO_VALUE_BUTTON_1 BIT(1)
#define EIZO_VALUE_BUTTON_2 BIT(2)
#define EIZO_VALUE_BUTTON_3 BIT(3)
#define EIZO_VALUE_BUTTON_4 BIT(4)
#define EIZO_VALUE_BUTTON_5 BIT(5)
#define EIZO_VALUE_BUTTON_6 BIT(6)
#define EIZO_VALUE_BUTTON_7 BIT(7)

struct eizo_data {
    struct mutex lock;
    ushort counter;
};

#endif // EIZO_H_FILE
