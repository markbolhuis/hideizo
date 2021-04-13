// SPDX-License-Identifier: GPL-2.0

/*
 *  HID driver for Eizo EV FlexScan Monitors
 *
 *  Supported models:
 *      EV2760
 *
 *  Copyright (c) 2021 Mark Bolhuis <mark@bolhuis.dev>
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/hid.h>

#include "eizo.h"


static int eizo_set_value(struct hid_device *hdev, int usage, int value) {
    struct eizo_data *data;
    ushort counter;
    u8 *report;
    int ret;

    data = hid_get_drvdata(hdev);
    if (data == NULL) {
        hid_err(hdev, "failed to get eizo_data\n");
        return -ENODATA; // No data available
    }

    // TODO: I don't like allocating a buffer on every file write
    //  so replace this with some buffer stored in eizo_data
    report = kzalloc(39, GFP_KERNEL);
    if (report == NULL) {
        hid_err(hdev, "failed to allocate hid report\n");
        return -ENOMEM; // Out of memory
    }

    mutex_lock(&data->lock);
    counter = data->counter;

    report[1] = (usage >> 0) & 0xff;
    report[2] = (usage >> 8) & 0xff;
    report[3] = (usage >> 16) & 0xff;
    report[4] = (usage >> 24) & 0xff;

    report[5] = (counter >> 0) & 0xff;
    report[6] = (counter >> 8) & 0xff;

    report[7] = (value >> 0) & 0xff;
    report[8] = (value >> 8) & 0xff;
    report[9] = (value >> 16) & 0xff;
    report[10] = (value >> 24) & 0xff;

    ret = hid_hw_raw_request(hdev, 2, report, 39, HID_FEATURE_REPORT, HID_REQ_SET_REPORT);
    hid_hw_wait(hdev);
    if (ret < 0) {
        hid_err(hdev, "failed to set hid report: %d\n", ret);
        mutex_unlock(&data->lock);
        kfree(report);
        return -ECOMM; // Communication error on send
    }

    mutex_unlock(&data->lock);
    kfree(report);
    return 0;
}

static int eizo_get_value(struct hid_device *hdev, int usage, int *value) {
    struct eizo_data *data;
    int ret, counter;
    u8 *report;

    data = hid_get_drvdata(hdev);
    if (data == NULL) {
        hid_err(hdev, "failed to get eizo_data\n");
        return -ENODATA; // No data available
    }

    report = kzalloc(39, GFP_KERNEL);
    if (report == NULL) {
        return -ENOMEM; // Out of memory
    }

    mutex_lock(&data->lock);
    counter = data->counter;

    report[1] = (usage >>  0) & 0xff;
    report[2] = (usage >>  8) & 0xff;
    report[3] = (usage >> 16) & 0xff;
    report[4] = (usage >> 24) & 0xff;

    report[5] = (counter >> 0) & 0xff;
    report[6] = (counter >> 8) & 0xff;

    ret = hid_hw_raw_request(hdev, 3, report, 39, HID_FEATURE_REPORT, HID_REQ_SET_REPORT);
    hid_hw_wait(hdev);
    if (ret < 0) {
        hid_err(hdev, "failed to set hid report: %d\n", ret);
        mutex_unlock(&data->lock);
        kfree(report);
        return -ECOMM; // Communication error on send
    }

    ret = hid_hw_raw_request(hdev, 3, report, 39, HID_FEATURE_REPORT, HID_REQ_GET_REPORT);
    hid_hw_wait(hdev);
    if (ret < 0) {
        hid_err(hdev, "failed to get hid report: %d\n", ret);
        mutex_unlock(&data->lock);
        kfree(report);
        return -ECOMM; // Communication error on send
    }

    *value = report[7] | (report[8] << 8) | (report[9] << 16) | (report[10] << 24);

    mutex_unlock(&data->lock);
    kfree(report);
    return 0;
}


static ssize_t eizo_attr_store_brightness(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
    struct hid_device *hdev;
    int value, res;

    res = kstrtoint(buf, 10, &value);
    if (res < 0) {
        return -EINVAL;
    }
    value = clamp(value, 0, 200);

    hdev = to_hid_device(dev);

    hid_info(hdev, "store %s: %d\n", attr->attr.name, value);

    res = eizo_set_value(hdev, EIZO_USAGE_BRIGHTNESS, value);
    if (res < 0) {
        hid_err(hdev, "failed to set %s value to %d, error %d\n", attr->attr.name, value, res);
        return -EPERM;
    }

    return count;
}

static ssize_t eizo_attr_show_brightness(struct device *dev, struct device_attribute *attr, char *buf) {
    struct hid_device *hdev;
    int value, res;

    hdev = to_hid_device(dev);
    res = eizo_get_value(hdev, EIZO_USAGE_BRIGHTNESS, &value);
    if (res < 0) {
        hid_err(hdev, "failed to get %s value, error %d\n", attr->attr.name, res);
        return -ENODATA;
    }
    hid_info(hdev, "show %s: %d\n", attr->attr.name, value);

    return sprintf(buf, "%d\n", value);
}


static DEVICE_ATTR(brightness, 0664, eizo_attr_show_brightness, eizo_attr_store_brightness);

static struct attribute *eizo_attrs[] = {
        &dev_attr_brightness.attr,
        NULL
};

static struct attribute_group eizo_attr_group = {
        .name = "settings",
        .attrs = eizo_attrs,
};

static void eizo_data_init(struct eizo_data *data, struct hid_device *hdev) {
    mutex_init(&data->lock);
    data->counter = 0x0001;
}

static void eizo_data_uninit(struct eizo_data *data) {
    mutex_destroy(&data->lock);
}

static int eizo_hid_driver_probe(struct hid_device *hdev, const struct hid_device_id *id) {
    struct eizo_data *data;
    int retval = 0;

    data = devm_kzalloc(&hdev->dev, sizeof(struct eizo_data), GFP_KERNEL);
    if (data == NULL) {
        hid_err(hdev, "failed to allocate eizo_data\n");
        retval = -ENOMEM;
        goto exit;
    }

    retval = hid_parse(hdev);
    if(retval < 0) {
        hid_err(hdev, "hid_parse failed\n");
        goto exit;
    }

    retval = hid_hw_start(hdev, HID_CONNECT_HIDRAW);
    if (retval < 0) {
        hid_err(hdev, "hid_hw_start failed\n");
        goto exit;
    }

    retval = hid_hw_open(hdev);
    if (retval < 0) {
        hid_err(hdev, "hid_hw_open failed\n");
        goto stop;
    }

    retval = sysfs_create_group(&hdev->dev.kobj, &eizo_attr_group);
    if (retval < 0) {
        hid_err(hdev, "sysfs_create_group failed\n");
        goto close;
    }

    eizo_data_init(data, hdev);
    hid_set_drvdata(hdev, data);

    return 0;
close:
    hid_hw_close(hdev);
stop:
    hid_hw_stop(hdev);
exit:
    return retval;
}

static void eizo_hid_driver_remove(struct hid_device *hdev) {
    struct eizo_data *data;
    data = hid_get_drvdata(hdev);

    eizo_data_uninit(data);
    sysfs_remove_group(&hdev->dev.kobj, &eizo_attr_group);
    hid_hw_close(hdev);
    hid_hw_stop(hdev);
}

static int eizo_hid_driver_raw_event(struct hid_device *hdev, struct hid_report *report, u8 *data, int size) {
    int id, usage, counter, value;

    id = data[0];
    usage = data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24);
    counter = data[5] | (data[6] << 8);
    value = data[7] | (data[8] << 8) | (data[9] << 16) | (data[10] << 24);

    hid_info(hdev, "raw_event: %02x %08x %04x %08x\n", id, usage, counter, value);
    return 0;
}

static const struct hid_device_id eizo_hid_driver_id_table[] = {
        { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, USB_PRODUCT_ID_EIZO_EV2460) },
        { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, USB_PRODUCT_ID_EIZO_EV2760) },
        // Known PIDs of monitors which have not been tested.
        // { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, USB_PRODUCT_ID_EIZO_EV2785) },
        // { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, USB_PRODUCT_ID_EIZO_EV3237) },
        { }
};

MODULE_DEVICE_TABLE(hid, eizo_hid_driver_id_table);

static struct hid_driver eizo_hid_driver = {
        .name =         "eizo",
        .id_table =     eizo_hid_driver_id_table,
        .probe =        eizo_hid_driver_probe,
        .remove =       eizo_hid_driver_remove,
        .raw_event =    eizo_hid_driver_raw_event,
};

module_hid_driver(eizo_hid_driver);

MODULE_AUTHOR("Mark Bolhuis");
MODULE_DESCRIPTION("HID device driver for EIZO FlexScan monitors");
MODULE_LICENSE("GPL v2");