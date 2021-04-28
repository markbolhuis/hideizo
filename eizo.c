// SPDX-License-Identifier: GPL-2.0

/*
 *  HID driver for Eizo EV FlexScan Monitors
 *
 *  Copyright (c) 2021 Mark Bolhuis <mark@bolhuis.dev>
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/hid.h>

#include "eizo.h"

int eizo_get_pseudo_descriptor(struct hid_device *hdev, u8 **desc, unsigned *desc_len) {
    u8 *report, *temp;
    unsigned int size, size2, offset, cpy, pos;
    int ret;

    report = kzalloc(517, GFP_KERNEL);
    if (!report) {
        return -ENOMEM;
    }

    ret = hid_hw_raw_request(hdev, EIZO_REPORT_DESC, report, 517, HID_FEATURE_REPORT, HID_REQ_SET_REPORT);
    if (ret < 0) {
        hid_err(hdev, "failed to set hid report: %d\n", ret);
        kfree(report);
        return ret;
    }

    ret = hid_hw_raw_request(hdev, EIZO_REPORT_DESC, report, 517, HID_FEATURE_REPORT, HID_REQ_GET_REPORT);
    if (ret < 0) {
        hid_err(hdev, "failed to get block at 0x0000 of pseudo descriptor: %d\n", ret);
        kfree(report);
        return ret;
    }

    offset = report[1] | (report[2] << 8);
    size   = report[3] | (report[4] << 8);

    if (offset != 0) {
        hid_err(hdev, "pseudo descriptor block offset incorrect: 0x%04x != 0x0000\n", offset);
        kfree(report);
        return -EPERM;
    }

    temp = devm_kmalloc(&hdev->dev, size, GFP_KERNEL);
    if (!temp) {
        kfree(report);
        return -ENOMEM;
    }

    cpy = min_t(unsigned int, size, 512);
    memcpy(temp, report + 5, cpy);

    for (pos = 512; pos < size; pos += 512) {
        cpy = min_t(unsigned int, size - pos, 512);

        ret = hid_hw_raw_request(hdev, EIZO_REPORT_DESC, report, 517, HID_FEATURE_REPORT, HID_REQ_GET_REPORT);
        if (ret < 0) {
            hid_err(hdev, "failed to get block at 0x%04x of pseudo descriptor: %d\n", pos, ret);
            goto free;
        }

        offset = report[1] | (report[2] << 8);
        size2  = report[3] | (report[4] << 8);

        if(offset != pos) {
            hid_err(hdev, "pseudo descriptor block offset incorrect: 0x%04x != 0x%04x\n", offset, pos);
            ret = -EPERM;
            goto free;
        }

        if (size != size2) {
            hid_err(hdev, "pseudo descriptor block size mismatch: %u != %u\n", size, size2);
            ret = -EPERM;
            goto free;
        }

        memcpy(temp + pos, report + 5, cpy);
    }

    kfree(report);
    *desc = temp;
    *desc_len = size;
    return 0;

free:
    devm_kfree(&hdev->dev, temp);
    kfree(report);
    return ret;
}

int eizo_set_value(struct hid_device *hdev, u32 usage, u8 value[32]) {
    struct eizo_data *data;
    u16 counter;
    u8 *report;
    int ret;

    data = hid_get_drvdata(hdev);
    if (!data) {
        return -ENODATA;
    }

    report = kzalloc(39, GFP_KERNEL);
    if (!report) {
        return -ENOMEM;
    }

    mutex_lock(&data->lock);
    counter = data->counter;

    report[1] = (usage >> 0) & 0xff;
    report[2] = (usage >> 8) & 0xff;
    report[3] = (usage >> 16) & 0xff;
    report[4] = (usage >> 24) & 0xff;

    report[5] = (counter >> 0) & 0xff;
    report[6] = (counter >> 8) & 0xff;

    memcpy(&report[7], value, 32);

    ret = hid_hw_raw_request(hdev, EIZO_REPORT_SET, report, 39, HID_FEATURE_REPORT, HID_REQ_SET_REPORT);
    if (ret < 0) {
        hid_err(hdev, "failed to set hid report: %d\n", ret);
        goto exit;
    }

    ret = 0;
exit:
    mutex_unlock(&data->lock);
    kfree(report);
    return ret;
}

int eizo_get_value(struct hid_device *hdev, u32 usage, u8 value[32]) {
    struct eizo_data *data;
    u16 counter;
    u8 *report;
    int ret;

    data = hid_get_drvdata(hdev);
    if (!data) {
        hid_err(hdev, "failed to get eizo_data\n");
        return -ENODATA;
    }

    report = kzalloc(39, GFP_KERNEL);
    if (!report) {
        hid_err(hdev, "failed to allocate report buffer");
        return -ENOMEM;
    }

    mutex_lock(&data->lock);
    counter = data->counter;

    report[1] = (usage >>  0) & 0xff;
    report[2] = (usage >>  8) & 0xff;
    report[3] = (usage >> 16) & 0xff;
    report[4] = (usage >> 24) & 0xff;

    report[5] = (counter >> 0) & 0xff;
    report[6] = (counter >> 8) & 0xff;

    ret = hid_hw_raw_request(hdev, EIZO_REPORT_GET, report, 39, HID_FEATURE_REPORT, HID_REQ_SET_REPORT);
    if (ret < 0) {
        hid_err(hdev, "failed to set hid report: %d\n", ret);
        goto exit;
    }

    ret = hid_hw_raw_request(hdev, EIZO_REPORT_GET, report, 39, HID_FEATURE_REPORT, HID_REQ_GET_REPORT);
    if (ret < 0) {
        hid_err(hdev, "failed to get hid report: %d\n", ret);
        goto exit;
    }

    memcpy(value, &report[7], 32);

    ret = 0;
exit:
    mutex_unlock(&data->lock);
    kfree(report);
    return ret;
}

int eizo_get_counter(struct hid_device *hdev, u16 *counter) {
    u8 *report;
    int ret;

    report = kzalloc(3, GFP_KERNEL);
    if (!report) {
        return -ENOMEM;
    }

    ret = hid_hw_raw_request(hdev, EIZO_REPORT_COUNTER, report, 3, HID_FEATURE_REPORT, HID_REQ_GET_REPORT);
    if (ret < 0) {
        hid_err(hdev, "failed to get hid report: %d\n", ret);
        goto exit;
    }

    *counter = report[1] | (report[2] << 8);
    ret = 0;
exit:
    kfree(report);
    return ret;
}


static int eizo_ll_parse(struct hid_device *hdev) {
    struct eizo_data *data;
    struct hid_device *parent;

    hid_info(hdev, "%s\n", __func__);

    parent = to_hid_device(hdev->dev.parent);
    data = hid_get_drvdata(parent);

    return hid_parse_report(hdev, data->pseudo_desc, data->pseudo_desc_size);
}

static int eizo_ll_start(struct hid_device *hdev) {
    hid_info(hdev, "%s\n", __func__);
    return 0;
}

static void eizo_ll_stop(struct hid_device *hdev) {
    hid_info(hdev, "%s\n", __func__);
}

static int eizo_ll_open(struct hid_device *hdev) {
    hid_info(hdev, "%s\n", __func__);
    return 0;
}

static void eizo_ll_close(struct hid_device *hdev) {
    hid_info(hdev, "%s\n", __func__);
}

static int eizo_ll_raw_request(struct hid_device *hdev,
                               unsigned char reportnum,
                               u8 *buf,
                               size_t count,
                               unsigned char report_type,
                               int reqtype) {
    hid_info(hdev, "%s\n", __func__);
    return 0;
}

static struct hid_ll_driver eizo_ll_driver = {
        .parse = eizo_ll_parse,
        .start = eizo_ll_start,
        .stop  = eizo_ll_stop,
        .open  = eizo_ll_open,
        .close = eizo_ll_close,
        .raw_request = eizo_ll_raw_request,
};


int eizo_create_hid_device(struct hid_device *hdev) {
    struct hid_device *vdev;
    struct eizo_data *data;
    int ret;

    data = hid_get_drvdata(hdev);
    if (!data) {
        hid_err(hdev, "failed to get eizo_data\n");
        return -ENODATA;
    }

    vdev = hid_allocate_device();
    if (!vdev) {
        hid_err(hdev, "failed to allocate vdev\n");
        return -ENOMEM;
    }

    vdev->ll_driver  = &eizo_ll_driver;

    vdev->dev.parent = &hdev->dev;
    vdev->bus        = hdev->bus;
    vdev->vendor     = hdev->vendor;
    vdev->product    = hdev->product;
    vdev->version    = hdev->version;
    vdev->type       = hdev->type;
    vdev->country    = hdev->country;

    vdev->group      = HID_GROUP_EIZO;

    strlcpy(vdev->name, hdev->name, sizeof(vdev->name));
    strlcpy(vdev->phys, hdev->phys, sizeof(vdev->phys));

    ret = hid_add_device(vdev);
    if (ret < 0) {
        hid_destroy_device(vdev);
        return ret;
    }

    data->vdev = vdev;
    data->is_vdev_open = false;

    hid_set_drvdata(vdev, data);

    return 0;
}

void eizo_init(struct hid_device *hdev) {
    struct eizo_data *data;
    int ret;

    data = hid_get_drvdata(hdev);

    mutex_init(&data->lock);

    ret = eizo_get_counter(hdev, &data->counter);
    if (ret < 0) {
        hid_err(hdev, "failed to get counter from monitor\n");
        return;
    }

    ret = eizo_get_pseudo_descriptor(hdev, &data->pseudo_desc, &data->pseudo_desc_size);
    if (ret < 0) {
        hid_err(hdev, "failed to get pseudo report descriptor from monitor\n");
        return;
    }

    ret = eizo_create_hid_device(hdev);
    if (ret < 0) {
        hid_err(hdev, "failed to create vdev\n");
        return;
    }
}

void eizo_uninit(struct hid_device *hdev) {
    struct eizo_data *data;

    data = hid_get_drvdata(hdev);

    if (data->vdev) {
        hid_destroy_device(data->vdev);
        data->vdev = NULL;
    }
    mutex_destroy(&data->lock);
}


static int eizo_hid_driver_probe(struct hid_device *hdev, const struct hid_device_id *id) {
    struct eizo_data *data;
    int retval = 0;

    retval = hid_parse(hdev);
    if(retval < 0) {
        hid_err(hdev, "hid_parse failed\n");
        return retval;
    }

    if (hdev->group == HID_GROUP_EIZO) {
        hid_info(hdev, "vdev device probe\n");
        return hid_hw_start(hdev, HID_CONNECT_DEFAULT);
    }

    data = devm_kzalloc(&hdev->dev, sizeof(struct eizo_data), GFP_KERNEL);
    if (!data) {
        hid_err(hdev, "failed to allocate eizo_data\n");
        return -ENOMEM;
    }

    retval = hid_hw_start(hdev, HID_CONNECT_HIDRAW);
    if (retval < 0) {
        hid_err(hdev, "hid_hw_start failed\n");
        goto exit;
    }

    hid_set_drvdata(hdev, data);
    eizo_init(hdev);

    retval = hid_hw_open(hdev);
    if (retval < 0) {
        hid_err(hdev, "hid_hw_open failed\n");
        goto stop;
    }

    return 0;
close:
    hid_hw_close(hdev);
stop:
    hid_hw_stop(hdev);
exit:
    return retval;
}

static void eizo_hid_driver_remove(struct hid_device *hdev) {
    if (hdev->group == HID_GROUP_EIZO) {
        hid_hw_stop(hdev);
        return;
    }
    eizo_uninit(hdev);
    hid_hw_close(hdev);
    hid_hw_stop(hdev);
}

static int eizo_hid_driver_raw_event(struct hid_device *hdev, struct hid_report *report, u8 *data, int size) {
    u32 usage, value;
    u16 counter;
    u8 id;

    switch(report->id) {
        case EIZO_REPORT_SET:
        case EIZO_REPORT_GET:
        case EIZO_REPORT_SET2:
        case EIZO_REPORT_GET2:
            id = data[0];
            usage = data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24);
            counter = data[5] | (data[6] << 8);
            value = data[7] | (data[8] << 8) | (data[9] << 16) | (data[10] << 24);

            hid_info(hdev, "event %d: %08x %04x %08x\n", id, usage, counter, value);
            break;

        default:
            hid_info(hdev, "event %d\n", report->id);
            break;
    }

    return 0;
}

static const struct hid_device_id eizo_hid_driver_id_table[] = {
        { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, USB_PRODUCT_ID_EIZO_EV2450) },
        { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, USB_PRODUCT_ID_EIZO_EV2451) },
        { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, USB_PRODUCT_ID_EIZO_EV2455) },
        { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, USB_PRODUCT_ID_EIZO_EV2456) },
        { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, USB_PRODUCT_ID_EIZO_EV2457) },
        { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, USB_PRODUCT_ID_EIZO_EV2460) },
        { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, USB_PRODUCT_ID_EIZO_EV2750) },
        { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, USB_PRODUCT_ID_EIZO_EV2760) },
        { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, USB_PRODUCT_ID_EIZO_EV2785) },
        { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, USB_PRODUCT_ID_EIZO_EV2795) },
        { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, USB_PRODUCT_ID_EIZO_EV3237) },
        { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, USB_PRODUCT_ID_EIZO_EV3285) },
        { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, USB_PRODUCT_ID_EIZO_EV3895) },
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