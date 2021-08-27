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
#include <asm/unaligned.h>

#include "eizo.h"

int eizo_verify(struct hid_device *hdev, u32 usage) {
    struct hid_report *report;
    u32 report_len, actual_usage;
    u8 *report_buf;
    // u16 counter;
    u8 value;
    int ret;

    report = hdev->report_enum[HID_FEATURE_REPORT].report_id_hash[EIZO_REPORT_VERIFY];
    report_len = hid_report_len(report);

    report_buf = kzalloc(report_len, GFP_KERNEL);
    if(!report_buf){
        return -ENOMEM;
    }

    ret = hid_hw_raw_request(
            hdev,
            EIZO_REPORT_VERIFY,
            report_buf,
            report_len,
            report->type,
            HID_REQ_GET_REPORT);
    if(ret < 0) {
        goto exit;
    }

    actual_usage = get_unaligned_le32(report_buf + 1);
    // counter      = get_unaligned_le16(report_buf + 5);
    value        = report_buf[7];

    if(usage != actual_usage || value != 0) {
        ret = -EIO;
        goto exit;
    }

    ret = 0;
exit:
    kfree(report_buf);
    return ret;
}

int eizo_set_value(struct hid_device *hdev, u32 usage, u8 *value, size_t value_len) {
    struct eizo_data *data;
    struct hid_report *report;
    u8 *report_buf;
    u32 report_len;
    u16 counter;
    int ret;

    data = hid_get_drvdata(hdev);
    counter = data->counter;

    report = hdev->report_enum[HID_FEATURE_REPORT].report_id_hash[EIZO_REPORT_SET];
    report_len = hid_report_len(report);

    if(value_len > (report_len - 7)) {
        report = hdev->report_enum[HID_FEATURE_REPORT].report_id_hash[EIZO_REPORT_SET2];
        report_len = hid_report_len(report);

        if(value_len > (report_len - 7)) {
            return -EINVAL;
        }
    }

    report_buf = kzalloc(report_len, GFP_KERNEL);
    if (!report_buf) {
        return -ENOMEM;
    }

    report_buf[0] = (u8)report->id;
    put_unaligned_le32(usage, report_buf + 1);
    put_unaligned_le16(counter, report_buf + 5);
    memcpy(report_buf + 7, value, value_len);

    ret = hid_hw_raw_request(
            hdev,
            report_buf[0],
            report_buf,
            report_len,
            report->type,
            HID_REQ_SET_REPORT);
    if (ret < 0) {
        hid_err(hdev, "%s failed to set report: %d\n", __func__, ret);
        goto exit;
    }

    ret = eizo_verify(hdev, usage);
exit:
    kfree(report_buf);
    return ret;
}

int eizo_get_value(struct hid_device *hdev, u32 usage, u8 *value, size_t value_len) {
    struct eizo_data *data;
    struct hid_report *report;
    u8 *report_buf;
    u32 report_len;
    u16 counter;
    int ret;

    data = hid_get_drvdata(hdev);
    counter = data->counter;

    report = hdev->report_enum[HID_FEATURE_REPORT].report_id_hash[EIZO_REPORT_GET];
    report_len = hid_report_len(report);

    if(value_len > (report_len - 7)) {
        report = hdev->report_enum[HID_FEATURE_REPORT].report_id_hash[EIZO_REPORT_GET2];
        report_len = hid_report_len(report);

        if(value_len > (report_len - 7)) {
            return -EINVAL;
        }
    }

    report_buf = kzalloc(report_len, GFP_KERNEL);
    if (!report_buf) {
        return -ENOMEM;
    }

    report_buf[0] = (u8)report->id;
    put_unaligned_le32(usage, report_buf + 1);
    put_unaligned_le16(counter, report_buf + 5);

    ret = hid_hw_raw_request(
            hdev,
            report_buf[0],
            report_buf,
            report_len,
            report->type,
            HID_REQ_SET_REPORT);
    if (ret < 0) {
        hid_err(hdev, "%s failed to set report: %d\n", __func__, ret);
        goto exit;
    }

    ret = hid_hw_raw_request(
            hdev,
            report_buf[0],
            report_buf,
            report_len,
            report->type,
            HID_REQ_GET_REPORT);
    if (ret < 0) {
        hid_err(hdev, "%s failed to get report: %d\n", __func__, ret);
        goto exit;
    }

    ret = eizo_verify(hdev, usage);
    if(ret == 0) {
        memcpy(value, report_buf + 7, value_len);
    }
exit:
    kfree(report_buf);
    return ret;
}

int eizo_get_counter(struct hid_device *hdev) {
    struct eizo_data *data;
    u8 *report;
    int ret;

    data = hid_get_drvdata(hdev);
    if(!data) {
        return -ENODATA;
    }

    report = kzalloc(3, GFP_KERNEL);
    if (!report) {
        return -ENOMEM;
    }

    ret = hid_hw_raw_request(hdev, EIZO_REPORT_COUNTER, report, 3, HID_FEATURE_REPORT, HID_REQ_GET_REPORT);
    if (ret < 0) {
        hid_err(hdev, "failed to get hid report: %d\n", ret);
        goto exit;
    }

    data->counter = get_unaligned_le16(report + 1);
    ret = 0;
exit:
    kfree(report);
    return ret;
}


u32 eizo_get_usage_from_report(struct hid_report *report) {
    u32 hid;

    if (report->maxfield == 0) {
        return 0;
    }

    hid = (u32)report->field[0]->usage->hid;
    return ((hid << 16) & 0xffff0000) | ((hid >> 16) & 0x0000ffff);
}

struct hid_report *eizo_get_report_from_usage(struct hid_device *hdev, int type, u32 usage) {
    struct hid_report *report;
    struct list_head *report_list;
    u32 hid;

    report_list = &hdev->report_enum[type].report_list;
    report = NULL;

    list_for_each_entry(report, report_list, list) {
        if(report->maxfield == 0) {
            continue;
        }

        hid = (u32)report->field[0]->usage->hid;
        hid = ((hid << 16) & 0xffff0000) | ((hid >> 16) & 0x0000ffff);
        if(usage == hid) {
            break;
        }
    }

    return report;
}


static int eizo_ll_parse(struct hid_device *hdev) {
    struct hid_device *parent;
    u8 *report, *temp;
    unsigned int size, size2, offset, cpy, pos;
    int ret;

    parent = to_hid_device(hdev->dev.parent);

    report = kzalloc(517, GFP_KERNEL);
    if (!report) {
        return -ENOMEM;
    }

    ret = hid_hw_raw_request(parent, EIZO_REPORT_DESC, report, 517, HID_FEATURE_REPORT, HID_REQ_SET_REPORT);
    if (ret < 0) {
        kfree(report);
        return ret;
    }

    ret = hid_hw_raw_request(parent, EIZO_REPORT_DESC, report, 517, HID_FEATURE_REPORT, HID_REQ_GET_REPORT);
    if (ret < 0) {
        kfree(report);
        return ret;
    }

    offset = get_unaligned_le16(report + 1);
    size   = get_unaligned_le16(report + 3);

    if (offset != 0) {
        kfree(report);
        return -EPERM;
    }

    temp = kmalloc(size, GFP_KERNEL);
    if (!temp) {
        kfree(report);
        return -ENOMEM;
    }

    cpy = min_t(unsigned int, size, 512);
    memcpy(temp, report + 5, cpy);

    for (pos = 512; pos < size; pos += 512) {
        cpy = min_t(unsigned int, size - pos, 512);

        ret = hid_hw_raw_request(parent, EIZO_REPORT_DESC, report, 517, HID_FEATURE_REPORT, HID_REQ_GET_REPORT);
        if (ret < 0) {
            goto free;
        }

        offset = get_unaligned_le16(report + 1);
        size2  = get_unaligned_le16(report + 3);

        if(offset != pos || size != size2) {
            ret = -EPERM;
            goto free;
        }

        memcpy(temp + pos, report + 5, cpy);
    }

    ret = hid_parse_report(hdev, temp, size);

free:
    kfree(temp);
    kfree(report);
    return ret;
}

static int eizo_ll_start(struct hid_device *hdev) {
    return 0;
}

static void eizo_ll_stop(struct hid_device *hdev) {

}

static int eizo_ll_open(struct hid_device *hdev) {
    struct eizo_data *data;

    data = dev_get_drvdata(hdev->dev.parent);
    mutex_lock(&data->lock);

    if(data->is_vdev_open) {
        mutex_unlock(&data->lock);
        return -EPERM;
    }

    data->is_vdev_open = true;

    mutex_unlock(&data->lock);
    return 0;
}

static void eizo_ll_close(struct hid_device *hdev) {
    struct eizo_data *data;

    data = dev_get_drvdata(hdev->dev.parent);
    mutex_lock(&data->lock);
    data->is_vdev_open = false;
    mutex_unlock(&data->lock);
}

static int eizo_ll_raw_request(struct hid_device *hdev,
                               unsigned char reportnum,
                               u8 *buf,
                               size_t count,
                               unsigned char report_type,
                               int reqtype) {
    struct hid_device *parent;
    struct hid_report *report;
    u32 usage;
    u32 rlen;
    int ret;

    hid_info(hdev, "%s: count %lu, report_type %u, reqtype %u, reportnum %u\n",
             __func__, count, report_type, reqtype, reportnum);

    report = hdev->report_enum[report_type].report_id_hash[reportnum];
    if (!report) {
        hid_err(hdev, "invalid report type %u and id %u\n", report_type, reportnum);
        return -EINVAL;
    }

    rlen = hid_report_len(report);
    if (count == 0 || count > rlen) {
        return -EINVAL;
    }

    parent = to_hid_device(hdev->dev.parent);
    usage  = eizo_get_usage_from_report(report);

    hid_info(hdev, "%s: usage 0x%08x, rlen: %d, id: %d\n",
             __func__,
             usage,
             rlen,
             report->id);

    switch (reqtype) {
        case HID_REQ_SET_REPORT:
            ret = eizo_set_value(parent, usage, buf + 1, count - 1);
            if(ret < 0) {
                hid_err(parent, "failed to set value: %d\n", ret);
                goto err;
            }
            break;

        case HID_REQ_GET_REPORT:
            ret = eizo_get_value(parent, usage, buf + 1, count - 1);
            if(ret < 0) {
                hid_err(parent, "failed to get value: %d\n", ret);
                goto err;
            }
            buf[0] = reportnum;
            break;

        default:
            hid_info(hdev, "unknown reqtype: %u\n", reqtype);
            break;
    }

    return count;
err:
    return ret;
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
    vdev->product    = 0x40ff; // hdev->product;
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
    if(!data) {
        hid_err(hdev, "failed to get eizo_data\n");
        return;
    }

    mutex_init(&data->lock);

    ret = eizo_get_counter(hdev);
    if (ret < 0) {
        hid_err(hdev, "failed to get counter from monitor\n");
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
    if(!data) {
        return;
    }
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
    struct eizo_data *e_data;
    struct hid_device *child;
    struct hid_report *child_report;
    u32 usage;
    u64 value;
    u16 counter;
    u8 id;
    u32 rlen;
    u8 *buffer;

    e_data = hid_get_drvdata(hdev);
    child = e_data->vdev;

    switch(report->id) {

        case EIZO_REPORT_SET:
        case EIZO_REPORT_SET2:
            break;

        case EIZO_REPORT_GET:
        case EIZO_REPORT_GET2:
            id      = data[0];
            usage   = get_unaligned_le32(data + 1);
            counter = get_unaligned_le16(data + 5);
            value   = get_unaligned_le64(data + 7);

            hid_info(hdev, "event %d: %08x %04x %016llx\n", id, usage, counter, value);

            child_report = eizo_get_report_from_usage(child, report->type, usage);
            if(!child_report) {
                hid_err(hdev, "failed to find report with usage %04x\n", usage);
                break;
            }

            rlen = hid_report_len(child_report);
            buffer = kzalloc(rlen, GFP_KERNEL);

            hid_info(hdev, "report: %u len: %u\n", child_report->id, rlen);

            buffer[0] = child_report->id;
            memcpy(buffer + 1, data + 7, rlen - 1);

            hid_report_raw_event(child, report->type, buffer, rlen, 1);

            kfree(buffer);
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
        { HID_USB_DEVICE(USB_VENDOR_ID_EIZO, 0x40ff) },
        { },
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