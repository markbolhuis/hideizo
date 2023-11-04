OpenEizo
========
A small WIP Linux HID device driver to control Eizo EV FlexScan monitors.

Aims
----
To reverse engineer the protocol used to control Eizo EV FlexScan monitors, and write an open source Linux driver as a 
replacement for Eizo's own proprietary and Windows only Screen InStyle software.

Monitor Support
---------------
This driver aims to support the following monitors.

Model   | Size    | PID    | Tested
--------|---------|--------|---------
EV3895  | 37.5    | 4065   |
EV2795  | 27      | 405F   |
EV2495  | 24.1    | 405E   |
EV3285  | 31.5    | 4037   |
EV2785  | 27      | 4036   |
EV2780  | 27      | 402b   |
EV2480  | 23.8    | 406a   |
EV2760  | 27      | 4059   | ✅
EV2750  | 27      | 4014   |
EV2457  | 24.1    | 4044   |
EV2456  | 24.1    | 4027   |
EV2455  | 24.1    | 4002   |
EV2460  | 23.8    | 405B   |
EV2451  | 23.8    | 4026   |
EV2450  | 23.9    | 4001   |
EV2360  | 22.5    | 405A   |
EV3237  | 31.5    | 4000   |
EV2490  | 23.8    | ?      |

Running
-------
By itself the driver only creates a child hid device using a secondary descriptor fetched from the monitor. This child
device provides a simplified interface for controlling the monitor.

Below is an example program using [hidapi](https://github.com/signal11/hidapi) to set the brightness to 85. Make sure
you have appropriate permissions using `udev/eizo.rules`, and add yourself to the `eizo` group.

```c
#include <stdio.h>
#include <hidapi/hidapi.h>

int main() {
    hid_init();
    
    // Open the HID raw device
    // Set this to the path of the device the driver creates.
    struct hid_device_ *dev = hid_open_path("/dev/hidraw13");
    if(dev) {
        // Define a buffer big enough for the report
        // The maximum size for any report is 513
        unsigned char val[3];
        
        // Set the report number to brightness
        val[0] = 82;
        
        // Set the le uint16 brightness value
        val[1] = 170;
        val[2] = 0;
        
        // Send the report and either return an error or the actual number 
        // of bytes written.
        int len = hid_send_feature_report(dev, val, sizeof(val));
        if (len >= 0) {
            printf("%d bytes written", len);
        } else {
            const wchar_t *err = hid_error(dev);
            fwprintf(stderr, L"%ls\n", err);
        }

        hid_close(dev);
    }

    hid_exit();
    return 0;
}
```

Contributing
------------
If you have an EV FlexScan monitor then please open an issue with info on which monitor you have with its PID, so we can
work towards supporting it.

```shell
$ lsusb | grep 056d
Bus 003 Device 006: ID 056d:4059 EIZO Corp. FlexScan EV2760
```

In order to reverse engineer you will need to run a windows virtual machine with Eizo's software running and some packet
sniffer such as Wireshark with USBPcap/usbmon.

Disclaimer
----------
This is experimental software and is neither endorsed nor supported by Eizo Corp.

It is provided in the hope that it will be useful and comes with absolutely no warranty.

Use at your own risk.
