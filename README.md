OpenEizo
========
A small WIP Linux HID device driver to control Eizo EV FlexScan monitors.

Aims
----
To reverse engineer the protocol used to control Eizo EV FlexScan
monitors, with the intention to write an open source Linux
driver as a replacement for Eizo's own proprietary and Windows
only Screen InStyle software.

I'm also taking this opportunity to learn how to write Linux device drivers.

Monitor Support
---------------
Currently the only monitor this software is tested against is the EV2760.
Almost all practical features have been reverse engineered including 
color control, and input selection. 

There are also some hidden settings not exposed in either the OSD or the 
Screen InStyle software such as OSD menu locking and a debug mode.

For the full list of features currently understood see the values in `eizo.h`.

Building and running
--------------------
Make sure you have linux kernel headers installed for your distribution
```shell
git clone https://github.com/markbolhuis/openeizo
cd openeizo
make
sudo insmod eizo
```

Interfacing is done through device files.
```shell
$ cd /sys/bus/hid/devices/<id>/settings
$ cat brightness
160
$ echo 170 > brightness
$ cat brightness
170
```
Since this is early software there is only brightness control.

Contributing
------------
If you have an EV FlexScan monitor then please open an issue
with info on which monitor you have with it's PID so we can 
work towards supporting it.
```shell
$ lsusb | grep 056d
Bus 003 Device 006: ID 056d:4059 EIZO Corp.
```
In order to reverse engineer you will need to run a windows virtual machine 
with Eizo's software running and some packet sniffer such as Wireshark with 
USBPcap/usbmon.

Disclaimer
----------
This is experimental software and is neither endorsed or
supported by Eizo Corp.

It is provided in the hope that it will be useful and comes
with absolutely no warranty.

Use at your own risk.