KDIR ?= /lib/modules/$(shell uname -r)/build
BUILD_DIR ?= build
BUILD_DIR_MAKEFILE ?= $(PWD)/build/Makefile

default: $(BUILD_DIR_MAKEFILE)
	$(MAKE) -C $(KDIR) M=$(PWD)/$(BUILD_DIR) src=$(PWD) modules

$(PWD)/$(BUILD_DIR):
	mkdir -p "$@"

$(BUILD_DIR_MAKEFILE): $(PWD)/$(BUILD_DIR)
	touch "$@"

clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/$(BUILD_DIR) src=$(PWD) clean

load:
	insmod $(shell pwd)/$(BUILD_DIR)/eizo.ko

unload:
	rmmod eizo