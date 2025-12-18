# Out-of-tree kernel module build for tcp_copa.c
obj-m += tcp_copa.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

MODULE := tcp_copa

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Insert the module (fails if already loaded)
load: all
	sudo insmod $(MODULE).ko

# Remove the module (ok if already removed)
unload:
	-sudo rmmod $(MODULE)

reload:clean unload load

# Convenience: set as current CC
enable:
	sudo sysctl -w net.ipv4.tcp_congestion_control=copa
	sysctl net.ipv4.tcp_congestion_control
	sysctl net.ipv4.tcp_available_congestion_control
