ifneq ($(KERNELRELEASE),)
obj-m	:= mynetlink.o
else
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
.PHONY:
clean:
	rm -f *.o *.ko *.o.* *.ko.* *.mod.* Module.* modules.* *.cmd
endif
