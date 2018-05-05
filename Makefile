ifneq ($(KERNELRELEASE),)
obj-m	:= myhook.o
else
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
.PHONY:
clean:
	rm -f *.o *.ko *.mod.* Module.* modules.*
endif
