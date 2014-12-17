CC=gcc

IPTABLES_SRC=/home/iptables-1.4.21
INCLUDE=-I$(IPTABLES_SRC)/include
KERNEL_SRC=/lib/modules/2.6.39/build
MOD=ipt_pool.ko

all: modules libipt_pool.so
modules: $(MOD)
ipt_pool.ko: ipt_pool.c
	$(MAKE) -C $(KERNEL_SRC) SUBDIRS=$(PWD) modules

libipt_pool.so: libipt_pool.c
	$(CC) -I$(INCLUDE) -fPIC -c libipt_pool.c
	ld -shared -o libipt_pool.so libipt_pool.o

clean:
	-rm -fr *.o *.so *.ko .*.cmd *.mod.c *.symvers *.order .tmp_versions

install: all
	cp -rf libipt_pool.so /usr/local/lib/xtables/
	cp -rf $(MOD) /lib/module/`unamr -r`/kernel/net/ipv4/netfilter/
