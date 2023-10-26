CC:= clang
CFLAGS_XDP:= -O2 -g -Wall -target bpf -c 
CFLAGS:= -O2 -g -Wall   
CPU_ARCH:= $(shell uname -m)
IFLAGS:= -I/usr/include/$(CPU_ARCH)-linux-gnu/ -I/usr/local/include/xdp/
CFLAGS+= $(IFLAGS) 
CFLAGS_XDP+= $(IFLAGS)
all:
	$(CC) $(CFLAGS_XDP) xdp_synproxy_kern.c -o xdp_synproxy_kern.bpf.o 
	$(CC) $(CFLAGS) xdp_synproxy.c -o xdp_synproxy -lxdp