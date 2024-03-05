default: clean icmpresponder

clean:
	rm -f icmpresponder.bpf.o
	rm -f icmpresponder

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

icmpresponder: vmlinux.h
	clang -Wall -Werror -g -O2 -c -target bpf -o icmpresponder.bpf.o icmpresponder.bpf.c
	clang -Wall -Werror -g -O2 -std=c17 -o icmpresponder icmpresponder.c -l:libbpf.a -lz -lelf