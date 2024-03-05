## XDP Based ICMP responder with packet size truncation

Just a fun little project I made in order to learn more about how to write BPF CO-RE (Compile Once - Run Everywhere) / libbpf programs.

`icmpresponder` is a user-space loader that loads the `icmpresponder.bpf` program and attaches it as an XDP program to the specified network interface.  

## Functionality
- Incoming ICMP echo-request packets are intercepted and replied to by the program
- ICMP requests with a payload of over 68 bytes in size are truncated to prevent returning huge replies
- Two types of request rate limiting are implemented:
    - Per SRC IP limiting
    - Limit for all ICMP requests targeting the host
- Other types of ICMP packets are passed through (but still rate limited)
- All other types of traffic are passed through as well

## Usage
Running `make` will compile both the user-space loader and the kernel-space programs. Please note a reasonably modern version of the Linux kernel and `clang` is required, along with `bpftool` and `libbpf`.

```
./icmpresponder attach eth0
./icmpresponder detach eth0
```

Configuration is possible by changing defines in `common.h`

## Testing
```bash
# Pinging the test machine from Mac
$ ping a.b.c.d -s 1400
PING a.b.c.d (a.b.c.d): 1400 data bytes
76 bytes from a.b.c.d: icmp_seq=0 ttl=92 time=10.613 ms
wrong total length 96 instead of 1428
76 bytes from a.b.c.d: icmp_seq=1 ttl=92 time=13.726 ms
wrong total length 96 instead of 1428
76 bytes from a.b.c.d: icmp_seq=2 ttl=92 time=11.824 ms
wrong total length 96 instead of 1428

# Pinging from Ubuntu
$ ping -s 1400 a.b.c.d
PING a.b.c.d (a.b.c.d) 1400(1428) bytes of data.
76 bytes from a.b.c.d: icmp_seq=1 ttl=93 (truncated)
76 bytes from a.b.c.d: icmp_seq=2 ttl=93 (truncated)
76 bytes from a.b.c.d: icmp_seq=3 ttl=93 (truncated)
```

It seems some versions of the `ping` utility treat truncated packets as broken and simply record them as no-answer / loss. The responder sets the outgoing packet TTL to 96, which should at least provide an immediate answer to whether it is actually replying or not - the default TTL across Linux systems is typically 64, hence there will be a change when it is loaded.

```
64 bytes from a.b.c.d: icmp_seq=2 ttl=60 time=10.605 ms
64 bytes from a.b.c.d: icmp_seq=3 ttl=60 time=11.708 ms
64 bytes from a.b.c.d: icmp_seq=4 ttl=92 time=10.750 ms <-- icmpresponder loaded
64 bytes from a.b.c.d: icmp_seq=5 ttl=92 time=11.563 ms
64 bytes from a.b.c.d: icmp_seq=6 ttl=92 time=11.449 ms
```

## Additional recommended learning resources
[BPF CO-RE reference guide by Andrii Nakryiko](https://nakryiko.com/posts/bpf-core-reference-guide/)  
[libbpf API reference](https://libbpf.readthedocs.io/en/latest/api.html)  
[xdp tutorial](https://github.com/xdp-project/xdp-tutorial)  
[NLnetLabs/XDPeriments](https://github.com/NLnetLabs/XDPeriments)

## Disclaimer
This code is intended as an educational resource and may or may not be production ready. No warranty are provided, use at your own risk.
