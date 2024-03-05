#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <errno.h>
#include <linux/if_link.h>
#include <stdlib.h>
#include <net/if.h>
#include "common.h"

char ifname[64] = {0};

int attach_xdp_prog_interface(int ifindex, struct bpf_object *obj)
{
    LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
    int err = -1;

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_icmp_responder");
    err = libbpf_get_error(obj);
    if (!prog)
    {
        fprintf(stderr, "ERR: Failed to load a BPF program err %d (%d)\n", err, errno);

        return EXIT_FAILURE;
    }

    int prog_fd = bpf_program__fd(prog);

    // Try attaching in DRV mode
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, &opts);
    if (err)
    {
        // Failed, try attaching in SKB mode
        err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, &opts);

        if (err)
        {
            fprintf(stderr, "ERR: Failed to attach XDP to interface err %d (%d)\n", err, errno);
        }
        else
        {
            printf("Attached prog to interface %s (%d) in generic/skb mode\n", ifname, ifindex);
        }

        return EXIT_FAILURE;
    }
    else
    {
        printf("Attached prog to interface %s (%d) in native/drv mode\n", ifname, ifindex);
    }

    return prog_fd;
}

int detach_xdp_interface(int ifindex, __u32 flags, struct bpf_xdp_attach_opts *opts)
{
    int err = bpf_xdp_detach(ifindex, flags, opts);
    if (err)
    {
        fprintf(stderr, "ERR: Failed to detach XDP from interface err %d (%d)\n", err, errno);

        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

struct bpf_object *open_bpf(char *bpf_file)
{
    int err;
    struct bpf_object *obj;

    obj = bpf_object__open_file(bpf_file, NULL);
    err = libbpf_get_error(obj);
    if (err)
    {
        fprintf(stderr, "ERR: Failed to open a BPF file err %d (%d)\n", err, errno);

        if (obj)
            bpf_object__close(obj);
        return 0;
    }

    err = bpf_object__load(obj);
    if (err)
    {
        fprintf(stderr, "ERR: Failed to load a BPF object err %d (%d)\n", err, errno);

        if (obj)
            bpf_object__close(obj);
        return 0;
    }

    return obj;
}

void usage()
{
    fprintf(stderr, "Usage: ./icmpresponder <[a]ttach|[d]etach> <interface>\n");
}

int func_attach(int ifindex)
{
    struct bpf_object *obj = NULL;
    int prog_fd;

    // Raise resource limits in order to have enough space for loading programs
    struct rlimit rlim = {
        .rlim_cur = 512UL << 20, /* 512 MBs */
        .rlim_max = 512UL << 20, /* 512 MBs */
    };

    int err = setrlimit(RLIMIT_MEMLOCK, &rlim);
    if (err)
    {
        fprintf(stderr, "ERR: Failed to configure resource limits\n");
        goto fail_cleanup;
    }

    // Load BPF program
    obj = open_bpf("./icmpresponder.bpf.o");
    if (!obj)
        goto fail_cleanup;

    prog_fd = attach_xdp_prog_interface(ifindex, obj);
    if (!prog_fd)
        goto fail_cleanup;

    bpf_object__close(obj);
    return EXIT_SUCCESS;

fail_cleanup:
    if (obj)
        bpf_object__close(obj);

    return EXIT_FAILURE;
}

int func_detach(int ifindex)
{
    LIBBPF_OPTS(bpf_xdp_attach_opts, opts);

    int err = detach_xdp_interface(ifindex, 0, &opts);

    if (err == 0)
    {
        printf("Detached prog from interface %s (%d)\n", ifname, ifindex);
        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}

int main(int argc, char **argv)
{
    int ifindex = -1;
    int command = 0;

    if (argc != 3)
    {
        usage();
        return EXIT_FAILURE;
    }

    // Parse function
    if (strncmp(argv[1], "attach", 1) == 0)
    {
        command = FUNC_ATTACH;
    }
    else if (strncmp(argv[1], "detach", 1) == 0)
    {
        command = FUNC_DETACH;
    }
    else
    {
        fprintf(stderr, "ERR: Invalid command\n");
        usage();
        return EXIT_FAILURE;
    }

    // Parse interface name
    if (strlen(argv[2]) >= 63)
    {
        fprintf(stderr, "ERR: The supplied interface name cannot be over 63 characters\n");
        usage();
        return EXIT_FAILURE;
    }
    strncpy(ifname, argv[2], 63);

    // Get interface
    ifindex = if_nametoindex(ifname);
    if (ifindex <= 0)
    {
        fprintf(stderr, "ERR: The supplied interface is invalid, cannot get ifindex\n");
        usage();
        return EXIT_FAILURE;
    }

    switch (command)
    {
    case FUNC_ATTACH:
        return func_attach(ifindex);
    case FUNC_DETACH:
        return func_detach(ifindex);
    }

    return EXIT_FAILURE;
}