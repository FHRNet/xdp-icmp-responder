// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>   /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_endian.h>    /* bpf_htons etc */
#include "common.h"

char _license[4] SEC("license") = "GPL";

// #define DEBUG_OUTPUT

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATELIMIT_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct ratelimitmap);
} icmp_ip_ratelimit_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, struct ratelimitmap);
} g_ratelimit_map SEC(".maps");

// Swaps destination and source MAC addresses inside an Ethernet header
static __always_inline void swap_src_dst_mac(struct ethhdr *eth)
{
    __u8 h_tmp[ETH_ALEN];

    __builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}

// Fold a checksum
static __always_inline __u16 csum_fold_helper(__u32 csum)
{
    __u32 sum;
    sum = (csum >> 16) + (csum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

// Calculate the checksum difference in between iphdr
static __always_inline __u16 ip_checksum_diff(__u16 seed, struct iphdr *iphdr_new, struct iphdr *iphdr_old)
{
    __u32 csum, size = sizeof(struct iphdr);

    csum = bpf_csum_diff((__be32 *)iphdr_old, size, (__be32 *)iphdr_new, size, seed);
    return csum_fold_helper(csum);
}

// Calculate the checksum difference in between icmphdr
static __always_inline __u16 icmp_checksum_diff(__u16 seed, struct icmphdr *icmphdr_new, struct icmphdr *icmphdr_old)
{
    __u32 csum, size = sizeof(struct icmphdr);

    csum = bpf_csum_diff((__be32 *)icmphdr_old, size, (__be32 *)icmphdr_new, size, seed);
    return csum_fold_helper(csum);
}

static __always_inline short int g_rate_limiter_do_limit(enum g_ratelimiter_types type, __u32 limit_per_frame)
{
    struct ratelimitmap *rlm = bpf_map_lookup_elem(&g_ratelimit_map, &type);

    __u64 btime_nsecs = bpf_ktime_get_boot_ns();
    if ((rlm && (rlm->bucket_time + RATELIMIT_BUCKET_SIZE) < btime_nsecs) || !rlm)
    {
        // Bucket does not exist or is outside of the time window
        struct ratelimitmap rlm = {btime_nsecs, 1};
        bpf_map_update_elem(&g_ratelimit_map, &type, &rlm, BPF_ANY);
        return 0;
    }

    lock_xadd(&rlm->bucket_packets, 1);

    if (rlm->bucket_packets > limit_per_frame)
    {
        return 1;
    }

    return 0;
}

static __always_inline short int icmp_rate_limiter_do_limit(__u32 saddr, __u32 limit_per_frame)
{
    struct ratelimitmap *rlm = bpf_map_lookup_elem(&icmp_ip_ratelimit_map, &saddr);

    __u64 btime_nsecs = bpf_ktime_get_boot_ns();
    if ((rlm && (rlm->bucket_time + RATELIMIT_BUCKET_SIZE) < btime_nsecs) || !rlm)
    {
        // Bucket does not exist or is outside of the time window
        struct ratelimitmap rlm = {btime_nsecs, 1};
        bpf_map_update_elem(&icmp_ip_ratelimit_map, &saddr, &rlm, BPF_ANY);
        return 0;
    }

    lock_xadd(&rlm->bucket_packets, 1);

    if (rlm->bucket_packets > limit_per_frame)
    {
        return 1;
    }

    return 0;
}

static __always_inline int handle_icmp(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph)
{
    void *data_end = (void *)(long)ctx->data_end;

    __u32 iphlen = (iph->ihl * 4);

    struct icmphdr *icmph = (void *)iph + iphlen;

    if ((void *)icmph + sizeof(struct icmphdr) > data_end)
    {
        return XDP_DROP;
    }

    if (g_rate_limiter_do_limit(G_RATELIMIT_TYPE_ICMP, ICMP_G_RATELIMIT))
    {
        return XDP_DROP;
    }

    if (icmp_rate_limiter_do_limit(bpf_ntohl(iph->saddr), ICMP_IP_RATELIMIT))
    {
        return XDP_DROP;
    }

    // Respond to ICMP echo requests
    if (icmph->type == ICMP_ECHO)
    {
        // Flip the packet MAC
        swap_src_dst_mac(eth);

        // Flip the packet IP
        __be32 orig_daddr = iph->daddr;
        iph->daddr = iph->saddr;
        iph->saddr = orig_daddr;

        // Keep the old IP checksum and header and reset the IP checksum
        __u16 iph_checksum_old = iph->check;
        iph->check = 0;
        struct iphdr iph_old = *iph;

        // Keep the old ICMP checksum and header and reset the ICMP checksum
        __u16 icmp_checksum_old = icmph->checksum;
        icmph->checksum = 0;
        struct icmphdr icmph_old = *icmph;

        // Reset the TTL
        iph->ttl = DEFAULT_TTL;

        // Change the type to an ICMP reply
        icmph->type = ICMP_ECHOREPLY;

        // Truncate - if datalen > ICMP_MAXIMUM_DATALEN then truncate
        iphlen = (iph->ihl * 4);
        __s16 to_strip = bpf_ntohs(iph->tot_len) - (ICMP_MAXIMUM_DATALEN + sizeof(struct icmphdr) + iphlen);

        if (to_strip > 0)
        {
            // Reset the TTL
            iph->ttl = DEFAULT_TTL;

            // Set the new IP header size
            iph->tot_len = bpf_htons(ICMP_MAXIMUM_DATALEN + sizeof(struct icmphdr) + iphlen);

            // Recalculate IP checksum
            iph->check = ip_checksum_diff(~iph_checksum_old, iph, &iph_old);

            // Adjust the total length
            if (bpf_xdp_adjust_tail(ctx, -to_strip))
            {
#ifdef DEBUG_OUTPUT
                bpf_trace_printk("Invalid ICMP tail call");
#endif

                // Drop the packet if adjusting fails
                return XDP_DROP;
            }

            // Recheck ethoffset boundaries to make verifier happy
            if (ethoffset < 0 || ethoffset > 32)
            {
                return XDP_DROP;
            }

            // Parse the new IP header
            struct iphdr *iph_n = (void *)(long)ctx->data + ethoffset;

            // Boundary check on IP header
            if ((void *)iph_n + sizeof(*iph_n) > data_end)
            {
                return XDP_DROP;
            }

            // Get the ICMP header again after adjusting the packet length
            struct icmphdr *icmph_n = (void *)iph_n + iphlen;

            // Boundary check on the new packet
            if ((void *)icmph_n + ICMP_MAXIMUM_DATALEN + sizeof(struct icmphdr) > (void *)(long)ctx->data_end)
            {
                return XDP_DROP;
            }

            // Recalculate the ICMP checksum from scratch
            __u32 csum_buf = 0;
            __u16 *csum_icmp_buf = (void *)icmph_n;

            // The checksum field is the 16 bit one's complement of the one's
            // complement sum of all 16 bit words in the header - RFC 791
            for (__u8 i = 0; i < (ICMP_MAXIMUM_DATALEN + sizeof(struct icmphdr)); i += 2)
            {
                csum_buf += *csum_icmp_buf;
                csum_icmp_buf++;
            }
            icmph_n->checksum = csum_fold_helper(csum_buf);

            // Transmit the packet
            return XDP_TX;
        }

        // Recalculate IP checksum
        iph->check = ip_checksum_diff(~iph_checksum_old, iph, &iph_old);

        // Recalculate ICMP checksum
        icmph->checksum = icmp_checksum_diff(~icmp_checksum_old, icmph, &icmph_old);

        // Transmit the packet
        return XDP_TX;
    }

    // Forward everything else
    return XDP_PASS;
}

static __always_inline int handle_ipv4(struct xdp_md *ctx, struct ethhdr *eth)
{
    void *data_end = (void *)(long)ctx->data_end;

    // Parse IP header
    struct iphdr *iph = (void *)eth + ethoffset;

    // Boundary check on IP header
    if ((void *)iph + sizeof(*iph) > data_end)
    {
        // Header does not fit
        return XDP_PASS;
    }

    if (iph->protocol == IPPROTO_ICMP)
    {
        return handle_icmp(ctx, eth, iph);
    }

    return XDP_PASS;
}

SEC("xdp")
int xdp_icmp_responder(struct xdp_md *ctx)
{
    struct ethhdr *eth = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Boundary check on Ethernet header
    if ((void *)eth + sizeof(*eth) > data_end)
    {
        return XDP_PASS;
    }

    // Offset from packet start to the end of the Ethernet header
    ethoffset = sizeof(*eth);
    __u16 eth_type = __bpf_htons(eth->h_proto);

    // De-encap VLANs
    for (short unsigned int i = 0; i < 2; i++)
    {
        if (eth_type == ETH_P_8021Q || eth_type == ETH_P_8021AD)
        {
            struct vlan_hdr *vlan_hdr;

            vlan_hdr = (void *)eth + ethoffset;
            ethoffset += sizeof(*vlan_hdr);

            // Boundary check
            if ((void *)eth + ethoffset > data_end)
            {
                return XDP_PASS;
            }

            eth_type = __bpf_htons(vlan_hdr->h_vlan_encapsulated_proto);
        }
    }

    // Check which L2 protocol we are dealing with
    switch (eth_type)
    {
    case ETH_P_IP: // IPv4
        return handle_ipv4(ctx, eth);
    }

    return XDP_PASS;
}