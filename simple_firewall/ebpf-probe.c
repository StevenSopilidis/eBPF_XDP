#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <linux/in.h>
#include <bcc/helpers.h>

BPF_ARRAY(packet_count_map, __u64, 1);
BPF_PERF_OUTPUT(debug_events);

// function that drops packet if destination address matches blocked_ip
static int drop_packet_to_destination(struct xdp_md* ctx, __be32 blocked_ip) {
    // extract end of packet
    void* data_end = (void*)(long)ctx->data_end;

    // extract the start of the packet
    void* data = (void*)(long)ctx->data;

    // pointer to ethernet header of packet
    struct ethhdr* eth = data;

    // if eth header extends beyond end of packet pass
    if ((void*)(eth+1) > data_end)
        return XDP_PASS;

    // if protocol used is not IP pass packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // get pointer to ip header
    struct iphdr* iphdr = (struct iphdr*)(data + ETH_HLEN);

    // if IP header extends beyond end of packet data pass packet
    if ((void*)(iphdr + 1) > data_end)
        return XDP_PASS;

    if (iphdr->saddr == blocked_ip) {
        __be32 saddr_copy = iphdr->saddr;
        debug_events.perf_submit(ctx, &saddr_copy, sizeof(saddr_copy));

        return XDP_DROP;
    }

    return XDP_PASS; 
}


int xdp_packet_counter(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *counter;

    counter = packet_count_map.lookup(&key);
    if (!counter)
        return XDP_ABORTED;

    __sync_fetch_and_add(counter, 1);

    // call drop_packet_to_destination with the desired destination ip (8:8:8:8)
    __be32 blocked_ip = (8 << 24)|(8 << 16)|(8 << 8)|8;
    return drop_packet_to_destination(ctx, blocked_ip);
}