#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/types.h>

#include <stddef.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_ALLOWED_REQUESTS_PER_MINUTE 10

struct element {
    int val;
    int ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);
    __type(value, struct element*);
} map SEC(".maps");

struct packet {
    struct xdp_md* ctx;
    struct ethhdr* ether;
    struct  iphdr* ip;
    struct udphdr* udp;
};

int process_udp53(struct packet* pkt) {
    struct element* elem = bpf_map_lookup_elem(&map, &pkt->ip->daddr);

    int ts = ((bpf_ktime_get_ns() / 1000000000) / 60);

    if (elem) {
        if (elem->ts < ts) {
            elem->ts = ts;
            elem->val = 1;
        } else {
            elem->val++;
        }

        if (elem->val > MAX_ALLOWED_REQUESTS_PER_MINUTE) return XDP_DROP;
    } else {
        struct element new_element;

        new_element.val = 0;
        new_element.ts  = ts;

        bpf_map_update_elem(&map, &pkt->ip->daddr, &new_element, BPF_NOEXIST);
    }

    return XDP_PASS;
}

int process_udp(struct packet* pkt) {
    if (bpf_ntohs(pkt->udp->dest) != 53) return XDP_PASS;

    return process_udp53(pkt);
}

int process_ip(struct packet* pkt) {
    if (pkt->ip->protocol != IPPROTO_UDP) return XDP_PASS;

    pkt->udp = (struct udphdr*)(pkt->ip + 1);

    if ((size_t)(pkt->udp + 1) > (size_t)pkt->ctx->data_end) return XDP_DROP;

    return process_udp(pkt);
}

int process_ether(struct packet* pkt) {
    if (pkt->ether->h_proto != bpf_ntohs(ETH_P_IP)) return XDP_PASS;

    pkt->ip = (struct iphdr*)(pkt->ether + 1);

    if ((size_t)(pkt->ip + 1) > (size_t)pkt->ctx->data_end) return XDP_DROP;

    return process_ip(pkt);
}

int process_packet(struct packet* pkt) {
    pkt->ether = (struct ethhdr*)(size_t)pkt->ctx->data;

    if ((size_t)(pkt->ether + 1) > (size_t)pkt->ctx->data_end) return XDP_PASS;

    return process_ether(pkt);
}

SEC("prog")
int xdp_main(struct xdp_md* ctx) {
    struct packet pkt;
    pkt.ctx = ctx;

    return process_packet(&pkt);
}

char _license[] SEC("license") = "GPL";
