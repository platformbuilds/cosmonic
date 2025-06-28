#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_VNICS 16

struct vnic_key {
    __u32 ip_addr;
    __u16 vlan_id;
};

struct vnic_info {
    __u32 vnic_id;
    __u32 active_port;
    __u64 packet_count;
    __u64 byte_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct vnic_key);
    __type(value, struct vnic_info);
    __uint(max_entries, MAX_VNICS);
} vnic_map SEC(".maps");

SEC("xdp_vnic_filter")
int vnic_packet_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;
    
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_ABORTED;
    
    struct vnic_key key = { .ip_addr = ip->daddr, .vlan_id = 0 };
    struct vnic_info *vnic = bpf_map_lookup_elem(&vnic_map, &key);
    
    if (!vnic)
        return XDP_PASS;
    
    __sync_fetch_and_add(&vnic->packet_count, 1);
    __sync_fetch_and_add(&vnic->byte_count, data_end - data);
    
    return bpf_redirect(vnic->active_port, 0);
}

char _license[] SEC("license") = "GPL";
