#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct session_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

struct session_stats {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;
    __u16 assigned_interface;
    __u8 connection_state;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct session_key);
    __type(value, struct session_stats);
    __uint(max_entries, 65536);
} session_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 16);
} interface_stats SEC(".maps");

static inline int parse_packet(void *data, void *data_end, struct session_key *key) {
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return -1;
    
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;
    
    key->src_ip = ip->saddr;
    key->dst_ip = ip->daddr;
    key->protocol = ip->protocol;
    
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return -1;
        key->src_port = tcp->source;
        key->dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return -1;
        key->src_port = udp->source;
        key->dst_port = udp->dest;
    } else {
        key->src_port = 0;
        key->dst_port = 0;
    }
    
    return 0;
}

SEC("xdp_session_lb")
int session_load_balancer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct session_key key;
    
    if (parse_packet(data, data_end, &key) < 0)
        return XDP_PASS;
    
    struct session_stats *stats = bpf_map_lookup_elem(&session_map, &key);
    
    if (stats) {
        // Existing session
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, data_end - data);
        stats->last_seen = bpf_ktime_get_ns();
        
        // Update interface stats
        __u32 iface_key = stats->assigned_interface;
        __u64 *iface_packets = bpf_map_lookup_elem(&interface_stats, &iface_key);
        if (iface_packets)
            __sync_fetch_and_add(iface_packets, 1);
        
        return bpf_redirect(stats->assigned_interface, 0);
    } else {
        // New session - simple hash-based assignment
        __u32 hash = key.src_ip ^ key.dst_ip ^ key.src_port ^ key.dst_port;
        __u16 target_interface = hash % 4; // Assume 4 interfaces
        
        struct session_stats new_stats = {
            .packets = 1,
            .bytes = data_end - data,
            .last_seen = bpf_ktime_get_ns(),
            .assigned_interface = target_interface,
            .connection_state = 1
        };
        
        bpf_map_update_elem(&session_map, &key, &new_stats, BPF_NOEXIST);
        
        // Update interface stats
        __u32 iface_key = target_interface;
        __u64 *iface_packets = bpf_map_lookup_elem(&interface_stats, &iface_key);
        if (iface_packets)
            __sync_fetch_and_add(iface_packets, 1);
        
        return bpf_redirect(target_interface, 0);
    }
}

char _license[] SEC("license") = "GPL";
