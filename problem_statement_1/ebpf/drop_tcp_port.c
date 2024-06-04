#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#define TYPE_ENTER 1
#define TYPE_DROP 2
#define TYPE_PASS 3

// Define a structure for tracing events
struct perf_trace_event {
    __u64 timestamp;           // Event timestamp
    __u32 processing_time_ns;  // Processing time in nanoseconds
    __u8 type;                 // Type of the event (enter, drop, pass)
};

// Define a BPF map to hold the port number we are interested in
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);    // Array map type
    __uint(max_entries, 1);              // Only one entry
    __type(key, __u32);                  // Key type is unsigned 32-bit integer
    __type(value, __u16);                // Value type is unsigned 16-bit integer (port number)
} port_map SEC(".maps");

// Define a BPF map to output trace events to user space
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);  // Perf event array map type
    __uint(max_entries, 1024);                    // Maximum number of entries
} output_map SEC(".maps");

// XDP program entry point
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    // Initialize a trace event with current timestamp and enter type
    struct perf_trace_event e = {};
    e.timestamp = bpf_ktime_get_ns();
    e.type = TYPE_ENTER;
    e.processing_time_ns = 0;
    bpf_perf_event_output(ctx, &output_map, BPF_F_CURRENT_CPU, &e, sizeof(e));

    // Get pointers to the packet data and its end
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // Check if the packet is long enough to contain an Ethernet header
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // Check if the packet is an IP packet
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    // Get the IP header and check if the packet is long enough to contain it
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // Check if the packet is a TCP packet
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    // Get the TCP header and check if the packet is long enough to contain it
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    // Lookup the port number from the map
    __u32 key = 0;
    __u16 *port = bpf_map_lookup_elem(&port_map, &key);
    if (!port) return XDP_PASS;

    // Check if the destination port matches the port we are interested in
    if (tcp->dest == __constant_htons(*port)) {
        // If it matches, drop the packet and record the event
        e.type = TYPE_DROP;
        __u64 ts = bpf_ktime_get_ns();
        e.processing_time_ns = ts - e.timestamp;
        e.timestamp = ts;
        bpf_perf_event_output(ctx, &output_map, BPF_F_CURRENT_CPU, &e, sizeof(e));
        bpf_printk("dropping packet");
        return XDP_DROP;
    }

    // If it doesn't match, pass the packet and record the event
    e.type = TYPE_PASS;
    __u64 ts = bpf_ktime_get_ns();
    e.processing_time_ns = ts - e.timestamp;
    e.timestamp = ts;
    bpf_perf_event_output(ctx, &output_map, BPF_F_CURRENT_CPU, &e, sizeof(e));
    bpf_printk("passing packet");
    return XDP_PASS;
}

// Specify the license for this program
char _license[] SEC("license") = "GPL";
