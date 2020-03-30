#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <inttypes.h>
#include <bpf/bpf_helpers.h>

#include <stdint.h>
#include <stdatomic.h>

#include "csum.h"
#include "common.h"

struct bpf_map_def SEC("maps") interface_map = 
{
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1
};

SEC("xdp_prog")
int xdp_prog_direct(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *ethhdr = data;

    if (ethhdr + 1 > (struct ethhdr *)data_end)
    {
        return XDP_PASS;
    }

    // Check Ethernet protocol and ensure it's IP.
    if (likely(ethhdr->h_proto == htons(ETH_P_IP)))
    {
        struct iphdr *iphdr = data + sizeof(struct ethhdr);

        if (unlikely(iphdr + 1 > (struct iphdr *)data_end))
        {
            return XDP_PASS;
        }

        // Check for IPIP protocol.
        if (likely(iphdr->protocol == IPPROTO_IPIP))
        {
            //bpf_printk("Got IPIP packet! %" PRIu32 " is source address...\n", iphdr->saddr);
            
            struct iphdr *inner_ip = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

            if (inner_ip + 1 > (struct iphdr *)data_end)
            {
                return XDP_ABORTED;
            }

            // Get interface IP from map.
            uint32_t *IP;
            uint32_t key = 0;

            IP = bpf_map_lookup_elem(&interface_map, &key);

            if (!IP)
            {
                return XDP_ABORTED;
            }

            //bpf_printk("%" PRIu32 " => %" PRIu32 "... %" PRIu32 " is IP from stuff.\n", iphdr->saddr, iphdr->daddr, *IP);

            // Check source address and see if it matches interface's IP.
            if (likely(iphdr->saddr == *IP))
            {
                uint32_t anycastAddr = iphdr->saddr;
                //bpf_printk("Found IPIP packet that matches! %" PRIu32 " is Anycast addr.\n", anycastAddr);

                // Remove outer IP header.
                if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct iphdr)))
                {
                    return XDP_DROP;
                }

                //bpf_printk("Got passed removing outer frame\n.");
                
                // Reinitialize values.
                data_end = (void *)(long)ctx->data_end;
                data = (void *)(long)ctx->data;
                inner_ip = data + sizeof(struct ethhdr);

                if (inner_ip + 1 > (struct iphdr *)data_end)
                {
                    return XDP_PASS;
                }

                //bpf_printk("Got passed checking inner IP header\n.");

                // Save previous address.
                uint32_t oldAddr;

                oldAddr = inner_ip->saddr;

                // Change source address to Anycast address.
                inner_ip->saddr = anycastAddr;

                //bpf_printk("Passing IP from %" PRIu32 " to %" PRIu32".\n", inner_ip->saddr, inner_ip->daddr);

                // Recalculate checksum.
                inner_ip->check = csum_diff4(oldAddr, inner_ip->saddr, inner_ip->check);

                // Recalculate transport protocol header.
                switch (inner_ip->protocol)
                {
                    case IPPROTO_UDP:
                    {
                        struct udphdr *udphdr = data + sizeof(struct ethhdr) + (inner_ip->ihl * 4);

                        //bpf_printk("Got to recalculating UDP header.\n");

                        if (udphdr + 1 > (struct udphdr *)data_end)
                        {
                            return XDP_DROP;
                        }

                        //bpf_printk("Got passed recalculating UDP header.\n");

                        udphdr->check = csum_diff4(oldAddr, inner_ip->saddr, udphdr->check);

                        break;
                    }

                    case IPPROTO_TCP:
                    {
                        struct tcphdr *tcphdr = data + sizeof(struct ethhdr) + (inner_ip->ihl * 4);

                        //bpf_printk("Got to recalculating TCP header.\n");

                        if (tcphdr + 1 > (struct tcphdr *)data_end)
                        {
                            return XDP_DROP;
                        }

                        //bpf_printk("Got passed recalculating TCP header.\n");

                        tcphdr->check = csum_diff4(oldAddr, inner_ip->saddr, tcphdr->check);

                        break;
                    }

                    case IPPROTO_ICMP:
                    {
                        struct icmphdr *icmphdr = data + sizeof(struct ethhdr) + (inner_ip->ihl * 4);

                        //bpf_printk("Got to recalculating ICMP header.\n");

                        if (icmphdr + 1 > (struct icmphdr *)data_end)
                        {
                            return XDP_DROP;
                        }

                        //bpf_printk("Got passed recalculating ICMP header.\n");

                        icmphdr->checksum = csum_diff4(oldAddr, inner_ip->saddr, icmphdr->checksum);

                        break;
                    }
                }

                return XDP_TX;
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";