/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <linux/seg6.h>
#include <linux/seg6_local.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define V6_V4_HEADER_DIFF 20
#define V6_ADDRESS_SIZE 16

#define assert_len(target, end)   \
  if ((void *)(target + 1) > end) \
    return XDP_DROP;

#define printk(fmt, ...)                       \
({                                           \
	char ____fmt[] = fmt;                      \
	bpf_trace_printk(____fmt, sizeof(____fmt), \
					##__VA_ARGS__);           \
})

static inline unsigned short checksum(unsigned short *buf, int bufsz) {
	unsigned long sum = 0;

	while (bufsz > 1) {
		sum += *buf;
		buf++;
		bufsz -= 2;
	}

	if (bufsz == 1) {
		sum += *(unsigned char *)buf;
	}

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

static inline void l2_swap(struct ethhdr *eth) {
	__u8 tmp[ETH_ALEN];
	memcpy(tmp, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, tmp, ETH_ALEN);
}

__attribute__((__always_inline__)) static inline int process_ipv4hdr(struct xdp_md *ctx, void *nxt_ptr, struct ethhdr *eth) {
	void *data_end = (void *)(long)ctx->data_end;

	struct iphdr *ipv4 = (struct iphdr *)nxt_ptr;
	assert_len(ipv4, data_end);

	if(bpf_xdp_adjust_head(ctx, -(V6_V4_HEADER_DIFF)) != 0) {
		return XDP_PASS;
	}

	void *shift_data = (void *)(long)ctx->data;
	void *shift_data_end = (void *)(long)ctx->data_end;

	struct ethhdr *shift_eth = shift_data;
	assert_len(shift_eth, shift_data_end);

	eth = shift_data + V6_V4_HEADER_DIFF;
	assert_len(eth, shift_data_end);

	memcpy(shift_eth, eth, ETH_HLEN);
	shift_eth->h_proto = bpf_htons(ETH_P_IPV6);
	l2_swap(shift_eth);

	ipv4 = (void *)(eth + 1);
	assert_len(ipv4, shift_data_end);

	struct ipv6hdr *ipv6 = (struct ipv6hdr *)((void *)(long)ctx->data + sizeof(*shift_eth));
	assert_len(ipv6, shift_data_end);

	ipv6->version = 6;
	ipv6->priority = 0;
	ipv6->flow_lbl[0] = 0;
	ipv6->flow_lbl[1] = 0;
	ipv6->flow_lbl[2] = 0;
	ipv6->payload_len = bpf_htons(bpf_ntohs(ipv4->tot_len) - V6_V4_HEADER_DIFF);
	ipv6->nexthdr = ipv4->protocol;
	ipv6->hop_limit = ipv4->ttl;

	__u8 src_u6_addr8[sizeof(ipv6->saddr.in6_u.u6_addr8)] = {
		0x00, 0x64,
		0xff, 0x9b,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		(ipv4->saddr >>  0) & 0xff, (ipv4->saddr >>  8) & 0xff,
		(ipv4->saddr >> 16) & 0xff, (ipv4->saddr >> 24) & 0xff,
	};
	memcpy(ipv6->saddr.in6_u.u6_addr8, src_u6_addr8, sizeof(src_u6_addr8));

	__u8 dst_u6_addr8[sizeof(ipv6->daddr.in6_u.u6_addr8)] = {
		0x00, 0x64,
		0xff, 0x9b,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		(ipv4->daddr >>  0) & 0xff, (ipv4->daddr >>  8) & 0xff,
		(ipv4->daddr >> 16) & 0xff, (ipv4->daddr >> 24) & 0xff,
	};
	memcpy(ipv6->daddr.in6_u.u6_addr8, dst_u6_addr8, sizeof(dst_u6_addr8));

	return XDP_TX;
}


__attribute__((__always_inline__)) static inline int process_ipv6hdr(struct xdp_md *ctx, void *nxt_ptr, struct ethhdr *eth) {
	void *data_end = (void *)(long)ctx->data_end;
	struct ipv6hdr *ipv6 = (struct ipv6hdr *)nxt_ptr;
	assert_len(ipv6, data_end);

	struct ethhdr tmp_eth = {};
	memcpy(&tmp_eth, eth, ETH_HLEN);
	l2_swap(&tmp_eth);
	tmp_eth.h_proto = bpf_htons(ETH_P_IP);

	struct iphdr tmp_ipv4 = {
		.version = 4,
		.ihl = 5,
		.tos = 0,
		.tot_len = bpf_htons(bpf_ntohs(ipv6->payload_len) + V6_V4_HEADER_DIFF),
		.id = 0,
		.frag_off = bpf_htons(0x01 << 14),
		.ttl = ipv6->hop_limit,
		.protocol = ipv6->nexthdr,
		.saddr = ipv6->saddr.in6_u.u6_addr32[3],
		.daddr = ipv6->daddr.in6_u.u6_addr32[3],
		.check = 0
	};
	tmp_ipv4.check = checksum(&tmp_ipv4, sizeof(tmp_ipv4));

	if(bpf_xdp_adjust_head(ctx, V6_V4_HEADER_DIFF) != 0) {
		return XDP_PASS;
	}

	void *shift_data = (void *)(long)ctx->data;
	void *shift_data_end = (void *)(long)ctx->data_end;

	struct ethhdr *shift_eth = shift_data;
	assert_len(shift_eth, shift_data_end);
	memcpy(shift_eth, &tmp_eth, ETH_HLEN);

	struct iphdr *ipv4 = (struct iphdr *)((void *)(long)ctx->data + sizeof(*shift_eth));
	assert_len(ipv4, shift_data_end);
	memcpy(ipv4, &tmp_ipv4, sizeof(tmp_ipv4));

	return XDP_TX;
}

__attribute__((__always_inline__)) static inline int xdp_parse_l2(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	assert_len(eth, data_end);

	if(eth->h_proto == bpf_htons(ETH_P_IP)) {
		return process_ipv4hdr(ctx, eth + 1, eth);
	}

	if(eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		return process_ipv6hdr(ctx, eth + 1, eth);
	}

	return XDP_PASS;
}

SEC("xdp")
__attribute__((__always_inline__)) static inline int nat64(struct xdp_md *ctx) {
	return xdp_parse_l2(ctx);
}
char _license[] SEC("license") = "GPL";
