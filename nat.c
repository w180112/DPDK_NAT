#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_flow.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_timer.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <linux/if_ether.h>
#include "nat.h"


#define RX_RING_SIZE 		128

#define TX_RING_SIZE 		512

#define NUM_MBUFS 			8191

#define MBUF_CACHE_SIZE 	250

#define BURST_SIZE 			32

#define RING_SIZE 			16384

#define MAX_PATTERN_NUM		4

void 		nat_learning(struct rte_mbuf *single_pkt, struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct icmp_hdr *icmphdr, uint32_t *new_port_id);
uint16_t 	get_checksum(const void *const addr, const size_t bytes);
void 		nat_rule_timer(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) *arg);
void 		send_arp(__attribute__((unused)) struct rte_timer *tim, uint32_t dst_addr);

typedef struct addr_table {
	unsigned char 	mac_addr[6];
	unsigned char 	dst_mac[ETH_ALEN];
	uint32_t		src_ip;
	uint32_t		dst_ip;
	uint16_t		port_id;
	uint32_t		shift;
	int 			is_fill;
	uint8_t			is_alive;
}__rte_cache_aligned addr_table_t;

addr_table_t 			addr_table[65535];

struct rte_timer 		nat,arp;
struct rte_mempool 		*mbuf_pool;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN, },
	.txmode = { .offloads = DEV_TX_OFFLOAD_IPV4_CKSUM ,
								 DEV_TX_OFFLOAD_UDP_CKSUM, }

};

static uint16_t nb_rxd = RX_RING_SIZE;
static uint16_t nb_txd = TX_RING_SIZE;

unsigned char 	mac_addr[2][6];
uint32_t 		ip_addr[2];
//struct rte_ring *rte_ring;

struct rte_flow *generate_flow(uint16_t port_id, uint16_t rx_q_udp, uint16_t rx_q_tcp, struct rte_flow_error *error)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_PATTERN_NUM];
	struct rte_flow *flow = NULL;
	struct rte_flow_action_queue queue[2];// = {{ .index = rx_q_tcp },{ .index = rx_q_udp }};
	struct rte_flow_item_eth eth_spec;
	struct rte_flow_item_eth eth_mask;
	struct rte_flow_item_ipv4 ip_spec;
	struct rte_flow_item_ipv4 ip_mask;
	int res;

	queue[0].index = rx_q_tcp;
	queue[1].index = rx_q_udp;
	/* Below are for detecting PPPoE packet */
	memset(pattern,0,sizeof(pattern));
	memset(action,0,sizeof(action));

	/*
	 * set the rule attribute.
	 * in this case only ingress packets will be checked.
	 */
	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	/*
	 * create the action sequence.
	 * one action only,  move packet to queue
	 */

	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &queue[0];
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/*
	 * set the first level of the pattern (eth).
	 * since in this example we just want to get the
	 * ipv4 we set this level to allow all.
	 */
	memset(&eth_spec,0,sizeof(struct rte_flow_item_eth));
	memset(&eth_mask,0,sizeof(struct rte_flow_item_eth));
	for(int i=0; i<ETH_ALEN; i++) {
		eth_spec.dst.addr_bytes[i] = mac_addr[port_id][i];
		eth_mask.dst.addr_bytes[i] = 0xff;
	}
	eth_spec.type = rte_cpu_to_be_16(0x0800);
	eth_mask.type = 0xffff;
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &eth_spec;
	pattern[0].mask = &eth_mask;

	memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
	ip_spec.hdr.next_proto_id = 0x06;
	ip_mask.hdr.next_proto_id = 0xff;
	
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ip_spec;
	pattern[1].mask = &ip_mask;

	/* the final level must be always type end */
	pattern[2].type = RTE_FLOW_ITEM_TYPE_END;

	res = rte_flow_validate(port_id, &attr, pattern, action, error);
	if (!res)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);

	/* below are for icmp packet from LAN to gateway IP */

	memset(pattern,0,sizeof(pattern));
	memset(action,0,sizeof(action));

	/*
	 * set the rule attribute.
	 * in this case only ingress packets will be checked.
	 */
	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	/*
	 * create the action sequence.
	 * one action only,  move packet to queue
	 */

	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &(queue[1]);
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/*
	 * set the first level of the pattern (eth).
	 * since in this example we just want to get the
	 * ipv4 we set this level to allow all.
	 */
	memset(&eth_spec,0,sizeof(struct rte_flow_item_eth));
	memset(&eth_mask,0,sizeof(struct rte_flow_item_eth));
	for(int i=0; i<ETH_ALEN; i++) {
		eth_spec.dst.addr_bytes[i] = mac_addr[port_id][i];
		eth_mask.dst.addr_bytes[i] = 0xff;
	}
	eth_spec.type = rte_cpu_to_be_16(0x0800);
	eth_mask.type = 0xffff;
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &eth_spec;
	pattern[0].mask = &eth_mask;

	/*
	 * setting the third level of the pattern (ip).
	 * in this example this is the level we care about
	 * so we set it according to the parameters.
	 */
	memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
	ip_spec.hdr.next_proto_id = 0x11;
	ip_mask.hdr.next_proto_id = 0xff;
	
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ip_spec;
	pattern[1].mask = &ip_mask;

	/* the final level must be always type end */
	pattern[2].type = RTE_FLOW_ITEM_TYPE_END;

	res = rte_flow_validate(port_id, &attr, pattern, action, error);
	if (!res)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);

	return flow;
}

static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	struct rte_eth_dev_info dev_info;
	const uint16_t rx_rings = 3, tx_rings = 3;
	int retval;
	uint16_t q;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;
	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;
	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd,&nb_txd);
	printf("nb rx ring size = %x tx ring size = %x\n", nb_rxd, nb_txd);
	if (retval < 0)
		rte_exit(EXIT_FAILURE,"Cannot adjust number of descriptors: err=%d, ""port=%d\n", retval, port);

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;
	//rte_eth_promiscuous_enable(port);
	return 0;
}

int down_icmp_stream(struct rte_mempool *mbuf_pool)
{
	uint64_t total_tx;
	struct rte_mbuf *single_pkt;
	struct rte_mbuf *pkt[BURST_SIZE];
	struct icmp_hdr *icmphdr;
	uint16_t ori_port_id;

	for(;;) {
		total_tx = 0;
		uint16_t nb_rx = rte_eth_rx_burst(1,0,pkt,BURST_SIZE);
		if(nb_rx == 0)
			continue;
		struct ether_hdr * eth_hdr;
		for(int i=0;i<nb_rx;i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct ether_hdr*);
			if (eth_hdr->ether_type == rte_cpu_to_be_16(ARP)) {
				rte_memcpy(eth_hdr->d_addr.addr_bytes,eth_hdr->s_addr.addr_bytes,6);
				rte_memcpy(eth_hdr->s_addr.addr_bytes,mac_addr[1],6);
				struct arp_hdr *arphdr = (struct arp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr));
				if (arphdr->arp_op == rte_cpu_to_be_16(ARP_OP_REQUEST) && arphdr->arp_data.arp_tip == ip_addr[1]) {
					rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes,arphdr->arp_data.arp_sha.addr_bytes,6);
					rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes,mac_addr[1],6);
					arphdr->arp_data.arp_tip = arphdr->arp_data.arp_sip;
					arphdr->arp_data.arp_sip = ip_addr[1];
					arphdr->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
					rte_eth_tx_burst(1,0,&single_pkt,1);
				}
				else if (arphdr->arp_op == rte_cpu_to_be_16(ARP_OP_REPLY)) {
					for(int j=0; j<65536; j++) {
						if (arphdr->arp_data.arp_sip == addr_table[j].dst_ip) {
							if (addr_table[j].is_fill == 0) {
								rte_memcpy(addr_table[j].dst_mac,arphdr->arp_data.arp_sha.addr_bytes,ETH_ALEN);
								addr_table[j].is_fill = 1;
							}
						}
					}
					rte_pktmbuf_free(single_pkt);
				}
				continue;
			}
			struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr));
			single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
			single_pkt->l2_len = sizeof(struct ether_hdr);
			single_pkt->l3_len = sizeof(struct ipv4_hdr);
			ip_hdr->hdr_checksum = 0;
			icmphdr = (struct icmp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
			switch(ip_hdr->next_proto_id) {
				case IPV4_ICMP:
					ori_port_id = rte_be_to_cpu_16(icmphdr->icmp_ident);
					rte_memcpy(eth_hdr->d_addr.addr_bytes,addr_table[ori_port_id].mac_addr,6);
					rte_memcpy(eth_hdr->s_addr.addr_bytes,mac_addr[0],6);
					ip_hdr->dst_addr = addr_table[ori_port_id].src_ip;
					icmphdr->icmp_ident = addr_table[ori_port_id].port_id;
					addr_table[ori_port_id].is_alive = 10;

					icmphdr->icmp_cksum = 0;
					icmphdr->icmp_cksum = get_checksum(icmphdr,single_pkt->data_len - sizeof(struct ipv4_hdr));
					pkt[total_tx++] = single_pkt;
					puts("nat mapping at port 1");
					break;
				default:
					rte_pktmbuf_free(single_pkt);
			}
		}
		if (total_tx > 0) {
			uint16_t nb_tx = rte_eth_tx_burst(0, 0,pkt, total_tx);
			if (unlikely(nb_tx < total_tx)) {
				uint16_t buf;
				for(buf = nb_tx; buf < total_tx; buf++)
					rte_pktmbuf_free(pkt[buf]);
			}
		}
	}
	return 0;
}

int down_udp_stream(struct rte_mempool *mbuf_pool)
{
	uint64_t total_tx;
	struct rte_mbuf *single_pkt;
	struct rte_mbuf *pkt[BURST_SIZE];
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udphdr;
	uint16_t ori_port_id;
	uint16_t nb_rx, nb_tx;
	int i;

	for(;;) {
		total_tx = 0;
		nb_rx = rte_eth_rx_burst(1, 1,pkt,BURST_SIZE);
		if(nb_rx == 0) {
			continue;
		}
		for(i=0; i<nb_rx; i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct ether_hdr*);
			ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr));
			single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
			single_pkt->l2_len = sizeof(struct ether_hdr);
			single_pkt->l3_len = sizeof(struct ipv4_hdr);
			ip_hdr->hdr_checksum = 0;
			udphdr = (struct udp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
			ori_port_id = rte_be_to_cpu_16(udphdr->dst_port);
			rte_memcpy(eth_hdr->d_addr.addr_bytes,addr_table[ori_port_id].mac_addr,6);
			rte_memcpy(eth_hdr->s_addr.addr_bytes,mac_addr[0],6);
			ip_hdr->dst_addr = addr_table[ori_port_id].src_ip;
					//ip_hdr->src_addr = ip_addr[0];
			udphdr->dst_port = addr_table[ori_port_id].port_id;
			addr_table[ori_port_id].is_alive = 10;

			udphdr->dgram_cksum = 0;
			pkt[total_tx++] = single_pkt;
		}
		if (total_tx > 0) {
			nb_tx = rte_eth_tx_burst(0, 1,pkt, total_tx);
			if (unlikely(nb_tx < total_tx)) {
				uint16_t buf;
				for(buf = nb_tx; buf < total_tx; buf++)
					rte_pktmbuf_free(pkt[buf]);
			}
		}
	}
	return 0;
}

int down_tcp_stream(struct rte_mempool *mbuf_pool)
{
	uint64_t total_tx;
	struct rte_mbuf *single_pkt;
	struct rte_mbuf *pkt[BURST_SIZE];
	struct ipv4_hdr *ip_hdr;
	struct ether_hdr *eth_hdr;
	struct tcp_hdr *tcphdr;
	uint16_t ori_port_id;
	int i;
	uint16_t nb_rx, nb_tx;

	for(;;) {
		total_tx = 0;
		nb_rx = rte_eth_rx_burst(1,2,pkt,BURST_SIZE);
		if(nb_rx == 0) {
			continue;
		}
		for(i=0; i<nb_rx; i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct ether_hdr*);
			ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr));
			single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
			single_pkt->l2_len = sizeof(struct ether_hdr);
			single_pkt->l3_len = sizeof(struct ipv4_hdr);
			ip_hdr->hdr_checksum = 0;
			tcphdr = (struct tcp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));				
			ori_port_id = rte_be_to_cpu_16(tcphdr->dst_port);
			rte_memcpy(eth_hdr->d_addr.addr_bytes,addr_table[ori_port_id].mac_addr,6);
			rte_memcpy(eth_hdr->s_addr.addr_bytes,mac_addr[0],6);
			ip_hdr->dst_addr = addr_table[ori_port_id].src_ip;
			//ip_hdr->src_addr = ip_addr[0];
			tcphdr->dst_port = addr_table[ori_port_id].port_id;
			addr_table[ori_port_id].is_alive = 10;

			tcphdr->cksum = 0;
			pkt[total_tx++] = single_pkt;
		}
		if (total_tx > 0) {
			nb_tx = rte_eth_tx_burst(0,2,pkt,total_tx);
			if (unlikely(nb_tx < total_tx)) {
				uint16_t buf;
				for(buf = nb_tx; buf < total_tx; buf++)
					rte_pktmbuf_free(pkt[buf]);
			}
		}
	}
	return 0;
}

int up_icmp_stream(struct rte_mempool *mbuf_pool)
{
	uint64_t total_tx;
	struct rte_mbuf *single_pkt;
	struct rte_mbuf *pkt[BURST_SIZE];
	struct ether_hdr *eth_hdr;
	struct icmp_hdr *icmphdr;
	uint32_t new_port_id;
	int i;
	uint16_t nb_rx, nb_tx;

	for(;;) {
		total_tx = 0;
		nb_rx = rte_eth_rx_burst(0,0,pkt,BURST_SIZE);
		if(nb_rx == 0)
			continue;
		for(i=0; i<nb_rx; i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct ether_hdr*);
			if (eth_hdr->ether_type == rte_cpu_to_be_16(ARP)) {
				rte_memcpy(eth_hdr->d_addr.addr_bytes,eth_hdr->s_addr.addr_bytes,6);
				rte_memcpy(eth_hdr->s_addr.addr_bytes,mac_addr[0],6);
				struct arp_hdr *arphdr = (struct arp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr));
				if (arphdr->arp_op == rte_cpu_to_be_16(ARP_OP_REQUEST) && arphdr->arp_data.arp_tip == ip_addr[0]) {
					rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes,arphdr->arp_data.arp_sha.addr_bytes,6);
					rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes,mac_addr[0],6);
					arphdr->arp_data.arp_tip = arphdr->arp_data.arp_sip;
					arphdr->arp_data.arp_sip = ip_addr[0];
					arphdr->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
					rte_eth_tx_burst(0,0,&single_pkt,1);
				}
				continue;	
			}
			else {
				struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr));
				single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
				single_pkt->l2_len = sizeof(struct ether_hdr);
				single_pkt->l3_len = sizeof(struct ipv4_hdr);
				ip_hdr->hdr_checksum = 0;

				switch (ip_hdr->next_proto_id) {
					case IPV4_ICMP:
					 	icmphdr = (struct icmp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
					 	nat_icmp_learning(single_pkt,eth_hdr,ip_hdr,icmphdr,&new_port_id);
					 	addr_table[new_port_id].is_alive = 10;
					 	if (addr_table[new_port_id].is_fill == 0) {
					 		rte_pktmbuf_free(single_pkt);
					 		break;
					 	}
					 	rte_memcpy(eth_hdr->d_addr.addr_bytes,addr_table[new_port_id].dst_mac,6);
						rte_memcpy(eth_hdr->s_addr.addr_bytes,mac_addr[1],6);
						ip_hdr->src_addr = ip_addr[1];
						icmphdr->icmp_ident = rte_cpu_to_be_16(new_port_id);
						icmphdr->icmp_cksum = 0;
						icmphdr->icmp_cksum = get_checksum(icmphdr,single_pkt->data_len - sizeof(struct ipv4_hdr));
						  
						pkt[total_tx++] = single_pkt;
						puts("nat icmp at port 0");
						break;
					default:
						  rte_pktmbuf_free(single_pkt);
						  puts("recv other packet");
						;
				}
			}
		}
		if (total_tx > 0) {
			nb_tx = rte_eth_tx_burst(1,0,pkt,total_tx);
			if (unlikely(nb_tx < total_tx)) {
				uint16_t buf;
				for(buf=nb_tx; buf<total_tx; buf++)
					rte_pktmbuf_free(pkt[buf]);
			}
		}
	}
	return 0;

}

int up_udp_stream(struct rte_mempool *mbuf_pool)
{
	uint64_t 			total_tx;
	struct rte_mbuf 	*single_pkt;
	struct rte_mbuf 	*pkt[BURST_SIZE];
	struct ether_hdr 	*eth_hdr;
	struct ipv4_hdr 	*ip_hdr;
	struct udp_hdr 		*udphdr;
	uint32_t 			new_port_id;
	int 				i;
	uint16_t 			nb_rx, nb_tx;

	for(;;) {
		total_tx = 0;
		nb_rx = rte_eth_rx_burst(0,1,pkt,BURST_SIZE);
		if(nb_rx == 0)
			continue;
		for(i=0; i<nb_rx; i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct ether_hdr*);
			ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr));
			//printf("src ip = %x, dst ip = %x\n", ip_hdr->src_addr, ip_hdr->dst_addr);
			single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
			single_pkt->l2_len = sizeof(struct ether_hdr);
			single_pkt->l3_len = sizeof(struct ipv4_hdr);
			ip_hdr->hdr_checksum = 0;

			udphdr = (struct udp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
		 	nat_udp_learning(single_pkt,eth_hdr,ip_hdr,udphdr,&new_port_id);
		 	addr_table[new_port_id].is_alive = 10;
			if (addr_table[new_port_id].is_fill == 0) {
				rte_pktmbuf_free(single_pkt);
				break;
			}
		 	rte_memcpy(eth_hdr->d_addr.addr_bytes,addr_table[new_port_id].dst_mac,6);
			rte_memcpy(eth_hdr->s_addr.addr_bytes,mac_addr[1],6);
			ip_hdr->src_addr = ip_addr[1];
			udphdr->src_port = rte_cpu_to_be_16(new_port_id);
			udphdr->dgram_cksum = 0;
							
			pkt[total_tx++] = single_pkt;
		}
		if (total_tx > 0) {
			nb_tx = rte_eth_tx_burst(1,1,pkt,total_tx);
			if (unlikely(nb_tx < total_tx)) {
				uint16_t buf;
				for(buf = nb_tx; buf < total_tx; buf++)
					rte_pktmbuf_free(pkt[buf]);
			}
		}
	}
	return 0;
}

int up_tcp_stream(struct rte_mempool *mbuf_pool)
{
	uint64_t 			total_tx;
	struct rte_mbuf 	*single_pkt;
	struct ether_hdr 	*eth_hdr;
	struct ipv4_hdr 	*ip_hdr;
	struct tcp_hdr 		*tcphdr;
	uint32_t 			new_port_id;
	struct rte_mbuf 	*pkt[BURST_SIZE];
	int 				i;
	uint16_t 			nb_rx, nb_tx;

	for(;;) {
		total_tx = 0;
		nb_rx = rte_eth_rx_burst(0,2,pkt,BURST_SIZE);
		if(nb_rx == 0)
			continue;
		for(i=0;i<nb_rx;i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct ether_hdr*);
			ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr));
				//printf("src ip = %x, dst ip = %x\n", ip_hdr->src_addr, ip_hdr->dst_addr);
			single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
			single_pkt->l2_len = sizeof(struct ether_hdr);
			single_pkt->l3_len = sizeof(struct ipv4_hdr);
			ip_hdr->hdr_checksum = 0;

			tcphdr = (struct tcp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
			nat_tcp_learning(single_pkt,eth_hdr,ip_hdr,tcphdr,&new_port_id);
			addr_table[new_port_id].is_alive = 10;
			if (addr_table[new_port_id].is_fill == 0) {
				rte_pktmbuf_free(single_pkt);
				break;
			}
			rte_memcpy(eth_hdr->d_addr.addr_bytes,addr_table[new_port_id].dst_mac,6);
			rte_memcpy(eth_hdr->s_addr.addr_bytes,mac_addr[1],6);
			ip_hdr->src_addr = ip_addr[1];
			tcphdr->src_port = rte_cpu_to_be_16(new_port_id);
			tcphdr->cksum = 0;
						  
			pkt[total_tx++] = single_pkt;
		}
		if (total_tx > 0) {
			nb_tx = rte_eth_tx_burst(1,2,pkt,total_tx);
			if (unlikely(nb_tx < total_tx)) {
				uint16_t buf;
				for(buf = nb_tx; buf < total_tx; buf++)
					rte_pktmbuf_free(pkt[buf]);
			}
		}
	}
	return 0;

}

void nat_icmp_learning(struct rte_mbuf *single_pkt, struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct icmp_hdr *icmphdr, uint32_t *new_port_id)
{
	*new_port_id = rte_be_to_cpu_16(icmphdr->icmp_ident + (ip_hdr->src_addr) / 10000);
	if (*new_port_id > 0xffff)
		*new_port_id = *new_port_id / 0xffff + 1000;
	for (int j=1000,shift=0; j<65535; j++) {
		if (addr_table[*new_port_id].is_fill == 1) {
			if (addr_table[*new_port_id].src_ip == ip_hdr->src_addr && addr_table[*new_port_id].dst_ip == ip_hdr->dst_addr ) {
				puts("nat rule exist");
				return;
			}
			shift++;
			*new_port_id++;
		}
		else {
			//addr_table[*new_port_id].is_fill = 1;
			addr_table[*new_port_id].shift = shift;
			break;
		}
	}
	rte_timer_reset(&arp,rte_get_timer_hz(),SINGLE,0,send_arp,ip_hdr->dst_addr);
	puts("learning new icmp nat rule");
	send_arp(&arp,ip_hdr->dst_addr);
	rte_memcpy(addr_table[*new_port_id].mac_addr,eth_hdr->s_addr.addr_bytes,6);
	addr_table[*new_port_id].src_ip = ip_hdr->src_addr;
	addr_table[*new_port_id].dst_ip = ip_hdr->dst_addr; 
	addr_table[*new_port_id].port_id = icmphdr->icmp_ident;
}

void nat_udp_learning(struct rte_mbuf *single_pkt, struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct udp_hdr *udphdr, uint32_t *new_port_id)
{
	*new_port_id = rte_be_to_cpu_16(udphdr->src_port + (ip_hdr->src_addr) / 10000);
	if (*new_port_id > 0xffff)
		*new_port_id = *new_port_id / 0xffff + 1000;
	for (int j=1000,shift=0; j<65535; j++) {
		if (addr_table[*new_port_id].is_fill == 1) {
			if (addr_table[*new_port_id].src_ip == ip_hdr->src_addr && addr_table[*new_port_id].dst_ip == ip_hdr->dst_addr ) {
				//puts("nat rule exist");
				return;
			}
			shift++;
			*new_port_id++;
		}
		else {
			//addr_table[*new_port_id].is_fill = 1;
			addr_table[*new_port_id].shift = shift;
			break;
		}
	}
	rte_timer_reset(&arp,rte_get_timer_hz(),SINGLE,0,send_arp,ip_hdr->dst_addr);
	puts("learning new udp nat rule");
	send_arp(&arp,ip_hdr->dst_addr);
	rte_memcpy(addr_table[*new_port_id].mac_addr,eth_hdr->s_addr.addr_bytes,6);
	addr_table[*new_port_id].src_ip = ip_hdr->src_addr;
	addr_table[*new_port_id].dst_ip = ip_hdr->dst_addr; 
	addr_table[*new_port_id].port_id = udphdr->src_port;
}

void nat_tcp_learning(struct rte_mbuf *single_pkt, struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct tcp_hdr *tcphdr, uint32_t *new_port_id)
{
	*new_port_id = rte_be_to_cpu_16(tcphdr->src_port + (ip_hdr->src_addr) / 10000);
	if (*new_port_id > 0xffff)
		*new_port_id = *new_port_id / 0xffff + 1000;
	for (int j=1000,shift=0; j<65535; j++) {
		if (addr_table[*new_port_id].is_fill == 1) {
			if (addr_table[*new_port_id].src_ip == ip_hdr->src_addr && addr_table[*new_port_id].dst_ip == ip_hdr->dst_addr ) {
				//puts("nat rule exist");
				return;
			}
			shift++;
			*new_port_id++;
		}
		else {
			//addr_table[*new_port_id].is_fill = 1;
			addr_table[*new_port_id].shift = shift;
			break;
		}
	}
	puts("learning new tcp nat rule");
	rte_timer_reset(&arp,rte_get_timer_hz(),SINGLE,0,send_arp,ip_hdr->dst_addr);
	send_arp(&arp,ip_hdr->dst_addr);
	rte_memcpy(addr_table[*new_port_id].mac_addr,eth_hdr->s_addr.addr_bytes,6);
	addr_table[*new_port_id].src_ip = ip_hdr->src_addr;
	addr_table[*new_port_id].dst_ip = ip_hdr->dst_addr; 
	addr_table[*new_port_id].port_id = tcphdr->src_port;
}

uint16_t get_checksum(const void *const addr, const size_t bytes)
{
	const uint16_t 	*word;
	uint32_t 		sum;
	uint16_t 		checksum;
	size_t 			nleft;

	assert (addr);
	assert (bytes > 8 - 1);
	word = (const uint16_t *)addr;
	nleft = bytes;
  
	for(sum=0; nleft>1; nleft-=2) {
    	sum += *word;
      	++word;
    }
  	sum += nleft ? *(uint8_t *)word : 0;
  	sum = (sum >> 16) + (sum & 0xffff);
  	sum += (sum >> 16);
  
  	return checksum = ~sum;
}

void send_arp(__attribute__((unused)) struct rte_timer *tim, uint32_t dst_addr)
{
	struct rte_mbuf *pkt;
	struct ether_hdr *eth_hdr;
	struct arp_hdr *arphdr;

	pkt = rte_pktmbuf_alloc(mbuf_pool);
	eth_hdr = rte_pktmbuf_mtod(pkt,struct ether_hdr*);
	for(int i=0; i<ETH_ALEN; i++)
		eth_hdr->d_addr.addr_bytes[i] = 0xff;
	rte_memcpy(eth_hdr->s_addr.addr_bytes,mac_addr[1],ETH_ALEN);
	eth_hdr->ether_type = rte_cpu_to_be_16(ARP);

	arphdr = (struct arp_hdr *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr));
	arphdr->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
	arphdr->arp_pro = rte_cpu_to_be_16(0x0800);
	arphdr->arp_hln = 0x6;
	arphdr->arp_pln = 0x4;
	arphdr->arp_op = rte_cpu_to_be_16(ARP_OP_REQUEST);
	rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes,mac_addr[1],ETH_ALEN);
	arphdr->arp_data.arp_sip = ip_addr[1];
	for(int i=0; i<ETH_ALEN; i++)
		arphdr->arp_data.arp_tha.addr_bytes[i] = 0;
	arphdr->arp_data.arp_tip = dst_addr;

	int pkt_size = sizeof(struct arp_hdr) + sizeof(struct ether_hdr);
	pkt->data_len = pkt_size;
	pkt->pkt_len = pkt_size;

	uint16_t nb_tx = rte_eth_tx_burst(1,0,&pkt,1);
}

void nat_rule_timer(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) *arg)
{
	for(int i=0; i<65535; i++) {
		if (addr_table[i].is_fill == 1) {
			if (addr_table[i].is_alive > 0)
				addr_table[i].is_alive--;
			else
				memset(&(addr_table[i]),0,sizeof(addr_table_t));
		}
	}
}

#define TIMER_RESOLUTION_CYCLES 20000000ULL /* around 10ms at 2 Ghz */

__attribute__((noreturn)) int timer_loop(__attribute__((unused)) void *arg)
{
	uint64_t prev_tsc = 0, cur_tsc, diff_tsc;

	for(;;) {
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
	}
}

uint32_t convert_ip_to_hex(char addr[])
{
    uint32_t 	ip = 0, val;
    char 		*tok, *ptr;

    tok = strtok(addr,".");
    while(tok != NULL) {
        val = strtoul(tok,&ptr,0);
        ip = (ip << 8) + val;
        tok = strtok(NULL,".");
    }
    return ip;
}

int main(int argc, char *argv[])
{
	uint16_t 				portid;
	struct rte_flow 		*flow;
	struct rte_flow_error 	error;

	int ret = rte_eal_init(argc-3,argv+3);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "initlize fail!");

	if (rte_lcore_count() < 7)
		rte_exit(EXIT_FAILURE, "We need at least 7 cores.\n");
	if (rte_eth_dev_count_avail() < 2)
		rte_exit(EXIT_FAILURE, "We need at least 2 eth ports.\n");

	ip_addr[0] = rte_cpu_to_be_32(convert_ip_to_hex(argv[1]));  //LAN : 192.168.1.102
	ip_addr[1] = rte_cpu_to_be_32(convert_ip_to_hex(argv[2]));  //WAN : 192.168.2.112

	argc -= ret;
	argv += ret;

	memset(addr_table,0,65535*sizeof(addr_table_t));
	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",NUM_MBUFS,
		MBUF_CACHE_SIZE,0,RTE_MBUF_DEFAULT_BUF_SIZE,rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
	//rte_ring = rte_ring_create("state_machine",RING_SIZE,rte_socket_id(),0);
	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid) {
		if (port_init(portid,mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",portid);
	}
	rte_eth_macaddr_get(0,(struct ether_addr *)mac_addr[0]);
	rte_eth_macaddr_get(1,(struct ether_addr *)mac_addr[1]);
	flow = generate_flow(0,1,2,&error);
	if (!flow) {
		printf("Flow can't be created %d message: %s\n", error.type, error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in creating flow");
	}
	flow = generate_flow(1,1,2,&error);
	if (!flow) {
		printf("Flow can't be created %d message: %s\n", error.type, error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in creating flow");
	}
	rte_timer_subsystem_init();
	rte_timer_init(&nat);
	rte_timer_init(&arp);

	//unsigned lcore_id;
	//RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        rte_eal_remote_launch(up_icmp_stream,mbuf_pool,1);
        rte_eal_remote_launch(down_icmp_stream,mbuf_pool,2);
        rte_eal_remote_launch(up_udp_stream,mbuf_pool,3);
        rte_eal_remote_launch(down_udp_stream,mbuf_pool,4);
        rte_eal_remote_launch(up_tcp_stream,mbuf_pool,5);
        rte_eal_remote_launch(down_tcp_stream,mbuf_pool,6);
        //rte_eal_remote_launch(ring_buf,mbuf_pool,4);
    //}
    rte_timer_reset(&nat,rte_get_timer_hz(),PERIODICAL,0,(rte_timer_cb_t)nat_rule_timer,NULL);
    timer_loop(NULL);
    rte_eal_mp_wait_lcore();
	
	return 0;
}