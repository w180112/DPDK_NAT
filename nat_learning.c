#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_flow.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_timer.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include "nat_learning.h"
#include <assert.h>

#define ARP 0x0806
#define IPV4_ICMP 1
#define TCP 0x6
#define UDP 0X11

void 					nat_tcp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct tcp_hdr *tcphdr, uint32_t *new_port_id);
void 					nat_udp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct udp_hdr *udphdr, uint32_t *new_port_id);
void 					nat_icmp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct icmp_hdr *icmphdr, uint32_t *new_port_id);
uint16_t 				get_checksum(const void *const addr, const size_t bytes);
void 					send_arp(__attribute__((unused)) struct rte_timer *tim, uint32_t *dst_addr);

addr_table_t 			addr_table[65535];
unsigned char 		mac_addr[2][6];
uint32_t 				ip_addr[2];
struct rte_mempool 		*mbuf_pool;
struct rte_timer 		arp;

void nat_icmp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct icmp_hdr *icmphdr, uint32_t *new_port_id)
{
	*new_port_id = rte_be_to_cpu_16(icmphdr->icmp_ident + (ip_hdr->src_addr) / 10000);
	if (*new_port_id > 0xffff)
		*new_port_id = *new_port_id / 0xffff + 1000;
	for (int j=1000,shift=0; j<65535; j++) {
		if (addr_table[*new_port_id].is_fill == 1) {
			if (addr_table[*new_port_id].src_ip == ip_hdr->src_addr && addr_table[*new_port_id].dst_ip == ip_hdr->dst_addr) {
				puts("nat rule exist");
				return;
			}
			shift++;
			(*new_port_id)++;
		}
		else {
			//addr_table[*new_port_id].is_fill = 1;
			addr_table[*new_port_id].shift = shift;
			break;
		}
	}
	rte_timer_reset(&arp,rte_get_timer_hz(),SINGLE,0,(rte_timer_cb_t)send_arp,&(ip_hdr->dst_addr));
	puts("learning new icmp nat rule");
	send_arp(&arp,&(ip_hdr->dst_addr));
	rte_memcpy(addr_table[*new_port_id].mac_addr,eth_hdr->s_addr.addr_bytes,6);
	addr_table[*new_port_id].src_ip = ip_hdr->src_addr;
	addr_table[*new_port_id].dst_ip = ip_hdr->dst_addr; 
	addr_table[*new_port_id].port_id = icmphdr->icmp_ident;
}

void nat_udp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct udp_hdr *udphdr, uint32_t *new_port_id)
{
	*new_port_id = rte_be_to_cpu_16(udphdr->src_port + (ip_hdr->src_addr) / 10000);
	if (*new_port_id > 0xffff)
		*new_port_id = *new_port_id / 0xffff + 1000;
	for (int j=1000,shift=0; j<65535; j++) {
		if (likely(addr_table[*new_port_id].is_fill == 1)) {
			if (likely(addr_table[*new_port_id].src_ip == ip_hdr->src_addr && addr_table[*new_port_id].dst_ip == ip_hdr->dst_addr)) {
				//puts("nat rule exist");
				return;
			}
			shift++;
			(*new_port_id)++;
		}
		else {
			//addr_table[*new_port_id].is_fill = 1;
			addr_table[*new_port_id].shift = shift;
			break;
		}
	}
	rte_timer_reset(&arp,rte_get_timer_hz(),SINGLE,0,(rte_timer_cb_t)send_arp,&(ip_hdr->dst_addr));
	puts("learning new udp nat rule");
	send_arp(&arp,&(ip_hdr->dst_addr));
	rte_memcpy(addr_table[*new_port_id].mac_addr,eth_hdr->s_addr.addr_bytes,6);
	addr_table[*new_port_id].src_ip = ip_hdr->src_addr;
	addr_table[*new_port_id].dst_ip = ip_hdr->dst_addr; 
	addr_table[*new_port_id].port_id = udphdr->src_port;
}

void nat_tcp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct tcp_hdr *tcphdr, uint32_t *new_port_id)
{
	*new_port_id = rte_be_to_cpu_16(tcphdr->src_port + (ip_hdr->src_addr) / 10000);
	if (*new_port_id > 0xffff)
		*new_port_id = *new_port_id / 0xffff + 1000;
	for (int j=1000,shift=0; j<65535; j++) {
		if (likely(addr_table[*new_port_id].is_fill == 1)) {
			if (likely(addr_table[*new_port_id].src_ip == ip_hdr->src_addr && addr_table[*new_port_id].dst_ip == ip_hdr->dst_addr)) {
				//puts("nat rule exist");
				return;
			}
			shift++;
			(*new_port_id)++;
		}
		else {
			//addr_table[*new_port_id].is_fill = 1;
			addr_table[*new_port_id].shift = shift;
			break;
		}
	}
	puts("learning new tcp nat rule");
	rte_timer_reset(&arp,rte_get_timer_hz(),SINGLE,0,(rte_timer_cb_t)send_arp,&(ip_hdr->dst_addr));
	send_arp(&arp,&(ip_hdr->dst_addr));
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

	assert(addr);
	assert(bytes > 8 - 1);
	word = (const uint16_t *)addr;
	nleft = bytes;
  
	for(sum=0; nleft>1; nleft-=2) {
    	sum += *word;
      	++word;
    }
  	sum += nleft ? *(const uint8_t *)word : 0;
  	sum = (sum >> 16) + (sum & 0xffff);
  	sum += (sum >> 16);
  
  	return checksum = ~sum;
}

void send_arp(__attribute__((unused)) struct rte_timer *tim, uint32_t *dst_addr)
{
	struct rte_mbuf 	*pkt;
	struct ether_hdr 	*eth_hdr;
	struct arp_hdr 		*arphdr;

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
	arphdr->arp_data.arp_tip = *dst_addr;

	int pkt_size = sizeof(struct arp_hdr) + sizeof(struct ether_hdr);
	pkt->data_len = pkt_size;
	pkt->pkt_len = pkt_size;

	rte_eth_tx_burst(1,0,&pkt,1);
}