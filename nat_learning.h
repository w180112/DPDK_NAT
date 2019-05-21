#include <linux/if_ether.h>

extern void 					nat_tcp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct tcp_hdr *tcphdr, uint32_t *new_port_id);
extern void 					nat_udp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct udp_hdr *udphdr, uint32_t *new_port_id);
extern void 					nat_icmp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct icmp_hdr *icmphdr, uint32_t *new_port_id);
extern uint16_t 				get_checksum(const void *const addr, const size_t bytes);
//extern void 					send_arp(__attribute__((unused)) struct rte_timer *tim, uint32_t *dst_addr);

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

extern addr_table_t 	addr_table[65535];
extern unsigned char 	mac_addr[2][6];
extern uint32_t 		ip_addr[2];
extern struct rte_timer 		arp;
extern struct rte_mempool 		*mbuf_pool;