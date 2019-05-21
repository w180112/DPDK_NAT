#include <linux/if_ether.h>

#define IPV4_UDP 17
#define IPV4_TCP 6
#define IPV4_ICMP 1
#define ARP 0x0806

extern int down_icmp_stream(void);
extern int down_udp_stream(void);
extern int down_tcp_stream(void);
extern int up_icmp_stream(void);
extern int up_udp_stream(void);
extern int up_tcp_stream(void);