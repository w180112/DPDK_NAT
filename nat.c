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
#include <rte_version.h>
#include <rte_bus_pci.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <linux/if_ether.h>
#include <linux/ethtool.h>
#include "nat.h"
#include "ethtool.h"
#include "mlx5_nat.h"
#include "mlx5_flow.h"
#include "ixgbe_82599_nat.h"
#include "ixgbe_82599_flow.h"
#include "nat_learning.h"
#include "others_nat.h"

#define RX_RING_SIZE 		128
#define TX_RING_SIZE 		512
#define NUM_MBUFS 			8191
#define MBUF_CACHE_SIZE 	250
#define RING_SIZE 			16384

#define IPV4_UDP 				17
#define IPV4_TCP 				6
#define IPV4_ICMP 			1
#define ARP 					0x0806

uint32_t 							convert_ip_to_hex(char addr[]);
static void 						nat_rule_timer(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) void *arg);
__attribute__((noreturn)) int 	timer_loop(__attribute__((unused)) void *arg);
void 								vendor_init(void);

typedef struct nic_vendor {
	const char 		*vendor;
	uint8_t			vendor_id;
}nic_vendor_t;

nic_vendor_t 				nic_vendor[3];
struct rte_timer 		nat;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN, },
	.txmode = { .offloads = DEV_TX_OFFLOAD_IPV4_CKSUM,
							DEV_TX_OFFLOAD_UDP_CKSUM, 
							DEV_TX_OFFLOAD_TCP_CKSUM, }
};

static uint16_t nb_rxd = RX_RING_SIZE;
static uint16_t nb_txd = TX_RING_SIZE;
//struct rte_ring *rte_ring;

static inline int port_init(uint16_t port, uint8_t vendor_id, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	struct rte_eth_dev_info dev_info;
	uint16_t rx_rings, tx_rings;
	int retval;
	uint16_t q;

	switch(vendor_id) {
		case VENDOR_MLX5:
			rx_rings = 3;
			tx_rings = 3;
			break;
		case VENDOR_IXGBE_82599:
			rx_rings = 2;
			tx_rings = 2;
			break;
		default:
			rx_rings = 1;
			tx_rings = 1;
	}
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

	/* Allocate and set up 3 RX queue per Ethernet port. */
	for(q=0; q<rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port,q,nb_rxd,rte_eth_dev_socket_id(port),NULL,mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 3 TX queue per Ethernet port. */
	for(q=0; q<tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port,q,nb_txd,rte_eth_dev_socket_id(port),NULL);
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

static void nat_rule_timer(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) void *arg)
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

void vendor_init(void)
{
	nic_vendor[0].vendor = "net_mlx5";
	nic_vendor[0].vendor_id = VENDOR_MLX5;
	nic_vendor[1].vendor = "net_ixgbe";
	nic_vendor[1].vendor_id = VENDOR_IXGBE_82599;
	nic_vendor[2].vendor = "net_others";
	nic_vendor[2].vendor_id = VENDOR_OTHERS;
}

int main(int argc, char *argv[])
{
	uint16_t 				portid;
	struct rte_flow 		*flow;
	struct rte_flow_error 	error;
	struct ethtool_drvinfo 	info;
	uint8_t vendor_id = VENDOR_OTHERS;

	int ret = rte_eal_init(argc-3,argv+3);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "initlize fail!");

	if (rte_eth_dev_count_avail() < 2)
		rte_exit(EXIT_FAILURE, "We need at least 2 eth ports.\n");

	ip_addr[0] = rte_cpu_to_be_32(convert_ip_to_hex(argv[1]));  //LAN : 192.168.1.102
	ip_addr[1] = rte_cpu_to_be_32(convert_ip_to_hex(argv[2]));  //WAN : 192.168.2.112
	vendor_init();

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
		memset(&info, 0, sizeof(info));
		if (rte_ethtool_get_drvinfo(portid,&info)) {
			printf("Error getting info for port %i\n", portid);
			return -1;
		}
		printf("Port %i driver: %s (ver: %s)\n", portid, info.driver, info.version);
		printf("firmware-version: %s\n", info.fw_version);
		printf("bus-info: %s\n", info.bus_info);
		for(int i=0; i<3; i++) {
			if (strcmp((const char *)(info.driver),nic_vendor[i].vendor) == 0) {
				if (port_init(portid,nic_vendor[i].vendor_id,mbuf_pool) != 0)
					rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",portid);
				vendor_id = nic_vendor[i].vendor_id;
				break;
			}
			if (i == 2) {
				if (port_init(portid,vendor_id,mbuf_pool) != 0)
					rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",portid);
			}
		}
	}

	rte_eth_macaddr_get(0,(struct ether_addr *)mac_addr[0]);
	rte_eth_macaddr_get(1,(struct ether_addr *)mac_addr[1]);

	rte_timer_subsystem_init();
	rte_timer_init(&nat);
	rte_timer_init(&arp);

	switch(vendor_id) {
		case VENDOR_MLX5:
			if (rte_lcore_count() < 7)
				rte_exit(EXIT_FAILURE, "We need at least 7 cores.\n");
			flow = generate_flow_mlx5(0,1,2,&error);
			if (!flow) {
				printf("Flow can't be created %d message: %s\n", error.type, error.message ? error.message : "(no stated reason)");
				rte_exit(EXIT_FAILURE, "error in creating flow");
			}
			flow = generate_flow_mlx5(1,1,2,&error);
			if (!flow) {
				printf("Flow can't be created %d message: %s\n", error.type, error.message ? error.message : "(no stated reason)");
				rte_exit(EXIT_FAILURE, "error in creating flow");
			}
			rte_eal_remote_launch((lcore_function_t *)up_icmp_stream_mlx5,NULL,1);
        	rte_eal_remote_launch((lcore_function_t *)down_icmp_stream_mlx5,NULL,2);
        	rte_eal_remote_launch((lcore_function_t *)up_udp_stream_mlx5,NULL,3);
        	rte_eal_remote_launch((lcore_function_t *)down_udp_stream_mlx5,NULL,4);
        	rte_eal_remote_launch((lcore_function_t *)up_tcp_stream_mlx5,NULL,5);
        	rte_eal_remote_launch((lcore_function_t *)down_tcp_stream_mlx5,NULL,6);
        	break;
		case VENDOR_IXGBE_82599:
			if (rte_lcore_count() < 5)
				rte_exit(EXIT_FAILURE, "We need at least 5 cores.\n");
			flow = generate_flow_ixgbe_82599(0,1,&error);
			if (!flow) {
				printf("Flow can't be created %d message: %s\n", error.type, error.message ? error.message : "(no stated reason)");
				rte_exit(EXIT_FAILURE, "error in creating flow");
			}
			flow = generate_flow_ixgbe_82599(1,1,&error);
			if (!flow) {
				printf("Flow can't be created %d message: %s\n", error.type, error.message ? error.message : "(no stated reason)");
				rte_exit(EXIT_FAILURE, "error in creating flow");
			}
			rte_eal_remote_launch((lcore_function_t *)up_icmp_stream_ixgbe_82599,NULL,1);
        	rte_eal_remote_launch((lcore_function_t *)down_icmp_stream_ixgbe_82599,NULL,2);
        	rte_eal_remote_launch((lcore_function_t *)up_udp_tcp_stream_ixgbe_82599,NULL,3);
        	rte_eal_remote_launch((lcore_function_t *)down_udp_tcp_stream_ixgbe_82599,NULL,4);
			break;
		default:
			rte_eal_remote_launch((lcore_function_t *)up_stream_others,NULL,1);
        	rte_eal_remote_launch((lcore_function_t *)down_stream_others,NULL,2);
	}

	//unsigned lcore_id;
	//RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        
        //rte_eal_remote_launch(ring_buf,mbuf_pool,4);
    //}
    rte_timer_reset(&nat,rte_get_timer_hz(),PERIODICAL,0,(rte_timer_cb_t)nat_rule_timer,NULL);
    timer_loop(NULL);
    rte_eal_mp_wait_lcore();
	
	return 0;
}