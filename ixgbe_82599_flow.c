#include <rte_flow.h>
#include <linux/if_ether.h>
#include "nat_learning.h"

#define MAX_PATTERN_NUM		4

struct rte_flow *	generate_flow_ixgbe_82599(uint16_t port_id, uint16_t rx_q, struct rte_flow_error *error);

struct rte_flow *generate_flow_ixgbe_82599(uint16_t port_id, uint16_t rx_q, struct rte_flow_error *error)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_PATTERN_NUM];
	struct rte_flow *flow = NULL;
	struct rte_flow_action_queue queue = { .index = rx_q };
	struct rte_flow_item_eth eth_spec, eth_mask;
	struct rte_flow_item_ipv4 ip_spec, ip_mask;
	int res;

	memset(pattern,0,sizeof(pattern));
	memset(action,0,sizeof(action));

	/*
	 * set the rule attribute.
	 * in this case only ingress packets will be checked.
	 */
	memset(&attr,0,sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	/*
	 * create the action sequence.
	 * one action only,  move packet to queue
	 */

	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &queue;
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

	memset(&ip_spec,0,sizeof(struct rte_flow_item_ipv4));
	memset(&ip_mask,0,sizeof(struct rte_flow_item_ipv4));
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

	memset(pattern,0,sizeof(pattern));
	memset(action,0,sizeof(action));

	/*
	 * set the rule attribute.
	 * in this case only ingress packets will be checked.
	 */
	memset(&attr,0,sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	/*
	 * create the action sequence.
	 * one action only,  move packet to queue
	 */

	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &queue;
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
	memset(&ip_spec,0,sizeof(struct rte_flow_item_ipv4));
	memset(&ip_mask,0,sizeof(struct rte_flow_item_ipv4));
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