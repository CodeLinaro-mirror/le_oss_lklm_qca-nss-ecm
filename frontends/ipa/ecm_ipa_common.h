/*
 **************************************************************************
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 **************************************************************************
 */

#include "ecm_ipa_common_public.h"
#include <ipa_api.h>

/*
 * Export the callback object for frontend usage.
 */
extern struct ecm_ipa_common_callbacks ecm_ipa_cb;

/*
 * This macro converts ECM ip_addr_t to IPA IPv6 address
 */
#define ECM_IP_ADDR_TO_IPA_IPV6_ADDR(ipa6, ipaddrt) \
	{ \
		ecm_type_check_ae_ipv6(ipa6); \
		ecm_type_check_ecm_ip_addr(ipaddrt); \
		ipa6[0] = htonl(ipaddrt[3]); \
		ipa6[1] = htonl(ipaddrt[2]); \
		ipa6[2] = htonl(ipaddrt[1]); \
		ipa6[3] = htonl(ipaddrt[0]); \
	}

/*
 * This macro converts IPA IPv6 address to ECM ip_addr_t
 */
#define ECM_IPA_IPV6_ADDR_TO_IP_ADDR(ipaddrt, ipa6) \
	{ \
		ecm_type_check_ecm_ip_addr(ipaddrt); \
		ecm_type_check_ae_ipv6(ipa6); \
		ipaddrt[0] = ntohl(ipa6[3]); \
		ipaddrt[1] = ntohl(ipa6[2]); \
		ipaddrt[2] = ntohl(ipa6[1]); \
		ipaddrt[3] = ntohl(ipa6[0]); \
	}

/*
 * ecm_ipa_common_get_interface_number_by_dev()
 *	Returns the acceleration engine interface number based on the net_device object.
 */
static inline int32_t ecm_ipa_common_get_interface_number_by_dev(struct net_device *dev)
{
	return dev->ifindex;
}

/*
 * ecm_ipa_common_get_interface_number_by_dev_type()
 *	Returns the acceleration engine interface number based on the net_device object and type.
 */
static inline int32_t ecm_ipa_common_get_interface_number_by_dev_type(struct net_device *dev, uint32_t type)
{

	return ecm_ipa_common_get_interface_number_by_dev(dev);
}

/*
 * ecm_ipa_common_connection_regenerate()
 *	Re-generate a specific connection in IPA front end
 */
static inline void ecm_ipa_common_connection_regenerate(struct ecm_front_end_connection_instance *feci, struct ecm_db_connection_instance *ci)
{
	/*
	 * Flag the connection as needing re-generation.
	 * Re-generation occurs when we next see traffic OR an acceleration engine sync for this connection.
	 * Refer to front end protocol specific process() functions.
	 */
	ecm_db_connection_regeneration_needed(ci);

	/*
	 * If the connection is accelerated then force deceleration.
	 * Under normal circumstances deceleration would occur on the next sync received,
	 * however, there is a situation where a sync may not occur if, say, a cable has been pulled.
	 * The acceleration engine would see no further traffic to trigger sending a sync and so
	 * re-generation would not occur.
	 * The connection would stall and no-regeneration would happen leaving the connection in bad state.
	 * NOTE: We can just call decelerate() upon the front end - if its not accelerated this will have no effect.
	 */
	feci->decelerate(feci);
}

/*
 * ecm_ipa_common_get_interface_type()
 *	Gets the IPA interface type based on some features.
 *
 * NOTE: There is no type for IPA now. This function is implemented just to
 * use it for the feci callback.
 */
static inline int32_t ecm_ipa_common_get_interface_type(struct ecm_front_end_connection_instance *feci, struct net_device *dev)
{
	/*
	 * By default return 0. IPA driver doesn't have any interface type.
	 */
	return 0;
}

/*
 * ecm_ipa_common_dummy_get_stats_bitmap()
 */
static inline uint32_t ecm_ipa_common_dummy_get_stats_bitmap(struct ecm_front_end_connection_instance *feci, ecm_db_obj_dir_t dir)
{
	return 0;
}

/*
 * ecm_ipa_common_dummy_set_stats_bitmap()
 */
static inline void ecm_ipa_common_dummy_set_stats_bitmap(struct ecm_front_end_connection_instance *feci, ecm_db_obj_dir_t dir, uint8_t bit)
{

}

bool ecm_ipa_ipv4_is_conn_limit_reached(void);
bool ecm_ipa_ipv6_is_conn_limit_reached(void);
bool ecm_ipa_common_is_l2_iface_supported(ecm_db_iface_type_t ii_type, int cur_heirarchy_index, int first_heirarchy_index);

void ecm_ipa_common_init_fe_info(struct ecm_front_end_common_fe_info *info);
void ecm_ipa_common_update_rule(struct ecm_front_end_connection_instance *feci, enum ecm_rule_update_type type, void *arg);
void ecm_ipa_common_tuple_set(struct ecm_front_end_connection_instance *feci,
			      int32_t from_iface_id, int32_t to_iface_id,
			      struct ecm_ipa_common_tuple *tuple);
bool ecm_ipa_feature_check(struct sk_buff *skb, struct ecm_tracker_ip_header *ip_hdr, bool is_routed);
#ifdef ECM_BRIDGE_VLAN_FILTERING_ENABLE
bool ecm_ipa_common_vlan_filter_set(struct ecm_db_connection_instance *ci, struct ipa_vlan_filter_rule *vlan_filter_rule, bool is_flow_dir);
#endif
