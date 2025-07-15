/*
 **************************************************************************
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 **************************************************************************
 */

#ifndef __ECM_IPA_STATS_V6_H
#define __ECM_IPA_STATS_V6_H

enum ecm_ipa_stats_v6_exception_multicast_events {
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_ACCEL_NOT_PERMITTED,
    /* Number of IPv6 packets ignored in multicast flow as accel not permitted */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_NO_MEM,
    /* Number of IPv6 packets ignored in multicast flow as msg alloc failed */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_NO_FROM_INTERFACES,
    /* Number of IPv6 packets ignored in multicast flow as no interface in from interface list */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_FROM_IFACE_INVALID_BOTTOM_IFACE,
    /* Number of IPv6 packets ignored in from interface multicast flow as first interface is unknown */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_FROM_IFACE_MACVLAN_NOT_ENABLED,
    /* Number of IPv6 packets ignored in from interface multicast flow as macvlan not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_FROM_IFACE_ONLY_TWO_VLANS_SUPPORTED,
    /* Number of IPv6 packets ignored in from interface multicast flow as multi vlan not supported */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_FROM_IFACE_VLAN_NOT_ENABLED,
    /* Number of IPv6 packets ignored in from interface multicast flow as vlan not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_FROM_IFACE_MORE_THAN_ONE_PPPOE_UNSUPPORTED,
    /* Number of IPv6 packets ignored in from interface multicast flow as multiple PPPOE not supported */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_FROM_IFACE_PPPOE_FLOW_INVALID,
    /* Number of IPv6 packets ignored in from interface multicast flow as PPPOE not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_NO_TO_INTERFACES,
    /* Number of IPv6 packets ignored in multicast flow as no interface in to interface list */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_TO_IFACE_BRIDGE_CASCADE,
    /* Number of IPv6 packets ignored in to interface multicast flow as bridge cascade not possible */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_TO_IFACE_INVALID_IFACE_ID,
    /* Number of IPv6 packets in to interface multicast flow as ipa can handle only one MAC, the outermost */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_TO_IFACE_LAG_ADDITIONAL_IGNORE,
    /* Number of IPv6 packets ignored in to interface multicast flow as these are usually as a result of address propagation */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_TO_IFACE_LAG_NOT_PRESENT,
    /* Number of IPv6 packets ignored in to interface multicast flow as LAG device is not present */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_TO_IFACE_LAG_NOT_MLO,
    /* Number of IPv6 packets ignored in to interface multicast flow as multicast offload supported only for MLO LAG devices */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_TO_IFACE_LAG_NOT_ENABLED,
    /* Number of IPv6 packets ignored in to interface multicast flow as LAG not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_TO_IFACE_MORE_THAN_ONE_PPPOE_UNSUPPORTED,
    /* Number of IPv6 packets ignored in to interface multicast flow as multiple PPPOE not supported */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_TO_IFACE_PPPOE_FLOW_INVALID,
    /* Number of IPv6 packets ignored in to interface multicast flow as PPPOE not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_TO_IFACE_ONLY_TWO_VLANS_SUPPORTED,
    /* Number of IPv6 packets ignored in to interface multicast flow as multi vlan not supported */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_TO_IFACE_VLAN_NOT_ENABLED,
    /* Number of IPv6 packets ignored in to interface multicast flow as vlan not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_REGEN_OCCURRED,
    /* Number of IPv6 packets ignored in multicast flow as connection regen occured */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_TX_FAILED,
    /* Number of IPv6 packets ignored in multicast flow as the ipa_ipv6_tx() failed */
    ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_MAX
};

enum ecm_ipa_stats_v6_exception_ported_events {
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_ACCEL_NOT_PERMITTED,
    /* Number of IPv6 packets ignored in ported flow as accel not permitted */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_NO_MEM,
    /* Number of IPv6 packets ignored in ported flow as msg alloc failed */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_NO_FROM_INTERFACES,
    /* Number of IPv6 packets ignored in ported flow as no interface in from interface list */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_NO_TO_INTERFACES,
    /* Number of IPv6 packets ignored in ported flow as no interface in to interface list */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_INVALID_BOTTOM_IFACE,
    /* Number of IPv6 packets ignored in ported flow as first interface is unknown */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_FROM_IFACE_BRIDGE_CASCADE,
    /* Number of IPv6 packets ignored in from interface ported flow as bridge cascade not possible */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_FROM_IFACE_OVS_BRIDGE_CASCADE,
    /* Number of IPv6 packets ignored in from interface ported flow as ovs bridge cascade not possible */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_FROM_IFACE_OVS_INTERNAL_CASCADE,
    /* Number of IPv6 packets ignored in from interface ported flow as ovs internal port cascade not possible */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_FROM_IFACE_OVS_BRIDGE_UNSUPPORTED,
    /* Number of IPv6 packets ignored in from interface ported flow as ovs bridge not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_FROM_IFACE_MORE_THAN_ONE_PPPOE_UNSUPPORTED,
    /* Number of IPv6 packets ignored in from interface ported flow as multiple PPPOE not supported */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_FROM_IFACE_PPPOE_FLOW_INVALID,
    /* Number of IPv6 ignored in from interface ported flow as PPPOE not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_FROM_IFACE_ONLY_TWO_VLANS_SUPPORTED,
    /* Number of IPv6 packets ignored in from interface ported flow as multi vlan not supported */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_FROM_IFACE_VLAN_NOT_ENABLED,
    /* Number of IPv6 packets ignored in from interface ported flow as vlan not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_FROM_IFACE_MACVLAN_NOT_ENABLED,
    /* Number of IPv6 packets ignored in from interface ported flow as macvlan not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_FROM_IFACE_ONLY_ONE_IPSEC_SUPPORTED,
    /* Number of IPv6 packets ignored in from interface ported flow as multiple ipsec not supported */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_FROM_IFACE_IPSEC_NOT_ENABLED,
    /* Number of IPv6 packets ignored in from interface ported flow as ipsec not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_FROM_IFACE_LAG_NOT_ENABLED,
    /* Number of IPv6 packets ignored in from interface ported flow as lag not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_FROM_IFACE_VXLAN_NOT_ENABLED,
    /* Number of IPv6 packets ignored in from interface ported flow as vxlan not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_FROM_IFACE_TUN6RD_NOT_ENABLED,
    /* Number of IPv6 packets ignored in from interface ported flow as tun6rd not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_TO_IFACE_BRIDGE_CASCADE,
    /* Number of IPv6 packets ignored in to interface ported flow as bridge cascade not possible */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_TO_IFACE_OVS_BRIDGE_CASCADE,
    /* Number of IPv6 packets ignored in to interface ported flow as ovs bridge cascade not possible */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_TO_IFACE_OVS_INTERNAL_CASCADE,
    /* Number of IPv6 packets ignored in to interface ported flow as ovs internal port cascade not possible */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_TO_IFACE_OVS_BRIDGE_UNSUPPORTED,
    /* Number of IPv6 packets ignored in to interface ported flow as ovs bridge not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_TO_IFACE_MORE_THAN_ONE_PPPOE_UNSUPPORTED,
    /* Number of IPv6 packets ignored in to interface ported flow as multiple PPPOE not supported */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_TO_IFACE_PPPOE_FLOW_INVALID,
    /* Number of IPv6 packets ignored in to interface ported flow as PPPOE not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_TO_IFACE_ONLY_TWO_VLANS_SUPPORTED,
    /* Number of IPv6 packets ignored in to interface ported flow as multi vlan not supported */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_TO_IFACE_VLAN_NOT_ENABLED,
    /* Number of IPv6 packets ignored in to interface ported flow as vlan not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_TO_IFACE_MACVLAN_NOT_ENABLED,
    /* Number of IPv6 packets ignored in to interface ported flow as macvlan not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_TO_IFACE_ONLY_ONE_IPSEC_SUPPORTED,
    /* Number of IPv6 packets ignored in to interface ported flow as multiple ipsec not supported */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_TO_IFACE_IPSEC_NOT_ENABLED,
    /* Number of IPv6 packets ignored in to interface ported flow as ipsec not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_TO_IFACE_LAG_NOT_ENABLED,
    /* Number of IPv6 packets ignored in to interface ported flow as lag not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_TO_IFACE_VXLAN_NOT_ENABLED,
    /* Number of IPv6 packets ignored in to interface ported flow as vxlan not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_TO_IFACE_TUN6RD_NOT_ENABLED,
    /* Number of IPv6 packets ignored in to interface ported flow as tun6rd not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_MHT_PORT_FAIL,
    /* Number of IPv6 packets ignored in ported flow as mht feature is enabled */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_REGEN_OCCURRED,
    /* Number of IPv6 packets ignored in ported flow as connection regen occured */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_TX_FAILED,
    /* Number of IPv6 packets ignored in ported flow as the ipa_ipv6_tx() failed */
    ECM_IPA_STATS_V6_EXCEPTION_PORTED_MAX
};

#ifdef ECM_NON_PORTED_SUPPORT_ENABLE
enum ecm_ipa_stats_v6_exception_non_ported_events {
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_ACCEL_NOT_PERMITTED,
    /* Number of IPv6 packets ignored in non-ported flow as accel not permitted */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_NO_MEM,
    /* Number of IPv6 packets ignored in non-ported flow as msg alloc failed */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_NO_FROM_INTERFACES,
    /* Number of IPv6 packets ignored in non-ported flow as no interface in from interface list */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_NO_TO_INTERFACES,
    /* Number of IPv6 packets ignored in non-ported flow as no interface in to interface list */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_INVALID_BOTTOM_IFACE,
    /* Number of IPv6 packets ignored in non-ported flow as first interface is unknown */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_FROM_IFACE_BRIDGE_CASCADE,
    /* Number of IPv6 packets ignored in from interface non-ported flow as bridge cascade not possible */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_FROM_IFACE_OVS_BRIDGE_CASCADE,
    /* Number of IPv6 packets ignored in from interface non-ported flow as ovs bridge cascade not possible */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_FROM_IFACE_OVS_BRIDGE_UNSUPPORTED,
    /* Number of IPv6 packets ignored in from interface non-ported flow as ovs bridge not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_FROM_IFACE_GRETAP_OR_L2TPV3_IFACE_MTU_UNKNOWN,
    /* Number of IPv6 packets ignored in from interface non-ported flow GRE tap interface mtu not available */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_FROM_IFACE_GRETUN_IFACE_MTU_UNKNOWN,
    /* Number of IPv6 packets ignored in from interface non-ported flow GRE tun interface mtu not available */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_FROM_IFACE_MORE_THAN_ONE_PPPOE_UNSUPPORTED,
    /* Number of IPv6 packets ignored in from interface non-ported flow as multiple PPPOE not supported */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_FROM_IFACE_PPPOE_FLOW_INVALID,
    /* Number of IPv6 packets ignored in from interface non-ported flow as PPPOE not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_FROM_IFACE_ONLY_TWO_VLANS_SUPPORTED,
    /* Number of IPv6 packets ignored in from interface non-ported flow as multi vlan not supported */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_FROM_IFACE_VLAN_NOT_ENABLED,
    /* Number of IPv6 packets ignored in from interface non-ported flow as vlan not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_FROM_IFACE_ONLY_ONE_IPSEC_SUPPORTED,
    /* Number of IPv6 packets ignored in from interface non-ported flow as multiple ipsec not supported */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_FROM_IFACE_IPSEC_NOT_ENABLED,
    /* Number of IPv6 packets ignored in from interface non-ported flow as ipsec not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_FROM_IFACE_LAG_NOT_ENABLED,
    /* Number of IPv6 packets ignored in from interface non-ported flow as lag not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_TO_IFACE_BRIDGE_CASCADE,
    /* Number of IPv6 packets ignored in to interface non-ported flow as bridge cascade not possible */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_TO_IFACE_OVS_BRIDGE_CASCADE,
    /* Number of IPv6 packets ignored in to interface non-ported flow as ovs bridge cascade not possible */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_TO_IFACE_OVS_BRIDGE_UNSUPPORTED,
    /* Number of IPv6 packets ignored in to interface non-ported flow as ovs bridge not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_TO_IFACE_MORE_THAN_ONE_PPPOE_UNSUPPORTED,
    /* Number of IPv6 packets ignored in to interface non-ported flow as multiple PPPOE not supported */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_TO_IFACE_PPPOE_FLOW_INVALID,
    /* Number of IPv6 packets ignored in to interface non-ported flow as PPPOE not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_TO_IFACE_ONLY_TWO_VLANS_SUPPORTED,
    /* Number of IPv6 packets ignored in to interface non-ported flow as multi vlan not supported */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_TO_IFACE_VLAN_NOT_ENABLED,
    /* Number of IPv6 packets ignored in to interface non-ported flow as vlan not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_TO_IFACE_ONLY_ONE_IPSEC_SUPPORTED,
    /* Number of IPv6 packets ignored in to interface non-ported flow as multiple ipsec not supported */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_TO_IFACE_IPSEC_NOT_ENABLED,
    /* Number of IPv6 packets ignored in to interface non-ported flow as ipsec not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_TO_IFACE_LAG_NOT_ENABLED,
    /* Number of IPv6 packets ignored in to interface non-ported flow as lag not enabled */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_MHT_PORT_FAIL,
    /* Number of IPv6 packets ignored in non-ported flow as mht feature is enabled or ipa tx failed and revert to decelerated */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_REGEN_OCCURRED,
    /* Number of IPv6 packets ignored in non-ported flow as connection regen occured */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_TX_FAILED,
    /* Number of IPv6 packets ignored in non-ported flow as the ipa_ipv6_tx() failed */
    ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_MAX
};
#endif

typedef enum ecm_ipa_stats_v6_exception_type {
	ECM_IPA_STATS_V6_EXCEPTION_MULTICAST,
	ECM_IPA_STATS_V6_EXCEPTION_PORTED,
	ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED,
	ECM_IPA_STATS_V6_EXCEPTION_MAX
} ecm_ipa_stats_v6_exception_type_t;

struct ecm_ipa_stats_v6 {
	atomic64_t ecm_ipa_stats_v6_exception_multicast[ECM_IPA_STATS_V6_EXCEPTION_MULTICAST_MAX];
	atomic64_t ecm_ipa_stats_v6_exception_ported[ECM_IPA_STATS_V6_EXCEPTION_PORTED_MAX];
#ifdef ECM_NON_PORTED_SUPPORT_ENABLE
	atomic64_t ecm_ipa_stats_v6_exception_non_ported[ECM_IPA_STATS_V6_EXCEPTION_NON_PORTED_MAX];
#endif
};

void ecm_ipa_stats_v6_inc(ecm_ipa_stats_v6_exception_type_t stat_type, int stat_idx);
int ecm_ipa_stats_v6_debugfs_init(struct dentry *dentry);

#endif
