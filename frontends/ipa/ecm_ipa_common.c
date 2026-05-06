/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#include <linux/version.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/module.h>
#include <linux/inet.h>
#include <net/ipv6.h>
#include <linux/etherdevice.h>
#include <net/sch_generic.h>

/*
 * Debug output levels
 * 0 = OFF
 * 1 = ASSERTS / ERRORS
 * 2 = 1 + WARN
 * 3 = 2 + INFO
 * 4 = 3 + TRACE
 */
#define DEBUG_LEVEL ECM_IPA_COMMON_DEBUG_LEVEL

#include <ipa_api.h>

#include "ecm_types.h"
#include "ecm_db_types.h"
#include "ecm_state.h"
#include "ecm_tracker.h"
#include "ecm_classifier.h"
#include "ecm_front_end_types.h"
#include "ecm_tracker_datagram.h"
#include "ecm_tracker_udp.h"
#include "ecm_tracker_tcp.h"
#include "ecm_db.h"
#include "ecm_interface.h"
#include "ecm_front_end_common.h"
#include "ecm_ipa_ipv4.h"
#include "ecm_ipa_ipv6.h"
#include "ecm_ipa_common.h"
#include "exports/ecm_ipa_common_public.h"
#include "ecm_ipa_ported_ipv4.h"
#include "ecm_ipa_ported_ipv6.h"
#include "ecm_ipa_stats_v4.h"
#include "ecm_ipa_stats_v6.h"




void *log_buf = NULL, *log_buf_low = NULL;

/*
 * Callback object to support IPA frontend interaction with external code
 */
struct ecm_ipa_common_callbacks ecm_ipa_cb;


/*
 * ecm_ipa_feature_check()
 *	Check some specific features for IPA acceleration
 */
bool ecm_ipa_feature_check(struct sk_buff *skb, struct ecm_tracker_ip_header *ip_hdr, bool is_routed)
{
	return ecm_front_end_feature_check(skb, ip_hdr);
}

/*
 * ecm_ipa_common_is_l2_iface_supported()
 *	Check if full offload can be supported in IPA engine for the given L2 interface and interface type
 */
bool ecm_ipa_common_is_l2_iface_supported(ecm_db_iface_type_t ii_type, int cur_heirarchy_index, int first_heirarchy_index)
{
	/*
	 * If extended feature is not supported, we dont need to check interface heirarchy.
	 */
	if (!ipa_is_l2_feature_enabled()) {
		IPAFEDBG_LOW("There is no support for extended features\n");
		return false;
	}

	switch (ii_type) {

	case ECM_DB_IFACE_TYPE_MACVLAN:
		return true;

	default:
		break;
	}

	return false;
}

/*
 * ecm_ipa_ipv4_is_conn_limit_reached()
 *	Connection limit is reached or not ?
 */
bool ecm_ipa_ipv4_is_conn_limit_reached(void)
{

#if !defined(ECM_FRONT_END_CONN_LIMIT_ENABLE)
	return false;
#endif

	if (likely(!((ecm_front_end_is_feature_supported(ECM_FE_FEATURE_CONN_LIMIT)) && ecm_front_end_conn_limit))) {
		return false;
	}

	if ((ecm_ipa_ipv4_pending_accel_count + ecm_ipa_ipv4_accelerated_count) >= ipa_be_ipv4_get_max_accel_conn()) {
		IPAFEDBG("ECM DB connection limit reached with accelerated count:%d, pending accel count:%d, for IPA frontend \
				new flows cannot be accelerated.\n",
				ecm_ipa_ipv4_accelerated_count, ecm_ipa_ipv4_pending_accel_count);
		return true;
	}

	return false;
}

#ifdef ECM_IPV6_ENABLE
/*
 * ecm_ipa_ipv6_is_conn_limit_reached()
 *	Connection limit is reached or not ?
 */
bool ecm_ipa_ipv6_is_conn_limit_reached(void)
{

#if !defined(ECM_FRONT_END_CONN_LIMIT_ENABLE)
	return false;
#endif

	if (likely(!((ecm_front_end_is_feature_supported(ECM_FE_FEATURE_CONN_LIMIT)) && ecm_front_end_conn_limit))) {
		return false;
	}

	if ((ecm_ipa_ipv6_pending_accel_count + ecm_ipa_ipv6_accelerated_count) >= ipa_be_ipv6_get_max_accel_conn()) {
		IPAFEDBG("ECM DB connection limit reached with accelerated count:%d, pending accel count:%d, for IPA frontend \
				new flows cannot be accelerated.\n",
				ecm_ipa_ipv6_accelerated_count, ecm_ipa_ipv6_pending_accel_count);
		return true;
	}

	return false;
}

#endif

/*
 * ecm_ipa_common_init_fe_info()
 *	Initialize common fe info
 */
void ecm_ipa_common_init_fe_info(struct ecm_front_end_common_fe_info *info)
{
	info->from_stats_bitmap = 0;
	info->to_stats_bitmap = 0;
	info->front_end_flags = 0;
}

#ifdef ECM_BRIDGE_VLAN_FILTERING_ENABLE
/*
 * ecm_ipa_common_vlan_filter_set()
 * 	Initialize rule create structure with Bridge VLAN Filter information in connection instance.
 */
bool ecm_ipa_common_vlan_filter_set(struct ecm_db_connection_instance *ci, struct ipa_vlan_filter_rule *vlan_filter_rule, bool is_flow_dir)
{
	uint16_t index;

	/*
	 * Bridge VLAN Filter offload can only be achieved when l2_feature is enabled in IPA.
	 */
	if (!ipa_is_l2_feature_enabled()) {
		IPAFEDBG_LOW("%px: Bridge VLAN filter rule is not programmed as IPA L2 Feature Flag is disabled\n", ci);
		goto no_rule;
	}

	/*
	 * Ingress
	 */
	index = ECM_VLAN_FILTER_RULE_MAX;
	if (is_flow_dir) {
		if (ci->vlan_filter[ECM_VLAN_FILTER_RULE_FLOW_INGRESS1].is_valid) {
			index = ECM_VLAN_FILTER_RULE_FLOW_INGRESS1;
		} else if (ci->vlan_filter[ECM_VLAN_FILTER_RULE_FLOW_EGRESS1].is_valid) {
			index = ECM_VLAN_FILTER_RULE_FLOW_EGRESS1;
		} else {
			IPAFEDBG_LOW("%px: Bridge VLAN filter rule: no valid index is valid at ingress for FLOW Dir\n", ci);
			goto no_rule;
		}
	} else {
		if (ci->vlan_filter[ECM_VLAN_FILTER_RULE_RET_INGRESS1].is_valid) {
			index = ECM_VLAN_FILTER_RULE_RET_INGRESS1;
		} else if (ci->vlan_filter[ECM_VLAN_FILTER_RULE_RET_EGRESS1].is_valid) {
			index = ECM_VLAN_FILTER_RULE_RET_EGRESS1;
		} else {
			IPAFEDBG_LOW("%px: Bridge VLAN filter rule: no valid index is valid at ingress for RET Dir\n", ci);
			goto no_rule;
		}
	}

	if (index != ECM_VLAN_FILTER_RULE_MAX) {
		IPAFEDBG_LOW("Ingress Rule selected: for index %d %s\n", index, ecm_db_connection_vlan_filter_type_strings[index]);
		vlan_filter_rule->ingress_vlan_tag = (
				((ci->vlan_filter[index].vlan_tpid) << 16) |
				ci->vlan_filter[index].vlan_tag);
		vlan_filter_rule->ingress_flags = ci->vlan_filter[index].flags;
	}

	/*
	 * Egress
	 */
	index = ECM_VLAN_FILTER_RULE_MAX;
	if (is_flow_dir) {
		if (ci->vlan_filter[ECM_VLAN_FILTER_RULE_FLOW_EGRESS2].is_valid) {
			index = ECM_VLAN_FILTER_RULE_FLOW_EGRESS2;
		} else if (ci->vlan_filter[ECM_VLAN_FILTER_RULE_FLOW_EGRESS1].is_valid) {
			index = ECM_VLAN_FILTER_RULE_FLOW_EGRESS1;
		} else if (ci->vlan_filter[ECM_VLAN_FILTER_RULE_FLOW_INGRESS2].is_valid) {
			index = ECM_VLAN_FILTER_RULE_FLOW_INGRESS2;
		} else {
			IPAFEDBG_LOW("%px: Bridge VLAN filter rule: no valid index is valid at egress for FLOW Dir\n", ci);
			goto no_rule;
		}
	} else {
		if (ci->vlan_filter[ECM_VLAN_FILTER_RULE_RET_EGRESS2].is_valid) {
			index = ECM_VLAN_FILTER_RULE_RET_EGRESS2;
		} else if (ci->vlan_filter[ECM_VLAN_FILTER_RULE_RET_EGRESS1].is_valid) {
			index = ECM_VLAN_FILTER_RULE_RET_EGRESS1;
		} else if (ci->vlan_filter[ECM_VLAN_FILTER_RULE_RET_INGRESS2].is_valid) {
			index = ECM_VLAN_FILTER_RULE_RET_INGRESS2;
		} else {
			IPAFEDBG_LOW("%px: Bridge VLAN filter rule: no valid index is valid at egress for RET Dir\n", ci);
			goto no_rule;
		}
	}

	if (index != ECM_VLAN_FILTER_RULE_MAX) {
		IPAFEDBG_LOW("Egress Rule selected: for index %d %s", index, ecm_db_connection_vlan_filter_type_strings[index]);
		vlan_filter_rule->egress_vlan_tag = (
				((ci->vlan_filter[index].vlan_tpid) << 16) |
				ci->vlan_filter[index].vlan_tag);
		vlan_filter_rule->egress_flags = ci->vlan_filter[index].flags;
	}

	IPAFEDBG_LOW("Filling ipa rule (is_flow:%d): ingress_vlan_tag: 0x%x : ingress_vlan_flags: %d , egress_vlan_tag: 0x%x : egress_vlan_flags: %d",
			is_flow_dir, vlan_filter_rule->ingress_vlan_tag, vlan_filter_rule->ingress_flags,
			vlan_filter_rule->egress_vlan_tag, vlan_filter_rule->egress_flags);

	return true;

no_rule:
	vlan_filter_rule->ingress_vlan_tag = IPA_VLAN_ID_NOT_CONFIGURED;
	vlan_filter_rule->egress_vlan_tag = IPA_VLAN_ID_NOT_CONFIGURED;
	vlan_filter_rule->ingress_flags = 0;
	return false;
}
#endif

/*
 * ecm_ipa_common_update_rule()
 *	Updates the frontend specifc data.
 *
 * Currently, only updates the mark values of the connection and updates the IPA AE.
 */
void ecm_ipa_common_update_rule(struct ecm_front_end_connection_instance *feci, enum ecm_rule_update_type type, void *arg)
{

	bool status = true;

	switch (type) {
		case ECM_RULE_UPDATE_TYPE_UNI_DI_QOS:
		{
			if (feci->ip_version == 4) {
#if 0
				/* TODO: enable once IPA BE lands ipa_ipv4_msg_init / ecm_ipa_ported_ipv4_unidir_rule_update */
				struct ipa_ipv4_msg *msg_v4;
				struct ecm_cmn_unidir_update_info *update_info = (struct ecm_cmn_unidir_update_info *)arg;

				msg_v4 = (struct ipa_ipv4_msg *)kzalloc(sizeof(struct ipa_ipv4_msg), GFP_ATOMIC | __GFP_NOWARN);
				if (!msg_v4) {
					DEBUG_WARN("%px: no memory for ipa ipv4 message structure instance: %px\n", feci, feci->ci);
					ecm_ipa_stats_v4_inc(ECM_IPA_STATS_V4_EXCEPTION_PORTED, ECM_IPA_STATS_V4_EXCEPTION_PORTED_UNIDIR_UPDATE_NO_MEM);
					return;
				}

				ipa_ipv4_msg_init(msg_v4, IPA_SPECIAL_INTERFACE_IPV4, IPA_TX_UPDATE_RULE_MSG,
					sizeof(struct ipa_rule_update_msg), NULL, NULL);

				status = ecm_ipa_ported_ipv4_unidir_rule_update(feci->ci, update_info->pr, update_info->sender, msg_v4);
				kfree(msg_v4);
#endif
				if (!status) {
					DEBUG_WARN("%px: Uni-directional v4 flow update failed in IPA.\n", feci);
					ecm_ipa_stats_v4_inc(ECM_IPA_STATS_V4_EXCEPTION_PORTED, ECM_IPA_STATS_V4_EXCEPTION_PORTED_UNIDIR_UPDATE_FAIL);
				}
			} else {
#if 0
				/* TODO: enable once IPA BE lands ipa_ipv6_msg_init / ecm_ipa_ported_ipv6_unidir_rule_update */
				struct ipa_ipv6_msg *msg_v6;
				struct ecm_cmn_unidir_update_info *update_info = (struct ecm_cmn_unidir_update_info *)arg;

				msg_v6 = (struct ipa_ipv6_msg *)kzalloc(sizeof(struct ipa_ipv6_msg), GFP_ATOMIC | __GFP_NOWARN);
				if (!msg_v6) {
					DEBUG_WARN("%px: no memory for ipa ipv6 message structure instance: %px\n", feci, feci->ci);
					ecm_ipa_stats_v6_inc(ECM_IPA_STATS_V6_EXCEPTION_PORTED, ECM_IPA_STATS_V6_EXCEPTION_PORTED_UNIDIR_UPDATE_NO_MEM);
					return;
				}

				ipa_ipv6_msg_init(msg_v6, IPA_SPECIAL_INTERFACE_IPV6, IPA_TX_UPDATE_RULE_MSG,
					sizeof(struct ipa_rule_update_msg), NULL, NULL);

				status = ecm_ipa_ported_ipv6_unidir_rule_update(feci->ci, update_info->pr, update_info->sender, msg_v6);
				kfree(msg_v6);
#endif
				if (!status) {
					DEBUG_WARN("%px: Uni-directional v6 flow update failed in IPA.\n", feci);
					ecm_ipa_stats_v6_inc(ECM_IPA_STATS_V6_EXCEPTION_PORTED, ECM_IPA_STATS_V6_EXCEPTION_PORTED_UNIDIR_UPDATE_FAIL);
				}
			}
			break;
		}
		case ECM_RULE_UPDATE_TYPE_CONNMARK:
		{
			struct nf_conn *ct = (struct nf_conn *)arg;
			ip_addr_t src_addr;
			ip_addr_t dest_addr;
			int aci_index;
			int assignment_count;
			struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
			struct ipa_rule_update_msg *update_msg = NULL;

			if (feci->ip_version == 4) {
				struct ipa_ipv4_msg *msg_v4;

				msg_v4 = (struct ipa_ipv4_msg *)kzalloc(sizeof(struct ipa_ipv4_msg), GFP_ATOMIC | __GFP_NOWARN);
				if (!msg_v4) {
					DEBUG_WARN("%px: no memory for ipa ipv4 message structure instance: %px\n", feci, feci->ci);
					ecm_ipa_stats_v4_inc(ECM_IPA_STATS_V4_EXCEPTION_PORTED, ECM_IPA_STATS_V4_EXCEPTION_PORTED_UNIDIR_UPDATE_NO_MEM);
					return;
				}

				/*ipa_ipv4_msg_init(msg_v4, IPA_SPECIAL_INTERFACE_IPV4, IPA_TX_UPDATE_RULE_MSG,
										sizeof(struct ipa_rule_update_msg), NULL, NULL);*/
				update_msg = &msg_v4->msg.rule_update;

				if (ecm_front_end_connection_accel_state_get(feci) != ECM_FRONT_END_ACCELERATION_MODE_ACCEL) {
					DEBUG_WARN("%px: connection is not in accelerated mode\n", feci);
					kfree(msg_v4);
					return;
				}

				/*
				 * Get connection information
				 */
				update_msg->flow_rule_id = ecm_db_connection_serial_get(feci->ci);
				update_msg->type = IPA_CONNECTION_MARK_TYPE_CONNMARK;
				update_msg->protocol = (int32_t)ecm_db_connection_protocol_get(feci->ci);
				update_msg->src_port = htons(ecm_db_connection_port_get(feci->ci, ECM_DB_OBJ_DIR_FROM));
				update_msg->dest_port = htons(ecm_db_connection_port_get(feci->ci, ECM_DB_OBJ_DIR_TO_NAT));
				ecm_db_connection_address_get(feci->ci, ECM_DB_OBJ_DIR_FROM, src_addr);
				ecm_db_connection_address_get(feci->ci, ECM_DB_OBJ_DIR_TO_NAT, dest_addr);
				update_msg->info.connmark.flow_mark = ct->mark;
				update_msg->info.connmark.return_mark = ct->mark;

				DEBUG_INFO("%px: Update the mark value for the IPA connection\n", feci);

				ECM_IP_ADDR_TO_NIN4_ADDR(update_msg->src_ip[0], src_addr);
				ECM_IP_ADDR_TO_NIN4_ADDR(update_msg->dest_ip[0], dest_addr);

				/*if (ipa_ipv4_tx(NULL, msg_v4) != IPA_TX_SUCCESS) {
					DEBUG_WARN("%px: Failed to update mark value in IPA", feci);
					kfree(msg_v4);
					return;
				}*/

				DEBUG_INFO("%px: src_ip: %pI4 dest_ip: %pI4 src_port: %d dest_port: %d protocol: %d\n",
						feci, &update_msg->src_ip[0], &update_msg->dest_ip[0],
						ntohs(update_msg->src_port), ntohs(update_msg->dest_port), update_msg->protocol);

				/*
				 * Get the assigned classifiers and call their update callbacks. If they are interested in this type of
				 * update, they will handle the event.
				 */
				assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(feci->ci, assignments);
				for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
					struct ecm_classifier_instance *aci;
					aci = assignments[aci_index];
					if (aci->update) {
						aci->update(aci, type, ct);
					}
				}
				ecm_db_connection_assignments_release(assignment_count, assignments);
				kfree(msg_v4);
			} else {
				struct ipa_ipv6_msg *msg_v6;

				msg_v6 = (struct ipa_ipv6_msg *)kzalloc(sizeof(struct ipa_ipv6_msg), GFP_ATOMIC | __GFP_NOWARN);
				if (!msg_v6) {
					DEBUG_WARN("%px: no memory for ipa ipv6 message structure instance: %px\n", feci, feci->ci);
					ecm_ipa_stats_v6_inc(ECM_IPA_STATS_V6_EXCEPTION_PORTED, ECM_IPA_STATS_V6_EXCEPTION_PORTED_UNIDIR_UPDATE_NO_MEM);
					return;
				}

				/*ipa_ipv6_msg_init(msg_v6, IPA_SPECIAL_INTERFACE_IPV6, IPA_TX_UPDATE_RULE_MSG,
							sizeof(struct ipa_rule_update_msg), NULL, NULL);*/
				update_msg = &msg_v6->msg.rule_update;

				if (ecm_front_end_connection_accel_state_get(feci) != ECM_FRONT_END_ACCELERATION_MODE_ACCEL) {
					DEBUG_WARN("%px: connection is not in accelerated mode\n", feci);
					kfree(msg_v6);
					return;
				}

				/*
				* Get connection information
				*/
				update_msg->type = IPA_CONNECTION_MARK_TYPE_CONNMARK;
				update_msg->flow_rule_id = ecm_db_connection_serial_get(feci->ci);
				update_msg->protocol = (int32_t)ecm_db_connection_protocol_get(feci->ci);
				update_msg->src_port = htons(ecm_db_connection_port_get(feci->ci, ECM_DB_OBJ_DIR_FROM));
				update_msg->dest_port = htons(ecm_db_connection_port_get(feci->ci, ECM_DB_OBJ_DIR_TO_NAT));
				ecm_db_connection_address_get(feci->ci, ECM_DB_OBJ_DIR_FROM, src_addr);
				ecm_db_connection_address_get(feci->ci, ECM_DB_OBJ_DIR_TO_NAT, dest_addr);
				update_msg->info.connmark.flow_mark = ct->mark;
				update_msg->info.connmark.return_mark = ct->mark;

				DEBUG_INFO("%px: Update the mark value for the IPA connection\n", feci);

				ECM_IP_ADDR_TO_IPA_IPV6_ADDR(update_msg->src_ip, src_addr);
				ECM_IP_ADDR_TO_IPA_IPV6_ADDR(update_msg->dest_ip, dest_addr);

				/*if (ipa_ipv6_tx(NULL, msg_v6) != IPA_TX_SUCCESS) {
					DEBUG_WARN("%px: Failed to update mark value in IPA", feci);
					kfree(msg_v6);
					return;
				}*/

				DEBUG_TRACE("%px: src_ip: " ECM_IP_ADDR_OCTAL_FMT "dest_ip: " ECM_IP_ADDR_OCTAL_FMT
						" src_port: %d dest_port: %d protocol: %d\n",
						feci, ECM_IP_ADDR_TO_OCTAL(src_addr), ECM_IP_ADDR_TO_OCTAL(dest_addr),
						ntohs(update_msg->src_port), ntohs(update_msg->dest_port), update_msg->protocol);

				/*
				 * Get the assigned classifiers and call their update callbacks. If they are interested in this type of
				 * update, they will handle the event.
				 */
				assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(feci->ci, assignments);
				for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
					struct ecm_classifier_instance *aci;
					aci = assignments[aci_index];
					if (aci->update) {
						aci->update(aci, type, ct);
					}
				}
				ecm_db_connection_assignments_release(assignment_count, assignments);
				kfree(msg_v6);
			}
			break;
		}
		case ECM_RULE_UPDATE_TYPE_BI_DI_SAWF_QOS:
		{
			struct ecm_front_end_flowsawf_msg *msg = (struct ecm_front_end_flowsawf_msg *)arg;
			int aci_index;
			int assignment_count;
			struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
			struct ipa_rule_update_msg *update_msg = NULL;
			ipa_tx_status_t ipa_tx_status = IPA_TX_SUCCESS;

			if (feci->ip_version == 4) {
				struct ipa_ipv4_msg *msg_v4;

				msg_v4 = (struct ipa_ipv4_msg *)kzalloc(sizeof(struct ipa_ipv4_msg), GFP_ATOMIC | __GFP_NOWARN);
				if (!msg_v4) {
					DEBUG_WARN("%px: no memory for ipa ipv4 message structure instance: %px\n", feci, feci->ci);
					ecm_ipa_stats_v4_inc(ECM_IPA_STATS_V4_EXCEPTION_PORTED, ECM_IPA_STATS_V4_EXCEPTION_PORTED_UNIDIR_UPDATE_NO_MEM);
					return;
				}

				/*ipa_ipv4_msg_init(msg_v4, IPA_SPECIAL_INTERFACE_IPV4, IPA_TX_UPDATE_RULE_MSG,
										sizeof(struct ipa_rule_update_msg), NULL, NULL);*/
				update_msg = &msg_v4->msg.rule_update;

				DEBUG_INFO("control reached to deprio in update rule \n");

				update_msg->type = IPA_CONNECTION_MARK_TYPE_BIDIR_SAWF_MARK;
				update_msg->info.sawf.flow_mark = msg->flow_mark;
				update_msg->info.sawf.flow_svc_id = msg->flow_service_class_id;

				if (IPA_GET_SAWF_TAG(update_msg->info.sawf.flow_mark) == IPA_SAWF_VALID_TAG ||
						(msg->flags & ECM_FRONT_END_PRIO_UPDATE_FLOW)) {
					update_msg->flags |= IPA_UPDATE_RULE_SAWF_FLOW_VALID;
				}

				update_msg->info.sawf.return_mark = msg->return_mark;
				update_msg->info.sawf.return_svc_id = msg->return_service_class_id;

				if (IPA_GET_SAWF_TAG(update_msg->info.sawf.return_mark) == IPA_SAWF_VALID_TAG
						|| (msg->flags & ECM_FRONT_END_PRIO_UPDATE_RETURN)) {
					update_msg->flags |= IPA_UPDATE_RULE_SAWF_RETURN_VALID;
				}

				update_msg->flow_rule_id = ecm_db_connection_serial_get(feci->ci);
				update_msg->protocol = msg->protocol;
				update_msg->src_port = msg->flow_src_port;
				update_msg->dest_port = msg->flow_dest_port;
				update_msg->src_ip[0] = msg->flow_src_ip[0];
				update_msg->dest_ip[0] = msg->flow_dest_ip[0];

				/*ipa_tx_status = ipa_ipv4_tx(NULL, msg_v4);

				atomic64_set(&feci->unidir_accel_fail_reason, ecm_front_end_set_ae_failure_reason(ipa_tx_status));*/
				if (ipa_tx_status != IPA_TX_SUCCESS) {
					DEBUG_WARN("%px: Failed to update mark value in IPA", feci);
					kfree(msg_v4);
					return;
				}

				DEBUG_TRACE("%px: sawf flow/return mark=0x%08x/0x%08x %pI4:%u -> %pI4:%u protocol=%u\n",
						feci, update_msg->info.sawf.flow_mark, update_msg->info.sawf.return_mark,
						update_msg->src_ip, ntohs(update_msg->src_port),
						update_msg->dest_ip, ntohs(update_msg->dest_port),
						update_msg->protocol);

				/*
				 * Get the assigned classifiers and call their update callbacks. If they are interested in this type of
				 * update, they will handle the event.
				 */
				assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(feci->ci, assignments);
				for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
					struct ecm_classifier_instance *aci;
					aci = assignments[aci_index];
					if (aci->update) {
						aci->update(aci, type, msg);
					}
				}
				ecm_db_connection_assignments_release(assignment_count, assignments);
				kfree(msg_v4);
			} else {
				struct ipa_ipv6_msg *msg_v6;

				msg_v6 = (struct ipa_ipv6_msg *)kzalloc(sizeof(struct ipa_ipv6_msg), GFP_ATOMIC | __GFP_NOWARN);
				if (!msg_v6) {
					DEBUG_WARN("%px: no memory for ipa ipv6 message structure instance: %px\n", feci, feci->ci);
					ecm_ipa_stats_v6_inc(ECM_IPA_STATS_V6_EXCEPTION_PORTED, ECM_IPA_STATS_V6_EXCEPTION_PORTED_UNIDIR_UPDATE_NO_MEM);
					return;
				}

				/*ipa_ipv6_msg_init(msg_v6, IPA_SPECIAL_INTERFACE_IPV6, IPA_TX_UPDATE_RULE_MSG,
							sizeof(struct ipa_rule_update_msg), NULL, NULL);*/
				update_msg = &msg_v6->msg.rule_update;

				DEBUG_INFO("control reached to deprio in update rule \n");

				update_msg->type = IPA_CONNECTION_MARK_TYPE_BIDIR_SAWF_MARK;
				update_msg->info.sawf.flow_mark = msg->flow_mark;
				update_msg->info.sawf.flow_svc_id = msg->flow_service_class_id;

				if (IPA_GET_SAWF_TAG(update_msg->info.sawf.flow_mark) == IPA_SAWF_VALID_TAG
						|| (msg->flags & ECM_FRONT_END_PRIO_UPDATE_FLOW)) {
					update_msg->flags |= IPA_UPDATE_RULE_SAWF_FLOW_VALID;
				}

				update_msg->info.sawf.return_mark = msg->return_mark;
				update_msg->info.sawf.return_svc_id = msg->return_service_class_id;

				if (IPA_GET_SAWF_TAG(update_msg->info.sawf.return_mark) == IPA_SAWF_VALID_TAG
						|| (msg->flags & ECM_FRONT_END_PRIO_UPDATE_RETURN)) {
					update_msg->flags |= IPA_UPDATE_RULE_SAWF_RETURN_VALID;
				}

				update_msg->flow_rule_id = ecm_db_connection_serial_get(feci->ci);
				update_msg->protocol = msg->protocol;
				update_msg->src_port = msg->flow_src_port;
				update_msg->dest_port = msg->flow_dest_port;

				ECM_IP_ADDR_COPY(update_msg->src_ip, msg->flow_src_ip);
				ECM_IP_ADDR_COPY(update_msg->dest_ip, msg->flow_dest_ip);

				/*ipa_tx_status = ipa_ipv6_tx(NULL, msg_v6);

				atomic64_set(&feci->unidir_accel_fail_reason, ecm_front_end_set_ae_failure_reason(ipa_tx_status));*/
				if (ipa_tx_status != IPA_TX_SUCCESS) {
					DEBUG_WARN("%px: Failed to update mark value in IPA", feci);
					kfree(msg_v6);
					return;
				}

				DEBUG_TRACE("%px: sawf flow/return mark=0x%08x/0x%08x %pI6c@%u -> %pI6c@%u protocol=%u\n",
						feci, update_msg->info.sawf.flow_mark, update_msg->info.sawf.return_mark,
						update_msg->src_ip, ntohs(update_msg->src_port),
						update_msg->dest_ip, ntohs(update_msg->dest_port),
						update_msg->protocol);

				/*
				 * Get the assigned classifiers and call their update callbacks. If they are interested in this type of
				 * update, they will handle the event.
				 */
				assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(feci->ci, assignments);
				for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
					struct ecm_classifier_instance *aci;
					aci = assignments[aci_index];
					if (aci->update) {
						aci->update(aci, type, msg);
					}
				}
				ecm_db_connection_assignments_release(assignment_count, assignments);
				kfree(msg_v6);
			}
			break;
		}
		default:
		{
			DEBUG_WARN("%px: unsupported update rule type: %d\n", feci, type);
			break;
		}
	}
		
}

/*
 * ecm_ipa_common_tuple_set()
 *	Sets the IPA common tuple object with the ECM connection rule paramaters.
 *
 * This tuple object will be used by external module to make decision on L2 acceleration.
 */
void ecm_ipa_common_tuple_set(struct ecm_front_end_connection_instance *feci,
			      int32_t from_iface_id, int32_t to_iface_id,
			      struct ecm_ipa_common_tuple *tuple)
{
	ip_addr_t saddr;
	ip_addr_t daddr;

	tuple->protocol = ecm_db_connection_protocol_get(feci->ci);
	tuple->ip_ver = feci->ip_version;

	tuple->src_port = ecm_db_connection_port_get(feci->ci, ECM_DB_OBJ_DIR_FROM);
	tuple->dest_port = ecm_db_connection_port_get(feci->ci, ECM_DB_OBJ_DIR_TO);

	tuple->src_ifindex = from_iface_id;
	tuple->dest_ifindex = to_iface_id;

	ecm_db_connection_address_get(feci->ci, ECM_DB_OBJ_DIR_FROM, saddr);
	ecm_db_connection_address_get(feci->ci, ECM_DB_OBJ_DIR_TO, daddr);

	if (feci->ip_version == 4) {
		ECM_IP_ADDR_TO_NIN4_ADDR(tuple->src_addr[0], saddr);
		ECM_IP_ADDR_TO_NIN4_ADDR(tuple->dest_addr[0], daddr);
	} else {
		ECM_IP_ADDR_TO_IPA_IPV6_ADDR(tuple->src_addr, saddr);
		ECM_IP_ADDR_TO_IPA_IPV6_ADDR(tuple->dest_addr, daddr);
	}
}

/*
 * ecm_ipa_common_defunct_5tuple_connection()
 *	Defunct an IPv4/v6 5-tuple connection.
 */
bool ecm_ipa_common_defunct_5tuple_connection(char *buf)
{
	return ecm_db_connection_defunct_5tuple_buffer(buf);
}
EXPORT_SYMBOL(ecm_ipa_common_defunct_5tuple_connection);

/*
 * ecm_ipa_common_defunct_by_protocol()
 *	Defunct the connections by the protocol type (e.g:TCP, UDP)
 */
void ecm_ipa_common_defunct_by_protocol(int protocol)
{
	ecm_db_connection_defunct_by_protocol(protocol);
}
EXPORT_SYMBOL(ecm_ipa_common_defunct_by_protocol);

/*
 * ecm_ipa_common_defunct_by_port()
 *	Defunct the connections associated with this port in the direction
 * relative to the ECM's connection direction as well.
 *
 * TODO:
 *	For now, all the connections from/to this port number are defuncted.
 *	Directional defunct can be implemented later, but there is a trade of here:
 *	For each connection in the database, the connection's from/to interfaces will
 *	be checked with the wan_name and direction will be determined and then the connection
 *	will be defuncted if there is a match with this port number. This process may be heavier
 *	than defuncting all the connections from/to this port number. So, the direction and  wan_name
 *	are optional for this API for now.
 */
void ecm_ipa_common_defunct_by_port(int port, int direction, char *wan_name)
{
	ecm_db_connection_defunct_by_port(htons(port), ECM_DB_OBJ_DIR_FROM);
	ecm_db_connection_defunct_by_port(htons(port), ECM_DB_OBJ_DIR_TO);
}
EXPORT_SYMBOL(ecm_ipa_common_defunct_by_port);

/*
 * ecm_ipa_common_callbacks_register()
 *	Registers IPA common callbacks.
 */
int ecm_ipa_common_callbacks_register(struct ecm_ipa_common_callbacks *ipa_cb)
{
	if (!ipa_cb || !ipa_cb->l2_accel_check) {
		IPAFEERR("IPA L2 acceleration check callback is NULL\n");
		return -EINVAL;
	}

	rcu_assign_pointer(ecm_ipa_cb.l2_accel_check, ipa_cb->l2_accel_check);
	synchronize_rcu();

	return 0;
}
EXPORT_SYMBOL(ecm_ipa_common_callbacks_register);

/*
 * ecm_ipa_common_callbacks_unregister()
 *	Unregisters IPA common callbacks.
 */
void ecm_ipa_common_callbacks_unregister(void)
{
	rcu_assign_pointer(ecm_ipa_cb.l2_accel_check, NULL);
	synchronize_rcu();
}
EXPORT_SYMBOL(ecm_ipa_common_callbacks_unregister);
