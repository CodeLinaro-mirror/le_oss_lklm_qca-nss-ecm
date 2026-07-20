/*
 **************************************************************************
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 **************************************************************************
 */

#ifndef __ECM_IPA_IPV6_H
#define __ECM_IPA_IPV6_H
#include <ipa_api.h>
#include "ecm_ipa_log.h"

extern int ecm_ipa_ipv6_no_action_limit_default;		/* Default no-action limit. */
extern int ecm_ipa_ipv6_driver_fail_limit_default;		/* Default driver fail limit. */
extern int ecm_ipa_ipv6_nack_limit_default;			/* Default nack limit. */
extern int ecm_ipa_ipv6_accelerated_count;			/* Total offloads */
extern int ecm_ipa_ipv6_pending_accel_count;			/* Total pending offloads issued to the IPA / awaiting completion */
extern int ecm_ipa_ipv6_pending_decel_count;			/* Total pending deceleration requests issued to the IPA / awaiting completion */

/*
 * Limiting the acceleration of connections.
 *
 * By default there is no acceleration limiting.
 * This means that when ECM has more connections (that can be accelerated) than the acceleration
 * engine will allow the ECM will continue to try to accelerate.
 * In this scenario the acceleration engine will begin removal of existing rules to make way for new ones.
 * When the accel_limit_mode is set to FIXED ECM will not permit more rules to be issued than the engine will allow.
 */
extern uint32_t ecm_ipa_ipv6_accel_limit_mode;

/*
 * Locking of the classifier - concurrency control for file global parameters.
 * NOTE: It is safe to take this lock WHILE HOLDING a feci->lock.  The reverse is NOT SAFE.
 */
extern spinlock_t ecm_ipa_ipv6_lock;			/* Protect against SMP access between netfilter, events and private threaded function. */

/*
 * IPA driver linkage
 */
extern struct ipa_ctx_instance *ecm_ipa_ipv6_mgr;

/*
 * ecm_ipa_ipv6_accel_pending_set()
 *	Set pending acceleration for the connection object.
 *
 * Return false if the acceleration is not permitted or is already in progress.
 */
static inline bool ecm_ipa_ipv6_accel_pending_set(struct ecm_front_end_connection_instance *feci)
{
	IPAFEDBG_LOW_RL("%px: Accel conn: %px\n", feci, feci->ci);

	/*
	 * If re-generation is required then we cannot permit acceleration
	 */
	if (ecm_db_connection_regeneration_required_peek(feci->ci)) {
		IPAFEDBG_LOW_RL("%px: accel %px failed - regen required\n", feci, feci->ci);
		return false;
	}

	/*
	 * Is connection acceleration permanently failed?
	 */
	spin_lock_bh(&feci->lock);
	if (ECM_FRONT_END_ACCELERATION_FAILED(feci->accel_mode)) {
		spin_unlock_bh(&feci->lock);
		IPAFEDBG_LOW_RL("%px: accel %px failed\n", feci, feci->ci);
		return false;
	}

	/*
	 * If acceleration mode is anything other than "not accelerated" then ignore.
	 */
	if (feci->accel_mode != ECM_FRONT_END_ACCELERATION_MODE_DECEL) {
		spin_unlock_bh(&feci->lock);
		IPAFEDBG_LOW_RL("%px: Ignoring wrong mode accel for conn: %px mode:%d\n",
				feci, feci->ci, feci->accel_mode);
		return false;
	}

	/*
	 * Do we have a fixed upper limit for acceleration?
	 */
	spin_lock_bh(&ecm_ipa_ipv6_lock);
	if (ecm_ipa_ipv6_accel_limit_mode & ECM_FRONT_END_ACCEL_LIMIT_MODE_FIXED) {
		if ((ecm_ipa_ipv6_pending_accel_count + ecm_ipa_ipv6_accelerated_count) >= ipa_be_ipv6_get_max_accel_conn()) {
			spin_unlock_bh(&ecm_ipa_ipv6_lock);
			spin_unlock_bh(&feci->lock);
			IPAFEDBG_LOW_RL("%px: Accel limit reached, accel denied: %px\n", feci, feci->ci);
			return false;
		}
	}

	/*
	 * Okay to accelerate
	 */
	ecm_ipa_ipv6_pending_accel_count++;
	spin_unlock_bh(&ecm_ipa_ipv6_lock);

	/*
	 * Okay connection can be set to pending acceleration
	 */
	feci->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING;
	spin_unlock_bh(&feci->lock);
	return true;
}

/*
 * _ecm_ipa_ipv6_accel_pending_clear()
 *	Clear pending acceleration for the connection object, setting it to the desired state.
 *
 * Returns true if "decelerate was pending".
 *
 * The feci->lock AND ecm_ipa_ipv6_lock must be held on entry.
 */
static inline bool _ecm_ipa_ipv6_accel_pending_clear(struct ecm_front_end_connection_instance *feci, ecm_front_end_acceleration_mode_t mode)
{
	bool decel_pending;

	/*
	 * Set the mode away from its accel pending state.
	 */
	DEBUG_ASSERT(feci->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING, "%px: Accel mode unexpected: %d\n", feci, feci->accel_mode);
	feci->accel_mode = mode;

	/*
	 * Clear decelerate pending flag.
	 * This flag is only set when we are ACCEL_PENDING -
	 * and we are moving from that to the given mode anyway.
	 */
	decel_pending = feci->stats.decelerate_pending;
	feci->stats.decelerate_pending = false;

	/*
	 * Decrement pending counter
	 */
	ecm_ipa_ipv6_pending_accel_count--;
	DEBUG_ASSERT(ecm_ipa_ipv6_pending_accel_count >= 0, "Accel pending underflow\n");
	return decel_pending;
}

/*
 * ecm_ipa_ipv6_accel_pending_clear()
 *	Clear pending acceleration for the connection object, setting it to the desired state.
 */
static inline bool ecm_ipa_ipv6_accel_pending_clear(struct ecm_front_end_connection_instance *feci, ecm_front_end_acceleration_mode_t mode)
{
	bool decel_pending;
	spin_lock_bh(&feci->lock);
	spin_lock_bh(&ecm_ipa_ipv6_lock);
	decel_pending = _ecm_ipa_ipv6_accel_pending_clear(feci, mode);
	spin_unlock_bh(&ecm_ipa_ipv6_lock);
	spin_unlock_bh(&feci->lock);
	return decel_pending;
}

extern void ecm_ipa_ipv6_accel_done_time_update(struct ecm_front_end_connection_instance *feci);
extern void ecm_ipa_ipv6_decel_done_time_update(struct ecm_front_end_connection_instance *feci);
extern int ecm_ipa_ipv6_init(struct dentry *dentry);
extern void ecm_ipa_ipv6_exit(void);
#endif //__ECM_IPA_IPV6_H
