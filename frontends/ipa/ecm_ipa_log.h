/*
 **************************************************************************
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 **************************************************************************
 */

#ifndef __ECM_IPA_LOG_H
#define __ECM_IPA_LOG_H

#include <linux/ipc_logging.h>


extern void *log_buf, *log_buf_low;

#define DRV_NAME "ipa_fe"
#define IPA_FE_RATELIMIT_BURST 1

#define pr_err_ratelimited_ipa_fe(fmt, args...)	\
({												\
 	static DEFINE_RATELIMIT_STATE(_rs,			\
		DEFAULT_RATELIMIT_INTERVAL,				\
		IPA_FE_RATELIMIT_BURST);				\
 												\
	if (__ratelimit(&_rs))						\
 		pr_err(fmt, ## args);					\
 })

#define IPA_FE_IPC_LOGGING(buf, fmt, args...) \
	do { \
		if (buf) \
			ipc_log_string((buf), fmt, __func__, __LINE__, \
				## args); \
	} while (0)

#define IPAFEDBG(fmt, args...) \
	do { \
		DEBUG_INFO(DRV_NAME fmt, ## args); \
		if (log_buf) { \
			IPA_FE_IPC_LOGGING(log_buf, \
				DRV_NAME " %s:%d " fmt, ## args); \
			IPA_FE_IPC_LOGGING(log_buf_low, \
				DRV_NAME " %s:%d " fmt, ## args); \
		} \
	} while (0)

#define IPAFEDBG_LOW(fmt, args...) \
	do { \
		DEBUG_TRACE(DRV_NAME fmt, ## args); \
		if (log_buf) \
			IPA_FE_IPC_LOGGING(log_buf_low, \
				DRV_NAME " %s:%d " fmt, ## args); \
	} while (0)

#define IPAFEERR(fmt, args...) \
	do { \
		DEBUG_ERROR(DRV_NAME fmt, ## args); \
		if (log_buf) { \
			IPA_FE_IPC_LOGGING(log_buf, \
				DRV_NAME " %s:%d " fmt, ## args); \
			IPA_FE_IPC_LOGGING(log_buf_low, \
				DRV_NAME " %s:%d " fmt, ## args); \
		} \
	} while (0)

#define IPAFEERR_RL(fmt, args...) \
	do { \
		DEBUG_ERROR_RATELIMITED(DRV_NAME fmt, ## args); \
		if (log_buf) { \
			IPA_FE_IPC_LOGGING(log_buf, \
				DRV_NAME " %s:%d " fmt, ## args); \
			IPA_FE_IPC_LOGGING(log_buf_low, \
				DRV_NAME " %s:%d " fmt, ## args); \
		} \
	} while (0)

#define IPAFEWARN(fmt, args...) \
		do { \
			DEBUG_WARN(DRV_NAME fmt, ## args); \
			if (log_buf) { \
				IPA_FE_IPC_LOGGING(log_buf, \
					DRV_NAME " %s:%d " fmt, ## args); \
				IPA_FE_IPC_LOGGING(log_buf_low, \
					DRV_NAME " %s:%d " fmt, ## args); \
			} \
		} while (0)

#endif //__ECM_IPA_LOG_H
