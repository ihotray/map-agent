/*
 * agent_ubus.c - provides 'agent' object
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#include <stdio.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <uci.h>

#include <netlink/netlink.h>
#include <linux/if_bridge.h>

#include <cmdu.h>
#include <1905_tlvs.h>

#include <easy/easy.h>
#include "wifidefs.h"
#include <map_module.h>
#include <easymesh.h>
#include <i1905_wsc.h>
#ifdef AGENT_SYNC_DYNAMIC_CNTLR_CONFIG
#include <cntlrsync.h>
#endif

#include "timer.h"
#include "wifi.h"
#include "nl.h"
#include "utils/utils.h"
#include "utils/debug.h"
#include "wifi_ubus.h"
#include "config.h"
#include "agent.h"
#include "agent_map.h"
#include "agent_ubus.h"
#include "agent_cmdu.h"
#include "agent_ubus.h"

#define OBJECT_INVALID	((uint32_t)-1)

#define MULTICAST_ADDR_STR "01:80:c2:00:00:13"

/* steer policy */
enum {
	STEER_POLICY_IFNAME,
	STEER_POLICY_RULE,     /* "rssi","load","capacity","user","custom" */
	_STEER_POLICY_MAX,
};

static const struct blobmsg_policy steer_policy_params[_STEER_POLICY_MAX] = {
	[STEER_POLICY_IFNAME] = { .name = "vif", .type = BLOBMSG_TYPE_STRING },
	[STEER_POLICY_RULE] = { .name = "rule", .type = BLOBMSG_TYPE_STRING },
};

/* steer */
enum {
	STEER_IFNAME,
	STEER_TYPE,     /* opportunity or  mandate */
	STEER_STA,      /* STA to be steered */
	STEER_TO_BSS,   /* array of desired target BSSes */
	STEER_OPTIME,   /* steer opportunity time window (in seconds) */
	_STEER_MAX,
};

static const struct blobmsg_policy steer_params[_STEER_MAX] = {
	[STEER_IFNAME] = { .name = "vif", .type = BLOBMSG_TYPE_STRING },
	[STEER_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
	[STEER_STA] = { .name = "sta", .type = BLOBMSG_TYPE_STRING },
	[STEER_TO_BSS] = { .name = "to_bss", .type = BLOBMSG_TYPE_ARRAY },
	[STEER_OPTIME] = { .name = "optime", .type = BLOBMSG_TYPE_INT32 },
};

/* assoc_control (timed blocking of STA association) */
enum {
	ASSOC_CONTROL_IFNAME,
	ASSOC_CONTROL_STA,     /* control assoc for this STA */
	ASSOC_CONTROL_ENABLE,  /* enable or disable */
	ASSOC_CONTROL_TIME,    /* till how long (in seconds) */
	_ASSOC_CONTROL_MAX,
};

static const struct blobmsg_policy assoc_control_params[_ASSOC_CONTROL_MAX] = {
	[ASSOC_CONTROL_IFNAME] = { .name = "vif", .type = BLOBMSG_TYPE_STRING },
	[ASSOC_CONTROL_STA] = { .name = "sta", .type = BLOBMSG_TYPE_STRING },
	[ASSOC_CONTROL_ENABLE] = { .name = "enable", .type = BLOBMSG_TYPE_BOOL },
	[ASSOC_CONTROL_TIME] = { .name = "time", .type = BLOBMSG_TYPE_INT32 },
};

/* fh_toggle */
enum {
	TOGGLE_FH_ENABLE,   /* enable or disable */
#ifdef AGENT_ISLAND_PREVENTION
	TOGGLE_FH_ISL_PREV, /* remote island formation prevention */
#endif
	TOGGLE_FH_IFNAME,
	_TOGGLE_FH_MAX,
};

static const struct blobmsg_policy toggle_fh_params[_TOGGLE_FH_MAX] = {
	[TOGGLE_FH_ENABLE] = { .name = "enable", .type = BLOBMSG_TYPE_BOOL },
#ifdef AGENT_ISLAND_PREVENTION
	[TOGGLE_FH_ISL_PREV] = { .name = "prevent_island", .type = BLOBMSG_TYPE_BOOL },
#endif
	[TOGGLE_FH_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
};

enum {
	UNASSOC_STA_LM_QUERY_AGENT,
	UNASSOC_STA_LM_QUERY_OPCLASS,
	UNASSOC_STA_LM_QUERY_METRICS,
	__UNASSOC_STA_LM_QUERY_MAX,
};

static const struct blobmsg_policy
		unassoc_sta_lm_query_params[__UNASSOC_STA_LM_QUERY_MAX] = {
	[UNASSOC_STA_LM_QUERY_AGENT] = { .name = "agent",
		.type = BLOBMSG_TYPE_STRING },
	[UNASSOC_STA_LM_QUERY_OPCLASS] = { .name = "opclass",
		.type = BLOBMSG_TYPE_INT32 },
	[UNASSOC_STA_LM_QUERY_METRICS] = { .name = "metrics",
		.type = BLOBMSG_TYPE_ARRAY },
};

/* topology query */
enum {
	TOPOLOGY_QUERY_AGENT,
	__TOPOLOGY_QUERY_MAX,
};

static const struct blobmsg_policy topology_query_params[__TOPOLOGY_QUERY_MAX] = {
	[TOPOLOGY_QUERY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
};


/* bcn_metrics_query */
enum {
	BCN_METRICS_AGENT,
	BCN_METRICS_STA,
	BCN_METRICS_OPCLASS,
	BCN_METRICS_CHANNEL,
	BCN_METRICS_BSSID,
	BCN_METRICS_REPORTING_DETAIL,
	BCN_METRICS_SSID,
	BCN_METRICS_CHAN_REPORT,
	BCN_METRICS_ELEMENT_IDS,
	__BCN_METRICS_QUERY_MAX,
};

static const struct blobmsg_policy
		bcn_metrics_query_params[__BCN_METRICS_QUERY_MAX] = {
	[BCN_METRICS_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[BCN_METRICS_STA] = { .name = "sta", .type = BLOBMSG_TYPE_STRING },
	[BCN_METRICS_OPCLASS] = { .name = "opclass",
			.type = BLOBMSG_TYPE_INT32 },
	[BCN_METRICS_CHANNEL] = { .name = "channel",
			.type = BLOBMSG_TYPE_INT32 },
	[BCN_METRICS_BSSID] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING },
	[BCN_METRICS_REPORTING_DETAIL] = { .name = "reporting_detail",
			.type = BLOBMSG_TYPE_INT32 },
	[BCN_METRICS_SSID] = { .name = "ssid", .type = BLOBMSG_TYPE_STRING },
	[BCN_METRICS_CHAN_REPORT] = { .name = "channel_report",
			.type = BLOBMSG_TYPE_ARRAY },
	[BCN_METRICS_ELEMENT_IDS] = { .name = "request_element",
			.type = BLOBMSG_TYPE_ARRAY },
};

enum {
	HLD_AGENT,
	HLD_PROTOCOL,
	HLD_DATA,
	_HLD_MAX,
};

static const struct blobmsg_policy higher_layer_data_params[_HLD_MAX] = {
	[HLD_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[HLD_PROTOCOL] = { .name = "protocol", .type = BLOBMSG_TYPE_INT32 },
	[HLD_DATA] = { .name = "data", .type = BLOBMSG_TYPE_STRING },
};


/* cmd (f.e. from controller) */
enum {
	CMD_ID,
	CMD_DATA,
	_CMD_MAX,
};

static const struct blobmsg_policy cmd_params[_CMD_MAX] = {
	[CMD_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
	[CMD_DATA] = { .name = "data", .type = BLOBMSG_TYPE_STRING },
};

#if 0
enum {
	CFG_POLICY_AGENT,
	CFG_POLICY_BSSID,
	__CFG_POLICY_MAX,
};

static const struct blobmsg_policy config_policy_params[__CFG_POLICY_MAX] = {
	[CFG_POLICY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[CFG_POLICY_BSSID] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING },
};
#endif

enum {
	SEARCH_POLICY_BAND,
	__SEARCH_POLICY_MAX,
};

static const struct blobmsg_policy search_policy_params[__SEARCH_POLICY_MAX] = {
	[SEARCH_POLICY_BAND] = { .name = "band", .type = BLOBMSG_TYPE_INT32 },
};

static int steer_policy(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct blob_attr *tb[_STEER_POLICY_MAX];
	char ifname[16] = {0};


	blobmsg_parse(steer_policy_params, _STEER_POLICY_MAX, tb,
		blob_data(msg), blob_len(msg));

	if (!(tb[STEER_POLICY_IFNAME])) {
		dbg("%s(): ifname not specified!\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	memset(ifname, '\0', sizeof(ifname));
	strncpy(ifname, blobmsg_data(tb[STEER_POLICY_IFNAME]),
			sizeof(ifname) - 1);

	if (!(tb[STEER_POLICY_RULE])) {
		dbg("%s(): Steer rule not specified!\n", __func__);
		/* TODO:
		 * dump current rules
		 */
	} else {
		/* TODO:
		 * validate rules ...
		 */
	}

	/* TODO: steer rules */
	/* if (wifiagent_update_steer_policy(ifname, policy) != 0) {
	 *	return UBUS_STATUS_UNKNOWN_ERROR;
	 * }
	 */

	return UBUS_STATUS_OK;
}

static int assoc_control(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct blob_attr *tb[_ASSOC_CONTROL_MAX];
	unsigned char sta_macaddr[6] = {0};
	char ifname[16] = {0};
	unsigned int time = 0;
	char sta[18] = {0};
	int enable = 1;

	blobmsg_parse(assoc_control_params, _ASSOC_CONTROL_MAX,
			tb, blob_data(msg), blob_len(msg));

	if (!(tb[ASSOC_CONTROL_IFNAME])) {
		dbg("%s(): ifname not specified!\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	memset(ifname, '\0', sizeof(ifname));
	strncpy(ifname, blobmsg_data(tb[ASSOC_CONTROL_IFNAME]),
			sizeof(ifname) - 1);

	if (!(tb[ASSOC_CONTROL_STA])) {
		dbg("%s(): STA not specified!\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	strncpy(sta, blobmsg_data(tb[ASSOC_CONTROL_STA]), sizeof(sta)-1);
	if (hwaddr_aton(sta, sta_macaddr) == NULL) {
		dbg("%s(): Invalid sta address. Use 00:10:22:..\n",
				__func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (tb[ASSOC_CONTROL_ENABLE])
		enable = blobmsg_get_bool(tb[ASSOC_CONTROL_ENABLE]);

	if (tb[ASSOC_CONTROL_TIME])
		time = blobmsg_get_u32(tb[ASSOC_CONTROL_TIME]);

	if (wifiagent_assoc_control_sta(ifname, sta_macaddr, enable, time) != 0)
		return UBUS_STATUS_UNKNOWN_ERROR;

	return UBUS_STATUS_OK;
}

static int toggle_fh(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct blob_attr *tb[_TOGGLE_FH_MAX];
	char ifname[16] = {0};
	int enable = 0;
	int isl_prev = 0;

	blobmsg_parse(toggle_fh_params, _TOGGLE_FH_MAX,
			tb, blob_data(msg), blob_len(msg));

	if (!tb[TOGGLE_FH_ENABLE])
		return UBUS_STATUS_UNKNOWN_ERROR;

	enable = blobmsg_get_bool(tb[TOGGLE_FH_ENABLE]);

#ifdef AGENT_ISLAND_PREVENTION
	if (tb[TOGGLE_FH_ISL_PREV])
		isl_prev = blobmsg_get_bool(tb[TOGGLE_FH_ISL_PREV]);
#endif

	memset(ifname, '\0', sizeof(ifname));
	if (tb[TOGGLE_FH_IFNAME])
		strncpy(ifname, blobmsg_data(tb[TOGGLE_FH_IFNAME]),
				sizeof(ifname) - 1);
	else
		/* toggle all interfaces */
		strncpy(ifname, "all", sizeof(ifname) - 1);

	if (wifiagent_toggle_fh(obj, isl_prev, ifname, enable) != 0)
		return UBUS_STATUS_UNKNOWN_ERROR;

	return UBUS_STATUS_OK;
}

static int bcn_metrics_query(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct agent *a = container_of(obj, struct agent, obj);
	struct blob_attr *tb[__BCN_METRICS_QUERY_MAX];
	char agent[18] = {0};
	char sta[18] = {0};
	char bssid[18] = {0};
	uint8_t agent_mac[6] = {0};
	uint8_t sta_mac[6] = {0};
	uint8_t bssid_mac[6] = {0};
	uint8_t opclass = 0;
	uint8_t channel = 0;
	uint8_t reporting_detail = 0;
	char ssid[33] = {0};
	uint8_t num_report = 0;
	struct sta_channel_report *reports = NULL;
	uint8_t num_element = 0;
	uint8_t *element = NULL;
	int ret = UBUS_STATUS_OK;
	struct cmdu_buff *cmdu = NULL;

	trace("agent: %s: --->\n", __func__);

	blobmsg_parse(bcn_metrics_query_params, __BCN_METRICS_QUERY_MAX,
			tb, blob_data(msg), blob_len(msg));

	if (!tb[BCN_METRICS_AGENT] || !tb[BCN_METRICS_STA]) {
		fprintf(stderr, "Beacon metrics query:" \
				" provide agent & STA" \
				" in format 11:22:33...\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	strncpy(agent, blobmsg_data(tb[BCN_METRICS_AGENT]),
			sizeof(agent) - 1);
	strncpy(sta, blobmsg_data(tb[BCN_METRICS_STA]),
			sizeof(sta) - 1);

	if (tb[BCN_METRICS_BSSID])
		strncpy(bssid, blobmsg_data(tb[BCN_METRICS_BSSID]),
				sizeof(bssid) - 1);
	else
		strncpy(bssid, "ff:ff:ff:ff:ff:ff", sizeof(bssid));

	if (!hwaddr_aton(agent, agent_mac)
			|| !hwaddr_aton(sta, sta_mac)
			|| !hwaddr_aton(bssid, bssid_mac))
		return UBUS_STATUS_UNKNOWN_ERROR;

	if (tb[BCN_METRICS_OPCLASS])
		opclass = (int) blobmsg_get_u32(
				tb[BCN_METRICS_OPCLASS]);

	if (tb[BCN_METRICS_CHANNEL])
		channel = (int) blobmsg_get_u32(
				tb[BCN_METRICS_CHANNEL]);

	if (tb[BCN_METRICS_REPORTING_DETAIL])
		reporting_detail = (int) blobmsg_get_u32(
				tb[BCN_METRICS_REPORTING_DETAIL]);

	if (tb[BCN_METRICS_SSID])
		strncpy(ssid, blobmsg_data(tb[BCN_METRICS_SSID]),
				sizeof(ssid) - 1);

	/* Example ubus call:
	 * ubus call map.agent bcn_metrics_query '{"agent":
	 * "44:d4:37:42:47:b9", "sta":"44:d4:37:4d:84:83",
	 * "bssid":"44:d4:37:42:47:bf", "ssid":"MAP-$BASEMAC-5GHz",
	 * "channel":255, "channel_report":[{"opclass":81,"channels":
	 * [1, 6, 13]}, {"opclass":82, "channels": [1, 6, 13]}],
	 * "reporting_detail":1, "request_element": [7, 33]}'
	 */

	if (tb[BCN_METRICS_CHAN_REPORT]) {
		struct blob_attr *cur;
		static const struct blobmsg_policy supp_attrs[2] = {
				[0] = { .name = "opclass",
						.type = BLOBMSG_TYPE_INT32 },
				[1] = { .name = "channels",
						.type = BLOBMSG_TYPE_ARRAY },
		};
		int rem, i = 0;

		num_report = blobmsg_check_array(tb[BCN_METRICS_CHAN_REPORT],
				BLOBMSG_TYPE_TABLE);

		reports = calloc(num_report, sizeof(struct sta_channel_report));
		if (!reports) {
			ret = UBUS_STATUS_UNKNOWN_ERROR;
			goto out;
		}

		blobmsg_for_each_attr(cur, tb[BCN_METRICS_CHAN_REPORT], rem) {
			int remm, j = 0;
			struct blob_attr *data[2], *attr;

			blobmsg_parse(supp_attrs, 2, data, blobmsg_data(cur),
					blobmsg_data_len(cur));

			if (!data[0] || !data[1])
				continue;

			reports[i].opclass = (uint8_t) blobmsg_get_u32(data[0]);
			reports[i].num_channel = blobmsg_check_array(
					data[1], BLOBMSG_TYPE_INT32);

			// Iterate through all channels of the opclass
			blobmsg_for_each_attr(attr, data[1], remm) {
				if (blobmsg_type(attr) != BLOBMSG_TYPE_INT32)
					continue;

				/* Channel List */
				reports[i].channel[j++]
					= (uint8_t) blobmsg_get_u32(attr);
			}

			if (reports[i].num_channel != j) {
				dbg("%s(): invalid channel!\n", __func__);
				ret = UBUS_STATUS_INVALID_ARGUMENT;
				goto out;
			}

			i++;
		}

		if (num_report != i) {
			dbg("%s(): invalid report!\n", __func__);
			ret = UBUS_STATUS_INVALID_ARGUMENT;
			goto out;
		}
	}

	/* TODO: consider overriding reporting_detail */
	if (tb[BCN_METRICS_ELEMENT_IDS] && reporting_detail == 1) {
		struct blob_attr *attr_id;
		int rem_id, k = 0;

		num_element = blobmsg_check_array(
				tb[BCN_METRICS_ELEMENT_IDS],
				BLOBMSG_TYPE_INT32);

		element = calloc(num_element, sizeof(uint8_t));
		if (!element) {
			ret = UBUS_STATUS_UNKNOWN_ERROR;
			goto out;
		}

		blobmsg_for_each_attr(attr_id,
				tb[BCN_METRICS_ELEMENT_IDS], rem_id) {
			if (blobmsg_type(attr_id) != BLOBMSG_TYPE_INT32)
				continue;
			element[k] = (uint8_t) blobmsg_get_u32(attr_id);
			k++;
		}

		if (k != num_element) {
			dbg("%s(): invalid element ID!\n", __func__);
			ret = UBUS_STATUS_INVALID_ARGUMENT;
			goto out;
		}
	}

	cmdu = agent_gen_beacon_metrics_query(a, agent_mac,
				sta_mac, opclass, channel, bssid_mac,
				reporting_detail, ssid, num_report, reports,
				num_element, element);

	if (!cmdu) {
		ret = UBUS_STATUS_UNKNOWN_ERROR;
		goto out;
	}

	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

out:
	if (element)
		free(element);
	if (reports)
		free(reports);
	return ret;
}

static int unassoc_sta_lm_query(struct ubus_context *ctx,
		struct ubus_object *obj, struct ubus_request_data *req,
		const char *method, struct blob_attr *msg)
{
	struct agent *a = container_of(obj, struct agent, obj);
	struct cmdu_buff *cmdu;
	char mac_str[18];
	uint8_t agent_mac[6] = { 0 };
	struct blob_attr *tb[__UNASSOC_STA_LM_QUERY_MAX];
	uint8_t opclass = 0;
	int num_metrics = 0;
	struct unassoc_sta_metric *metrics = NULL;
	int ret = UBUS_STATUS_OK;

	blobmsg_parse(unassoc_sta_lm_query_params, __UNASSOC_STA_LM_QUERY_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (!tb[UNASSOC_STA_LM_QUERY_AGENT]) {
		fprintf(stderr, "Unassociated STA link metric query: provide Agent" \
				"address in format aa:bb:cc:dd:ee:ff\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	memset(mac_str, 0, sizeof(mac_str));
	strncpy(mac_str, blobmsg_data(tb[UNASSOC_STA_LM_QUERY_AGENT]),
			sizeof(mac_str) - 1);
	if (!hwaddr_aton(mac_str, agent_mac))
		return UBUS_STATUS_UNKNOWN_ERROR;

	if (tb[UNASSOC_STA_LM_QUERY_OPCLASS])
		opclass = (int) blobmsg_get_u32(
				tb[UNASSOC_STA_LM_QUERY_OPCLASS]);

	if (!opclass) {
		fprintf(stderr, "%s(): missing opclass\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	/* Example ubus call:
	 * ubus call map.agent unassoc_sta_lm_query '{"agent":
	 * "44:d4:37:42:47:b9", "opclass":81, "metrics":
	 * [{"channel":11, "stamacs": ["44:d4:37:42:3a:c6", "44:d4:37:42:47:be"]}]}'
	 *
	 * ubus call map.agent unassoc_sta_lm_query '{"agent":
	 * "44:d4:37:42:47:b9", "opclass":128,
	 * "metrics":[{"channel":36,"stamacs: ["e0:d4:e8:79:c4:ef"]}]}'
	 */

	if (tb[UNASSOC_STA_LM_QUERY_METRICS]) {
		struct blob_attr *cur;
		static const struct blobmsg_policy supp_attrs[2] = {
			[0] = { .name = "channel",
					.type = BLOBMSG_TYPE_INT32 },
			[1] = { .name = "stamacs",
					.type = BLOBMSG_TYPE_ARRAY },
		};
		int rem, i = 0;

		num_metrics = blobmsg_check_array(tb[UNASSOC_STA_LM_QUERY_METRICS],
				BLOBMSG_TYPE_TABLE);

		if (!num_metrics) {
			fprintf(stderr, "%s(): missing metrics\n", __func__);
			return UBUS_STATUS_INVALID_ARGUMENT;
		}

		metrics = calloc(num_metrics, sizeof(struct unassoc_sta_metric));
		if (!metrics) {
			ret = UBUS_STATUS_UNKNOWN_ERROR;
			goto out;
		}

		blobmsg_for_each_attr(cur, tb[UNASSOC_STA_LM_QUERY_METRICS], rem) {
			int remm, j = 0;
			struct blob_attr *data[2], *attr;
			char mac[18];

			blobmsg_parse(supp_attrs, 2, data, blobmsg_data(cur),
					blobmsg_data_len(cur));

			if (!data[0] || !data[1])
				continue;

			metrics[i].channel = (uint8_t) blobmsg_get_u32(data[0]);
			metrics[i].num_sta = blobmsg_check_array(
					data[1], BLOBMSG_TYPE_STRING);

			if (!metrics[i].channel) {
				fprintf(stderr, "unassoc_sta_lm_query: missing channel \
						for metrics [%d]\n", i);
				ret = UBUS_STATUS_INVALID_ARGUMENT;
				goto out;
			}

			if (!metrics[i].num_sta) {
				fprintf(stderr, "unassoc_sta_lm_query: no stations for \
						channel %d\n", metrics[i].channel);
				ret = UBUS_STATUS_INVALID_ARGUMENT;
				goto out;
			}

			if (metrics[i].num_sta > MAX_UNASSOC_STAMACS) {
				fprintf(stderr, "unassoc_sta_lm_query: max 10 stations \
						allowed per channel!\n");
				ret = UBUS_STATUS_INVALID_ARGUMENT;
				goto out;
			}

			/* Iterate through all metrics of given channel */
			blobmsg_for_each_attr(attr, data[1], remm) {
				if (blobmsg_type(attr) != BLOBMSG_TYPE_STRING)
					continue;

				/* STA list */
				strncpy(mac, blobmsg_get_string(attr), sizeof(mac) - 1);
				hwaddr_aton(mac, metrics[i].sta[j].macaddr);

				j++;
			}

			if (metrics[i].num_sta != j) {
				dbg("%s(): invalid metric [%d]!\n", __func__, i);
				ret = UBUS_STATUS_INVALID_ARGUMENT;
				goto out;
			}

			i++;
		}

		if (num_metrics != i) {
			dbg("%s(): invalid metrics!\n", __func__);
			ret = UBUS_STATUS_INVALID_ARGUMENT;
			goto out;
		}
	}


	cmdu = agent_gen_unassoc_sta_metric_query(a, agent_mac,
			opclass, num_metrics, metrics);

	if (!cmdu) {
		ret = UBUS_STATUS_UNKNOWN_ERROR;
		goto out;
	}

	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

out:
	if (metrics)
		free(metrics);

	return ret;
}

static int topology_query(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct agent *a = container_of(obj, struct agent, obj);
	struct blob_attr *tb[__TOPOLOGY_QUERY_MAX];
	char agent[18] = { 0 };
	uint8_t agent_mac[6] = { 0 };
	struct cmdu_buff *cmdu;

	blobmsg_parse(topology_query_params, __TOPOLOGY_QUERY_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (tb[TOPOLOGY_QUERY_AGENT]) {
		strncpy(agent, blobmsg_data(tb[TOPOLOGY_QUERY_AGENT]),
				sizeof(agent) - 1);
	} else {
		strncpy(agent, MULTICAST_ADDR_STR, 18);
	}
	if (!hwaddr_aton(agent, agent_mac))
		return UBUS_STATUS_UNKNOWN_ERROR;

	cmdu = agent_gen_topology_query(a, agent_mac);
	if (!cmdu)
		return UBUS_STATUS_UNKNOWN_ERROR;

	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	return UBUS_STATUS_OK;
}

static int steer(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	unsigned char sta_macaddr[6] = {0};
	unsigned char bss_macaddr[6] = {0};
	unsigned char bsslist[72] = {0};
	struct blob_attr *tb[_STEER_MAX];
	struct blob_attr *attr;
	char ifname[16] = {0};
	char type[12] = {0};
	int steer_type = STA_STEER_MANDATE; /* default is mandate */
	unsigned int optime = 0;
	char sta[18] = {0};
	char bss[18] = {0};
	int i = 0;
	int rem;

	blobmsg_parse(steer_params, _STEER_MAX, tb, blob_data(msg),
			blob_len(msg));
	if (!(tb[STEER_IFNAME])) {
		dbg("%s(): ifname not specified!\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	memset(ifname, '\0', sizeof(ifname));
	strncpy(ifname, blobmsg_data(tb[STEER_IFNAME]), sizeof(ifname)-1);

	if (!(tb[STEER_STA])) {
		dbg("%s(): STA's macaddress not specified!\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	strncpy(sta, blobmsg_data(tb[STEER_STA]), sizeof(sta)-1);
	if (hwaddr_aton(sta, sta_macaddr) == NULL) {
		dbg("%s(): Invalid address. Use 00:10:22:..\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (tb[STEER_TYPE]) {
		snprintf(type, 12, "%s", (char *)blobmsg_data(tb[STEER_TYPE]));
		if (!strncasecmp(type, "opportunity", 11))
			steer_type = STA_STEER_OPPORTUNITY;
	}

	if (steer_type == STA_STEER_OPPORTUNITY) {
		if (!tb[STEER_OPTIME]) {
			dbg("%s(): 'optime' not specified for steer " \
					"opportunity\n", __func__);
			return UBUS_STATUS_INVALID_ARGUMENT;
		}
		optime = blobmsg_get_u32(tb[STEER_OPTIME]);
	}

	if (tb[STEER_TO_BSS]) {
		blobmsg_for_each_attr(attr, tb[STEER_TO_BSS], rem) {
			if (blobmsg_type(attr) != BLOBMSG_TYPE_STRING)
				continue;

			strncpy(bss, blobmsg_data(attr), sizeof(bss)-1);
			if (hwaddr_aton(bss, bss_macaddr) == NULL) {
				dbg("%s(): Invalid Bss address. " \
						"Use 00:10:22:..\n", __func__);
				return UBUS_STATUS_INVALID_ARGUMENT;
			}
			memcpy(&bsslist[i*6], bss_macaddr, 6);
			if (++i > 9)
				break;
		}
	}

#ifdef DEBUG
	{
		int l;

		for (l = 0; l < i; l++)
			dbg("bsslist[%d] = %02x:%02x:%02x:%02x:%02x:%02x\n",
				l,
				bsslist[0 + l*6], bsslist[1 + l*6],
				bsslist[2 + l*6], bsslist[3 + l*6],
				bsslist[4 + l*6], bsslist[5 + l*6]);
	}
#endif

	if (wifiagent_steer_sta(ctx, ifname, sta_macaddr, i, bsslist, optime))
		return UBUS_STATUS_UNKNOWN_ERROR;

	return UBUS_STATUS_OK;
}

static int higher_layer_data(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct agent *a = container_of(obj, struct agent, obj);
	struct cmdu_buff *cmdu;
	struct blob_attr *tb[_HLD_MAX];
	uint8_t agent_mac[6];
	uint8_t proto;
	int len, tmp;
	uint8_t *data;
	char *datastr;

	dbg("Agent: received '%s'\n", __func__);
	blobmsg_parse(higher_layer_data_params, _HLD_MAX, tb, blob_data(msg),
			blob_len(msg));

	if (!tb[HLD_AGENT]) {
		dbg("%s(): ADDR not specified!\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	len = blobmsg_data_len(tb[HLD_AGENT]);
	if (len < 17) {
		dbg("%s(): wrong ADDR length %d!\n", __func__, len);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	if (hwaddr_aton(blobmsg_data(tb[HLD_AGENT]), agent_mac) == NULL) {
		dbg("%s(): wrong ADDR!\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (!tb[HLD_PROTOCOL]) {
		dbg("%s(): PROTOCOL not specified!\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	tmp = blobmsg_get_u32(tb[HLD_PROTOCOL]);
	if (tmp < 0 || tmp > 255) {
		dbg("%s(): PROTOCOL not withing the 0-255 range !\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	proto = (uint8_t) tmp;

	if (!tb[HLD_DATA]) {
		dbg("%s(): DATA not specified!\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	datastr = blobmsg_get_string(tb[HLD_DATA]);
	len = blobmsg_data_len(tb[HLD_DATA]);
	if (len % 2 != 1) {
		/* expect n*2 hex digits + '\0' termination character  */
		dbg("%s(): wrong DATA length %d!\n", __func__, len);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	len = len / 2;
	data = calloc(len, sizeof(uint8_t));
	if (!data) {
		dbg("%s(): alloc failure!\n", __func__);
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (strtob(datastr, len, data) == NULL) {
		dbg("%s(): wrong DATA %d!\n", __func__, len);
		goto error;
	}

	cmdu = agent_gen_higher_layer_data(a, agent_mac, proto, data, len);
	if (!cmdu)
		goto error;

	free(data);

	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	dbg("Agent: CMD returned OK\n");
	return UBUS_STATUS_OK;

error:
	free(data);
	return UBUS_STATUS_UNKNOWN_ERROR;
}

#if AGENT_SYNC_DYNAMIC_CNTLR_CONFIG
static int sync_dyn_controller_config(struct ubus_context *ctx, struct ubus_object *obj,
				      struct ubus_request_data *req, const char *method,
				      struct blob_attr *msg)
{
	struct agent *a = container_of(obj, struct agent, obj);
	uint16_t sync_config_reqsize = 0;
	uint8_t *sync_config_req;
	struct cmdu_buff *cmdu;
	uint8_t proto = 0xac;
	void *key;
	int ret;


	ret = build_sync_config_request(a->almac, &sync_config_req,
					&sync_config_reqsize, &key);
	if (ret) {
		err("Failed to build sync-dyn-controller-config request!\n");
		return ret;
	}

	agent_free_cntlr_sync(a);

	a->sync_config_reqsize = sync_config_reqsize;
	a->sync_config_req = sync_config_req;
	a->privkey = key;

	cmdu = agent_gen_higher_layer_data(a, a->cntlr_almac, proto,
					   sync_config_req, sync_config_reqsize);
	if (!cmdu)
		goto error;

	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	return UBUS_STATUS_OK;

error:
	return UBUS_STATUS_UNKNOWN_ERROR;
}
#endif

static int cmd(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct blob_attr *tb[_CMD_MAX];
	int cmd_id = 0;
	char cmd_data[512] = {0};
	int len = 0;

	dbg("Agent: received '%s'\n", __func__);
	blobmsg_parse(cmd_params, _CMD_MAX, tb, blob_data(msg), blob_len(msg));

	if (!(tb[CMD_ID])) {
		dbg("%s(): ID not specified!\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	cmd_id = blobmsg_get_u32(tb[CMD_ID]);

	if (tb[CMD_DATA]) {
		len = blobmsg_data_len(tb[CMD_DATA]);
		memcpy(cmd_data, blobmsg_data(tb[CMD_DATA]),
					blobmsg_data_len(tb[CMD_DATA]));
	}

	dbg("Agent: received CMD-%d with len = %d\n", cmd_id, len);
	if (wifiagent_process_cmd(ctx, req, cmd_id, cmd_data, len) != 0)
		return UBUS_STATUS_UNKNOWN_ERROR;

	dbg("Agent: CMD returned OK\n");
	return UBUS_STATUS_OK;
}

static int agent_timers(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_buf bb;
	struct agent *a = container_of(obj, struct agent, obj);
	void *t;
	struct timespec now = {0};

	timestamp_update(&now);

	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);
	blobmsg_add_u32(&bb, "autoconfig_trigger", timer_remaining_ms(&a->autocfg_dispatcher));
	t = blobmsg_open_table(&bb, "dynamic_backhaul");
	blobmsg_add_u32(&bb, "next_attempt", timer_remaining_ms(&a->upgrade_backhaul_scheduler));
	blobmsg_add_u32(&bb, "last_attempt_start", timestamp_diff_ms(now, a->dynbh_last_start));
	blobmsg_add_u32(&bb, "last_attempt_end", timestamp_diff_ms(now, a->dynbh_last_end));
	blobmsg_close_table(&bb, t);
	blobmsg_add_u32(&bb, "bh_lost_timer", timer_remaining_ms(&a->bh_lost_timer));
	blobmsg_add_u32(&bb, "bh_reconf_timer", timer_remaining_ms(&a->bh_reconf_timer));
#ifdef AGENT_ISLAND_PREVENTION
	blobmsg_add_u32(&bb, "sta_disconnect_timer", timer_remaining_ms(&a->sta_disconnect_timer));
	blobmsg_add_u32(&bb, "fh_disable_timer", timer_remaining_ms(&a->fh_disable_timer));
#endif /* AGENT_ISLAND_PREVENTION */
	blobmsg_add_u32(&bb, "disable_unconnected_bstas_scheduler", timer_remaining_ms(&a->disable_unconnected_bstas_scheduler));
	blobmsg_add_u32(&bb, "onboarding_scheduler", timer_remaining_ms(&a->onboarding_scheduler));
	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

static int agent_backhaul_blacklist(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_buf bb;
	struct agent *a = container_of(obj, struct agent, obj);
	struct netif_bk *bk;
	void *t;

	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);

	t = blobmsg_open_array(&bb, "backhauls");

	list_for_each_entry(bk, &a->bklist, list) {
		void *tt, *ttt;
		char mac[18] = {0};
		int i;

		tt = blobmsg_open_table(&bb, "");
		blobmsg_add_string(&bb, "ifname", bk->name);
		hwaddr_ntoa(bk->bssid, mac);
		blobmsg_add_string(&bb, "macaddr", mac);
		blobmsg_add_u32(&bb, "num_blacklist_bssids", bk->num_blacklist_bssids);
		ttt = blobmsg_open_array(&bb, "blacklist_bssid");
		for (i = 0; i < bk->num_blacklist_bssids; i++) {
			hwaddr_ntoa(bk->blacklist_bssid[i], mac);
			blobmsg_add_string(&bb, "", mac);
		}
		blobmsg_close_array(&bb, ttt);
		blobmsg_close_table(&bb, tt);
	}

	blobmsg_close_array(&bb, t);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

static int agent_trigger_dynamic_upgrade(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct agent *a = container_of(obj, struct agent, obj);

	if (timer_remaining_ms(&a->upgrade_backhaul_scheduler) > 0)
		timer_set(&a->upgrade_backhaul_scheduler, 0);

	return UBUS_STATUS_OK;
}

static int agent_status(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	return wifiagent_get_status(ctx, req);
}

static int agent_nodes(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	return wifiagent_get_nodes(ctx, req);
}


static int agent_info(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	return wifiagent_get_info(ctx, req);
}

static int agent_bk_info(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	return wifiagent_get_bk_info(ctx, req);
}

#if 0
static int agent_config_ap(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	return 0;

	struct agent *a = container_of(obj, struct agent, obj);
	struct blob_attr *tb[__CFG_POLICY_MAX];
	char agent[18] = {0}, bssidstr[18] = {0};
	struct wifi_radio_element *radio, *found = NULL;
	uint8_t hwaddr[6] = {0}, bssid[6] = {0};
	int i;

	blobmsg_parse(config_policy_params, __CFG_POLICY_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (!tb[CFG_POLICY_AGENT] || !tb[CFG_POLICY_BSSID]) {
		fprintf(stderr, "STA Capability Query: provide BSSID " \
				"address in format 11:22:33...\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	strncpy(agent, blobmsg_data(tb[CFG_POLICY_AGENT]), sizeof(agent) - 1);
	if (!hwaddr_aton(agent, hwaddr))
		return UBUS_STATUS_UNKNOWN_ERROR;

	strncpy(bssidstr, blobmsg_data(tb[CFG_POLICY_BSSID]),
			sizeof(bssidstr) - 1);
	if (!hwaddr_aton(bssidstr, bssid))
		return UBUS_STATUS_UNKNOWN_ERROR;

	for (i = 0; i < a->num_radios; i++) {
		radio = a->radios + i;

		if (memcmp(radio->macaddr, bssid, 6))
			continue;
		found = radio;
	}
	if (!found)
		return UBUS_STATUS_UNKNOWN_ERROR;

	build_ap_autoconfig_wsc(a, hwaddr, radio, i);

	return 0;
}
#endif

static int agent_ap_search(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	return 0;
//	struct agent *a = container_of(obj, struct agent, obj);
//	struct blob_attr *tb[__SEARCH_POLICY_MAX];
//	int i, band = 0;
//
//	blobmsg_parse(search_policy_params, __SEARCH_POLICY_MAX, tb,
//			blob_data(msg), blob_len(msg));
//
//	if (tb[SEARCH_POLICY_BAND]) {
//		band = blobmsg_get_u32(tb[SEARCH_POLICY_BAND]);
//
//		if (band == 2)
//			band = BAND_2;
//		else if (band == 5)
//			band = BAND_5;
//		else {
//			trace("|%s:%d| Please provide band as '2', '5' or N/A\n",
//					__func__, __LINE__);
//			return UBUS_STATUS_UNKNOWN_ERROR;
//		}
//	}
//
//	for (i = 0; i < a->num_radios; i++) {
//		struct cmdu_cstruct *cmdu;
//		struct wifi_radio_element *radio = &a->radios[i];
//
//		if (tb[SEARCH_POLICY_BAND])
//			if (band != radio->band)
//				continue;
//
//		cmdu = agent_gen_ap_autoconfig_search(a, radio, NULL, 0x02);
//		if (!cmdu)
//			continue;
//
//		trace("|%s:%d| Sending Autoconfig Search for radio %s(%s)\n",
//				__func__, __LINE__, radio->name,
//				(radio->band == BAND_2 ? "2.4GHz" : "5GHz"));
//		agent_send_cmdu(a, cmdu);
//		map_free_cmdu(cmdu);
//	}
//
//	return 0;
}

enum {
	ASSOC_NOTIFY_BSSARR,
	_ASSOC_NOTIFY_MAX
};

static const struct blobmsg_policy assoc_notify_params[_ASSOC_NOTIFY_MAX] = {
	[ASSOC_NOTIFY_BSSARR] = { .name = "bss_status_list", .type = BLOBMSG_TYPE_ARRAY }
};

/* i.e.
 * ubus call map.agent assoc_notify '{"bss_status_list":[{"bssid":"11:11:11:11:11:11","status":0},{"bssid":"12:12:12:12:12:12","status":1}]}'
 */
static int assoc_notify(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	int rem, num_data = 0;
	struct blob_attr *cur;
	struct bss_data {
		uint8_t bssid[6];
		uint8_t status;
	} *bss_data = NULL;

	void *tmp = NULL;
	struct blob_attr *tb[_ASSOC_NOTIFY_MAX];
	struct cmdu_buff *cmdu;
	struct agent *a = container_of(obj, struct agent, obj);

	blobmsg_parse(assoc_notify_params, _ASSOC_NOTIFY_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (!tb[ASSOC_NOTIFY_BSSARR])
		return UBUS_STATUS_UNKNOWN_ERROR;

	blobmsg_for_each_attr(cur, tb[ASSOC_NOTIFY_BSSARR], rem) {
		int status, idx;
		char bss[18] = {0};
		struct blob_attr *tb1[2];
		struct blobmsg_policy assoc_notify_data[] = {
			[0] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING },
			[1] = { .name = "status", .type = BLOBMSG_TYPE_INT32 }
		};

		blobmsg_parse(assoc_notify_data, 2,
				tb1, blobmsg_data(cur), blobmsg_data_len(cur));

		if (!tb1[0] || !tb1[1])
			continue;

		/* allowed status value should be
		 * '0x00' or '0x01'
		 */
		status = blobmsg_get_u32(tb1[1]);
		if (!((status == 0x00) || (status == 0x01)))
			continue;

		tmp = realloc(bss_data, (num_data + 1) * sizeof(*bss_data));
		if (!tmp) {
			dbg("%s: -ENOMEM\n", __func__);
			goto error;
		}

		bss_data = tmp;
		idx = num_data;
		memset(bss_data + idx, 0, sizeof(struct bss_data));
		strncpy(bss, blobmsg_data(tb1[0]),
				sizeof(bss) - 1);
		if (!hwaddr_aton(bss, bss_data[idx].bssid))
			goto error;

		bss_data[idx].status = (uint8_t) status;
		num_data++;
	}

	if (!num_data)
		return UBUS_STATUS_UNKNOWN_ERROR;

	cmdu = agent_gen_association_status_notify(a, num_data, (void *)bss_data);
	if (!cmdu)
		goto error;

	free(bss_data);
	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	return UBUS_STATUS_OK;

error:
	free(bss_data);

	return UBUS_STATUS_UNKNOWN_ERROR;
}

#if (EASYMESH_VERSION > 2)
static int bss_config_request(struct ubus_context *ctx, struct ubus_object *obj,
			      struct ubus_request_data *req, const char *method,
			      struct blob_attr *msg)
{
	struct agent *agent = container_of(obj, struct agent, obj);

	if (send_bss_configuration_request(agent))
		return UBUS_STATUS_UNKNOWN_ERROR;

	return UBUS_STATUS_OK;
}
#endif /*EASYMESH_VERSION > 2*/

int agent_publish_object(struct agent *a, const char *objname)
{
	struct ubus_method m[] = {
		UBUS_METHOD("apconfig", agent_ap_search, search_policy_params),
		//UBUS_METHOD("config_ap", agent_config_ap, config_policy_params),
		UBUS_METHOD("steer_policy", steer_policy, steer_policy_params),
		UBUS_METHOD("steer", steer, steer_params),
		UBUS_METHOD("assoc_control", assoc_control,
				assoc_control_params),
		UBUS_METHOD("toggle_fh", toggle_fh, toggle_fh_params),
		UBUS_METHOD("bcn_metrics_query", bcn_metrics_query,
				bcn_metrics_query_params),
		UBUS_METHOD("unassoc_sta_lm_query", unassoc_sta_lm_query,
				unassoc_sta_lm_query_params),
		UBUS_METHOD("topology_query", topology_query,
				topology_query_params),
		UBUS_METHOD("cmd", cmd, cmd_params),
		UBUS_METHOD("higher_layer_data", higher_layer_data, higher_layer_data_params),
		UBUS_METHOD_NOARG("backhaul_info", agent_bk_info),
		UBUS_METHOD_NOARG("status", agent_status),
		UBUS_METHOD_NOARG("nodes", agent_nodes),
		UBUS_METHOD_NOARG("info", agent_info),
		UBUS_METHOD("assoc_notify", assoc_notify,
				assoc_notify_params),
#ifdef AGENT_SYNC_DYNAMIC_CNTLR_CONFIG
		UBUS_METHOD_NOARG("sync", sync_dyn_controller_config),
#endif
		UBUS_METHOD_NOARG("timers", agent_timers),
		UBUS_METHOD_NOARG("dynamic_backhaul_upgrade", agent_trigger_dynamic_upgrade),
		UBUS_METHOD_NOARG("backhaul_blacklist", agent_backhaul_blacklist),
#if (EASYMESH_VERSION > 2)
		UBUS_METHOD_NOARG("bss_config_request", bss_config_request),
#endif
	};

	int num_methods = ARRAY_SIZE(m);
	struct ubus_object_type *obj_type;
	struct ubus_method *obj_methods;
	struct ubus_object *obj;
	int ret;


	obj = &a->obj;
	memset(obj, 0, sizeof(*obj));

	obj_type = calloc(1, sizeof(struct ubus_object_type));
	if (!obj_type)
		return -1;

	obj_methods = calloc(num_methods, sizeof(struct ubus_method));
	if (!obj_methods) {
		free(obj_type);
		return -1;
	}

	obj->name = objname;
	memcpy(obj_methods, m, num_methods * sizeof(struct ubus_method));
	obj->methods = obj_methods;
	obj->n_methods = num_methods;

	obj_type->name = obj->name;
	obj_type->n_methods = obj->n_methods;
	obj_type->methods = obj->methods;
	obj->type = obj_type;

	ret = ubus_add_object(a->ubus_ctx, obj);
	if (ret) {
		err("Failed to add '%s' err = %s\n",
				objname, ubus_strerror(ret));
		free(obj_methods);
		free(obj_type);
		return ret;
	}

	info("Published '%s' object\n", objname);

	return ret;
}

void agent_remove_object(struct agent *a)
{
	if (a->ubus_ctx && a->obj.id != OBJECT_INVALID) {
		ubus_remove_object(a->ubus_ctx, &a->obj);
		free(a->obj.type);
		free((void *) a->obj.methods);
	}
}

void agent_notify_event(struct agent *a, void *ev_type, void *ev_data)
{
	struct blob_buf b;

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);
	if (ev_data)
		blobmsg_add_json_from_string(&b, (char *)ev_data);

	ubus_send_event(a->ubus_ctx, (char *)ev_type, b.head);
	blob_buf_free(&b);
}

