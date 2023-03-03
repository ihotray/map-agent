/*
 * agent_map.c - implements MAP2 CMDUs handling
 *
 * Copyright (C) 2019 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>

#include <linux/if_bridge.h>

#define AGENT_WIFI_IFACE_MAX_NUM 8
#define BSTA_STEER_TIMEOUT 7

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <uci.h>

#include "timer.h"

#include <i1905_wsc.h>
#ifdef AGENT_SYNC_DYNAMIC_CNTLR_CONFIG
#include <cntlrsync.h>
#endif

#include <cmdu.h>
#include <cmdu_ackq.h>
#include <1905_tlvs.h>
#include <easymesh.h>
#include <easy/easy.h>
#include <easy/utils.h>
#include <map_module.h>


//#include "map_module.h"
#include "utils/1905_ubus.h"
#include "utils/utils.h"
#include "utils/debug.h"
#include "utils/liblist.h"
#include "steer_rules.h"
#include "config.h"
#include "nl.h"
#include "agent.h"

#include "agent_cmdu.h"
#include "agent_tlv.h"

#include "wifi.h"
#include "agent_ubus.h"
#include "agent_map.h"
#include "cmdu_validate.h"
#include "backhaul.h"

#define UBUS_TIMEOUT            1000

/* TODO/FIXME: hardcoded 5 sec */
#define UTIL_THRESHOLD_TIMER	(5 * 1000)
/* TODO: Use UCI config instead */
#define UNA_STA_MEAS_TIMER (10 * 1000)
#define UNA_STA_MEAS_MAXTRIES 2

#define MAX_RADIO 20

struct channel_response {
	uint8_t radio_id[6];
	uint8_t response;
};

typedef int (*map_cmdu_handler_t)(void *agent, struct cmdu_buff *cmdu,
				  struct node *n);
typedef int (*map_cmdu_sendfunc_t)(void *agent, struct cmdu_buff *cmdu);

struct tlv *map_cmdu_get_tlv(struct cmdu_buff *cmdu, uint8_t type)
{
	struct tlv *t;

	if (!cmdu || !cmdu->cdata) {
		map_error = MAP_STATUS_ERR_CMDU_MALFORMED;
		return NULL;
	}

	t = cmdu_peek_tlv(cmdu, type);
	if (!t) {
		map_error = MAP_STATUS_ERR_CMDU_MALFORMED;
		return NULL;
	}

/*
	if (tlv_length(t) < tlv_minsize(type)) {
		map_error = MAP_STATUS_ERR_TLV_MALFORMED;
		return NULL;
	}
*/

	return t;
}

int send_topology_notification(void *agent, struct cmdu_buff *cmdu)
{
	return 0;
}

int send_topology_query(void *agent, uint8_t *origin)
{
	struct agent *a = (struct agent *) agent;
	struct cmdu_buff *cmdu;

	cmdu = agent_gen_topology_query(a, origin);
	if (!cmdu)
		return -1;

	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	return 0;
}

int send_topology_response(void *agent, struct cmdu_buff *cmdu)
{
	return 0;
}

int send_ap_autoconfig_search(void *agent, struct cmdu_buff *cmdu)
{
	return 0;
}

int send_ap_autoconfig_response(void *agent, struct cmdu_buff *cmdu)
{
	return 0;
}

int send_ap_autoconfig_wsc(void *agent, struct cmdu_buff *cmdu)
{
	return 0;
}

int send_1905_ack(void *agent, struct cmdu_buff *cmdu)
{
	return 0;
}

int send_ap_caps_report(void *agent, struct cmdu_buff *cmdu)
{
	return 0;
}

int send_channel_pref_report(void *agent, struct cmdu_buff *cmdu)
{
	return 0;
}

int send_oper_channel_report(void *agent, struct cmdu_buff *rx_cmdu)
{
	struct agent *a = (struct agent *) agent;
	struct cmdu_buff *cmdu;

	cmdu = agent_gen_oper_channel_response(a, NULL, 0, 0, 1);
	if (!cmdu)
		return -1;

	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	return 0;
}

int send_sta_steer_complete(void *agent, uint8_t *origin, const char *intf_name)
{
	trace("agent: %s: --->\n", __func__);

	struct agent *a = (struct agent *) agent;
	struct cmdu_buff *cmdu;
	uint16_t mid = 0;

	cmdu = cmdu_alloc_simple(CMDU_STEERING_COMPLETED, &mid);
	if (!cmdu) {
		dbg("%s: -ENOMEM\n", __func__);
		return -1;
	}

	memcpy(cmdu->origin, origin, 6);

	if (a->is_sta_steer_start) {
		/**
		 * Here we are sending the steering completed message
		 * so we need to reset all the values of the
		 * steering opportunity
		 */
		a->is_sta_steer_start = 0;
		a->sta_steerlist_count = 0;
		memset(a->sta_steer_list, 0, sizeof(a->sta_steer_list));
		/* stop the timer if it is running */
		timer_del(&a->sta_steer_req_timer);
	}

	cmdu_put_eom(cmdu);
	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	return 0;
}

int send_steer_btm_report(void *agent, uint8_t *origin, const char *intf_name,
		uint8_t *target_bssid, uint8_t *src_bssid,
		uint8_t *sta, uint8_t status_code)
{

	trace("agent: %s: --->\n", __func__);
	struct agent *a = (struct agent *) agent;
	struct cmdu_buff *cmdu;
	uint16_t mid = 0;
	int ret = 0, all_complete = 1;

	cmdu = cmdu_alloc_simple(CMDU_CLIENT_STEERING_BTM_REPORT, &mid);
	if (!cmdu) {
		dbg("%s: -ENOMEM\n", __func__);
		return -1;
	}

	memcpy(cmdu->origin, origin, 6);

	/* Clent Steering BTM Report TLV 17.2.30 */
	ret = agent_gen_steer_btm_report(a, cmdu, target_bssid,
			src_bssid, sta, status_code);
	if (ret) {
		cmdu_free(cmdu);
		return -1;
	}

	cmdu_put_eom(cmdu);
	ret = agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	trace("is_steer is %d steer count %d\n",
			a->is_sta_steer_start, a->sta_steerlist_count);

	/**
	 * Check that the report is sent for a steering opportunity.
	 * Here we store the status in the sta list and check
	 * if the steering completed message can be sent
	 */
	if (a->is_sta_steer_start) {
		int i;

		/* iterate list of clients attempted to be steered */
		for (i = 0; i < a->sta_steerlist_count; i++) {

			/* mark all steered clients as completed */
			ret = memcmp(sta, a->sta_steer_list[i].sta_mac, 6);
			if (ret == 0)
				a->sta_steer_list[i].complete = 1;
		}

		/**
		 * Now we need to check if the steering completed
		 * message can be sent
		 */
		for (i = 0; i < a->sta_steerlist_count; i++) {
			if (a->sta_steer_list[i].complete != 1) {
				all_complete = 0;
				break;
			}
		}

		if (all_complete) {
			/* Here we need to send the steering completed CMDU */
			send_sta_steer_complete(agent, origin, intf_name);
		}
	}

	return ret;
}

int send_sta_caps_report(void *agent, struct cmdu_buff *cmdu)
{
	return 0;
}

int send_ap_metrics_response(void *agent, struct cmdu_buff *rx_cmdu,
			     struct node *n)
{
	trace("%s: --->\n", __func__);
	struct cmdu_buff *cmdu;
	struct agent *a = (struct agent *)agent;

	cmdu = agent_gen_ap_metrics_response(a, rx_cmdu, n);
	if (!cmdu)
		return -1;

	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	return 0;
}

int send_sta_link_metrics_response(void *agent, struct cmdu_buff *cmdu)
{
	return 0;
}

int send_unassoc_sta_link_metrics_response(void *agent,
		struct netif_fh *fh, uint8_t opclass)
{
	struct agent *a = (struct agent *) agent;
	struct wifi_radio_element *radio;
	struct cmdu_buff *cmdu;
	uint16_t mid = 0;
	int ret = -1;

	dbg("agent: %s: --->\n", __func__);

	cmdu = cmdu_alloc_simple(CMDU_UNASSOC_STA_LINK_METRIC_RESPONSE, &mid);
	if (!cmdu) {
		dbg("%s: -ENOMEM\n", __func__);
		return -1;
	}

	memcpy(cmdu->origin, a->cntlr_almac, 6);
	radio = wifi_ifname_to_radio_element(a, fh->name);

	ret = agent_gen_tlv_unassoc_sta_lm_report(a, cmdu, opclass, radio);

	if (ret) {
		cmdu_free(cmdu);
		return -1;
	}

	cmdu_put_eom(cmdu);
	ret = agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	return ret;
}

int send_beacon_metrics_response(void *agent, uint8_t *sta_addr,
		uint8_t report_elems_nr, uint8_t *report_elem,
		uint16_t elem_len)
{
	struct cmdu_buff *response;
	struct agent *a = (struct agent *) agent;
	int ret = 0;

	trace("agent: %s: --->\n", __func__);

	response = agent_gen_cmdu_beacon_metrics_resp(a, sta_addr,
					report_elems_nr, report_elem, elem_len);

	if (!response)
		return -1;

	ret = agent_send_cmdu(a, response);
	cmdu_free(response);

	return ret;
}

int send_backhaul_sta_steer_response(void *agent, struct cmdu_buff *cmdu)
{
	return 0;
}

int send_channel_scan_report(void *agent, struct cmdu_buff *cmdu)
{
	return 0;
}

int send_sta_disassoc_stats(void *agent, struct cmdu_buff *cmdu)
{
	return 0;
}

int send_assoc_status_notification(void *agent, struct cmdu_buff *cmdu)
{
	return 0;
}

int send_tunneled_message(void *agent, struct cmdu_buff *cmdu)
{
	return 0;
}

int send_backhaul_sta_caps_report(void *agent, struct cmdu_buff *cmdu)
{
	return 0;
}

int send_failed_connection_msg(void *agent, uint8_t *sta, int status_code, int reason_code)
{
	struct cmdu_buff *cmdu = NULL;
	struct agent *a = (struct agent *)agent;

	cmdu = agent_gen_failed_connection(a, sta, status_code, reason_code);
	if (!cmdu)
		return -1;

	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	return 0;
}

#if (EASYMESH_VERSION > 2)
int send_bss_configuration_request(struct agent *agent)
{
	struct cmdu_buff *req_cmdu;
	int ret;

	req_cmdu = agent_gen_bss_configuration_request(agent);
	if (!req_cmdu) {
		dbg("%s: agent_gen_bss_configuration_request failed.\n", __func__);
		return -1;
	}

	memcpy(req_cmdu->origin, agent->cntlr_almac, sizeof(req_cmdu->origin));

	ret = agent_send_cmdu(agent, req_cmdu);
	if (ret == 0xffff) {
		ret = -1;
		dbg("%s: agent_send_cmdu failed.\n", __func__);
	} else {
		ret = 0;
		dbg("%s: bss configuration request sent.\n", __func__);
	}

	cmdu_free(req_cmdu);
	return ret;
}

int send_bss_configuration_result(struct agent *agent)
{
	struct cmdu_buff *result_cmdu;
	int ret;

	result_cmdu = agent_gen_bss_configuration_result(agent);
	if (!result_cmdu) {
		dbg("%s: agent_gen_bss_configuration_result failed.\n", __func__);
		return -1;
	}

	memcpy(result_cmdu->origin, agent->cntlr_almac, sizeof(result_cmdu->origin));
	ret = agent_send_cmdu(agent, result_cmdu);
	if (ret == 0xffff) {
		ret = -1;
		dbg("%s: agent_send_cmdu failed.\n", __func__);
	} else {
		ret = 0;
		dbg("%s: bss configuration result sent.\n", __func__);
	}

	cmdu_free(result_cmdu);
	return ret;
}
#endif //EASYMESH_VERSION > 2

#if 0
static const map_cmdu_sendfunc_t i1905txftable[] = {
	[0x01] = send_topology_notification,
	//[0x02] = send_topology_query,
	[0x03] = send_topology_response,
	[0x07] = send_ap_autoconfig_search,
	[0x08] = send_ap_autoconfig_response,
	[0x09] = send_ap_autoconfig_wsc,
};
#endif

#if 0
static const map_cmdu_sendfunc_t agent_maptxftable[] = {
	[0x00] = send_1905_ack,
	[0x02] = send_ap_caps_report,
	[0x05] = send_channel_pref_report,
	//[0x07] = send_channel_sel_response,
	[0x08] = send_oper_channel_report,
	[0x0a] = send_sta_caps_report,
	[0x0c] = send_ap_metrics_response,
	[0x0e] = send_sta_link_metrics_response,
	//[0x10] = send_unassoc_sta_link_metrics_response,
	//[0x12] = send_beacon_metrics_response,
	//[0x15] = send_steer_btm_report,
	//[0x17] = send_sta_steer_complete,
	[0x1a] = send_backhaul_sta_steer_response,
	[0x1c] = send_channel_scan_report,
	[0x22] = send_sta_disassoc_stats,
	[0x25] = send_assoc_status_notification,
	[0x26] = send_tunneled_message,
	[0x28] = send_backhaul_sta_caps_report,
	[0x33] = send_failed_connection_msg,
};
#endif


int handle_topology_discovery(void *agent, struct cmdu_buff *cmdu,
			     struct node *n)
{
	trace("%s: --->\n", __func__);
	struct agent *a = (struct agent *) agent;
	static const struct blobmsg_policy bk_attr[3] = {
		[0] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "backhaul_macaddr", .type = BLOBMSG_TYPE_STRING },
		[2] = { .name = "backhaul_device_id", .type = BLOBMSG_TYPE_STRING },
	};
	struct tlv *tv[2][16] = {0};
	int ret = -1;
	char ul_ifname[16] = {0};
	struct blob_buf bk = {0};
	struct blob_attr *tb[3];
	uint8_t almac[6] = {0};
	uint8_t hwaddr[6] = {0};
	struct tlv_aladdr *aladdr;
	struct tlv *t;

	t = map_cmdu_get_tlv(cmdu, TLV_TYPE_AL_MAC_ADDRESS_TYPE);
	if (!t) {
		dbg("|%s:%d| Malformed topology notification!\n", __func__,
		    __LINE__);
		return -1;
	}

	aladdr = (struct tlv_aladdr *) t->data;

	memcpy(almac, aladdr->macaddr, 6);

	if (hwaddr_is_zero(almac)) {
		trace("%s: Discard topology notification from aladdr = 0!\n",
			__func__);

		return -1;
	}

	n = agent_add_node(a, almac);
	if (!n) {
		err("|%s:%d| node allocation for "MACFMT" failed!\n",
		      __func__, __LINE__, MAC2STR(almac));
		return -1;
	}

	ret = map_cmdu_parse_tlvs(cmdu, tv, 2, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return -1;
	}


	memcpy(hwaddr, tv[1][0]->data, 6);

	blob_buf_init(&bk, 0);

        if (!blobmsg_add_json_from_file(&bk, MAP_UPLINK_PATH)) {
		dbg("|%s:%d| Failed to parse %s\n", __func__, __LINE__,
				MAP_UPLINK_PATH);
		goto out;
        }

	blobmsg_parse(bk_attr, 3, tb, blob_data(bk.head), blob_len(bk.head));
	if (!tb[0])
		goto out;

	strncpy(ul_ifname, blobmsg_data(tb[0]), IFNAMSIZ);

	if (!strncmp(ul_ifname, cmdu->dev_ifname, IFNAMSIZ)) {
		memcpy(a->ul_dev.ul_almac, almac, 6);
		memcpy(a->ul_dev.ul_hwaddr, hwaddr, 6);

		if (!tb[1] || !tb[2]) {
			runCmd("/lib/wifi/multiap set_uplink_backhaul_info "
					MACFMT " " MACFMT,
					MAC2STR(a->ul_dev.ul_almac),
					MAC2STR(a->ul_dev.ul_hwaddr));
		}
	}

out:
	blob_buf_free(&bk);
	return ret;
}

int handle_topology_notification(void *agent, struct cmdu_buff *cmdu,
				 struct node *n)
{
	struct agent *a = (struct agent *) agent;
	uint8_t almac[6] = {0};
	struct tlv_aladdr *aladdr;
	struct tlv *t;
	trace("%s: --->\n", __func__);

	t = map_cmdu_get_tlv(cmdu, TLV_TYPE_AL_MAC_ADDRESS_TYPE);
	if (!t) {
		dbg("|%s:%d| Malformed topology notification!\n", __func__,
		    __LINE__);
		return -1;
	}

	aladdr = (struct tlv_aladdr *) t->data;

	memcpy(almac, aladdr->macaddr, 6);

	if (hwaddr_is_zero(almac)) {
		trace("%s: Discard topology notification from aladdr = 0!\n",
			__func__);

		return -1;
	}

	n = agent_add_node(a, almac);
	if (!n) {
		err("|%s:%d| node allocation for "MACFMT" failed!\n",
		      __func__, __LINE__, MAC2STR(almac));
		return -1;
	}


#if 0
	ret = map_cmdu_parse_tlvs(cmdu, tv, 2, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return -1;
	}
#endif
	return 0;
}

int handle_topology_query(void *agent, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	struct cmdu_buff *resp;
	struct agent *a = (struct agent *) agent;

#if 0 // Disable due to ieee1905 topology plugin sending without profile
	agent_set_link_profile(a, n, cmdu);
#endif
	resp = agent_gen_topology_response(a, cmdu->origin, cmdu_get_mid(cmdu));
	if (!resp)
		return -1;

	if (hwaddr_is_zero(resp->origin)) {
		memcpy(resp->origin, cmdu->dev_macaddr, 6);
		strncpy(resp->dev_ifname, cmdu->dev_ifname, 15);
	}

	agent_send_cmdu(agent, resp);
	cmdu_free(resp);

	return 0;
}

/* 9.4.2.37 - Neighbor Report El.: BSID Information field */
static uint32_t get_basic_bssid_info(struct netif_fh *fh)
{
	trace("%s: --->\n", __func__);

	uint32_t bssid_info = 0; /* IEEE 802.11-2016 9.4.2.37 */

	/* AP Reachability: 3 - Reachable */
	agent_bssid_info_set(bssid_info, BSSID_INFO_REACHABILITY_B0);
	agent_bssid_info_set(bssid_info, BSSID_INFO_REACHABILITY_B1);

	/* Security: 1 - AP supports same provisioning */
	agent_bssid_info_set(bssid_info, BSSID_INFO_SECURITY);

	/* Key Scope: 1 - AP has the same authenticator */
	agent_bssid_info_set(bssid_info, BSSID_INFO_KEY_SCOPE);

	/* Capabilities: Spectrum Management: 0 */
	// agent_bssid_info_set(bssid_info, BSSID_INFO_CAP_SPECTRUM_MGMT);

	/* Capabilities: QoS */
	if (fh->caps.wmm) /* assuming same across whole mesh */
		agent_bssid_info_set(bssid_info, BSSID_INFO_CAP_WMM);

	/* Capabilities: APSD: 0 */
	// agent_bssid_info_set(bssid_info, BSSID_INFO_CAP_APSD);

	/* Capabilities: Radio Measurement: 1 */
	agent_bssid_info_set(bssid_info, BSSID_INFO_CAP_RADIO_MEAS);

	/* Capabilities: Delayed Block Ack: 0 */
	// agent_bssid_info_set(bssid_info, BSSID_INFO_CAP_DELAYED_BA);

	/* Capabilities: Immediate Block Ack: 0 */
	// agent_bssid_info_set(bssid_info, BSSID_INFO_CAP_IMMEDIATE_BA);

	/* Mobility Domain: 0 */
	// agent_bssid_info_set(bssid_info, BSSID_INFO_MOBILITY_DOMAIN);

	/* HT & VHT will be updated based on AP capabilities exchange */

	/* Fine Timing Measurement Responder field: 0 */
	// agent_bssid_info_set(bssid_info, BSSID_INFO_FMT);

	return bssid_info;
}

static int neighbor_list_add(struct netif_fh *fh, struct nbr *nbr,
				uint8_t *radio_mac)
{
	struct neighbor *new;

	/* add new neighbor node */
	new = malloc(sizeof(struct neighbor));
	if (!new) {
		warn("OOM: neighbor entry malloc failed!\n");
		return -1;
	}
	memset(new, 0, sizeof(struct neighbor));
	memcpy(new->nbr.bssid, nbr->bssid, 6);
	new->nbr.bssid_info = nbr->bssid_info;
	new->nbr.reg = nbr->reg;
	new->nbr.channel = nbr->channel;
	new->nbr.phy = nbr->phy;
	timestamp_update(&new->tsp);
	new->flags &= ~NBR_FLAG_DRV_UPDATED;
	if (radio_mac)
		memcpy(new->radio_mac, radio_mac, 6);
	list_add(&new->list, &fh->nbrlist);
	/* keep number of neighbors up to date */
	fh->nbr_nr++;

	return 0;
}

static int maybe_add_neighbor(struct agent *a,
		struct netif_fh *fh, uint8_t *bssid, uint8_t *radio_mac)
{
	dbg("|%s:%d| adding neighbor " MACFMT " for %s\n",
	    __func__, __LINE__, MAC2STR(bssid), fh->name);

	struct nbr nbr = { 0 };
	struct neighbor *n = NULL;
	struct wifi_radio_element *r;
	int added = 0;

	list_for_each_entry(n, &fh->nbrlist, list) {
		if (!memcmp(n->nbr.bssid, bssid, 6)) {
			/* bss already on the nbrlist, refresh last seen */
			timestamp_update(&n->tsp);
			added = 0; /* none added */
			goto out;
		}
	}

	/* add new neighbor to the nbrlist & fill in basic info */
	memcpy(nbr.bssid, bssid, 6);

	/* basic bssid info - will get updated later from AP caps, etc */
	nbr.bssid_info = get_basic_bssid_info(fh);

	/* Opclass & channel */
	r = wifi_get_radio_by_mac(a, radio_mac);
	if (r) {
		/* own radio */
		nbr.reg = r->current_opclass;
		nbr.channel = r->current_channel;
	} else {
		/* use scanresults if present, each consecutive radio scan
		 * will also cause update of reg & chan of neighbor list entries
		 */
		nbr.reg = 0;
		nbr.channel = 0;
		r = wifi_radio_to_radio_element(a, fh->radio_name);
		if (r)
			update_neighbors_from_scanlist(a, r);
	}

	/* Assume OFDM, will update to HT/VHT/HE based on AP caps */
	nbr.phy = PHY_OFDM;

	/* Add to the nbrlist */
	added = !!neighbor_list_add(fh, &nbr, radio_mac);

	if (added)
		reschedule_nbrlist_update(fh);

out:
	return added;
}

static int agent_send_ap_caps_query(struct agent *a, uint8_t *origin)
{
	struct cmdu_buff *resp;

	resp = agent_gen_ap_caps_query(a, origin);

	if (!resp)
		return -1;

	agent_send_cmdu(a, resp);
	cmdu_free(resp);

	return 0;
}

int handle_topology_response(void *agent, struct cmdu_buff *cmdu,
			     struct node *n)
{
	trace("%s: --->\n", __func__);

	struct agent *a = (struct agent *) agent;
	struct tlv *tv[12][16] = {0};

	agent_set_link_profile(a, n, cmdu);

	if (!validate_topology_response(cmdu, tv, n->map_profile)) {
		dbg("cmdu validation: [TOPOLOGY_RESPONSE] failed\n");
		return -1;
	}

	if (tv[7][0]) {
		struct tlv_ap_oper_bss *tlv;
		uint8_t *tv_data;
		uint16_t i, offset = 0;
		int updated = 0;

		tlv = (struct tlv_ap_oper_bss *)tv[7][0]->data;
		if (!tlv)
			return -1;
		tv_data = (uint8_t *)tlv;

		offset += 1; /* num_radio */

		for (i = 0; i < tlv->num_radio; i++) {
			uint8_t num_bss = 0;
			uint8_t radio_id[6];
			int j;

			memcpy(radio_id, &tv_data[offset], 6);

			/* TODO: revisit (BSSes from own radio) */

			offset += 6; /* hw macaddr */

			memcpy(&num_bss, &tv_data[offset], 1);

			offset += 1; /* num_bss */
			for (j = 0; j < num_bss; j++) {
				uint8_t ssidlen = 0, len = 0;
				uint8_t bssid[6];
				struct netif_fh *fh = NULL;
				char ssid[33] = {0};

				memcpy(bssid, &tv_data[offset], 6);

				/* TODO: check bssid is a valid hwaddr */

				offset += 6; /* bssid */

				memcpy(&ssidlen, &tv_data[offset], 1);

				offset += 1; /* ssidlen */

				memset(ssid, 0, sizeof(ssid));
				len = (ssidlen > sizeof(ssid) - 1
					? sizeof(ssid) - 1 : ssidlen);

				memcpy(ssid, &tv_data[offset], len);

				offset += ssidlen; /* ssid */

				list_for_each_entry(fh, &a->fhlist, list) {
					uint8_t maxlen = 0;

					maxlen = (strlen(fh->ssid) > len ?
						   strlen(fh->ssid) : len);
					if (!strncmp(ssid, fh->ssid, maxlen)) {
						dbg("|%s:%d| add neighbor " MACFMT "\n",
						    __func__, __LINE__, MAC2STR(bssid));
						updated += maybe_add_neighbor(a, fh,
							bssid, radio_id);
					}
				}

				backhaul_mod_blacklist(a, cmdu->dev_ifname, ssid, len, bssid);
				/* TODO: add bh neighbors for bsta steering */
			}
		}

		if (updated) {
			/* At least one neighbor added for current fh */

			/* Query sender for AP capability to update bssid_info */
			agent_send_ap_caps_query(a, cmdu->origin);

			/* TODO: query for phy, channel and reg domain here */
		}
	}

	return 0;
}


int handle_vendor_specific(void *agent, struct cmdu_buff *rx_cmdu,
			   struct node *n)
{
	trace("%s: --->\n", __func__);
#if 0
	struct agent *a = (struct agent *) agent;
	struct tlv_vendor_specific *p;
	time_t now;
	uint8_t depth = 2;

	time(&now);
	p = extract_tlv_by_type(rec_cmdu, TLV_TYPE_VENDOR_SPECIFIC);
	if (!p)
		return -1;

	trace("|%s:%d| num_tlvs = %d, type = %02x, len = %04x%04x, value = %d\n", __func__, __LINE__, (uint8_t) p->m[0], (uint8_t)p->m[1], (uint16_t)p->m[2], p->m[3], (uint8_t)p->m[4]);

	depth = p->m[4];

	/* no action if it is not known vendor-oui */
	if (memcmp(p->vendor_oui, EASYMESH_VENDOR_EXT_OUI, 3))
		return -1;

	trace("|%s:%d| iopsys vendor oui CMDU received %02x%02x%02x\n", __func__, __LINE__, p->vendor_oui[0], p->vendor_oui[1], p->vendor_oui[2]);

	/* no action if it is local rec_cmdu */
	if (!memcmp(a->almac, rec_cmdu->origin, 6))
		return -1;

	trace("|%s:%d| rec_cmdu->id = %d, rx_id = %d, tx_id = %d\n", __func__, __LINE__, rec_cmdu->message_id, a->loop_detection.rx_mid, a->loop_detection.tx_mid);
	if (rec_cmdu->message_id == a->loop_detection.rx_mid && depth > a->depth) {
		trace("|%s:%d| LOOP DETECTED\n", __func__, __LINE__);
		if (difftime(now, a->loop_detection.rx_time) < 3) {
			trace("|%s:%d| LOOP DETECTED WITHIN TIME FRAME LIMIT OF 3(s)\n", __func__, __LINE__);
			struct cmdu_cstruct *cmdu;

			cmdu = agent_gen_vendor_specific_cmdu(a, rec_cmdu->origin, a->depth);
			if (cmdu) {
				trace("|%s:%d| TRIGGERED LOOP DETECTION RESPONSE\n", __func__, __LINE__);
				cmdu->message_id = rec_cmdu->message_id;
				agent_send_cmdu(a, cmdu);
				map_free_cmdu(cmdu);
			}

		}
	} else if (rec_cmdu->message_id == a->loop_detection.tx_mid) {
		struct netif_bk *bk;
		bool reload = false;

		trace("|%s:%d| Received response, loop has been detected! Disable bSTAs\n", __func__, __LINE__);

		list_for_each_entry(bk, &a->bklist, list) {
			if (!config_disable_bsta(bk->cfg))
				reload = true;

			wifi_mod_bridge(a, bk->name, "remove");
		}

		if (reload)
			uci_reload_services("wireless");
	}

	a->loop_detection.rx_time = now;
	a->loop_detection.rx_mid = rec_cmdu->message_id;
#endif
	return 0;
}

#define CTRL_MAC_ERROR		-1
#define CTRL_MAC_OLD		0
#define CTRL_MAC_NEW		1

static int agent_update_controller_data(struct agent *a, struct cmdu_buff *cmdu)
{
	int ret = CTRL_MAC_OLD;
	char mac_str[18] = {0};

	dbg("cntlr_almac " MACFMT " origin " MACFMT " self " MACFMT "\n",
			MAC2STR(a->cntlr_almac),
			MAC2STR(cmdu->origin),
			MAC2STR(a->almac));

	a->active_cntlr = true;
	a->multiple_cntlr = false;

	if (is_local_cntlr_available()
			&& is_local_cntlr_running()
			&& memcmp(cmdu->origin, a->almac, 6)) {

		/* Local controller running and cmdu is not from self */

		if (a->cntlr_select.local) {
			/* Only notify multiple detected Controller to user.
			 * Do not update the Controller-ID and the timestamp.
			 */
			a->multiple_cntlr = true;
			wifiagent_log_cntlrinfo(a);
			return CTRL_MAC_OLD;
		} else {
			/* If a MAP controller is running in its own device, and local = false,
			 * then stop the local Controller once other is detected.
			 */
			agent_disable_local_cntlr(a);
		}
	}

	/* Expect autoconfig from self if a primary cntlr runs on own device */
	if (a->cntlr_select.local == false
			|| !memcmp(cmdu->origin, a->almac, 6)) {

		/* Update the Controller-ID and the last-seen timestamp. */
		timestamp_update(&a->observed_time);

		/* if it is a new controller, update cntlr_almac and uci */
		if (memcmp(a->cntlr_almac, cmdu->origin, 6)) {
			memcpy(a->cntlr_almac, cmdu->origin, 6);
			if (!hwaddr_ntoa(a->cntlr_almac, mac_str))
				return CTRL_MAC_ERROR;

			set_value_by_string("mapagent",
					"agent",
					"controller_macaddr",
					mac_str, UCI_TYPE_STRING);

			ret = CTRL_MAC_NEW;
		}
	}

	return ret;
}

#define MAX_IMMEDIATE_AUTOCFG_DELAY 3
static void agent_trigger_immediate_autocfg(struct agent *a)
{
	int remaining = timer_remaining_ms(&a->autocfg_dispatcher);

	if (remaining > (MAX_IMMEDIATE_AUTOCFG_DELAY * 1000) || remaining < 0) { /* ms */
		/* slight delay to allow local controller to have time to teardown */
		dbg("|%s:%d| Scheduling AP-Autoconfig search in 1 second\n",
				__func__, __LINE__);
		timer_set(&a->autocfg_dispatcher, 1 * 1000);
	}
}

int handle_ap_autoconfig_search(void *agent, struct cmdu_buff *rx_cmdu,
				struct node *n)
{
	trace("agent: %s: --->\n", __func__);
	struct agent *a = (struct agent *) agent;
	bool cntlr = false;
	int i;
	uint8_t almac[6] = {0};
	struct tlv *tv[7][16] = {0};
	struct tlv_aladdr *aladdr;
	struct tlv *t;

	t = map_cmdu_get_tlv(rx_cmdu, TLV_TYPE_AL_MAC_ADDRESS_TYPE);
	if (!t) {
		dbg("|%s:%d| Malformed topology notification!\n", __func__,
		    __LINE__);
		return -1;
	}

	aladdr = (struct tlv_aladdr *) t->data;

	memcpy(almac, aladdr->macaddr, 6);

	if (hwaddr_is_zero(almac)) {
		trace("%s: Discard topology notification from aladdr = 0!\n",
			__func__);

		return -1;
	}

	n = agent_add_node(a, almac);
	if (!n) {
		err("|%s:%d| node allocation for "MACFMT" failed!\n",
		      __func__, __LINE__, MAC2STR(almac));
		return -1;
	}

	agent_set_link_profile(a, n, rx_cmdu);

	if (!validate_ap_autoconfig_search(rx_cmdu, tv, n->map_profile)) {
		dbg("cmdu validation: [AP_AUTOCONFIG_SEARCH] failed\n");
		return -1;
	}

	/* Discard autoconfig search in case it's been sent by ourself */
	for (i = 0; i < a->num_radios; i++) {
		if (a->radios[i].mid == cmdu_get_mid(rx_cmdu)) {
			trace("%s %d skip handling autoconfig sent by self\n",
					__func__, __LINE__);
			return -1;
		}
	}

	if (tv[3][0]) {
		for (i = 1; i <= tv[3][0]->data[0]; i++) {
			if (tv[3][0]->data[i] == SUPPORTED_SERVICE_MULTIAP_CONTROLLER)
				cntlr = true;
			else if (tv[3][0]->data[i] == SUPPORTED_SERVICE_MULTIAP_AGENT)
				/* send topology query to the agent to get oper bss */
				send_topology_query(a, almac);
		}
	}

	if (cntlr) {
		if (agent_update_controller_data(a, rx_cmdu) == CTRL_MAC_NEW) {
			dbg("|%s:%d| new controller found!"\
					" Activate autoconfig configuration"\
					" for all radios\n",
					__func__, __LINE__);

			for (i = 0; i < a->num_radios; i++)
				a->radios[i].state = AUTOCFG_ACTIVE;

			/* Report status of the new map controller to user */
			wifiagent_log_cntlrinfo(a);

			if (!a->cntlr_select.local) {
				/* New, non-local controller found: trigger
				 * autoconfig immediatelly for fast reconfiguration
				 */
				dbg("|%s:%d| Triggering immediate autoconfig search\n",
						__func__, __LINE__);
				agent_trigger_immediate_autocfg(a);
			}
		}
	}

	return 0;
}

static void agent_reschedule_heartbeat_autocfg(struct agent *a, uint16_t interval)
{
	uint16_t remaining, elapsed = 0;
	int i;

	/* don't modify interval if there is an active radio */
	if (a->autocfg_interval < interval) {
		for (i = 0; i < a->num_radios; i++) {
			if (a->radios[i].state == AUTOCFG_ACTIVE)
				return;
		}
	}

	if (a->autocfg_interval == interval)
		return;

	remaining = timer_remaining_ms(&a->autocfg_dispatcher);
	remaining /= 1000; /* seconds */

	if (a->autocfg_interval > remaining)
		elapsed = a->autocfg_interval - remaining;

	a->autocfg_interval = interval;

	dbg("|%s:%d| Rescheduling autoconfig in %u seconds\n",
			__func__, __LINE__, a->autocfg_interval - elapsed);

	timer_set(&a->autocfg_dispatcher,
			(a->autocfg_interval - elapsed) * 1000);
}

int handle_ap_autoconfig_response(void *agent, struct cmdu_buff *rx_cmdu,
				  struct node *n)
{
	trace("agent: %s: --->\n", __func__);
	struct agent *a = (struct agent *) agent;
	struct wifi_radio_element *radio = NULL;
	struct tlv *tv[7][16] = {0};
	bool cntlr = false;
	uint8_t band;
	int i;
	struct cmdu_buff *resp;

	agent_set_link_profile(a, n, rx_cmdu);

	if (!validate_ap_autoconfig_response(rx_cmdu, tv, n->map_profile)) {
		dbg("cmdu validation: [AP_AUTOCONFIG_RESPONSE] failed\n");
		return -1;
	}

#ifdef EASYMESH_R2_CERT
	resp = agent_gen_topology_discovery(a);
	if (resp) {
		agent_send_cmdu(a, resp);
		cmdu_free(resp);
	}
#endif

	if (hwaddr_is_zero(rx_cmdu->origin)) {
		dbg("|%s:%d| origin is zeroed out, drop response\n", __func__,
				__LINE__);
		return -1;
	}

	/* If MID is not the one we sent, discard response */
	for (i = 0; i < a->num_radios; i++) {
		trace("radio %s has mid %d\n", a->radios[i].name, a->radios[i].mid);
		if (a->radios[i].mid != cmdu_get_mid(rx_cmdu))
			continue;

		radio = &a->radios[i];
		break;
	}
	if (!radio) {
		dbg("autoconfig response mid did not match!\n");
		return -1;
	}

	if (tv[2][0]) {
		for (i = 0; i < tv[2][0]->data[0]; i++) {
			if (tv[2][0]->data[(i+1)] == SUPPORTED_SERVICE_MULTIAP_CONTROLLER) {
				cntlr = true;
				break;
			}
		}
	}
	if (!cntlr) {
		dbg("autoconfig response does not support controller!\n");
		return -1;
	}

	dbg("cntlr_almac " MACFMT " origin " MACFMT "\n",
			MAC2STR(a->cntlr_almac), MAC2STR(rx_cmdu->origin));

	if (agent_update_controller_data(a, rx_cmdu) == CTRL_MAC_NEW) {
		dbg("|%s:%d| new controller found! Activate autoconfiguration"\
				" for all radios\n", __func__, __LINE__);

		for (i = 0; i < a->num_radios; i++)
			a->radios[i].state = AUTOCFG_ACTIVE;

		/* report status of the new map controller to user */
		wifiagent_log_cntlrinfo(a);
	}

	if (radio->state == AUTOCFG_ACTIVE) {
		struct tlv_supported_band *data;
		uint16_t mid;

		if (a->cntlr_select.local == true &&
				memcmp(rx_cmdu->origin, a->almac, 6)) {
			dbg("|%s:%d| local set in controller_select - don't"\
					"trigger WSC with "\
					"non-local controller\n",
					__func__, __LINE__);
			/* local cntlr enforced: don't WSC with non-local one */
			return -1;
		}

#if 0
		if (radio->dedicated_backhaul) {
			dbg("|%s:%d| don't trigger WSC for dedicated backhaul,"\
					"setting radio to heartbeat\n",
					__func__, __LINE__);
			return -1;
		}
#endif

		data = (struct tlv_supported_band *) tv[1][0]->data;

		band = wifi_band_to_ieee1905band(radio->band);
		if (band != data->band)
			return -1;

		dbg("|%s:%d| generate wsc for radio %s\n", __func__, __LINE__,
				radio->name);

		resp = agent_gen_ap_autoconfig_wsc(a, rx_cmdu, radio);
		if (!resp)
			return -1;

		mid = agent_send_cmdu(a, resp);
		if (mid) {
			radio->wsc_mid = mid;
			trace("assigned radio mid %d %d\n", radio->wsc_mid, mid);
		}
		cmdu_free(resp);
		agent_reschedule_heartbeat_autocfg(a, a->cntlr_select.probe_int);
	} else if (radio->state == AUTOCFG_HEARTBEAT) {
		/* heartbeat from controller - no activity */
		dbg("|%s:%d| Received autoconfig search response from" \
				" controller during heartbeat\n", __func__, __LINE__);
		/* Autoconfig answered - increase search interval if needed */
		agent_reschedule_heartbeat_autocfg(a, HEARTBEAT_AUTOCFG_INTERVAL);
	}

	return 0;
}

int wifi_get_radio_index_by_mac(struct agent *a,
		uint8_t *hwaddr)
{
	struct wifi_radio_element *radio;
	int i;

	for (i = 0; i < a->num_radios; i++) {
		radio = a->radios + i;

		if (memcmp(radio->macaddr, hwaddr, 6))
			continue;

		return i;
	}

	return -1;
}

int wifi_teardown_iface(const char *ifname)
{
	char fmt[128] = {0};

	snprintf(fmt, sizeof(fmt), "teardown_iface %s", ifname);
	agent_exec_platform_scripts(fmt);

	dbg("|%s:%d|Disabled interface %s\n", __func__, __LINE__, ifname);
	return 0;
}

int wifi_teardown_map_ifaces_by_radio(struct agent *a, char *device)
{
	struct netif_fhcfg *fh, *fh_tmp;

	list_for_each_entry_safe(fh, fh_tmp, &a->cfg.fhlist, list) {
		struct netif_fh *f;

		if (strncmp(fh->device, device, sizeof(fh->device) - 1))
			continue;

		wifi_teardown_iface(fh->name);
		f = get_netif_by_name(a, fh->name);
		if (f)
			f->torndown = true;
	}

	agent_config_reload(a);
	return 0;
}

int wifi_teardown_map_ifaces_by_band(struct agent *a, enum wifi_band band)
{
	struct netif_fhcfg *fh = NULL, *fh_tmp;

	list_for_each_entry_safe(fh, fh_tmp, &a->cfg.fhlist, list) {
		if (fh->band != band)
			continue;

		wifi_teardown_iface(fh->name);
		clean_fh(fh);
	}

	agent_config_reload(a);
	return 0;
}

/* return true if valid ifname is available */
int check_wireless_ifname(struct agent *a, const char *device,
		const char *ifname)
{
	enum {
		W_IFNAME,
		W_DEV,
		NUM_POLICIES
	};
	const struct uci_parse_option opts[] = {
		{ .name = "ifname", .type = UCI_TYPE_STRING },
		{ .name = "device", .type = UCI_TYPE_STRING }
	};
	struct uci_option *tb[NUM_POLICIES];
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_element *e;
	bool rv = false;
	int num_ifs = 0;

	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	if (uci_load(ctx, "wireless", &pkg)) {
		uci_free_context(ctx);
		return -1;
	}

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (strncmp(s->type, "wifi-iface", strlen("wifi-iface")))
			continue;

		uci_parse_section(s, opts, NUM_POLICIES, tb);

		if (tb[W_DEV]) {
			const char *cfg_dev;

			cfg_dev = tb[W_DEV]->v.string;
			if (!strncmp(cfg_dev, device, IFNAMSIZ))
				num_ifs++;
		}

		/* TODO: should work with 16 instead of 8 */
		if (num_ifs >= AGENT_WIFI_IFACE_MAX_NUM) {
			rv = true;
			break;
		}

		if (tb[W_IFNAME]) {
			char *cfg_ifname;

			cfg_ifname = tb[W_IFNAME]->v.string;
			if (!strncmp(cfg_ifname, ifname, IFNAMSIZ)) {
				rv = true;
				break;
			}
		}
	}

	uci_free_context(ctx);
	return rv;
}

/* return ifname buffer */
char *wifi_gen_first_ifname(struct agent *a, char *device, char *ifname)
{
	int i;
	uint8_t devnum = get_device_num_from_name(device);

	/* TODO: should work with 16 instead of 8 */
	for (i = 0; i <= AGENT_WIFI_IFACE_MAX_NUM; i++) {

		config_calc_ifname(&a->cfg, devnum, i, ifname);

		if (!check_wireless_ifname(a, device, ifname))
			return ifname;
	}

	return NULL;
}

/* return ifname buffer */
struct netif_fh *wifi_ssid_to_ifname(struct agent *a, char *device,
					char *ssid, char *ifname)
{
	struct netif_fh *fh = NULL;

	list_for_each_entry(fh, &a->fhlist, list) {
		if (!fh->torndown)
			continue;

		if (!fh->cfg)
			continue;

		if (strncmp(fh->cfg->device, device, IFNAMSIZ))
			continue;

		if (strncmp(fh->cfg->ssid, ssid, 32))
			continue;

		strncpy(ifname, fh->name, IFNAMSIZ - 1);
		return fh;
	}

	return NULL;
}

/* return ifname buffer */
struct netif_fh *wifi_get_first_available_ifname(struct agent *a, char *device, char *ifname)
{
	struct netif_fh *fh = NULL;

	list_for_each_entry(fh, &a->fhlist, list) {
		if (!fh->torndown)
			continue;

		if (fh->cfg && strncmp(fh->cfg->device, device, IFNAMSIZ))
			continue;

		strncpy(ifname, fh->name, IFNAMSIZ - 1);
		return fh;
	}

	return NULL;
}

int agent_free_wsc_vendor_ies(struct wsc_ext *exts)
{
	struct wsc_vendor_ie *ext;
	int i;

	for (i = 0; i < exts->num_ven_ies; i++) {
		ext = &exts->ven_ies[i];
		if (ext->len)
			free(ext->payload);
	}

	exts->num_ven_ies = 0;

	return 0;
}

int agent_add_wsc_exts(struct wsc_ext *exts, uint8_t *oui, uint8_t len,
		       uint8_t *payload)
{
	struct wsc_vendor_ie *ext;

	if (exts->num_ven_ies >= VEN_IES_MAX)
		return -1;

	ext = &exts->ven_ies[exts->num_ven_ies];

	if (len && payload) {
		ext->payload = calloc(1, len);
		if (!ext->payload)
			return -1;

		memcpy(ext->payload, payload, len);
		ext->len = len;
	}

	memcpy(ext->oui, oui, 3);
	exts->num_ven_ies++;
	return 0;
}

int wsc_get_exts(uint8_t *msg, uint16_t msglen, struct wsc_ext *exts)
{
	uint8_t *p;
	uint8_t *msg_end;
#ifdef EASYMESH_VENDOR_EXT
#define ATTR_ENABLED (0x4C) /* IOPSYS m2 vendor extension */
#endif
	if (!msg || msglen == 0 || !exts)
		return 0;

	p = msg;
	msg_end = msg + msglen;

	while (labs(p - msg) < msglen - 4) {
		uint16_t attr_type;
		uint16_t attr_len;

		attr_type = buf_get_be16(p);
		p += 2;
		attr_len = buf_get_be16(p);
		p += 2;

		if (p + attr_len > msg_end)
			return -1;

		if (attr_type == ATTR_VENDOR_EXTENSION) {
			uint8_t id[3] = {0};
			uint8_t *end_of_ext;

			/* May be one or more subelements (Section 12 of WSC spec) */
			end_of_ext = p + attr_len;

			while (p < end_of_ext) {
				memcpy(id, p, sizeof(id));
				p += 3;
				attr_len -= 3;

				agent_add_wsc_exts(exts, (uint8_t *)id, attr_len, p);
#ifdef EASYMESH_VENDOR_EXT
				if (!memcmp(id, EASYMESH_VENDOR_EXT_OUI, 3)) {
					uint8_t subelem;
					uint8_t len;

					memcpy(&subelem, p, 1);
					p += 1;
					attr_len -= 1;

					memcpy(&len, p, 1);
					p += 1;
					attr_len -= 1;

					if (subelem == ATTR_ENABLED)
						memcpy(&exts->enabled, p, len);

					p += len;
					attr_len -= len;
				} else
#endif /*EASYMESH_VENDOR_EXT*/
					break;
			}
		}

		p += attr_len;
	}

	return 0;
}

void agent_autoconfig_event(struct agent *a, char *radio, char *status,
		char *reason)
{
	char data[128] = { 0 };

	snprintf(data, sizeof(data), "{"\
			"\"ifname\":\"%s\","\
			"\"event\":\"ap-autoconfiguration\","\
			"\"data\": {"\
				"\"status\":\"%s\","\
				"\"reason\":\"%s\""\
			"}"\
		"}", radio, status, reason);

	agent_notify_event(a, "wifi.radio", data);

	snprintf(data, sizeof(data), "{"\
			"\"radio\":\"%s\","\
			"\"event\":\"ap-autoconfiguration\","\
			"\"data\": {"\
				"\"status\":\"%s\","\
				"\"reason\":\"%s\""\
			"}"\
		"}", radio, status, reason);
	agent_notify_event(a, "map.agent", data);
}

/* TODO: vlan bridge and logical ethernet interface names hardcoded for now */
#define VLAN_BRIDGE "map"
#define VLAN_IFACE  "lei"
#if 0	// handled by init script now
/* Set up Multi-AP subsystem separation */
int agent_prepare_traffic_separation(struct agent *a)
{
	trace("%s: --->\n", __func__);
	struct netif_fh *fh;
	struct netif_bk *bk;

	a->ts.setup = true;

	/* TODO: streamline for efficiency */

	if (uci_set_bridge("network", VLAN_BRIDGE, "static", NULL)) {
		info("Error seting up bridge for Traffic Separation!\n");
		return -1;
	}
	dbg("|%s:%d| bridge \"%s\" added => reloading network config\n",
	    __func__, __LINE__, VLAN_BRIDGE);

	list_for_each_entry(fh, &a->fhlist, list) {
		uci_set_wireless_interface_option("wireless", "wifi-iface",
						  "ifname", fh->name,
						  "network", VLAN_BRIDGE);
	}
	list_for_each_entry(bk, &a->bklist, list) {
		uci_set_wireless_interface_option("wireless", "wifi-iface",
						  "ifname", bk->name,
						  "network", VLAN_BRIDGE);
	}
	dbg("|%s:%d| wifi interfaces moved to bridge \"%s\" => reloading wireless config\n",
	    __func__, __LINE__, VLAN_BRIDGE);

	uci_reload_services("network");

	return 0;
}
#endif

static inline bool is_vid_valid(unsigned int vid)
{
#if 0
	dbg("%s: vid %u\n", __func__,  vid);

	if (vid > TS_VID_INVALID)
		abort();
#endif
	return (vid < TS_VID_INVALID) && (vid > 0);
}

/* Set up Traffic Separation rules */
int agent_apply_traffic_separation(struct agent *a)
{
	struct agent_config *cfg;
	struct policy_cfg *c;

	trace("%s: --->\n", __func__);

	if (!a)
		return -1;

	cfg = &a->cfg;
	if (!cfg) {
		err("%s:%d - missing configuration!\n", __func__, __LINE__);
		return -1;
	}

	c = cfg->pcfg;
	if (!c) {
		err("%s:%d - missing policy configuration!\n", __func__, __LINE__);
		return -1;
	}

	if (c->pvid == 0)
		return 0;

	if (!is_vid_valid(c->pvid)) {
		warn("Invalid primary vlan id %u", c->pvid);
		return -1;
	}

	nl_check_vlan(a, true);

	return 0;
}

#define RELOAD_TIMEOUT 5

int handle_ap_autoconfig_wsc(void *agent, struct cmdu_buff *rx_cmdu,
			     struct node *n)
{
	struct agent *a = (struct agent *) agent;
	uint8_t bssid[6];
	struct wifi_radio_element *radio;
	struct tlv *tv[4][16] = {0};
	int ret = 0, num = 0;

	trace("%s: --->\n", __func__);

	if (memcmp(rx_cmdu->origin, a->cntlr_almac, 6)) {
		dbg("|%s:%d| response not from an active controller!\n",
				__func__, __LINE__);
		return -1;
	}

	if (!validate_ap_autoconfig_wsc(rx_cmdu, tv, n->map_profile)) {
		dbg("cmdu validation: [AP_AUTOCONFIG_WSC] failed\n");
		return -1;
	}

	if (tv[2][0]) {
		struct tlv_default_8021q_settings *tlv = (struct tlv_default_8021q_settings *) tv[2][0]->data;
		//uci_apply_default_8021q_settings(tlv);
		agent_fill_8021q_setting_from_tlv(a, tlv);
	}

	memcpy(bssid, tv[0][0]->data, 6);

	radio = wifi_get_radio_by_mac(a, bssid);
	if (!radio)
		return -1;

	dbg("|%s:%d| found radio = %s\n", __func__, __LINE__, radio->name);

	if (radio->dedicated_backhaul) {
		dbg("|%s:%d| %s is dedicated backhaul"\
				" radio found - discard WSC and set to"\
				" HEARTBEAT\n", __func__, __LINE__,
				radio->name);
		radio->state = AUTOCFG_HEARTBEAT;
		goto teardown;
	}

	wifi_teardown_map_ifaces_by_radio(a, radio->name);

	while (tv[1][num]) {
		struct wps_credential out = {0};
		char ifname[IFNAMSIZ] = {0};
		uint8_t *ext = NULL;
		uint16_t extlen = 0;
		struct wsc_ext exts = {
			.enabled = true
		};
		struct netif_fh *fh = NULL;
		char ssid[33] = {0};

		ret = wsc_process_m2(radio->autconfig.m1_frame,
				radio->autconfig.m1_size,
				radio->autconfig.key, tv[1][num]->data,
				tlv_length(tv[1][num]),
				&out, &ext, &extlen);
		if (ret) {
			err("Failed to process M2 target for interface "\
					MACFMT "!\n", MAC2STR(bssid));

			wifi_teardown_map_ifaces_by_radio(a, radio->name);
			/* Return rather than freeing because it may belong to
			 * an updated frame
			 */
			agent_autoconfig_event(a, radio->name, "teardown",
					"M2 process failure");
			return -1;
		}

		memcpy(ssid, out.ssid, out.ssidlen);
		/* try to find good fit for interface*/
		fh = wifi_ssid_to_ifname(a, radio->name, ssid, ifname);
		if (!fh)
			fh = wifi_get_first_available_ifname(a, radio->name, ifname);

		/* no available interface found, try to generate*/
		if (!fh) {
			if (!wifi_gen_first_ifname(a, radio->name, ifname)) {
				err("Failed to find valid interface name, probably "\
				    "maximum number of interfaces have "\
				    "been reached\n" MACFMT "!\n", MAC2STR(bssid));
				/* TODO: what should be the correct course of action? */
				break;
			}

			fh = netif_alloc_fh(ifname);
			if (!fh)
				return -1;

			fh->wifi = WIFI_OBJECT_INVALID;
			fh->radio = WIFI_OBJECT_INVALID;
			fh->agent = a;
			fh->cfg = NULL;
			strncpy(fh->radio_name, radio->name, IFNAMSIZ-1);
			list_add_tail(&fh->list, &a->fhlist);
			dbg("[%s %d] new interface added",__func__, __LINE__);
		}

		ret = wsc_get_exts(ext, extlen, &exts);
		if (ret) {
			err("Failed to process IOPSYS vendor ext for interface "\
					MACFMT "!\n", MAC2STR(bssid));

			wifi_teardown_map_ifaces_by_radio(a, radio->name);
			/* Return rather than freeing because it may belong to
			 * an updated frame
			 */
			agent_autoconfig_event(a, radio->name, "teardown",
					"IOPSYS extension process error");
			if (ext)
				free(ext);
			if (fh) {
                                list_del(&fh->list);
                                free(fh);
                        }
			return -1;
		}

		if (BIT(4, out.mapie)) {
			err("MAP Extension had teardown bit set, tearing down "\
					"all MAP interfaces for bssid "	MACFMT \
					"\n", MAC2STR(bssid));
			wifi_teardown_map_ifaces_by_radio(a, radio->name);
			agent_autoconfig_event(a, radio->name, "teardown",
					"teardown bit set");
			if (ext)
				free(ext);
			if (fh) {
				list_del(&fh->list);
				free(fh);
			}
			agent_free_wsc_vendor_ies(&exts);
			goto teardown;
		}

		ret = uci_apply_m2(&a->cfg, ifname, radio->name, &out,
				radio->onboarded, &exts);
		if (ret) {
			err("Failure to apply M2, tearing down all MAP "\
					" interfaces for bssid " MACFMT "\n",
					MAC2STR(bssid));
			wifi_teardown_map_ifaces_by_radio(a, radio->name);
			agent_autoconfig_event(a, radio->name, "teardown",
					"M2 apply failure");
			if (ext)
				free(ext);
			if (fh) {
				list_del(&fh->list);
				free(fh);
			}
			agent_free_wsc_vendor_ies(&exts);
			goto teardown;
		}

		if (fh)
			fh->torndown = false;
		if (ext)
			free(ext);
		agent_free_wsc_vendor_ies(&exts);
		num++;
	}

	if (tv[3][0]) {
		struct tlv_traffic_sep_policy *tlv = (struct tlv_traffic_sep_policy *) tv[3][0]->data;

		dbg("|%s:%d| TS policy received\n", __func__, __LINE__);

		a->reconfig_reason |= AGENT_RECONFIG_REASON_VLAN_SETUP;
		agent_fill_traffic_sep_policy(a, tlv);
	} else
		a->reconfig_reason |= AGENT_RECONFIG_REASON_VLAN_TEARDOWN;

	dbg("|%s:%d| radio (%s) was configured! Apply heartbeat for this radio\n",
				__func__, __LINE__, radio->name);
	agent_exec_platform_scripts("write_credentials");
	agent_config_reload(a);
	radio->state = AUTOCFG_HEARTBEAT;
	agent_autoconfig_event(a, radio->name, "success", "completed");

	//uci_apply_wps_credentials(&a->cfg, radio->band);
teardown:
	// TODO: freeing from here risks freeing an updated frame
	agent_free_wsc_data(&radio->autconfig);
	radio->autconfig.key = NULL;
	radio->autconfig.m1_frame = NULL;
	a->reconfig_reason |= AGENT_RECONFIG_REASON_AP_AUTOCONF; /* ap autoconfig bit */
	timer_set(&a->reload_scheduler, RELOAD_TIMEOUT * 1000);
	return 0;
}

int handle_ap_autoconfig_renew(void *agent, struct cmdu_buff *rx_cmdu,
			       struct node *n)
{
	trace("agent: %s: --->\n", __func__);
	struct agent *a = (struct agent *) agent;
	int i;
	struct tlv *tv[3][16] = {0};
	struct tlv_aladdr *aladdr;
	struct tlv_supported_role *supp_role;

	if (!validate_ap_autoconfig_renew(rx_cmdu, tv, n->map_profile)) {
		dbg("cmdu validation: [AP_AUTOCONFIG_RENEW] failed\n");
		return -1;
	}

	aladdr = (struct tlv_aladdr *) tv[0][0]->data;
	supp_role = (struct tlv_supported_role *) tv[1][0]->data;

	/* local cntlr enforced: accept renew from self only */
	if (a->cntlr_select.local == true &&
			memcmp(aladdr->macaddr, a->almac, 6)) {
		dbg("|%s:%d| local set in controller_select - don't"\
				"trigger WSC with "\
				"non-local controller\n",
				__func__, __LINE__);
		/* local cntlr enforced: don't WSC with non-local one */
		return -1;
	}

	/* TODO: at the moment we discard all renews not from current cntlr */
	if (memcmp(aladdr->macaddr, a->cntlr_almac, 6))
		return -1;

	if (supp_role->role != IEEE80211_ROLE_REGISTRAR)
		return -1;

	for (i = 0; i < a->num_radios; i++) {
		struct cmdu_buff *resp;
		struct wifi_radio_element *radio;
		uint16_t mid = 0;

		radio = a->radios + i;
		radio->renew_mid = cmdu_get_mid(rx_cmdu);
#if 0
		if (radio->dedicated_backhaul) {
			dbg("|%s:%d| don't trigger WSC for dedicated backhaul,"\
					"setting radio to heartbeat\n",
					__func__, __LINE__);
			continue;
		}
#endif
		radio->state = AUTOCFG_ACTIVE;
		resp = agent_gen_ap_autoconfig_wsc(a, rx_cmdu, radio);
		if (!resp)
			continue;

		mid = agent_send_cmdu(a, resp);
		if (mid) {
			radio->wsc_mid = mid;
			trace("assigned radio mid %d %d\n", radio->wsc_mid, mid);
		}

		cmdu_free(resp);
	}

	return 0;
}

int get_radio_index(struct agent *a, uint8_t *mac)
{
	int i;

	for (i = 0; i < a->num_radios; i++) {
		if (hwaddr_equal(a->radios[i].macaddr, mac))
			return i;
	}

	return -1;
}

int get_bss_index(struct wifi_radio_element *radio, uint8_t *bssid)
{
	int i;

	for (i = 0; i < radio->num_bss; i++) {
		if (hwaddr_equal(radio->bsslist[i].bssid, bssid))
			return i;
	}

	return -1;
}

int get_radio_and_bss_index(struct agent *a, uint8_t *bssid,
		int *radio_index)
{
	int i;
	int bss_index;

	for (i = 0; i < a->num_radios; i++) {
		bss_index = get_bss_index(&a->radios[i], bssid);
		if (bss_index != -1) {
			*radio_index = i;
			return bss_index;
		}
	}

	return -1;
}

/* ifname: interface name, prepare the query for that specific interface;
 * ifname: NULL, include all the interface.
 */
static struct cmdu_buff *prepare_ap_metrics_query(
		void *agent, char *ifname)
{
	int i, j;
	int ret;
	struct agent *a = (struct agent *)agent;
	struct wifi_radio_element *radio;
	struct wifi_bss_element *bss;
	struct cmdu_buff *cmdu = NULL;
	uint16_t mid = 0;
	int total_bss = 0;
	int c_index = 0;
	uint8_t *bsslist = NULL;
	uint8_t *bsslist_orig = NULL;

	cmdu = cmdu_alloc_simple(CMDU_AP_METRICS_QUERY, &mid);
	if (!cmdu) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(cmdu->origin, a->cntlr_almac, 6);

	if (!ifname || ifname[0] == '\0') {
		for (i = 0; i < a->num_radios; i++) {
			radio = a->radios + i;

//#ifdef PROFILE2
			/* Radio Identifier TLV */
			ret = agent_gen_ap_radio_identifier(a,
					cmdu, radio->macaddr);
			if (ret)
				goto error;
//#endif

			total_bss += radio->num_bss;
			bsslist_orig = bsslist;
			bsslist = (uint8_t *)realloc(bsslist,
					total_bss * 6 * sizeof(uint8_t));
			if (!bsslist)
				goto error;
			bsslist_orig = NULL;

			for (j = 0; j < radio->num_bss; j++) {
				bss = radio->bsslist + j;
				memcpy(&bsslist[c_index * 6], bss->bssid, 6);
				c_index++;
			}
		}
	} else {
		radio = wifi_ifname_to_radio_element(a, ifname);
		if (!radio)
			goto error;

//#ifdef PROFILE2
		/* Radio Identifier TLV */
		ret = agent_gen_ap_radio_identifier(a,
				cmdu, radio->macaddr);
		if (ret)
			goto error;
//#endif

		total_bss += radio->num_bss;
		bsslist_orig = bsslist;
		bsslist = (uint8_t *)realloc(bsslist,
				total_bss * 6 * sizeof(uint8_t));
		if (!bsslist)
			goto error;
		bsslist_orig = NULL;

		for (j = 0; j < radio->num_bss; j++) {
			bss = radio->bsslist + j;
			memcpy(&bsslist[c_index * 6], bss->bssid, 6);
			c_index++;
		}
	}

	/* AP Metrics TLV */
	ret = agent_gen_ap_metric_query(a, cmdu, total_bss, bsslist);
	if (ret)
		goto error;

	if (bsslist)
		free(bsslist);

	return cmdu;

error:
	if (bsslist)
		free(bsslist);

	if (bsslist_orig)
		free(bsslist_orig);

	cmdu_free(cmdu);

	return NULL;
}

int handle_1905_ack(void *agent, struct cmdu_buff *cmdu, struct node *n)
{
	trace("agent: %s: --->\n", __func__);
	return 0;
}

int handle_ap_caps_query(void *agent, struct cmdu_buff *rx_cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	struct agent *a = (struct agent *) agent;
	int ret;
	/* The response cmdu */
	struct cmdu_buff *resp;

	/* Generate cmdu */
	resp = agent_gen_ap_caps_response(a, rx_cmdu);
	if (!resp)
		return -1;

	/* Send cmdu */
	ret = agent_send_cmdu(a, resp);
	cmdu_free(resp);
	return ret;
}

int handle_ap_caps_report(void *agent, struct cmdu_buff *rx_cmdu,
			  struct node *n)
{
	trace("%s: --->\n", __func__);

	struct agent *a = (struct agent *)agent;
	struct tlv *tv[13][16];
	int idx;

	if (!validate_ap_caps_report(rx_cmdu, tv, n->map_profile)) {
		dbg("cmdu validation: [AP_CAPS_REPORT] failed\n");
		return -1;
	}

	/* Zero or more AP HT capabilities (per radio) */
	idx = 0;
	while (tv[2][idx]) {
		struct tlv_ap_ht_cap *tlv;
		struct netif_fh *p = NULL;
		struct neighbor *nbr;

		tlv = (struct tlv_ap_ht_cap *)tv[2][idx]->data;
		if (tlv == NULL)
			return -1;

		list_for_each_entry(p, &a->fhlist, list) {
			bool found = false;

			list_for_each_entry(nbr, &p->nbrlist, list) {
				if (!memcmp(nbr->radio_mac, tlv->radio, 6)) {
					found = true;

					/* Set HT bit in bssid_info */
					agent_bssid_info_set(nbr->nbr.bssid_info,
							BSSID_INFO_HT);

					/* Update phy type */
					nbr->nbr.phy = PHY_HT;

					nbr->flags &= ~NBR_FLAG_DRV_UPDATED;
				}
			}

			if (found)
				/* Sync nbrlist in fh & driver */
				reschedule_nbrlist_update(p);
		}

		idx++;
	}

	/* Zero or more AP VTH capabilities (per radio) */
	idx = 0;
	while (tv[3][idx]) {
		struct tlv_ap_vht_cap *tlv;
		struct netif_fh *p = NULL;
		struct neighbor *nbr;

		tlv = (struct tlv_ap_vht_cap *)tv[3][idx]->data;
		if (tlv == NULL)
			return -1;

		list_for_each_entry(p, &a->fhlist, list) {
			bool found = false;

			list_for_each_entry(nbr, &p->nbrlist, list) {
				if (!memcmp(nbr->radio_mac, tlv->radio, 6)) {
					found = true;

					/* Set VHT bit in bssid_info */
					agent_bssid_info_set(nbr->nbr.bssid_info,
							BSSID_INFO_VHT);

					/* Update phy type */
					nbr->nbr.phy = PHY_VHT;

					nbr->flags &= ~NBR_FLAG_DRV_UPDATED;
				}
			}

			if (found)
				/* Sync nbrlist in fh & driver */
				reschedule_nbrlist_update(p);
		}

		idx++;
	}

	/* Zero or more AP HE capabilities (per radio) */
	idx = 0;
	while (tv[4][idx]) {
		struct tlv_ap_he_cap *tlv;
		struct netif_fh *p = NULL;
		struct neighbor *nbr;

		tlv = (struct tlv_ap_he_cap *)tv[4][idx]->data;
		if (tlv == NULL)
			return -1;

		list_for_each_entry(p, &a->fhlist, list) {
			bool found = false;

			list_for_each_entry(nbr, &p->nbrlist, list) {
				if (!memcmp(nbr->radio_mac, tlv->radio, 6)) {
					found = true;

					/* Update phy type */
					nbr->nbr.phy = PHY_HE;

					nbr->flags &= ~NBR_FLAG_DRV_UPDATED;
				}
			}

			if (found)
				/* Sync nbrlist in fh & driver */
				reschedule_nbrlist_update(p);
		}

		idx++;
	}

	return 0;
}

uint8_t rssi_to_rcpi(int rssi)
{
	if (!rssi)
		return 255;
	else if (rssi < -110)
		return 0;
	else if (rssi > 0)
		return 220;
	else
		return (rssi + 110) * 2;
}

static uint8_t calculate_radio_util(struct agent *a, char *ifname)
{
	struct wifi_radio_element *radio;

	radio = wifi_ifname_to_radio_element(a, ifname);
	if (!radio)
		return 0;

	return radio->total_utilization;
}

#if 0
static uint8_t calculate_radio_rcpi(struct agent *a, char *ifname)
{
	int j, k;
	struct wifi_radio_element *radio;
	struct wifi_bss_element *bss;
	struct wifi_sta_element *sta;
	int8_t rssi = 0;
	uint8_t rcpi = 0;

	radio = wifi_ifname_to_radio_element(a, ifname);
	if (!radio)
		return 0;

	for (j = 0; j < radio->num_bss; j++) {
		bss = radio->bsslist + j;
		/*TODO/Warning: bss->num_stations is not implemented */
		for (k = 0; k < bss->num_stations; k++) {
			sta = bss->stalist + k;
			rssi += sta->rssi;
		}
	}

	rcpi = rssi_to_rcpi(rssi);

	return rcpi;
}
#endif

static void agent_metric_report_timer_cb(atimer_t *t)
{
	struct agent_config *cfg =
		container_of(t, struct agent_config, metric_report_timer);
	struct agent *a = container_of(cfg, struct agent, cfg);
	struct cmdu_buff *cmdu;
	char *ifname = NULL;
	struct node *n;

	n = agent_find_node(a, a->almac);
	if (!n)
		goto refresh_interval;

	cmdu = prepare_ap_metrics_query((void *)a, ifname);
	if (!cmdu)
		goto refresh_interval;

	send_ap_metrics_response(a, cmdu, n);

refresh_interval:
	timer_set(&cfg->metric_report_timer,
			cfg->pcfg->report_interval * 1000);
}

static void agent_util_threshold_timer_cb(atimer_t *t)
{
	struct netif_fh *p = container_of(t, struct netif_fh,
			util_threshold_timer);
	struct agent *a = p->agent;
	struct cmdu_buff *cmdu;
	uint8_t curr_util = 0;
	uint8_t prev_util;
	struct agent_config_radio *rcfg;
	struct node *n;

	n = agent_find_node(a, a->almac);
	if (!n)
		goto refresh_interval;

	rcfg = get_agent_config_radio(&a->cfg, p->cfg->device);
	if (!rcfg)
		return;

	curr_util = calculate_radio_util(a, p->name);
	prev_util = p->prev_util;
	if (((prev_util > rcfg->util_threshold) &&
				(curr_util > rcfg->util_threshold)) ||
			((prev_util < rcfg->util_threshold) &&
			 (curr_util < rcfg->util_threshold)))
		goto refresh_interval;

	cmdu = prepare_ap_metrics_query((void *)a, p->name);
	if (!cmdu)
		goto refresh_interval;

	send_ap_metrics_response(a, cmdu, n);
	cmdu_free(cmdu);

refresh_interval:
	p->prev_util = curr_util;
	timer_set(&p->util_threshold_timer, UTIL_THRESHOLD_TIMER);
}

static int agent_process_policy_config(struct agent *a)
{
	trace("%s: --->\n", __func__);

	int i;
	struct agent_config *cfg = &a->cfg;
	struct policy_cfg *c = cfg->pcfg;

	/* timer cleanup */
	if (timer_pending(&cfg->metric_report_timer))	/* FIXME ? */
		timer_del(&cfg->metric_report_timer);

	if (c && (c->report_interval > 0)) {
		/* TODO: timer(s) here should be set only; do timer_init at agent init */
		timer_init(&cfg->metric_report_timer, agent_metric_report_timer_cb);
		timer_set(&cfg->metric_report_timer, c->report_interval * 1000);
	}

	for (i = 0; i < a->num_radios; i++) {
		struct netif_fh *p;
		struct agent_config_radio *rcfg;

		p = wifi_radio_to_ap(a, a->radios[i].name);
		if (!p)
			continue;

		rcfg = get_agent_config_radio(&a->cfg, p->cfg->device);
		if (!rcfg)
			return -1;

		/* timers cleanup fh specific */
		if (timer_pending(&p->util_threshold_timer))	/* FIXME ? */
			timer_del(&p->util_threshold_timer);

//		if (p->rcpi_threshold_timer.cb) {
//			timer_del(&p->rcpi_threshold_timer);
//			p->rcpi_threshold_timer.cb = NULL;
//		}

		if (rcfg->util_threshold > 0) {
			timer_init(&p->util_threshold_timer, agent_util_threshold_timer_cb);
			timer_set(&p->util_threshold_timer, UTIL_THRESHOLD_TIMER);
		}

//		if (p->cfg->rcpi_threshold > 0) {
//			p->rcpi_threshold_timer.cb =
//				agent_rcpi_thresold_timer_cb;
//			timer_set(&p->rcpi_threshold_timer,
//					RCPI_THRESHOLD_TIMER);
//		}
	}

	/* TODO:
	 * 17.2.37: report independent channel scan,
	 * will be useful while extending channel scan response
	 *
	 * 17.2.66: Backhaul configuration
	 * 17.2.49, 17.2.50: Will be used in traffic seperation
	 *
	 * 17.2.58: report unsuccesful association,
	 * Sta events should be checked & reported accordingly
	 */

	return 0;
}

int handle_map_policy_config(void *agent, struct cmdu_buff *cmdu,
			     struct node *n)
{
	trace("%s: --->\n", __func__);

	int idx = 0;
	struct agent *a = (struct agent *)agent;
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct tlv *tv[8][16] = {0};
	int ret;

	ret = map_cmdu_parse_tlvs(cmdu, tv, 8, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return -1;
	}

	/* send the 1905 ack message to controller */
	send_1905_acknowledge(a, cmdu->origin, cmdu_get_mid(cmdu), NULL, 0);

	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	if (uci_load(ctx, "mapagent", &pkg)) {
		uci_free_context(ctx);
		return -1;
	}

	if (tv[0][0]) {
		struct tlv_steering_policy *p =
			(struct tlv_steering_policy *)tv[0][0]->data;

		agent_fill_steering_policy(a, p, ctx, pkg);
	}

	if (tv[1][0]) {
		struct tlv_metric_report_policy *p =
			(struct tlv_metric_report_policy *)tv[1][0]->data;

		agent_fill_metric_report_policy(a, p, ctx, pkg);
	}

	if (tv[2][0]) {
		struct tlv_default_8021q_settings *p =
			(struct tlv_default_8021q_settings *)tv[2][0]->data;

		agent_fill_8021q_setting_from_tlv(a, p);
	}

	if (tv[3][0]) {
		struct tlv_traffic_sep_policy *p =
			(struct tlv_traffic_sep_policy *)tv[3][0]->data;

		dbg("|%s:%d| TS policy received\n", __func__, __LINE__);
		agent_fill_traffic_sep_policy(a, p);
		a->reconfig_reason |= AGENT_RECONFIG_REASON_VLAN_SETUP;
	} else
		a->reconfig_reason |= AGENT_RECONFIG_REASON_VLAN_TEARDOWN;

	/* set reload timer */
	timer_set(&a->reload_scheduler, RELOAD_TIMEOUT * 1000);

	if (tv[4][0]) {
		struct tlv_channel_scan_report_policy *p =
			(struct tlv_channel_scan_report_policy *)tv[4][0]->data;

		agent_fill_ch_scan_rep_policy(a, p, ctx, pkg);
	}

	if (tv[5][0]) {
		struct tlv_unsuccess_assoc_policy *p =
			(struct tlv_unsuccess_assoc_policy *)tv[5][0]->data;

		agent_fill_unsuccess_assoc_policy(a, p, ctx, pkg);
	}

	idx = 0;
	while (tv[6][idx]) {
		uint8_t generic_id[6] = {0xff, 0x0ff, 0xff, 0xff, 0xff, 0xff};
		struct tlv_bbss_config *p =
			(struct tlv_bbss_config *)tv[6][idx++]->data;

		if (!memcmp(p->bssid, generic_id, 6)) {
			agent_fill_backhaul_bss_config_all(a, p, ctx, pkg);
		} else
			agent_fill_backhaul_bss_config(a, p, ctx, pkg);
	}

	/* update agent config file */
	uci_commit(ctx, &pkg, false);
	uci_unload(ctx, pkg);
	uci_free_context(ctx);

	/* Reload agent config */
	agent_config_reload(a);

	agent_process_policy_config(a);
	return 0;
}

int handle_channel_pref_query(void *agent, struct cmdu_buff *rx_cmdu,
			      struct node *n)
{
	trace("%s: --->\n", __func__);

	struct cmdu_buff *cmdu;
	struct agent *a = (struct agent *)agent;

	cmdu = agent_gen_channel_preference_report(a, rx_cmdu);
	if (!cmdu)
		return -1;

	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	/* Send also latest/current channel report */
#ifndef STRICT_OPER_CHANNEL_REPORT
	send_oper_channel_report(a, NULL);
#endif

	return 0;
}

int send_channel_sel_response(void *agent, struct cmdu_buff *rx_cmdu,
		struct channel_response *channel_resp,
		uint32_t channel_response_nr)
{
	trace("agent: %s: --->\n", __func__);

	struct agent *a = (struct agent *) agent;
	uint32_t j, ret = 0;
	uint16_t mid = 0;
	struct cmdu_buff *cmdu;

	mid = cmdu_get_mid(rx_cmdu);
	cmdu = cmdu_alloc_simple(CMDU_CHANNEL_SELECTION_RESPONSE, &mid);
	if (!cmdu) {
		dbg("%s: -ENOMEM\n", __func__);
		return -1;
	}

	memcpy(cmdu->origin, rx_cmdu->origin, 6);

	/* Operating Channel Response TLV 17.2.16 */
	for (j = 0; j < channel_response_nr; j++) {
		/* Here we need to check that the radio
		 *response is for the radio for which we get request
		 */
		ret = agent_gen_channel_selection_resp(a, cmdu,
			channel_resp[j].radio_id, channel_resp[j].response);
		if (ret)
			goto error;
	}

	cmdu_put_eom(cmdu);
	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	return ret;

error:
	cmdu_free(cmdu);
	return -1;
}

int agent_fill_radio_max_preference(void *agent,
		struct channel_response *channel_resp,
		uint32_t *channel_response_nr)
{
	trace("agent: %s: --->\n", __func__);
	struct agent *a = agent;
	struct wifi_radio_element *radio = NULL;
	uint32_t j;

	*channel_response_nr = a->num_radios;

	for (j = 0; j < a->num_radios; j++) {
		radio = a->radios + j;
		memcpy(channel_resp[j].radio_id, radio->macaddr, 6);
		memcpy(&radio->req_opclass, &radio->opclass, sizeof(radio->opclass));
		wifi_opclass_set_preferences(&radio->req_opclass, 0x0f << 4);
		channel_resp[j].response = 0x00;
	}

	return 0;
}

int get_op_class_sec(int op_class)
{
	switch (op_class) {
	case 83:
		return 1;
	case 84:
		return -1;
	default:
		break;
	}

	return 0;
}

int get_op_class_bw(int op_class)
{
	switch (op_class) {

	case 115:
	case 118:
	case 121:
	case 125:
	case 81:
	case 82:
	case 124:
		return 20;
	case 116:
	case 119:
	case 122:
	case 117:
	case 120:
	case 123:
	case 83:
	case 84:
	case 126:
	case 127:
		return 40;
	case 128:
	case 130:
		return 80;
	case 129:
		return 160;
	default:
		return 0;
	}
}

enum wifi_bw get_op_class_wifi_bw(int op_class)
{
	switch (op_class) {

	case 115:
	case 118:
	case 121:
	case 125:
	case 81:
	case 82:
	case 124:
		return BW20;
	case 116:
	case 119:
	case 122:
	case 117:
	case 120:
	case 123:
	case 83:
	case 84:
	case 126:
	case 127:
		return BW40;
	case 128:
	case 130:
		return BW80;
	case 129:
		return BW160;
	default:
		return BW20;
	}
}

int agent_set_channel_preference_to_default(struct wifi_radio_element *radio)
{
	trace("%s: --->\n", __func__);
	wifi_opclass_set_preferences(&radio->req_opclass, 0x0f << 4);
	return 0;
}

/*This function return the channel with the highest preference*/
int agent_get_highest_preference(struct wifi_radio_element *radio,
		uint32_t op_class_id, uint32_t *channel_to_move,
		uint32_t *opclass_to_move)
{
	trace("%s: --->\n", __func__);
	uint8_t opclass;
	uint8_t channel;

	if (wifi_opclass_get_higest_preference(&radio->opclass, radio->current_bandwidth, &opclass, &channel))
		return -1;

	*opclass_to_move = opclass;
	*channel_to_move = channel;
	trace("|%s %d| channel switch to channel %d opclass %d\n", __func__, __LINE__, *channel_to_move, *opclass_to_move);
	return 0;
}

int agent_channel_switch(struct agent *a, uint8_t *radio_id, int channel, int opclass)
{
	int ret;
	struct chan_switch_param param = {};
	struct netif_fh *p = NULL;
	int found = 0;
	const char *radio_name = NULL;
	struct wifi_radio_element *radio = NULL;

	trace("%s: --->\n", __func__);

	list_for_each_entry(p, &a->fhlist, list) {
		radio_name = wifi_ifname_to_radio(a, p->name);
		if (!radio_name)
			continue;
		trace("|%s %d|radio name %s\n", __func__, __LINE__, radio_name);
		radio = wifi_radio_to_radio_element(a, radio_name);
		if (!radio) {
			dbg("|%s %d| couln'd find radio element for %s\n",
			      __func__, __LINE__, radio_name);
			return -1;
		}
		ret = memcmp(radio_id, &radio->macaddr, 6);
		if (ret == 0) {
			if (p->cfg->multi_ap != 2)
				continue;
			else {
				found = 1;
				break;
			}
		}
	}

	if (found != 1)
		return -1;

	param.bandwidth = get_op_class_bw(opclass);
	param.freq = c2f(channel);
	param.count = 5;
	param.sec_chan_offset = get_op_class_sec(opclass);

	if (radio->current_channel == channel &&
	    radio->current_bandwidth == param.bandwidth &&
	    !radio->cac_required) {
		/* Just in case controller don't know our oper channel */
		radio->report_oper_channel = true;
		return 0;
	}

	/* Check current mode/standard */
	if (strstr(p->standard, "ax"))
		param.he = true;
	if (strstr(p->standard, "ac"))
		param.vht = true;
	if (strstr(p->standard, "n"))
		param.ht = true;

	trace("|%s %d| channel %d bandwidth %d ht/vht/he: %d/%d/%d\n",
		__func__, __LINE__, channel, param.bandwidth,
		param.ht, param.vht, param.he);

	return wifi_chan_switch(p->name, &param);
}

int agent_config_channel_preference(struct agent *a,
		uint8_t *radio_id, uint32_t opclass_id)
{
	int l = 0;
	struct wifi_radio_element *radio;
	struct wifi_radio_opclass *opclass;
	int ret = 0, found = 0;

	trace("|%s %d| radio_id: " MACFMT "\n", __func__, __LINE__,
			MAC2STR(radio_id));

	/* Here we need to write the preferences in the config file
	 * only the channels in which the preferences are not
	 * highest preferences
	 */

	for (l = 0; l < a->num_radios; l++) {
		radio = a->radios + l;
		if (!memcmp(radio->macaddr, radio_id, 6)) {
			found = 1;
			break;
		}
	}

	if (found == 0)
		return -1;

	/* Save requested opclass */
	opclass = &radio->req_opclass;
	for (l = 0; l < opclass->entry_num; l++) {
		if (opclass->entry[l].id == opclass_id) {
			uint8_t channel_list[20] = {0};
			int m = 0, j = 0;
			int pref = 0x0f;

			for (m = 0; m < opclass->entry[l].channel_num ; m++) {
				pref = opclass->entry[l].channel[m].preference;
				channel_list[j++] = opclass->entry[l].channel[m].channel;
			}

			ret = wifi_set_opclass_preference(radio->name,
					opclass_id, pref, channel_list, j);
			if (ret != 0)
				err("cannot write preference in config\n");
		}
	}

	return ret;
}


static int agent_is_radio_backhaul(struct agent *a, uint8_t *radio_id)

{
	struct netif_fh *p = NULL;
	const char *radio_name = NULL;
	int found = 0;
	int ret = 0;

	trace("%s: --->\n", __func__);

	list_for_each_entry(p, &a->fhlist, list) {
		struct wifi_radio_element *radio = NULL;

		radio_name = wifi_ifname_to_radio(a, p->name);
		if (!radio_name)
			continue;
		radio = wifi_ifname_to_radio_element(a, p->name);
		if (!radio) {
			dbg("|%s:%d| Couldn't find radio_element for [%s]\n",
			     __func__, __LINE__, p->name);
			return -1;
		}
		ret = memcmp(radio_id, &radio->macaddr, 6);
		if (ret == 0) {
			if (p->cfg->multi_ap != 2)
				continue;
			else {
				found = 1;
				break;
			}
		}
	}
	if (found ==  1)
		ret = 0;
	else
		ret = -1;

	return ret;
}

int agent_process_channel_pref_tlv(void *agent, struct tlv_channel_pref *p,
		struct channel_response *channel_resp,
		uint32_t *channel_resp_nr)
{
	struct agent *a = (struct agent *) agent;
	struct wifi_radio_element *radio;
	struct wifi_radio_opclass opclass = {};
#ifdef LOCAL_ACS_SERVICE
	uint8_t bws[] = {80, 20};
#else
	uint8_t bws[] = {80, 40, 20};
#endif
	uint8_t target_opclass=0;
	uint8_t target_channel=0;
	uint32_t match, found = 0;
	uint8_t radio_id[6] = {0};
	uint8_t *data = (uint8_t *)p;
	uint8_t opclass_nr;
	uint8_t opclass_offset;
	int offset = 0;
	int ret = 0;
	int i, j;

	trace("%s: --->\n", __func__);

	/* Check radio and active bsta */
	memcpy(radio_id, &data[offset], 6);
	offset += 6;
	trace("\tradio_id: " MACFMT "\n", MAC2STR(radio_id));
	for (i = 0; i < a->num_radios; i++) {
		radio = a->radios + i;
		match = memcmp(radio->macaddr, radio_id, 6);
		if (match == 0) {
			ret = agent_is_radio_backhaul(a, radio_id);
			if (ret != 0) {
				err("radio is a backhaul radio\n");
				memcpy(channel_resp[*channel_resp_nr].radio_id,
					radio->macaddr, 6);
				channel_resp[*channel_resp_nr].response = 0x03;
				*channel_resp_nr = *channel_resp_nr + 1;
				return 0;
			}
			found = 1;
			memcpy(channel_resp[*channel_resp_nr].radio_id,
				radio->macaddr, 6);
			channel_resp[*channel_resp_nr].response = 0x00;
			break;
		}
	}
	if (found == 0) {
		memcpy(channel_resp[*channel_resp_nr].radio_id,
			radio_id, 6);
		/* No radio found so report preferences changed */
		channel_resp[*channel_resp_nr].response = 0x01;
		*channel_resp_nr = *channel_resp_nr + 1;

		return ret;
	}

	opclass_offset= offset;

	opclass_nr = data[offset++];
	trace("[%s]: ch_preference_op_class_nr: %d\n", radio->name, opclass_nr);

	/* Build E-4 table first */
	memcpy(&opclass, &radio->opclass, sizeof(opclass));
	wifi_opclass_set_preferences(&opclass, 0x0 << 4);

	/* Check reported opclasses and set higest pref for all channels */
	for (i = 0; i < opclass_nr; i++) {
		struct wifi_radio_opclass_entry *entry;
		uint8_t id;
		uint8_t channel_num;

		id = data[offset++];
		channel_num = data[offset++];
		offset += channel_num;
		offset++;

		entry = wifi_opclass_find_entry(&opclass, id);
		if (WARN_ON(!entry))
			continue;

		wifi_opclass_id_set_preferences(&opclass, id, 0x0f << 4);
	}

	/* Finally check requested preferences */
	offset = opclass_offset + 1;
	for (i = 0; i < opclass_nr; i++) {
		struct wifi_radio_opclass_entry *entry;
		struct wifi_radio_opclass_channel channel = {};
		struct wifi_radio_opclass_channel *chan;
		uint8_t id;
		uint8_t channel_num;
		uint8_t preference;

		id = data[offset++];
		channel_num = data[offset++];
		preference = data[offset + channel_num];

		entry = wifi_opclass_find_entry(&opclass, id);
		if (WARN_ON(!entry))
			continue;

		trace("[%s] -- opclass %d channels %d pref 0x%02X\n", radio->name, id, channel_num, preference);
		if (channel_num == 0) {
			/* Setup same preference for all channels inside opclass */
			wifi_opclass_id_set_preferences(&opclass, id, preference);
		} else {
			for (j = 0; j < channel_num; j++) {
				chan = wifi_opclass_find_channel(entry, data[offset]);
				if (chan)
					channel = *chan;
				channel.channel = data[offset++];
				channel.preference = preference;
				wifi_opclass_add_channel(entry, &channel);
				trace("[%s] \tchan %d\n", radio->name, channel.channel);
			}
		}

		offset++;
	}

	/* Remove unsupported channels */
	wifi_opclass_mark_unsupported(&opclass, &radio->opclass);

#ifdef CHANSWITCH_SKIP_DFS_UNAVAILABLE
	/* Check DFS ready also */
	wifi_opclass_mark_unavailable(&opclass, &radio->opclass);
#endif

	wifi_opclass_dump(&opclass);

#ifdef LOCAL_ACS_SERVICE
	if (wifi_opclass_channels_operable(&opclass, 20) > 1) {
		memcpy(&radio->req_opclass, &opclass, sizeof(opclass));
		trace("[%s] enable local ACS service, skip chan switch\n", radio->name);
		radio->report_oper_channel = true;
		radio->local_acs_enabled = true;
		goto exit;
	} else {
		trace("[%s] disable local ACS service\n", radio->name);
		radio->local_acs_enabled = false;
	}
#endif

	/* Switch to best channel */
	for (i = 0; i < ARRAY_SIZE(bws); i++) {
		ret = wifi_opclass_get_higest_preference(&opclass, bws[i],
							 &target_opclass,
							 &target_channel);

		if (!ret)
			break;
	}

	trace("[%s]: higest pref opclass %u chan %u ret %d\n",
	      radio->name, target_opclass, target_channel, ret);


	/* Save it in req_opclass */
	memcpy(&radio->req_opclass, &opclass, sizeof(opclass));

	/* Don't fail if all opclasses/channels with pref=0 */
	if (!target_opclass || !target_channel)
		goto exit;

	if (ret) {
		memcpy(channel_resp[*channel_resp_nr].radio_id, radio_id, 6);
		channel_resp[*channel_resp_nr].response = 0x02;
		*channel_resp_nr = *channel_resp_nr + 1;
		return 0;
	}

	ret = agent_channel_switch(a, radio_id, target_channel, target_opclass);
	if (ret) {
		memcpy(channel_resp[*channel_resp_nr].radio_id, radio_id, 6);
		channel_resp[*channel_resp_nr].response = 0x01;
	}

exit:
	*channel_resp_nr = *channel_resp_nr + 1;
	return 0;
}


int agent_process_transmit_power_tlv(struct agent *a, struct tlv_txpower_limit *p)
{
	int l = 0;
	struct wifi_radio_element *radio;
	uint32_t match;

	trace("tlv radio_id: " MACFMT "\n",
		MAC2STR(p->radio));
	for (l = 0; l < a->num_radios; l++) {
		radio = a->radios + l;
		match = memcmp(radio->macaddr, p->radio, 6);
		if (match == 0) {
			/* Here we set the
			 * transmit_power_limit
			 * of the radio this also needs to be set in
			 * the wireless file
			 */
			radio->transmit_power_limit = p->limit;
			//wifi_set_transmit_power(radio->name, p->limit);
			trace("|%s %d| radio name [%s] transmit power [%d]\n",
				__func__, __LINE__, radio->name, p->limit);
			break;
		}
	}
	return 0;
}

static void send_operating_channel_report_if_required(struct agent *agent)
{
	struct wifi_radio_element *radio;
	struct cmdu_buff *cmdu;
	int i;

	for (i = 0; i < agent->num_radios; i++) {
		radio = &agent->radios[i];

		if (!radio->report_oper_channel)
			continue;
		cmdu = agent_gen_oper_channel_response(agent, radio, radio->current_channel,
						       radio->current_bandwidth, 0);
		if (WARN_ON(!cmdu))
			continue;

		agent_send_cmdu(agent, cmdu);
		cmdu_free(cmdu);

		dbg("[%s] oper_channel_response (req) chan %d bw %d opclass %d\n",
		    radio->name, radio->current_channel, radio->current_bandwidth,
		    radio->current_opclass);
		radio->report_oper_channel = false;
	}
}

int handle_channel_sel_request(void *agent, struct cmdu_buff *cmdu,
			       struct node *n)
{
	trace("agent: %s: --->\n", __func__);

	struct agent *a = (struct agent *) agent;
	int ret = 0;
	struct channel_response channel_resp[MAX_RADIO];
	uint32_t channel_resp_nr = 0;
	int idx;
	//struct wifi_radio_element *radio;
	uint32_t pref_tlv_present = 0;
	struct tlv *tv[3][16];

	UNUSED(a);

	ret = map_cmdu_parse_tlvs(cmdu, tv, 3, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	/* Here we first need to update the channel preference values
	 * from the channel selection request
	 * then send the CMDU for channel selection response
	 */
	idx = 0;
	while (tv[0][idx]) {
		struct tlv_channel_pref *p =
			(struct tlv_channel_pref *)tv[0][idx++]->data;

		pref_tlv_present = 1;
		agent_process_channel_pref_tlv(agent, p, channel_resp, &channel_resp_nr);
	}

	idx = 0;
	while (tv[1][idx]) {
		struct tlv_txpower_limit *p =
			(struct tlv_txpower_limit *)tv[1][idx++]->data;

		agent_process_transmit_power_tlv(agent, p);
	}

	if (pref_tlv_present == 0) {
		/* Here the condition is that the
		 * channel selection request have no tlvs or only transmit power tlv
		 * so we need to set all the prefernce in all radios to max 15
		 */
		agent_fill_radio_max_preference(agent, channel_resp, &channel_resp_nr);
	}

	ret = send_channel_sel_response(agent, cmdu, channel_resp, channel_resp_nr);

	/* Check and send operating channel report */
	send_operating_channel_report_if_required(agent);

	return ret;
}

int handle_sta_caps_query(void *agent, struct cmdu_buff *rx_cmdu,
			  struct node *n)
{
	struct cmdu_buff *cmdu;
	struct agent *a = (struct agent *)agent;

	cmdu = agent_gen_sta_caps_response(a, rx_cmdu, n);
	if (!cmdu)
		return -1;

	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);
	return 0;
}

int handle_ap_metrics_query(void *agent, struct cmdu_buff *rx_cmdu,
			    struct node *n)
{
	trace("%s: --->\n", __func__);
	send_ap_metrics_response(agent, rx_cmdu, n);
	return 0;
}

int handle_sta_link_metrics_query(void *agent, struct cmdu_buff *rx_cmdu,
				  struct node *n)
{
	trace("%s: --->\n", __func__);
	struct cmdu_buff *cmdu;
	struct agent *a = (struct agent *)agent;

	cmdu = agent_gen_assoc_sta_metric_response(a, rx_cmdu, n);
	if (!cmdu)
		return -1;

	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	return 0;
}

static struct netif_fh *get_netif_by_sta(struct agent *a,
		uint8_t *sta)
{
	struct netif_fh *p;
	struct sta *s;
	bool found = false;

	list_for_each_entry(p, &a->fhlist, list) {
		trace("Looking for STAs in bssid = " MACFMT "\n",
				MAC2STR(p->bssid));

		list_for_each_entry(s, &p->stalist, list) {
			trace("stalist: " MACFMT "\n",
					MAC2STR(s->macaddr));
			if (memcmp(s->macaddr, sta, 6) == 0) {
				found = true;
				break;
			}
		}

		if (found)
			break;
	}

	if (!found)
		return NULL;

	return p;
}

#define MAX_UNASSOC_STAMACS 10
int handle_unassoc_sta_link_metrics_query(void *agent,
		struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	struct agent *a = (struct agent *) agent;
	struct tlv *tv[1][16] = {0};
	struct tlv_unassoc_sta_link_metrics_query *query;
	struct sta_error_response sta_resp[MAX_UNASSOC_STAMACS];
	struct netif_fh *fh = NULL;
	int err_tlv_cnt = 0;
	int i, j;
	uint8_t sta[6];
	int ret = 0;

	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);

	if (ret || !tv[0][0])
		return -1;

	query = (struct tlv_unassoc_sta_link_metrics_query *) tv[0][0]->data;

	for (i = 0; i < query->num_channel; i++) {
		for (j = 0; j < query->ch[i].num_sta; j++) {
			memcpy(sta, query->ch[i].sta[j].macaddr, 6);
			fh = get_netif_by_sta(a, sta);
			if (fh) {
				sta_resp[err_tlv_cnt].response = 0x01;
				memcpy(sta_resp[err_tlv_cnt].sta_mac, sta, 6);
				err_tlv_cnt++;
			}
			if (err_tlv_cnt >= MAX_UNASSOC_STAMACS)
				break;
		}
		if (err_tlv_cnt >= MAX_UNASSOC_STAMACS)
			break;
	}

	if (err_tlv_cnt) {
		/* If any of the STAs specified in the Unassociated STA Link Metrics
		 * Query message is associated with any BSS operated by the Multi-AP
		 * Agent (an error scenario), for each of those associated STAs,
		 * the Multi-AP Agent shall include an Error Code TLV with the reason
		 * code field set to 0x01 and the STA MAC address field included per
		 * section 17.2.36 in the 1905 Ack message.
		 */
		dbg("One or more STAs is associated with a BSS operated"\
				 " by the Multi-AP Agent!\n");
		ret = -1;
	}

	/* If a Multi-AP Agent receives a Beacon Metrics Query message,
	 * then it shall respond within one second with a 1905 Ack message.
	 */
	send_1905_acknowledge(agent, cmdu->origin,
		 cmdu_get_mid(cmdu), sta_resp, err_tlv_cnt);

	if (ret)
		return -1;

	return agent_process_unassoc_sta_lm_query_tlv(a, query, cmdu);

	trace("%s: --->\n", __func__);
	return 0;
}

int handle_unassoc_sta_link_metrics_response(void *agent,
		struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	return 0;
}

int handle_beacon_metrics_response(void *agent, struct cmdu_buff *cmdu,
				   struct node *n)
{
	trace("%s: --->\n", __func__);
	return 0;
}

int handle_combined_infra_metrics(void *agent, struct cmdu_buff *cmdu,
				  struct node *n)
{
	trace("%s: --->\n", __func__);
	return 0;
}

/* Add the rcpi based check according to section
 * 11.3
 */
bool agent_rcpi_steer(void)
{
	/**
	 * TODO: Implement proper logic to trigger steer
	 */
	trace("agent: %s: --->\n", __func__);
	return false;
}

static int agent_set_sta_resp(struct agent *a, struct netif_fh *fh,
		uint8_t req_mode, uint8_t num_sta, uint8_t *sta_list,
		struct sta_error_response  *sta_resp, uint32_t *cnt)
{
	struct sta *s;
	uint32_t res = 0;
	bool found = false;
	uint32_t count = 0;
	int i = 0;

	for (i = 0; i < num_sta; i++) {

		list_for_each_entry(s, &fh->stalist, list) {
			dbg("|%s:%d| sta:" MACFMT "\n",
			    __func__, __LINE__, MAC2STR(s->macaddr));
			res = memcmp(s->macaddr, &sta_list[i * 6], 6);
			if (!res) {
				found = true;
				/**
				 * Here as the sta is present check that in this case
				 * for steering opportunity put that in the array
				 */
				/* TODO: move smwhr else */
				if (req_mode == 0x00) {
					memcpy(a->sta_steer_list[a->sta_steerlist_count].sta_mac,
							&sta_list[i * 6], 6);
					a->sta_steerlist_count++;
				}
				break;
			}
		}
		if (!found) {
			dbg("|%s:%d| STA client not found\n",
			    __func__, __LINE__);
			memcpy(sta_resp[count].sta_mac, &sta_list[i * 6], 6);
			sta_resp[count].response = 0x02;
			count++;
		}
	}
	*cnt += count;

	if (num_sta == count)
		/* None of the stations from the list found on fh stalist */
		return -1;

	return 0;
}

static int agent_sent_request_monitor_add(struct agent *a,
	struct netif_fh *fh, uint8_t *sta_addr)
{
	trace("agent: %s: --->\n", __func__);
	return wifi_monitor_sta_add(fh->name, sta_addr);
}

static int agent_sent_request_monitor_del(struct agent *a,
	struct netif_fh *fh, uint8_t *sta_addr)
{
	trace("agent: %s: --->\n", __func__);
	return wifi_monitor_sta_del(fh->name, sta_addr);
}

static int agent_sent_request_monitor_get(struct agent *a,
	struct netif_fh *fh, uint8_t *sta_addr, int8_t *rssi)
{
	struct wifi_monsta monsta = {};
	int ret;

	trace("agent: %s: --->\n", __func__);

	ret = wifi_get_monitor_sta(fh->name, sta_addr, &monsta);
	if (!ret)
		*rssi = monsta.rssi[0];

	return ret;
}

static int agent_add_sta_bcn_req(struct sta *s, struct netif_fh *fh,
	uint8_t opclass, uint8_t channel, uint8_t *bssid,
	uint8_t reporting_detail, uint8_t ssidlen, char *ssid,
	uint8_t num_element, uint8_t *element)
{
	uint8_t len;
	struct sta_bcn_req *breq;

	trace("agent: %s: --->\n", __func__);

	if (s->sta_bcn_req_nr >= 16)
		/* Max number of requests stashed */
		return -1;

	/* LIFO */
	breq = &s->bcn_req_queue[s->sta_bcn_req_nr];
	if (!breq)
		return -1;

	memset(breq, 0, sizeof(struct sta_bcn_req));

	breq->fh = fh;
	breq->opclass = opclass;
	breq->channel = channel;
	memcpy(breq->bssid, bssid, 6);
	breq->reporting_detail = reporting_detail;

	breq->ssid_len = ssidlen;
	len = (ssidlen > sizeof(breq->ssid) - 1
			? sizeof(breq->ssid) - 1 : ssidlen);
	memcpy(breq->ssid, ssid, len);

	breq->num_element = num_element;
	memcpy(breq->element, element, num_element);

	s->sta_bcn_req_nr++;

	return 0;
}

static int agent_request_beacon_metrics(struct agent *a,
	struct netif_fh *fh, uint8_t *sta_addr, uint8_t opclass,
	uint8_t channel, uint8_t *bssid, uint8_t reporting_detail,
	uint8_t ssid_len, char *ssid, uint8_t num_report,
	uint8_t *report, uint8_t num_element, uint8_t *element)
{
	struct sta *s;
	int remaining = 0;
	int ret = 0;

	trace("agent: %s: --->\n", __func__);

	s = find_sta_by_mac(a, sta_addr);
	if (!s)
		return -1;

	dbg("%s:%d opclass = %u, channel = %u, num_report = %u\n",
	    __func__, __LINE__, opclass, channel, num_report);

	if (opclass && channel != 255) {
		/* Single opclass/channel pair, add directly */
		ret = agent_add_sta_bcn_req(s, fh,
				opclass, channel, bssid, reporting_detail,
				ssid_len, ssid, num_element, element);

		if (ret) {
			dbg("%s:%d Failed to add beacon request!\n",
			    __func__, __LINE__);
			goto out;
		}
	} else if (channel == 255 && num_report && report) {
		/* Split channel report into individual requests */
		uint8_t *pos;
		int i, j;

		pos = report;
		for (i = 0; i < num_report; i++) {
			struct ap_channel_report *rep =
					(struct ap_channel_report *) pos;

			for (j = 0; j < (rep->len - 1); j++) {
				ret = agent_add_sta_bcn_req(s, fh,
						rep->opclass, rep->channel[j],
						bssid, reporting_detail,
						ssid_len, ssid,
						num_element, element);
				if (ret) {
					dbg("%s:%d Failed to add beacon request!\n",
					    __func__, __LINE__);
					goto out;
				}
			}

			pos += 1 + rep->len;
		}

	} else {
		/* Error condition */
		dbg("%s:%d Wrong channel/opclass or no channel_report!\n",
		    __func__, __LINE__);
		return -1;
	}

out:
	/* Trigger sending beacon metrics request */
	remaining = timer_remaining_ms(&s->sta_bcn_req_timer);
	if (remaining == -1 && s->sta_bcn_req_nr > 0)
		timer_set(&s->sta_bcn_req_timer, 0 * 1000);

	return ret;
}

int agent_send_request_transition(void *agent, uint8_t *client_sta,
	struct netif_fh *fh, uint8_t *bssid, uint32_t timeout)
{
	trace("agent: %s: --->\n", __func__);
	if (!client_sta || !bssid)
		return -1;

	return wifi_req_bss_transition(fh->name, client_sta, 1, bssid, timeout);
}

/*TODO: 11.4 Multi-AP Agent determination of target BSS
 * Find best bssid based on link metrics, RCPI threshold
 * & channel utilization.
 */
int agent_find_best_bssid_for_sta(struct agent *a, uint8_t *sta, uint8_t *src_bssid,
		uint8_t *out_bssid)
{
	struct netif_fh *p;
	int ret = 0;

	trace("agent: %s: --->\n", __func__);
	list_for_each_entry(p, &a->fhlist, list) {
		trace("src_bssid = " MACFMT " pbssid = " MACFMT "\n",
			MAC2STR(src_bssid), MAC2STR(p->bssid));

		/* FIXME: using first non-self fh bssid */
		ret = memcmp(src_bssid, p->bssid, 6);
		if (ret != 0) {
			memcpy(out_bssid, p->bssid, 6);
			return 0;
		}
	}
	memcpy(out_bssid, src_bssid, 6);
	return 0;
}

int send_1905_acknowledge(void *agent,
	uint8_t *origin, uint16_t mid,
	struct sta_error_response *sta_resp, uint32_t sta_count)
{
	struct cmdu_buff *resp;
	struct agent *a = (struct agent *) agent;

	trace("agent: %s: --->\n", __func__);
	resp = agent_gen_cmdu_1905_ack(a, origin, mid, sta_resp, sta_count);
	if (!resp)
		return -1;

	agent_send_cmdu(agent, resp);
	cmdu_free(resp);

	return 0;
}

int agent_send_restrict_sta(void *agent, uint32_t count_sta,
			    uint8_t client_sta[][6], struct netif_fh *fh,
			    uint8_t enable)
{
	int ret = 0;
	int i;

	trace("agent: %s: --->\n", __func__);
	if (!client_sta)
		return -1;

	for (i = 0; i < count_sta; i++) {
		ret |= wifi_restrict_sta(fh->name, client_sta[i], enable);
	}

	return ret;
}

static void wifi_restrict_sta_timeout(atimer_t *t)
{
	struct netif_fh *fh;
	struct restrict_sta_entry *s =
		container_of(t, struct restrict_sta_entry, restrict_timer);
	uint8_t client_sta_list[1][6];

	trace("agent: %s: --->\n", __func__);
	fh = s->vif;
	if (!fh) {
		trace("[%s:%d] Error BSSID not present", __func__, __LINE__);
		return;
	}

	memcpy(client_sta_list[0], s->sta, 6);
	agent_send_restrict_sta(fh->agent, 1, client_sta_list, fh, 1);
	list_del(&s->list);
	free(s);
}

int agent_check_start_validity_tmr(uint16_t validity_period,
		uint32_t sta_count, uint8_t stalist[][6],
		struct netif_fh *fh)
{
	uint32_t i = 0;
	struct restrict_sta_entry *s, *tmp;
	struct restrict_sta_entry *ss;

	trace("agent: %s: --->\n", __func__);

	if (stalist == NULL)
		return -1;

	for (i = 0; i < sta_count; i++) {
		// check if the sta is already running a timer
		// delete the timer
		list_for_each_entry_safe(s, tmp, &fh->restrict_stalist, list) {
			if (!memcmp(s->sta, stalist[i], 6)) {
				timer_del(&s->restrict_timer);
				list_del(&s->list);
				free(s);
			}
		}

		// If the timer is not already running
		ss = calloc(1, sizeof(struct restrict_sta_entry));
		if (ss) {
			memcpy(ss->sta, stalist[i], 6);
			//memcpy(ss->bssid, fh->bssid, 6);
			ss->vif = fh;
			timer_init(&ss->restrict_timer, wifi_restrict_sta_timeout);
			timer_set(&ss->restrict_timer, validity_period * 1000);
			list_add_tail(&ss->list, &fh->restrict_stalist);
		}
	}
	return 0;
}

int agent_check_stop_validity_tmr(uint32_t sta_count, uint8_t stalist[][6],
		struct netif_fh *fh)
{
	uint32_t i = 0;
	struct restrict_sta_entry *s = NULL, *tmp = NULL;

	trace("agent: %s: --->\n", __func__);

	if (stalist == NULL)
		return -1;

	for (i = 0; i < sta_count; i++) {
		// check if the sta is already running a timer
		// delete the timer
		list_for_each_entry_safe(s, tmp, &fh->restrict_stalist, list) {
			if (s != NULL) {
				if (!memcmp(s->sta, stalist[i], 6)) {
					timer_del(&s->restrict_timer);
					list_del(&s->list);
					free(s);
				}
			}
		}
	}
	return 0;
}

int agent_process_assoc_cntl_tlv(void *agent, uint8_t *p,
				 struct cmdu_buff *cmdu)
{
	trace("agent: %s: --->\n", __func__);

	struct tlv_client_assoc_ctrl_request *data =
		(struct tlv_client_assoc_ctrl_request *)p;
	struct agent *a = (struct agent *) agent;
	uint32_t found = 0;
	int l, m;
	struct netif_fh *fh;
	struct sta *s;
	struct sta_error_response  sta_resp[MAX_STA];
	uint32_t count = 0;
	int offset = 0;
	uint8_t sta_list[30][6];
	uint16_t validity_period;
	int ret = 0;

	offset = sizeof(*data);
	for (m = 0; m < data->num_sta; m++) {
		memcpy(sta_list[m], &p[offset], 6);
		offset += 6;
	}

	fh = wifi_get_netif_by_bssid(a, data->bssid);
	if (!fh) {
		err("[%s:%d] BSSID not present", __func__, __LINE__);
		ret = -1;
	}

	/* First validate that the STA has been sent for blocking */
	if (!ret && data->control == 0x00) {

		/* Here we validate if the sta is associated with the bssid
		 * then we need to send an error TLV as the STA should not
		 * be associated with the bssid for which the blocking mode
		 * is set.
		 */
		for (l = 0; l < data->num_sta; l++) {
			found = 0;
			list_for_each_entry(s, &fh->stalist, list) {
				trace("stalist: " MACFMT "\n",
					MAC2STR(s->macaddr));
				if (!memcmp(s->macaddr, sta_list[l], 6)) {
					found = 1;
					break;
				}
			}

			/* If any of the STAs specified in the message
			 * with Association Control field set to 0x00
			 * is associated with the BSSID specified in the
			 * same message (an error scenario), then for
			 * each of those associated STAs, Agent shall
			 * include an Error Code TLV with the reason set
			 * to 0x01 and the STA MAC address field included.
			 */
			if (found == 1) {
				dbg("STA client already associated with the bssid!\n");
				memcpy(sta_resp[count].sta_mac, sta_list[l], 6);
				sta_resp[count].response = 0x01;
				count++;
			}
		}

	} else if (!ret && data->control != 0x01) {
		err("[%s:%d] Reserved mode is called!", __func__, __LINE__);
		ret = -1;
	}

	/* If a Multi-AP Agent receives a Client Association Control
	 * Request message, then it shall respond within one second
	 * with a 1905 ACK message.
	 */
	send_1905_acknowledge(agent, cmdu->origin, cmdu_get_mid(cmdu),
			      sta_resp, count);

	if (!ret) {

		if (data->control == 0x01) {
			/* Unblock: ignore the validity timer value in the
			 * request as the validity timer value is ignored
			 * in the unblock case. Check if the validity timer
			 * is running - in that case stop the validity timer
			 */
			ret = agent_check_stop_validity_tmr(data->num_sta,
						sta_list, fh);

			if (ret) {
				err("[%s:%d] Error in stop validity tmr\n",
						__func__, __LINE__);
				goto out;
			}
		}

		/* Call method with logic to block/unblock the STA */
		ret = agent_send_restrict_sta(agent, data->num_sta,
			sta_list, fh, data->control);

		if (ret) {
			err("[%s:%d] Error in agent_send_restrict_sta\n",
					__func__, __LINE__);
			goto out;
		}

		if (data->control == 0x00) {

			validity_period = BUF_GET_BE16(data->validity_period);

			/* Check if the validity timer value is not zero */
			if (validity_period == 0) {
				err("[%s:%d] Validity period is invalid\n",
					__func__, __LINE__);
				ret = -1;
				goto out;
			}

			/* Block: start the timer for which the sta is
			 * blocked as per the validity period also check
			 * if the sta is already in the blocking list.
			 */
			ret = agent_check_start_validity_tmr(validity_period,
					data->num_sta, sta_list, fh);

			if (ret)
				trace("[%s:%d] Error in start validity tmr\n",
						__func__, __LINE__);
		}
	}

out:
	return ret;
}

static bool is_wildcard_bssid(uint8_t *bssid)
{
	uint8_t wildcard[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	return !memcmp(bssid, wildcard, 6);
}

static int agent_sta_disallowed(struct agent *a,
		uint8_t *sta_mac, int type)
{
	struct agent_config *cfg;
	struct policy_cfg *pcfg;
	struct stax *ex_sta;
	struct list_head *head = NULL;
	int disallowed = 0;

	if (!a)
		return -1;

	cfg = &a->cfg;
	if (!cfg) {
		err("%s:%d - missing configuration!\n",
		    __func__, __LINE__);
		return -1;
	}

	pcfg = cfg->pcfg;
	if (!pcfg) {
		err("%s:%d - missing policy configuration!\n",
		    __func__, __LINE__);
		return -1;
	}

	if (type == STA_DISALLOWED_BTM)
		head = &pcfg->steer_btm_excludelist;
	else if (type == STA_DISALLOWED_LOCAL)
		head = &pcfg->steer_excludelist;
	else
		return -1;

	list_for_each_entry(ex_sta, head, list) {
		uint8_t xmac[6] = {0};

		hwaddr_aton(ex_sta->macstring, xmac);
		if (!memcmp(sta_mac, xmac, 6)) {
			dbg("STA " MACFMT " excluded from steering\n",
			    MAC2STR(sta_mac));
			disallowed = 1;
			break;
		}
	}

	return disallowed;
}

static int agent_try_steer_sta(struct agent *a, struct netif_fh *fh,
		uint8_t *src_bssid, uint8_t *sta_mac, uint8_t *dst_bssid,
		struct sta_error_response *sta_resp, int count, uint8_t req_mode)
{
	uint8_t target_bssid[6] = { 0 };
	int ret = 0;
	int i;

	trace("agent: %s: --->\n", __func__);

	dbg("steered STA mac: " MACFMT "\n", MAC2STR(sta_mac));
	dbg("target bssid: " MACFMT "\n", MAC2STR(dst_bssid));

	/* Check if STA is allowed for steering */
	ret = agent_sta_disallowed(a, sta_mac, STA_DISALLOWED_LOCAL);
	if (ret == 1)
		dbg("Error steering: STA disallowed (local)\n");

	if (ret)
		return -1;


	/* Check if STA is associated with the src bssid */
	dbg("num of error code stas %d\n", count);
	for (i = 0; i < count; i++) {
		dbg("sta error mac: " MACFMT "\n",
		    MAC2STR(sta_resp[i].sta_mac));
		if (!memcmp(sta_mac, sta_resp[i].sta_mac, 6))
			return -1;
	}

	/* Calculate target bssid for this STA */
	if (is_wildcard_bssid(dst_bssid))
		ret = agent_find_best_bssid_for_sta(a, sta_mac, src_bssid, target_bssid);
	else
		memcpy(target_bssid, dst_bssid, 6);

	if (ret)
		return -1;

	/* Check if STA is disallowed from BTM steering */
	ret = agent_sta_disallowed(a, sta_mac, STA_DISALLOWED_BTM);
	if (!ret) {
		/* BTM steering */
		ret = agent_send_request_transition(a, sta_mac, fh, target_bssid, 0);
	} else if (ret == 1) {
		/* BTM disallowed */
		dbg("Error steering: STA disallowed (BTM)\n");
		/* TODO: opportunity: try assoc control */
		//if (req_mode == 0x00) {
		//}
	}

	return ret;
}

int agent_process_steer_request_tlv(void *agent,
		struct tlv_steer_request *p, struct cmdu_buff *cmdu)
{
	trace("agent: %s: --->\n", __func__);

	struct agent *a = (struct agent *) agent;
	int ret = 0, offset = 0;
	int i;
	struct netif_fh *fh;
	struct sta *s;
	struct sta_error_response sta_resp[MAX_STA];
	uint32_t count = 0;
	uint8_t wildcard[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	uint8_t mode = 0x00;
	uint8_t req_mode = 0x00;
	uint16_t op_window;
	uint8_t bssid[6] = { 0 };
	uint8_t num_sta;
	uint8_t *stalist = NULL;
	uint8_t num_bss;
	struct bss_data{
		uint8_t bssid[6];
		uint8_t opclass;
		uint8_t channel;
	} *barray = NULL;
	uint8_t *data = (uint8_t *)p;

	memcpy(bssid, &data[offset], 6);
	offset += 6;
	mode = data[offset++];
	trace("mode: %d\n", mode);
	req_mode = (mode & STEER_REQUEST_MODE) >> 7;
	trace("request_mode: %d\n", req_mode);
	op_window = BUF_GET_BE16(data[offset]);
	offset += 2;

	if (req_mode == 0x00) {
		/* Here we start the steer opportunity timer */
		if (a->is_sta_steer_start == 1) {
			trace("Error steering opportunity timer already running\n");
			return -1;
		}

		/**
		 * Here we need to check the three conditions that needs to be
		 * satisfied according to section 11.2
		 */
		if (op_window == 0) {
			trace("Error steering opportunity timer value is zero\n");
			return -1;
		}

		a->is_sta_steer_start = 1;
		a->sta_steerlist_count = 0;
		timer_set(&a->sta_steer_req_timer, op_window * 1000);

	} else if (req_mode != 0x01) {
		trace("Invalid request mode");
		return -1;
	}

	/* TODO check the rcpi based steering rule section 11.3*/
	/* FIXME: not here */
	agent_rcpi_steer();

	/**
	 * The src bssid is with which the STA is associated so
	 * Here we need to check that the STA is associated with the
	 * src_bssid according to section 11.1 of the steer mandate
	 * Here we trace the values
	 */
	dbg("btm_disassoc_imminent: %d\n",
			/* FIXME unused */
			(mode & STEER_REQUEST_BTM_DISASSOC_IMM) >> 6);
	dbg("btm_abridged: %d\n",
			/* FIXME unused */
			(mode & STEER_REQUEST_BTM_ABRIDGED) >> 5);
	dbg("steer_opp_window: %d\n", op_window);
	dbg("btm_disassoc_timer: %d\n", BUF_GET_BE16(data[offset]));
	offset += 2;

	num_sta = data[offset++];
	dbg("[%s:%d] sta_list_cnt: %d\n",
	    __func__, __LINE__, num_sta);
	if (num_sta > 0) {
		stalist = calloc(num_sta, 6 * sizeof(uint8_t));
		if (!stalist) {
			dbg("%s:%d -ENOMEM\n", __func__, __LINE__);
			return -1;
		}
	}

	for (i = 0; i < num_sta; i++) {
		memcpy(&stalist[i * 6], &data[offset], 6);
		offset += 6;
		dbg("sta_mac: " MACFMT "\n", MAC2STR(&stalist[i * 6]));
	}

	num_bss = data[offset++];
	dbg("target_bssid_list_cnt: %d\n", num_bss);

	if (num_bss == 0 && req_mode != 0x00) {
		trace("[%s:%d]Error steer mandate: target BSSID not present\n",
		      __func__, __LINE__);
		ret = -1;
		goto out;
	}

	if (num_bss > 0) {
		barray = calloc(num_bss, sizeof(struct bss_data));
		if (!barray) {
			dbg("%s:%d -ENOMEM\n", __func__, __LINE__);
			ret = -1;
			goto out;
		}
	}

	for (i = 0; i < num_bss; i++) {
		memcpy(barray[i].bssid, &data[offset], 6);
		offset += 6;
		barray[i].opclass = data[offset++];
		barray[i].channel = data[offset++];
	}

	/* Check src bssid present */
	fh = wifi_get_netif_by_bssid(a, bssid);
	if (!fh) {
		trace("[%s:%d] Error BSSID " MACFMT " not present",
			  __func__, __LINE__, MAC2STR(bssid));
		for (i = 0; i < num_sta; i++) {
			memcpy(sta_resp[count].sta_mac, &stalist[i * 6], 6);
			sta_resp[count++].response = 0x02;
			goto send_ack;
		}
	}

	if (num_sta == 0) {
		/**
		 * No STA provided, Steering request applies to all associated STAs
		 * in the BSS, per policy setting.
		 */
		if (num_bss == 1) {
			int num_steered = 0;

			list_for_each_entry(s, &fh->stalist, list) {
				/* Call for transition of sta */
				ret = agent_try_steer_sta(a, fh, bssid,
						s->macaddr, barray[0].bssid,
						sta_resp, count, req_mode);
				if (ret)
					dbg("[%s:%d] Couldn't steer " MACFMT "\n",
					    __func__, __LINE__, MAC2STR(s->macaddr));
				else
					num_steered++;
			}
			ret = num_steered ? -1 : 0;
			goto send_ack;
		/* Zero or more than one BSS */
		} else {
			trace("[%s:%d] Error condition\n", __func__, __LINE__);
			ret = -1;
			goto out;
		}
	}

	/* At least one STA: check if associated with src bssid & fill-in sta_resp */
	ret = agent_set_sta_resp(a, fh, req_mode, num_sta, stalist, sta_resp, &count);
	if (ret == -1)
		/* None of the stations from the stalist found attached to fh */
		goto send_ack;

	/* Number of STAs and BSSIDs are equal, map STA to BSSID */
	if (num_sta == num_bss) {
		for (i = 0; i < num_sta; i++) {
			/* Call for transition of sta */
			ret = agent_try_steer_sta(a, fh, bssid,
					&stalist[i * 6], barray[i].bssid,
					sta_resp, count, req_mode);
		}
	}
	/* Multiple STAs and single BSSID, send all STAs to same BSSID */
	else if (num_bss == 1) {

		for (i = 0; i < num_sta; i++) {
			/* Call for transition of sta */
			ret = agent_try_steer_sta(a, fh, bssid,
					&stalist[i * 6], barray[0].bssid,
					sta_resp, count, req_mode);
		}
	}
	/* No BSSID specified for the STAs */
	else if (num_bss == 0) {
		dbg("[%s:%d] target BSSID not present\n", __func__, __LINE__);
		for (i = 0; i < num_sta; i++) {
			/* Call for transition of sta */
			ret = agent_try_steer_sta(a, fh, bssid,
					&stalist[i * 6], wildcard,
					sta_resp, count, req_mode);
		}
	/* Unspecified error condition */
	} else {
		trace("[%s:%d] Error condition\n", __func__, __LINE__);
		ret = -1;
		goto out;
	}

send_ack:
	send_1905_acknowledge(agent, cmdu->origin, cmdu_get_mid(cmdu), sta_resp, count);

out:
	if (stalist)
		free(stalist);

	if (barray)
		free(barray);

	return ret;
}

int handle_sta_steer_request(void *agent, struct cmdu_buff *cmdu,
			     struct node *n)
{
	trace("%s: --->\n", __func__);
	struct agent *a = (struct agent *) agent;
	int ret = 0;
	struct tlv *tv[2][16];

	UNUSED(a);

	ret = map_cmdu_parse_tlvs(cmdu, tv, 2, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	if (tv[0][0]) {
		struct tlv_steer_request *p =
			(struct tlv_steer_request *)tv[0][0]->data;

		ret = agent_process_steer_request_tlv(agent, p, cmdu);
	}

//#ifdef PROFILE2
	if (tv[1][0]) {
		/* TODO here we need to call the request transmission
		 * for the STAs are Agile Multiband capable
		 */
		struct tlv_profile2_steer_request *p =
			(struct tlv_profile2_steer_request *)tv[1][0]->data;
		UNUSED(p);
	}
//#endif

	return ret;
}

static void agent_una_sta_meas_timer_cb(atimer_t *t)
{
	struct netif_fh *fh = container_of(t, struct netif_fh,
							una_sta_meas_timer);
	struct agent *a = fh->agent;
	struct wifi_radio_element *radio;
	struct wifi_unassoc_sta_element *sta_elem;
	int num_sta;
	int8_t rssi = 0;
	int i;
	uint8_t macaddr[6];
	int max_num_tries = 0;
	bool retry = false;	/* retry if one or more rssi is 0 */
	bool send = false;	/* at least one result is non-zero */

	dbg("agent: %s: --->\n", __func__);

	radio = wifi_ifname_to_radio_element(a, fh->name);
	num_sta = radio->num_unassoc_sta;

	for (i = 0; i < num_sta; i++) {
		sta_elem = &radio->unassoc_stalist[i];

		if (sta_elem->monitor != true)
			continue;

		memcpy(macaddr, sta_elem->macaddr, 6);
		agent_sent_request_monitor_get(a, fh, macaddr, &rssi);

		if (rssi) {
			dbg("received unassoc STA measurement for " MACFMT
			    " rssi = %d\n", MAC2STR(macaddr), rssi);
			sta_elem->meas.rssi = rssi;
			sta_elem->meas.rcpi = rssi_to_rcpi(rssi);
			timestamp_update(&sta_elem->meas.timestamp);
			agent_sent_request_monitor_del(a, fh, macaddr);
			sta_elem->monitor = false;

			send = true;
		} else {
			sta_elem->meas.num_tries++;
			sta_elem->meas.rssi = 0;
			sta_elem->meas.rcpi = 255; /* Meas not available */
			sta_elem->meas.timestamp.tv_sec = 0;
			sta_elem->meas.timestamp.tv_nsec = 0;

			if (sta_elem->meas.num_tries > UNA_STA_MEAS_MAXTRIES) {
				dbg("[%s:%d] max number of measurements reached for " \
				    MACFMT "\n", __func__, __LINE__, MAC2STR(macaddr));
				agent_sent_request_monitor_del(a, fh, macaddr);
				sta_elem->monitor = false;
			} else {
				retry = true;
			}
		}
	}

	if (send || !retry)
		/* TODO: offchannel: send report separately for each opclass */
		send_unassoc_sta_link_metrics_response(a, fh, radio->current_opclass);

	if (retry) {
		/* at least one STA didn't return rssi & has remaining tries */
		dbg("[%s:%d] no rssi for one or more STA - retry (%d)\n",
		    __func__, __LINE__, max_num_tries);
		timer_set(&fh->una_sta_meas_timer, UNA_STA_MEAS_TIMER);
	}
}

static void agent_monitor_setup(struct wifi_radio_element *radio, int num_sta)
{
	/* TODO: OFF-channel measurement: opclass/channel via arg */
	radio->unassoc_stalist[num_sta].meas.opclass = radio->current_opclass;
	radio->unassoc_stalist[num_sta].meas.channel = radio->current_channel;
	radio->unassoc_stalist[num_sta].meas.num_tries = 0;
	radio->unassoc_stalist[num_sta].monitor = true;
}

/* Function adding station to the monitor for given netif/radio
 *
 * Returns:
 * 0 on success, -1 on failure
 */
static int agent_monitor_checkadd_sta(struct agent *a,
		struct netif_fh *fh, struct wifi_radio_element *radio,
		uint8_t *macaddr)
{
	size_t el_size = sizeof(struct wifi_unassoc_sta_element);
	int num_sta = radio->num_unassoc_sta;
	struct wifi_unassoc_sta_element *unassoc_stalist;
	int i;

	trace("agent: %s: --->\n", __func__);

	if (num_sta && radio->unassoc_stalist) {
		for (i = 0; i < num_sta; i++) {
			if (!memcmp(radio->unassoc_stalist[i].macaddr, macaddr, 6)) {
				/* STA already on the list */
				dbg("[%s:%d] STA " MACFMT " already added\n",
				    __func__, __LINE__, MAC2STR(macaddr));
				/* New request - reset some of the fields */
				agent_monitor_setup(radio, i);
				return 0;
			}
		}
	}

	agent_sent_request_monitor_add(a, fh, macaddr);

	/* STA not on the list yet - add */
	unassoc_stalist = realloc(radio->unassoc_stalist,
			(num_sta + 1) * el_size);

	if (!unassoc_stalist) {
		warn("[%s:%d] failed to (re)allocate unassoc_stalist\n",
		     __func__, __LINE__);
		return -1;
	}

	radio->unassoc_stalist = unassoc_stalist;
	radio->num_unassoc_sta++;

	memset(&radio->unassoc_stalist[num_sta],
			0, sizeof(struct wifi_unassoc_sta_element));
	memcpy(radio->unassoc_stalist[num_sta].macaddr, macaddr, 6);

	agent_monitor_setup(radio, num_sta);

	return 0;
}

/* A Multi-AP Agent shall attempt RCPI measurement on the current
 * operating channel(s) of its radio(s) and, if it indicated support
 * with the Off-Channel Unassociated STA Link Metrics bit in the AP
 * Capability TLV, shall attempt RCPI measurement on the other channels
 * and Operating Classes specified in the query. When a Multi-AP Agent
 * measures RCPI values for unassociated STA link metric reporting,
 * these values may be averaged over time using an implementation-specific
 * smoothing function.
 */
int agent_process_unassoc_sta_lm_query_tlv(struct agent *a,
		struct tlv_unassoc_sta_link_metrics_query *query,
		struct cmdu_buff *cmdu)
{
	trace("agent: %s: --->\n", __func__);
	int ri;

	/* TODO: check sta is not connected (also done in controller) */
	/* TODO: add/check UCI config for Off/On Channel support, return */

	for (ri = 0; ri < a->num_radios; ri++) {
		struct wifi_radio_element *radio = a->radios + ri;
		struct netif_fh *fh;

		/* TODO: Off Channel support -> switch opclass & channel */
		if (query->opclass != radio->current_opclass) {
			dbg("[%s:%d] query opclass (%d) differs from current (%d)\n",
			     __func__, __LINE__, query->opclass, radio->current_opclass);
			continue;
		}

		list_for_each_entry(fh, &a->fhlist, list) {
			int i;
			int num_sta_monitor = 0;

			if (strcmp(radio->name, fh->radio_name))
				continue;

			for (i = 0; i < query->num_channel; i++) {
				int j;

				if (radio->current_channel != query->ch[i].channel) {
					dbg("[%s:%d] query channel[%d]=%d differs " \
					    "from current (%d)\n", __func__, __LINE__, i,
					    query->ch[i].channel,
					    radio->current_channel);
					continue;
				}

				for (j = 0; j < query->ch[i].num_sta; j++) {
					if (!agent_monitor_checkadd_sta(a, fh, radio,
						query->ch[i].sta[j].macaddr))
						num_sta_monitor++;
				}
			}

			if (num_sta_monitor) {
				/* timer already started on given fh: reset */
				if (timer_pending(&fh->una_sta_meas_timer))
					timer_del(&fh->una_sta_meas_timer);

				/* TODO: add UCI config for default timeout */
				dbg("[%s:%d] setting up measurement timer for %d sec\n",
				    __func__, __LINE__, (UNA_STA_MEAS_TIMER / 1000));
				timer_init(&fh->una_sta_meas_timer, agent_una_sta_meas_timer_cb);
				timer_set(&fh->una_sta_meas_timer, UNA_STA_MEAS_TIMER);
			}

			/* TODO: use interface with fewer associated STAs */

			/* Measure over one interface per radio only */
			break;
		}
	}

	return 0;
}

int agent_process_beacon_metrics_query_tlv(struct agent *a,
		struct tlv_beacon_metrics_query *query,
		struct cmdu_buff *cmdu, struct netif_fh *fh)
{
	struct ssid_query *ssidq;
	char ssid[33] = {0};
	uint8_t *data;
	uint8_t num_report = 0;
	uint8_t *reports;
	uint8_t num_element = 0;
	uint8_t *elements;
	int i, offset = 0;
	int ret = 0;

	trace("agent: %s: --->\n", __func__);

	/* Since there's a flexible array member in the middle of
	 * the structure, one must proceed manually in order to
	 * properly recover remaining 'query' fields from 'data'.
	 */

	/* Still possible to use struct ssid_query here */
	ssidq = (struct ssid_query *) &(query->ssid);
	if (ssidq->ssidlen && ssidq->ssidlen < 33) {
		memcpy(ssid, ssidq->ssid, ssidq->ssidlen);
		ssid[ssidq->ssidlen] = '\0';
	}

	/* Must use data pointer to get rest of the tlv */

	/* query->num_report */
	data = (uint8_t *)query;
	offset += offsetof(struct tlv_beacon_metrics_query, ssid) + 1 + ssidq->ssidlen;
	num_report = data[offset++];

	/* query->report */
	reports = &data[offset];

	for (i = 0; i < num_report; i++) {
		struct ap_channel_report *rep =
				(struct ap_channel_report *)&data[offset];
		offset += 1 + rep->len;
	}

	/* query->num_element */
	num_element = data[offset++];

	/* query->element */
	elements = &data[offset];

	dbg("[%s:%d] num_report = %d, num_element = %d\n",
			__func__, __LINE__, num_report, num_element);

	/* Send an 802.11 Beacon request to STA */
	ret = agent_request_beacon_metrics(a, fh, query->sta_macaddr,
			query->opclass, query->channel, query->bssid,
			query->reporting_detail, ssidq->ssidlen, ssid,
			num_report, reports, num_element, elements);

	return ret;
}

int handle_beacon_metrics_query(void *agent, struct cmdu_buff *rx_cmdu,
				struct node *n)
{
	struct agent *a = (struct agent *) agent;
	struct tlv *tv[1][16] = {0};
	struct tlv_beacon_metrics_query *query;
	struct sta_error_response sta_resp[1] = {0};
	struct netif_fh *fh;
	int ret = 0;

	trace("%s: --->\n", __func__);

	ret = map_cmdu_parse_tlvs(rx_cmdu, tv, 1, n->map_profile);

	if (ret || !tv[0][0])
		return -1;

	query = (struct tlv_beacon_metrics_query *) tv[0][0]->data;

	if (!is_wildcard_bssid(query->bssid)) {
		trace("[%s:%d] checking bssid specified in query\n",
				__func__, __LINE__);
		fh = wifi_get_netif_by_bssid(a, query->bssid);
	} else {
		trace("[%s:%d] using wildcard bssid\n",
				__func__, __LINE__);
		fh = get_netif_by_sta(a, query->sta_macaddr);
	}

	if (!fh) {
		/*
		 * If the specified STA in the Beacon Metrics Query message
		 * is not associated with any of the BSS operated by the
		 * Multi-AP Agent (an error scenario), the Multi-AP Agent
		 * shall include an Error Code TLV with the reason code field
		 * set to 0x02 and the STA MAC address field included per
		 * section 17.2.36 in the 1905 Ack message.
		 */
		dbg("Specified STA not associated with a BSS operated"\
				 " by the Multi-AP Agent!\n");

		sta_resp[0].response = 0x02;
		memcpy(sta_resp[0].sta_mac, query->sta_macaddr, 6);

		/* If a Multi-AP Agent receives a Beacon Metrics Query message,
		 * then it shall respond within 1s with a 1905 Ack message.
		 */
		send_1905_acknowledge(agent, rx_cmdu->origin,
				      cmdu_get_mid(rx_cmdu),
				      sta_resp, 1);
		return -1;
	}

	send_1905_acknowledge(agent, rx_cmdu->origin, cmdu_get_mid(rx_cmdu),
			      sta_resp, 0);

	return agent_process_beacon_metrics_query_tlv(a, query, rx_cmdu, fh);
}

int handle_sta_assoc_control_request(void *agent, struct cmdu_buff *cmdu,
				     struct node *n)
{
	trace("%s: --->\n", __func__);

	int ret = -1, idx;
	struct tlv *tv[1][16];

	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	idx = 0;
	while (tv[0][idx]) {
		uint8_t *p = (uint8_t *)tv[0][idx++]->data;

		ret = agent_process_assoc_cntl_tlv(agent, p, cmdu);
	}

	return ret;
}

int agent_hld_event(struct agent *a, uint8_t proto, uint8_t *data,
		int data_len)
{
	const int len = data_len*2 + 128;
	char *str;
	int idx;

	str = calloc(len, sizeof(char));
	if (!str)
		return -1;

	idx = snprintf(str, len, "{\"protocol\":%d,\"data\":\"", proto);
	btostr(data, data_len, str + idx);
	idx += data_len*2;
	snprintf(str + idx, len - idx, "\"}");

	agent_notify_event(a, "map.agent.higher_layer_data", str);

	free(str);

	return 0;
}

int handle_hld_message(void *agent, struct cmdu_buff *rx_cmdu, struct node *n)
{
	struct agent *a = (struct agent *) agent;
	struct tlv *tv[1][16] = {0};
	uint8_t *usrdata;
	struct tlv *t;
	uint8_t proto;
	uint8_t *data;
#ifdef AGENT_SYNC_DYNAMIC_CNTLR_CONFIG
	bool cntlr_sync = (a->cfg.dyn_cntlr_sync & is_local_cntlr_available());
#endif
	int data_len;
	int tlen = 0;
	int ret;
	int idx;


	trace("%s: --->\n", __func__);
	ret = map_cmdu_parse_tlvs(rx_cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return -1;
	}

	if (!tv[0][0]) {
		err("%s: higher layer data TLV not found\n", __func__);
		return -1;
	}

	idx = 0;
	t = tv[0][0];
	proto = t->data[0];
	data_len = tlv_length(t) - 1;
	data = t->data + 1;
	tlen += data_len;

	dbg("%s HLD received proto = %u (0x%01x)\n", __func__, proto, proto);
	usrdata = calloc(data_len, sizeof(uint8_t));
	if (!usrdata) {
		err("%s: calloc() failed\n", __func__);
		return -1;
	}

	memcpy(usrdata, data, data_len);
	idx++;
	while (tv[0][idx]) {
		uint8_t *newdata = NULL;

		t = tv[0][idx];
		data_len = tlv_length(t);

		newdata = realloc(usrdata, tlen + data_len);
		if (!newdata) {
			free(usrdata);
			err("%s: realloc() failed\n", __func__);
			return -1;
		}

		memcpy(newdata + tlen, t->data, data_len);
		tlen += data_len;
		idx++;
		usrdata = newdata;
		dbg("\nRealloc'd userdata tlen = %d\n", tlen);
	}

	ret = agent_hld_event(a, proto, usrdata, tlen);
	if (ret == 0)
		send_1905_acknowledge(a, rx_cmdu->origin, cmdu_get_mid(rx_cmdu), NULL, 0);

#ifdef AGENT_SYNC_DYNAMIC_CNTLR_CONFIG
	if (proto == 0xab && cntlr_sync) {
		struct cmdu_buff *cmdu;
		uint8_t res_proto = 0xac;
		uint16_t sync_config_reqsize = 0;
		uint8_t *sync_config_req;
		void *key;

		dbg("*** handle dyn-controller-config-sync-start ***\n");
		ret = build_sync_config_request(a->almac, &sync_config_req,
						&sync_config_reqsize, &key);
		if (ret) {
			err("Failed to build sync-config-req frame!\n");
			goto error;
		}

		/* free old data if any */
		agent_free_cntlr_sync(a);

		a->sync_config_reqsize = sync_config_reqsize;
		a->sync_config_req = sync_config_req;
		a->privkey = key;

		cmdu = agent_gen_higher_layer_data(a, a->cntlr_almac, res_proto,
						   sync_config_req, sync_config_reqsize);
		if (!cmdu) {
			ret = -1;
			goto error;
		}

		agent_send_cmdu(a, cmdu);
		cmdu_free(cmdu);
	} else if (proto == 0xac && cntlr_sync) {
		struct sync_config out = {0};
		char enabled[2] = {0};

		dbg("*** Process dyn-controller-config-sync response ***\n");
		/*
		if (a->sync_config_resp)
			free(a->sync_config_resp);

		a->sync_config_resp = 0;
		a->sync_config_resp = calloc(data_len, sizeof(uint8_t));
		if (a->sync_config_resp) {
			memcpy(a->sync_config_resp, data, data_len);
			a->sync_config_respsize = data_len;
		}
		*/

		ret = process_sync_config_response(a->sync_config_req,
						   a->sync_config_reqsize,
						   a->privkey,
						   usrdata, tlen,
						   &out);
		if (ret) {
			err("Error processing dyn-controller-config-sync response\n");
			goto error;
		}

		agent_get_controller_enabled(a, enabled);

		ret = writeto_configfile("/etc/config/mapcontroller", out.data, out.len);
		if (ret)
			fprintf(stderr, "failed to write file\n");
		set_value_by_string("mapcontroller", "controller", "enabled",
				enabled, UCI_TYPE_STRING);

		free(out.data);
	}

error:
#endif /* AGENT_SYNC_DYNAMIC_CNTLR_CONFIG */
	free(usrdata);

	return ret;
}

int handle_backhaul_sta_steer_request(void *agent, struct cmdu_buff *rx_cmdu,
				      struct node *n)
{
	trace("%s: --->\n", __func__);
	struct agent *a = (struct agent *) agent;
	//uint8_t bssid[6];
	//struct tlv *tlv = NULL;
	struct tlv_backhaul_steer_request *req;
	struct tlv *tv[1][16] = {0};
	struct netif_bk *bk;
	struct cmdu_buff *cmdu;
	char fmt[128] = {0};
	int rv = 0;
	int timeout = BSTA_STEER_TIMEOUT;
	int ret;

	ret = map_cmdu_parse_tlvs(rx_cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return -1;
	}

	if (!tv[0][0])
		return -1;

	req = (struct tlv_backhaul_steer_request *) tv[0][0]->data;
	if (!req)
		return -1;

	bk = find_bkhaul_by_bssid(a, req->macaddr);
	if (!bk)
		return -1;

	cmdu = agent_gen_cmdu_backhaul_steer_resp(a, req->target_bssid,
			req->macaddr, cmdu_get_mid(rx_cmdu));
	if (!cmdu)
		return -1;

	if (bk->bsta_steer.cmdu)
		cmdu_free(bk->bsta_steer.cmdu);
	bk->bsta_steer.cmdu = cmdu;

	wifi_get_iface_bssid(bk->name, bk->bsta_steer.prev_bssid);

	snprintf(fmt, sizeof(fmt), "bsta_steer %s " MACFMT " %u", bk->name,
			MAC2STR(req->target_bssid), req->target_channel);

	trace("fmt = %s\n", fmt);

	wifi_mod_bridge(a, bk->name, "remove");

	rv = agent_exec_platform_scripts(fmt);
	if (rv) {
		wifi_mod_bridge(a, bk->name, "add");
		timeout = 0;
	}


	//wifi_set_iface_bssid(bk, req->target_bssid);
	timer_set(&bk->connect_timer, timeout * 1000); /* TODO: why the long timeout */

	memcpy(cmdu->origin, rx_cmdu->origin, 6);
	return 0;
}

/* Returns false if any of the requested opc/channel is not available
 * for scan. True otherwise.
 */
bool scan_supported(struct agent *a, struct wifi_scan_request_radio *req,
		struct wifi_netdev *ndev)
{
	trace("%s: --->\n", __func__);

	uint8_t classid;
	int i, j;

	if (!ndev)
		/* No such radio */
		return false;

	if (WARN_ON(!ndev->re))
		return false;

	if (req->num_opclass == 0)
		/* Scan all opclasses */
		return true;

	for (i = 0; i < req->num_opclass; i++) {
		if (req->opclass[i].num_channel == 0)
			/* Scan all channels */
			continue;

		for (j = 0; j < req->opclass[i].num_channel; j++) {
			uint8_t channel;

			channel = req->opclass[i].channel[j];

			if (req->opclass[i].classid)
				classid = req->opclass[i].classid;
			else
				classid =
					wifi_opclass_get_id(
							&ndev->re->opclass,
							channel,
							20);

			if (!is_channel_supported_by_radio(ndev->re,
					classid, channel))
				return false;
		}
	}

	return true;
}

static int wifi_radio_scan_req(struct agent *a, const char *radio, const char *ssid,
		int num_opclass, uint8_t *opclass,
		int num_channel, uint8_t *channel)
{
	struct scan_param_ex param = {};
	int res = 0;
	int i;

	if (ssid) {
		param.flag |= WIFI_SCAN_REQ_SSID;
		param.num_ssid = 1;

		strncpy(param.ssid[0], ssid, strlen(param.ssid[0]) - 1);
	}

	if (radio) {
		struct wifi_radio_element *re = wifi_radio_to_radio_element(a, radio);

		if (!re)
			return -1;

		re->scan_state = SCAN_REQUESTED;
		return wifi_scan(radio, &param, num_opclass, opclass,
						num_channel, channel);
	}

	for (i = 0; i < ARRAY_SIZE(a->radios); i++) {
		a->radios[i].scan_state = SCAN_REQUESTED;
		res |= wifi_scan(a->radios[i].name, &param, num_opclass, opclass,
						num_channel, channel);
	}

	return res;
}

int wifi_radio_scan_req_all(struct agent *a, const char *radio)
{
	return wifi_radio_scan_req(a, radio, NULL, 0, NULL, 0, NULL);
}

static int issue_channel_scan(struct agent *a,
		struct wifi_netdev *ndev,
		struct wifi_scan_request_radio *req)
{
	trace("%s: --->\n", __func__);

	uint8_t opclasses[128] = {};
	uint8_t channels[128] = {};
	int op_idx = 0, ch_idx = 0;
	int i, j;
	int ret = 0;

	if (WARN_ON(!a || !ndev || !ndev->re || !req))
		return -1;

	trace("Attempting to scan radio %s neighbors\n", ndev->radio);

	/* pass all opclasses & channels */
	for (i = 0; i < req->num_opclass; i++) {

		for (j = 0; j < req->opclass[i].num_channel; j++) {
			if (ch_idx >= ARRAY_SIZE(channels))
				break;

			if (req->opclass[i].channel[j] > 0)
				channels[ch_idx++] =
					req->opclass[i].channel[j];
		}

		/* Channels listed explicitly */
		if (req->opclass[i].num_channel)
			continue;

		if (req->opclass[i].classid == 0)
			/* only channels provided, skip opclass */
			// TODO: revisit
			continue;

		if (op_idx >= ARRAY_SIZE(opclasses))
			break;

		opclasses[op_idx++] = req->opclass[i].classid;

		/* num_channel == 0 indicates that the Multi-AP Agent is
		 * requested to scan on all channels in the Operating Class.
		 */
		if (req->opclass[i].num_channel == 0) {
			ch_idx = ARRAY_SIZE(channels);
			wifi_opclass_get_supported_ctrl_channels(
						&ndev->re->opclass,
						req->opclass[i].classid,
						channels,
						&ch_idx);
		}
	}

	/* Pass all the opclasses & channels from the request */
	if (op_idx > 0 || ch_idx > 0)
		ret = wifi_radio_scan_req(a, ndev->radio, NULL,
					op_idx, opclasses, ch_idx, channels);
	else
		ret = wifi_radio_scan_req_all(a, ndev->radio);

	return ret;
}

int parse_channel_scan_req(struct agent *a, struct cmdu_buff *req_cmdu,
			struct wifi_scan_request *req, uint8_t map_profile)
{
	struct tlv *tv[1][16] = {0};
	uint8_t *t = NULL;
	int i, j, k;
	int offset = 0;
	uint8_t mode;
	uint16_t mid;
	uint8_t num_radio;

	if (!validate_channel_scan_request(req_cmdu, tv, map_profile)) {
		dbg("cmdu validation: [CHANNEL_SCAN_REQ] failed\n");
		return -1;
	}

	t = (uint8_t *)tv[0][0]->data;

	/* store mid of the request */
	mid = cmdu_get_mid(req_cmdu);

	mode = t[offset++];

	req->mode = mode;

	num_radio = t[offset++];
	if (WARN_ON(num_radio > SCAN_MAX_RADIO))
		return -1;
	req->num_radio = num_radio;

	for (i = 0; i < num_radio; i++) {
		uint8_t radio_id[6];
		uint8_t num_opclass;

		/* radio id */
		memcpy(&radio_id, &t[offset], 6);
		memcpy(&req->radio[i].radio, &radio_id, 6);
		offset += 6;

		req->radio[i].mid = mid;

		/* num opclass */
		num_opclass = t[offset++];
		if (WARN_ON(num_opclass > SCAN_MAX_OPCLASS))
			return -1;

		req->radio[i].num_opclass = num_opclass;

		for (j = 0; j < num_opclass; j++) {
			uint8_t num_channel;

			/* class id */
			req->radio[i].opclass[j].classid = t[offset++];

			/* num channel */
			num_channel = t[offset++];
			if (WARN_ON(num_channel > SCAN_MAX_CHANNEL))
				return -1;

			req->radio[i].opclass[j].num_channel = num_channel;

			for (k = 0; k < num_channel; k++)
				req->radio[i].opclass[j].channel[k] = t[offset++];
		}
	}

	return 0;
}

int handle_channel_scan_request(void *agent, struct cmdu_buff *rx_cmdu,
				struct node *n)
{
	trace("%s: --->\n", __func__);

	struct agent *a = (struct agent *) agent;
	struct wifi_scan_request ch_scan_req = { 0 };
	struct wifi_netdev *ndev;
	int ret;
	int i;

	/* If a Multi-AP Agent receives a Channel Scan Request message,
	 * it shall respond within one second with a 1905 Ack message.
	 */
	send_1905_acknowledge(a, rx_cmdu->origin, cmdu_get_mid(rx_cmdu), NULL, 0);

	ret = parse_channel_scan_req(a, rx_cmdu, &ch_scan_req, n->map_profile);
	if (ret)
		return -1;

	for (i = 0; i < ch_scan_req.num_radio; i++) {
		bool scan = false;
		struct wifi_scan_request_radio *scan_req;

		scan_req = &ch_scan_req.radio[i];

		ndev = wifi_radio_id_to_netdev(a, scan_req->radio);
		if (!ndev)
			continue;

		if (WARN_ON(!ndev->re))
			continue;

		/* 'Pefrorm Fresh Scan' while 'On boot only' set in Caps */
		if (a->cfg.scan_on_boot_only
				&& ch_scan_req.mode & SCAN_REQUEST_FRESH_SCAN) {
			dbg("[Scan Status] radio %s: BOOT SCAN ONLY\n\n",
			    ndev->radio);

			/* Special status in 'boot only' mode for 'fresh scan' */
			scan_req->status = CH_SCAN_STATUS_BOOT_SCAN_ONLY;
		}
		/* Do not 'Perform Fresh Scan' */
		else if (!(ch_scan_req.mode & SCAN_REQUEST_FRESH_SCAN)) {
			if (a->cfg.scan_on_boot_only
					&& ndev->re->scan_state != SCAN_DONE)
				/* Some boot scan results missing yet */
				scan_req->status = CH_SCAN_STATUS_SCAN_NOT_COMPLETED;
			else
				scan_req->status = CH_SCAN_STATUS_SUCCESS;
		}
		/* Check all requested opc/chan pairs supported by radio */
		else if (!scan_supported(a, scan_req, ndev)) {
			/* Scan not supported for some opc/channel pairs */
			dbg("[Status code] SCAN NOT SUPPORTED\n\n");

			//TODO: separate status for individual opc/ch pairs

			scan_req->status = CH_SCAN_STATUS_SCAN_NOT_SUPPORTED;
		}
		/* Scan too soon */
		else if (!timestamp_expired(&ndev->last_scan_tsp,
						MIN_SCAN_ITV_SEC * 1000)) {
			dbg("[Status code] SCAN TOO SOON\n\n");

			scan_req->status = CH_SCAN_STATUS_TOO_SOON;
		}
		/* Ongoing scan in progress */
		else if (ndev->re->scan_state == SCAN_SCANNING) {
			dbg("[Status code] ONGOING SCAN ABORTED\n\n");

			scan_req->status = CH_SCAN_STATUS_SCAN_ABORTED;
		} else
			scan = true;

		/* Update scan timestamp */
		timestamp_update(&ndev->last_scan_tsp);

		if (!scan) {
			/* Do not scan - report failure or stored results */
			ret = agent_send_ch_scan_response(a, ndev, scan_req);
			if (ret)
				return -1;

			continue;
		}

		/* SCAN */

		/* Mark radio unscanned prior to a new scan (only) */
		ndev->re->scan_state = SCAN_NONE;

		trace("Trying to issue channel scan on the request of mid: %d\n",
			  scan_req->mid);

		/* Issue channel scan & check return code */
		ret = issue_channel_scan(a, ndev, scan_req);
		if (ret) {
			dbg("[Status code] RADIO BUSY\n\n");

			/* Send the 'busy' response */
			scan_req->status = CH_SCAN_STATUS_TOO_BUSY;
			ret = agent_send_ch_scan_response(a, ndev, scan_req);
			if (ret)
				return -1;

			continue;
		}

		trace("Scan started successfully.\n");
		ndev->re->scan_state = SCAN_REQUESTED;

		/* Wait (up to 5min) for the results */
		timer_set(&ndev->available_scan_timer, 300000);

		/* Store the request data */
		ndev->scan_req = *scan_req;

		/* Mark as success only after results available */
		ndev->scan_req.status = CH_SCAN_STATUS_SCAN_NOT_COMPLETED;
	}

	return 0;
}

int wifi_radio_update_opclass_preferences(struct agent *a, const char *radio, bool send_report)
{
	struct wifi_radio_opclass opclass = {};
	struct wifi_radio_element *radio_element;
	int send_pref_report = 0, i;
	struct cmdu_buff *cmdu;

	radio_element = wifi_radio_to_radio_element(a, radio);
	if (WARN_ON(!radio_element)) {
		for (i = 0; i < WIFI_DEVICE_MAX_NUM; i++) {
			if (a->radios[i].name[0] != '\0') {
				trace("!!!!radios[%d].name: %s, not match: %s\n", i, a->radios[i].name, radio);
			}
		}
		return -1;
	}

	/* Don't call lower layer so often */
	if (!wifi_opclass_expired(&radio_element->opclass, 5))
		return 0;

	if (WARN_ON(wifi_opclass_preferences(radio, &opclass))) {
		return -1;
	}

	if (!opclass.entry_num) {
		return 0;
	}

	/* Compare with old results */
	if (radio_element->opclass.entry_num != opclass.entry_num)
		send_pref_report = 1;
	else if (!radio_element->opclass.entry_num)
		send_pref_report = 1;
	else if (memcmp(&radio_element->opclass, &opclass, sizeof(opclass)))
		send_pref_report = 1;

	/* Setup new results */
	trace("[%s] update opclass preferences %d\n", radio_element->name, opclass.entry_num);
	memcpy(&radio_element->opclass, &opclass, sizeof(opclass));

	if (!send_report)
		return 0;

	trace("[%s] send channel_preference_report here %d\n", radio_element->name, send_pref_report);
	if (!send_pref_report)
		return 0;

	/* TODO check for better place to cover restart/crash of mapagent/mapcontroller */
	send_oper_channel_report(a, NULL);

	/* TODO send this for single radio element */
	cmdu = agent_gen_channel_preference_report(a, NULL);
	if (WARN_ON(!cmdu))
		return 0;

	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	return 0;
}

static void handle_wifi_radio_scan_post_action_opclass(struct agent *a,
		struct wifi_radio_element *re)
{
	bool action_required = false;

	trace("[%s] scan request finished - opclass action\n", re->name);

	/* Update requested on demand or due to age */
	if (re->post_scan_action.opclass_preferences) {
		trace("[%s] scan request finished - opclass action on demand\n",
			  re->name);
		action_required = true;
	} else if (wifi_opclass_expired(&re->opclass, 120)) {
		trace("[%s] scan request finished - opclass action due to age\n",
			  re->name);
		action_required = true;
	} else {
		trace("[%s] scan request finished - opclass action skip age\n",
			  re->name);
		action_required = false;
	}

	if (!action_required)
		return;

	if (wifi_radio_update_opclass_preferences(a, re->name, true))
		return;

	re->post_scan_action.opclass_preferences = false;
}

static void update_neighbor_params(struct agent *a, uint8_t *bssid,
		uint8_t classid, uint8_t channel, const struct timespec *tsp)
{
	dbg("|%s:%d| updating reg for neighbor " MACFMT "\n",
	    __func__, __LINE__, MAC2STR(bssid));

	struct netif_fh *p = NULL;
	struct neighbor *n = NULL;

	if (!channel || !classid)
		return;

	list_for_each_entry(p, &a->fhlist, list) {
		list_for_each_entry(n, &p->nbrlist, list) {
			if (!memcmp(n->nbr.bssid, bssid, 6)) {
				n->nbr.reg = classid;
				n->nbr.channel = channel;
				/* refresh last seen */
				if (!tsp)
					timestamp_update(&n->tsp);
				else
					n->tsp = *tsp;

				n->flags &= ~NBR_FLAG_DRV_UPDATED;
				reschedule_nbrlist_update(p);
			}
		}
	}
}

/* Uses data collected in scan cache to update neighbor
 * data, in particular opclass and channel information.
 */
void update_neighbors_from_scancache(struct agent *a,
		struct wifi_scanresults *results)
{
	int i;
	struct wifi_scanresults_entry *e;

	for (i = 0; i < results->entry_num; i++) {
		e = &results->entry[i];
		update_neighbor_params(a,
				e->bss.bssid,
				e->opclass,
				e->bss.channel,
				&e->tsp);
	}
}

/* TODO: deprecate */
void update_neighbors_from_scanlist(struct agent *a,
		struct wifi_radio_element *re)
{
	trace("%s --->\n", __func__);

	struct wifi_scanres_element *srel;
	struct wifi_scanres_channel_element *ch_scanlist;
	int i, j, k;

	if (WARN_ON(!re))
		return;

	/* Assuming scanlist already updated (agent_radio_scanresults) */
	srel = re->scanlist;
	if (!srel)
		return;

	for (i = 0; i < srel->num_opclass_scanned; i++) {
		for (j = 0; j < srel->opclass_scanlist[i].num_channels_scanned; j++) {
			ch_scanlist = &srel->opclass_scanlist[i].channel_scanlist[j];
			for (k = 0; k < ch_scanlist->num_neighbors; k++) {
				/* Update channel & reg of the neighbor in agent */
				update_neighbor_params(a,
							ch_scanlist->nbrlist[k].bssid,
							srel->opclass_scanlist[i].opclass,
							ch_scanlist->channel,
							NULL);
			}
		}
	}
}

static void handle_wifi_radio_scan_post_action_scanres(struct agent *a,
		struct wifi_radio_element *re)
{
	trace("%s --->\n", __func__);

	/* Request scan results from the driver */
	agent_radio_scanresults(a, re);

	/* Use scan results to update neighbor data (channel & opclass) */
	update_neighbors_from_scancache(a, &re->scanresults);
}

static void handle_wifi_radio_scan_post_actions(struct agent *a,
		struct wifi_radio_element *re)
{
	trace("%s --->\n", __func__);

	handle_wifi_radio_scan_post_action_opclass(a, re);

	/* Store the result of the last successful scan on each radio
	 * and operating class and channel combination
	 */
	handle_wifi_radio_scan_post_action_scanres(a, re);
}

static bool independent_channel_scan_supported(struct agent *a)
{
	struct agent_config *cfg = &a->cfg;
	struct policy_cfg *c;

	if (!cfg)
		return false;

	c = cfg->pcfg;

	if (!c || !c->report_scan)
		return false;

	return true;
}

int handle_wifi_radio_scan_finished(struct agent *a,
		struct wifi_netdev *ndev)
{
	/* If the scan was not completed in available time (0x04) */
	int ret = 0;

	if (WARN_ON(!ndev || !ndev->re))
		return -1;

	/* Post scan actions: get scan results, update scanlist, etc */
	handle_wifi_radio_scan_post_actions(a, ndev->re);

	/* Request induced scan */
	if (ndev->scan_req.mid) {
		/* Scan finished, stop waiting */
		timer_del(&ndev->available_scan_timer);
		trace("%s ---> scan_finished for radio %s\n",
			  __func__, ndev->re->name);
		ndev->scan_req.status = CH_SCAN_STATUS_SUCCESS;

		/* Send the response */
		ret = agent_send_ch_scan_response(a, ndev, &ndev->scan_req);

		/* Clean up stored request */
		ndev->scan_req = (const struct wifi_scan_request_radio){ 0 };
	} else if (independent_channel_scan_supported(a))
		/* Independent Channel Scan (scan results w/o query) */
		ret = agent_send_ch_scan_response(a, ndev, NULL);

	return ret;
}

int handle_cac_request(void *agent, struct cmdu_buff *cmdu, struct node *n)
{
	struct agent *a = agent;
	struct tlv *tv[1][16];
	struct tlv_cac_request *cac_request;
	struct wifi_radio_element *re;
	int ret = -1;
	int i;

	trace("%s: --->\n", __func__);
	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	if (WARN_ON(!tv[0][0]))
		return ret;

	/* Cast to tlv */
	cac_request = (struct tlv_cac_request *) tv[0][0]->data;

	/* TODO support more than one - queue the work in agent struct */
	if (cac_request->num_radio > 1)
		return -1;

	for (i = 0; i < cac_request->num_radio; i++) {
		enum wifi_cac_method method;
		enum wifi_bw bw;
		int cac_method;
		int opclass;
		int channel;

		re = wifi_radio_id_to_radio_element(a, cac_request->radio[i].radio);
		if (WARN_ON(!re))
			continue;

		channel = cac_request->radio[i].channel;
		bw = get_op_class_wifi_bw(cac_request->radio[i].opclass);
		opclass = cac_request->radio[i].opclass;
		cac_method = (cac_request->radio[i].mode & CAC_REQUEST_METHOD) >> 5;
		switch (cac_method) {
		case 0:
			method = WIFI_CAC_CONTINUOUS;
			break;
		case 1:
			method = WIFI_CAC_DEDICATED;
			break;
		case 2:
			method = WIFI_CAC_MIMO_REDUCED;
			break;
		default:
			method = WIFI_CAC_MIMO_REDUCED;
			break;
		}

		/* Lower layer expect control channel */
		switch (opclass) {
		case 128:
		case 130:
			channel -= 6;
			break;
		case 129:
			channel -= 14;
			break;
		default:
			break;
		}

		ret = wifi_start_cac(re->name, channel, bw, method);
		if (!ret)
			break;
	}

	if (WARN_ON(ret))
		ret = -1;

	return ret;
}

int handle_cac_stop(void *agent, struct cmdu_buff *cmdu, struct node *n)
{
	struct agent *a = agent;
	struct tlv *tv[1][16];
	struct tlv_cac_termination *cac_term;
	struct wifi_radio_element *re;
	int ret = -1;
	int i;

	trace("%s: --->\n", __func__);
	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	if (WARN_ON(!tv[0][0]))
		return ret;

	/* Cast to tlv */
	cac_term = (struct tlv_cac_termination *) tv[0][0]->data;

	/* TODO support more than one - check queue and terminate */
	if (cac_term->num_radio > 1)
		return -1;

	for (i = 0; i < cac_term->num_radio; i++) {
		re = wifi_radio_id_to_radio_element(a, cac_term->radio[i].radio);
		if (WARN_ON(!re))
			continue;

		ret = wifi_stop_cac(re->name);
		if (!ret)
			break;
	}

	if (WARN_ON(ret))
		ret = -1;

	return ret;
}

int handle_error_response(void *agent, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	return 0;
}

int prepare_tunneled_message(void *agent, const char *ifname,
		uint8_t protocol, const char *framestr)
{
	trace("%s: --->\n", __func__);
	struct agent *a = (struct agent *)agent;
	struct cmdu_buff *cmdu;
	struct netif_fh *fh;
	bool is_fh_found = false;
	uint8_t *frame;
	uint8_t sta_mac[6] = { 0 };
	uint8_t bss_mac[6] = { 0 };
	int len;
	int index;

	if (!framestr)
		return -1;

	/* check protocol type;
	 * 0x00: association req
	 * 0x01: re-association req
	 * 0x02: BTM query
	 * 0x03: WNM req
	 * 0x04: ANQP req
	 */
	if (protocol > 0x04)
		return -1;

	len = strlen(framestr);
	len = (len - 1) / 2;
	frame = calloc(len, sizeof(uint8_t));
	if (!frame)
		return -1;

	if (len < (2 + 2 + 6 + 6 + 6))
		goto error;

	if (!strtob((char *)framestr, len, frame))
		goto error;

	index = 2 + 2 + 6;	/* sta mac index */
	memcpy(sta_mac, frame + index, 6);

	index  = 2 + 2 + 6 + 6; /* bssid index */
	memcpy(bss_mac, frame + index, 6);

	cmdu = agent_gen_tunneled_msg(a, protocol, sta_mac,
			len, frame);
	if (!cmdu)
		goto error;

	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);
	free(frame);

	/* in case of BTM message type,
	 * generate BTM request to the STA
	 */
	if (protocol == 0x02) {
		list_for_each_entry(fh, &a->fhlist, list) {
			if (!strcmp(fh->name, ifname)) {
				is_fh_found = true;
				break;
			}
		}

		if (is_fh_found)
			agent_send_request_transition(a, sta_mac,
					fh, bss_mac, 0);
	}

	return 0;

error:
	free(frame);

	return -1;
}

int handle_backhaul_sta_caps_query(void *agent, struct cmdu_buff *cmdu,
				   struct node *n)
{
	trace("%s: --->\n", __func__);
	struct agent *a = (struct agent *) agent;
	struct cmdu_buff *cmdu_data;
	int ret;

	/* Generate response cmdu */
	cmdu_data = agent_gen_bk_caps_response(a, cmdu);
	if (!cmdu_data)
		return -1;

	/* Send cmdu */
	ret = agent_send_cmdu(a, cmdu_data);
	cmdu_free(cmdu_data);
	return ret;
}

int handle_backhaul_sta_caps_report(void *agent, struct cmdu_buff *cmdu,
				    struct node *n)
{
	trace("%s: --->\n", __func__);
	return 0;
}

#if (EASYMESH_VERSION > 2)
int agent_process_bss_configuration_response_tlv(struct agent *agent, struct tlv *t)
{
	// todo:
	// Process One or more JSON encoded DPP Configuration Object attributes
	// {
	//	"wi-fi_tech":"infra",
	//	"discovery":
	//		{
	//		"ssid":"mywifi"
	//		},
	//	"cred":
	//		{
	//		"akm":"dpp",
	//		...
	//		}
	//	...
	// }

	(void)t->data;
	(void)t->len;

	return 0;
}

int handle_dpp_cce_indication(void *agent, struct cmdu_buff *cmdu,
			      struct node *n)
{
	// struct agent *a = (struct agent *)agent;
	struct tlv *tv[1][16];
	int ret = -1;
	struct tlv_dpp_cce *data;

	trace("%s: --->\n", __func__);
	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: parse_tlv failed\n", __func__);
		return ret;
	}

	if (!tv[0][0])
		return -1;

	data = (struct tlv_dpp_cce *)tv[0][0]->data;
	dbg("%s: CCE Advertise flag: %d\n", __func__, data->enable);

	return 0;
}

int handle_bss_configuration_response(void *agent, struct cmdu_buff *cmdu,
				      struct node *n)
{
	trace("%s: --->\n", __func__);

	int i;
	struct agent *a = (struct agent *)agent;
	struct tlv *tlv;

	const int max_num_of_tlvs = 16;
	struct tlv *tlvs[BSS_CFG_RESP_MAX_NUMBER_OF_TLV_TYPES][16] = { 0 };

	if (!validate_bss_configuration_response(cmdu, tlvs, n->map_profile)) {
		dbg("cmdu validation: [BSS_CONFIGURATION_RESPONSE] failed\n");
		return -1;
	}

	/* One or more BSS Configuration Response TLV */
	i = 0;
	while ((i < max_num_of_tlvs) && tlvs[BSS_CFG_RESP_BSS_CONFIG_RESPONSE_IDX][i]) {
		if (agent_process_bss_configuration_response_tlv(
			    a, tlvs[BSS_CFG_RESP_BSS_CONFIG_RESPONSE_IDX][i]))
			return -1;
		++i;
	}

	/* Zero or one Default 802.1Q Settings TLV */
	tlv = tlvs[BSS_CFG_RESP_DEFAULT_8021Q_SETTINGS_IDX][0];
	if (tlv)
		if (agent_fill_8021q_setting_from_tlv(a, (struct tlv_default_8021q_settings *)tlv->data))
			return -1;

	/* Zero or one Traffic Separation Policy TLV */
	tlv = tlvs[BSS_CFG_RESP_TRAFFIC_SEPARATION_POLICY_IDX][0];
	if (tlv) {
		dbg("|%s:%d| TS policy received\n", __func__, __LINE__);
		if (agent_fill_traffic_sep_policy(a, (struct tlv_traffic_sep_policy *)tlv->data))
			return -1;
	} else {
		dbg("|%s:%d| TS policy is going to be cleared\n", __func__, __LINE__);
		if (agent_clear_traffic_sep(a))
			return -1;
	}

	return send_bss_configuration_result(a);
}
#endif //EASYMESH_VERSION > 2

/* Cmdu handlers commented out in the following two tables should be
 * handled in the controller.
 * Agent must implement the send cmdu functions corresponding to the
 * same.
 */

static const map_cmdu_handler_t i1905ftable[] = {
	[0x00] = handle_topology_discovery,
	[0x01] = handle_topology_notification,
	[0x02] = handle_topology_query,
	[0x03] = handle_topology_response,
	[0x04] = handle_vendor_specific,
	/* hole */
	[0x07] = handle_ap_autoconfig_search,
	[0x08] = handle_ap_autoconfig_response,
	[0x09] = handle_ap_autoconfig_wsc,
	[0x0a] = handle_ap_autoconfig_renew,
};


#define CMDU_TYPE_MAP_START	0x8000
#define CMDU_TYPE_MAP_END	0x8028

#if (EASYMESH_VERSION > 2)
	#undef CMDU_TYPE_MAP_END
	#define CMDU_TYPE_MAP_END	0x8035
#endif


static const map_cmdu_handler_t agent_mapftable[] = {
	[0x00] = handle_1905_ack,
	[0x01] = handle_ap_caps_query,
	[0x02] = handle_ap_caps_report,
	[0x03] = handle_map_policy_config,
	[0x04] = handle_channel_pref_query,
	/* [0x05] = handle_channel_pref_report, */
	[0x06] = handle_channel_sel_request,
	/* [0x07] = handle_channel_sel_response, */
	/* [0x08] = handle_oper_channel_report, */
	[0x09] = handle_sta_caps_query,
	/* [0x0a] = handle_sta_caps_report, */
	[0x0b] = handle_ap_metrics_query,
	/* [0x0c] = handle_ap_metrics_response, */
	[0x0d] = handle_sta_link_metrics_query,
	/* [0x0e] = handle_sta_link_metrics_response, */
	[0x0f] = handle_unassoc_sta_link_metrics_query,
	[0x10] = handle_unassoc_sta_link_metrics_response,
	[0x11] = handle_beacon_metrics_query,
	/* [0x12] = handle_beacon_metrics_response, */
	[0x13] = handle_combined_infra_metrics,
	[0x14] = handle_sta_steer_request,
	/*[0x15] = handle_sta_steer_btm_report,*/
	[0x16] = handle_sta_assoc_control_request,
	/* [0x17] = handle_sta_steer_complete, */
	[0x18] = handle_hld_message,
	[0x19] = handle_backhaul_sta_steer_request,
	/* [0x1a] = handle_backhaul_sta_steer_response, */
	[0x1b] = handle_channel_scan_request,
	/* [0x1c] = handle_channel_scan_report, */
	/* hole */
	[0x20] = handle_cac_request,
	[0x21] = handle_cac_stop,
	/* [0x22] = handle_sta_disassoc_stats, */
	/* hole */
	[0x24] = handle_error_response,
	/* [0x25] = handle_assoc_status_notification, */
	/* [0x26] = handle_tunneled_message, */
	[0x27] = handle_backhaul_sta_caps_query,
	[0x28] = handle_backhaul_sta_caps_report,
#if (EASYMESH_VERSION > 2)
	/* hole */
	[0x1d] = handle_dpp_cce_indication,
	[0x2d] = handle_bss_configuration_response,
	/* hole */
	/* [0x33] = handle_failed_connection_msg, */
	/* hole */
	[0x35] = handle_agent_list,
#endif
};


const char *tlv_friendlyname[] = {
	"supported_service",
	"searched_service",
	"ap_radio_id",
	"ap_oper_bss",
	"assoc_clients",
	"ap_caps",
	"ap_radio_basic_caps",
	"ap_caps_ht",
	"ap_caps_vht",
	"ap_caps_he",
	"steer_policy",
	"metric_report_policy",
	"channel_preference",
	"radio_oper_restriction",
	"tx_power_limit",
	"channel_sel_response",
	"oper_channel_report",
	"sta_info",
	"sta_caps_report",
	"sta_assoc_event",
	"ap_metric_query",
	"ap_metrics",
	"sta_macaddr",
	"sta_link_metrics",
	"unassoc_sta_link_metrics_query",
	"unassoc_sta_link_metrics_response",
	"beacon_metrics_query",
	"beacon_metrics_response",
	"steer_request",
	"steer_btm_report",
	"sta_assoc_control",
	"backhaul_steer_request",
	"backhaul_steer_response",
	"hld",
	"assoc_sta_stats",
	"error_code",
	"channel_scan_report_policy",
	"channel_scan_caps",
	"channel_scan_request",
	"channel_scan_result",
	"timestamp",
	"cac_request",
	"cac_stop",
	"cac_done_report",
	"cac_status_report",
	"cac_caps",
	"map_profile",
	"profile2_ap_caps",
	"default_8021q",
	"traffic_separation_policy",
	"profile2_error_code",
	"ap_radio_caps_advanced",
	"assoc_status_notification",
	"source_info",
	"tunneled_message",
	"tunneled",
	"profile2_steer_request",
	"unsuccessful_assoc_policy",
	"metric_collection_int",
	"radio_metrics",
	"ap_metrics_ext",
	"assoc_sta_link_metrics_ext",
	"status_code",
	"reason_code",
	"backhaul_sta_radio_caps",
	"backhaul_bss_config",
};


bool is_cmdu_for_us(struct agent *a, uint16_t type)
{
	// TODO: handle only cmdu types relevant for module's role/profile.
	/* Since map-plugin now sends cmdu events, agent must filter out cmdus
	 * that it is not supposed to handle.
	 * When map-plugin directly call's map-module's 'cmd', then the
	 * additonal cmdu type validation/filtering it does becomes useful. In
	 * the latter case, agent doesn't need to do additonal checks for valid
	 * cmdu types.
	 */

	/* until then, the following should be okay.. */

	if (type >= CMDU_TYPE_1905_START && type <= CMDU_TYPE_1905_END) {
		if (i1905ftable[type])
			return true;
	} else if (type >= CMDU_TYPE_MAP_START && type <= CMDU_TYPE_MAP_END) {
		if (agent_mapftable[type - CMDU_TYPE_MAP_START])
			return true;
	}
	return false;
}

static inline uint16_t a_cmdu_expect_response(uint16_t req_type)
{
	switch (req_type) {
		case CMDU_AP_CAPABILITY_QUERY:
			return CMDU_AP_CAPABILITY_REPORT;
		case CMDU_POLICY_CONFIG_REQ:
			return CMDU_1905_ACK;
		case CMDU_CHANNEL_PREFERENCE_QUERY:
			return CMDU_CHANNEL_PREFERENCE_REPORT;
		case CMDU_CHANNEL_SELECTION_REQ:
			return CMDU_CHANNEL_SELECTION_RESPONSE;
		case CMDU_OPERATING_CHANNEL_REPORT:
			return CMDU_1905_ACK;
		case CMDU_CLIENT_CAPABILITY_QUERY:
			return CMDU_CLIENT_CAPABILITY_REPORT;
		case CMDU_AP_METRICS_QUERY:
			return CMDU_AP_METRICS_RESPONSE;
		case CMDU_ASSOC_STA_LINK_METRICS_QUERY:
			return CMDU_ASSOC_STA_LINK_METRICS_RESPONSE;
		case CMDU_UNASSOC_STA_LINK_METRIC_QUERY:
			return CMDU_UNASSOC_STA_LINK_METRIC_RESPONSE;
		case CMDU_BEACON_METRICS_QUERY:
			return CMDU_BEACON_METRICS_RESPONSE;
		case CMDU_COMBINED_INFRA_METRICS:
			return CMDU_1905_ACK;
		case CMDU_CLIENT_STEERING_REQUEST:
		//	 FIX THIS: we need ACK ?
			return CMDU_CLIENT_STEERING_BTM_REPORT;
		case CMDU_CLIENT_ASSOC_CONTROL_REQUEST:
			return CMDU_1905_ACK;
		case CMDU_STEERING_COMPLETED:
			return CMDU_1905_ACK;
		case CMDU_HIGHER_LAYER_DATA:
			return CMDU_1905_ACK;
		case CMDU_BACKHAUL_STEER_REQUEST:
			return CMDU_BACKHAUL_STEER_RESPONSE;
		case CMDU_CHANNEL_SCAN_REQUEST:
			return CMDU_CHANNEL_SCAN_REPORT;
		case CMDU_CAC_REQUEST:
			return CMDU_TYPE_NONE;
		case CMDU_CAC_TERMINATION:
			return CMDU_TYPE_NONE;
		case CMDU_CLIENT_DISASSOCIATION_STATS:
			return CMDU_TYPE_NONE;
		case CMDU_ERROR_RESPONSE:
			return CMDU_TYPE_NONE;
		case CMDU_ASSOCIATION_STATUS_NOTIFICATION:
			return CMDU_TYPE_NONE;
		case CMDU_BACKHAUL_STA_CAPABILITY_QUERY:
			return CMDU_BACKHAUL_STA_CAPABILITY_REPORT;
		case CMDU_FAILED_CONNECTION:
			return CMDU_TYPE_NONE;
#if (EASYMESH_VERSION > 2)
		case CMDU_BSS_CONFIG_REQUEST:
			return CMDU_BSS_CONFIG_RESPONSE;
#endif
		default:
			break;
	}

	return CMDU_TYPE_NONE;
}

static uint16_t agent_cmdu_expect_response(struct agent *a, uint16_t req_type)
{
	uint16_t resp_type = a_cmdu_expect_response(req_type);

	if (resp_type == CMDU_TYPE_NONE)
		return CMDU_TYPE_NONE;

	if (map_cmdu_mask_isset(a->cmdu_mask, resp_type))
		return resp_type;
	else
		return CMDU_TYPE_NONE;
}

int agent_handle_map_cmd(struct agent *a, char *data, int len)
{
	uint8_t tlvbuf[len];

	trace("%s(): CMD_MAP_CMDU <<<<<<<<<\n", __func__);

	fprintf(stderr, "Len = %d  Data: '%s'\n", len, data);

	strtob(data, (len - 1) / 2, tlvbuf);

	//TODO

	return 0;
}

int agent_handle_map_event(struct agent *a, uint16_t cmdutype, uint16_t mid,
	char *rxif, uint8_t *src, uint8_t *origin, uint8_t *tlvs, int len)
{
	const map_cmdu_handler_t *f;
	struct cmdu_buff *cmdu = NULL;
	int ret = -1;
	int idx;
	uint16_t resp_type;
	struct cmdu_ackq_entry *entry;
	void *cookie;
	struct node *n;

	trace("%s: ---> cmdu = %04x from "MACFMT" \n", __func__,
		cmdutype, MAC2STR(origin));

	/* If request CMDU is from us, do not process is. This is for
	 * situation where controller and agent are on the same device,
	 * share the same MAC address and send CMDU's to each other.*/
	if (hwaddr_equal(a->almac, origin)) {
		resp_type = agent_cmdu_expect_response(a, cmdutype);
		entry = cmdu_ackq_lookup(&a->cmdu_ack_q, resp_type, mid, origin);
		if (entry) {
			dbg("%s: do not response for own cmdu %04x mid %u\n",
				__func__, cmdutype, mid);
			return 0;
		}
	}

	ret = cmdu_ackq_dequeue(&a->cmdu_ack_q, cmdutype, mid, origin, &cookie);
	if (ret == 0)
		cmdu_free((struct cmdu_buff *) cookie);

	if (cmdutype >= CMDU_TYPE_MAP_START) {
		idx = cmdutype - CMDU_TYPE_MAP_START;
		f = agent_mapftable;
		dbg("MSGID---> %d \n", idx);
	} else {
		idx = cmdutype;
		f = i1905ftable;
	}

	n = agent_find_node(a, origin);
	if (!n) {
		if (cmdutype != CMDU_TYPE_TOPOLOGY_DISCOVERY &&
		    cmdutype != CMDU_TYPE_TOPOLOGY_NOTIFICATION &&
		    cmdutype != CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH)
			return -1;
	}

	if (f[idx]) {
		dbg("mid pointer prev = %u src = "MACFMT"\n", mid, MAC2STR(src));
		cmdu = cmdu_alloc_custom(cmdutype, &mid, rxif, src, tlvs, len);
		if (cmdu) {
			memcpy(cmdu->origin, origin, 6);
			dbg("mid pointer post = %u src = "MACFMT"\n", mid, MAC2STR(cmdu->origin));
			dbg("%s: cmdu_alloc_custom() succeeded! cmdu->cdata->hdr.mid %u\n", __func__, cmdu_get_mid(cmdu));
			//test_cmdu(cmdu);
			ret = f[idx](a, cmdu, n);
			cmdu_free(cmdu);
		} else {
			dbg("agent: %s: cmdu_alloc_custom() failed!\n", __func__);
		}
	}

	//TODO: check ret

	return ret;
}

uint16_t agent_send_cmdu(struct agent *a, struct cmdu_buff *cmdu)
{
	uint16_t resp_type;
	int ret;
	void *cookie = NULL;
	const int resend_num = a->cfg.resend_num;
	uint16_t msgid, old_mid;

	trace("%s: ---> cmdu = %04x to "MACFMT" \n", __func__,
		cmdu_get_type(cmdu), MAC2STR(cmdu->origin));

	if (hwaddr_is_ucast(cmdu->origin)) {
		resp_type = agent_cmdu_expect_response(a, cmdu_get_type(cmdu));
		trace("%s: ---> resp_type %d\n", __func__, resp_type);
		if (resp_type != CMDU_TYPE_NONE)
			cookie = (void *) cmdu_clone(cmdu);
	}

	trace("%s: ---> cookie %p\n", __func__, cookie);

	ret = ieee1905_ubus_send_cmdu(a->ubus_ctx, cmdu, &msgid, a->pvid);
	if (ret) {
		err("fail to send cmdu %04x over ubus\n", cmdu_get_type(cmdu));
		goto error;
	}

	old_mid = cmdu_get_mid(cmdu);
	if (old_mid == 0)
		cmdu_set_mid(cmdu, msgid);
	else if (old_mid != msgid)
		warn("msgid differs %d %d for cmdu %04x\n", old_mid, msgid,
		     cmdu_get_type(cmdu));

	if (cookie) {
		ret = cmdu_ackq_enqueue(&a->cmdu_ack_q, resp_type,
					msgid, cmdu->origin,
					CMDU_DEFAULT_TIMEOUT, resend_num,
					cookie);
		if (ret < 0) {
			err("cmdu_ackq enqueue failed\n");
			goto error;
		}
	}

	return msgid;

error:
	cmdu_free((struct cmdu_buff *) cookie);
	return 0xffff;
}
#if (EASYMESH_VERSION > 2)
int handle_agent_list(void *agent, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s:--->\n", __func__);

	struct tlv *tv[1][16] = {0};

	if (!validate_agent_list(cmdu, tv, ARRAY_SIZE(tv), n->map_profile)) {
		dbg("cmdu validation: [AGENT LIST] failed\n");
		return -1;
	}

	if (tv[0][0]) {
		struct tlv_agent_list *tlv;
		uint16_t i;

		tlv = (struct tlv_agent_list *)tv[0][0]->data;
		if (!tlv)
			return -1;

		for (i = 0; i < tlv->num_agent; i++) {
			/* agent aladdr */
			dbg("\t\tagent_id: " MACFMT "\n", MAC2STR(tlv->agent[i].aladdr));
			/* profile */
			dbg("\t\tprofile: %d\n", tlv->agent[i].profile);
			/* security */
			dbg("\t\tsecurity: %d\n", tlv->agent[i].security);
		}
	}
	return 0;
}
#endif

int agent_set_link_profile(struct agent *a, struct node *n,
			   struct cmdu_buff *cmdu)
{
	int p = a->cfg.map_profile;
	int np = map_cmdu_get_multiap_profile(cmdu);

	if (p <= MULTIAP_PROFILE_1) {
		n->map_profile = MULTIAP_PROFILE_1;
		return n->map_profile;
	}

	if (np > p) {
		n->map_profile = p;
		return p;
	}

	n->map_profile = np;
	return np;
}
