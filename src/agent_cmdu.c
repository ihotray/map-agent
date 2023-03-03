/*
 * agent_cmdu.c - cmdu building functions
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: jakob.olsson@iopsys.eu
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>

#include <linux/if_bridge.h>

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

#include <cmdu.h>
#include <1905_tlvs.h>
#include <easymesh.h>
#include <i1905_wsc.h>
#include <map_module.h>

#include <uci.h>

#include "timer.h"
#include "utils/1905_ubus.h"
#include "utils/utils.h"
#include "utils/debug.h"
#include "utils/liblist.h"
#include "steer_rules.h"
#include "config.h"
#include "nl.h"
#include "agent.h"

#include "agent_tlv.h"
#include "agent_cmdu.h"
#include "cmdu_validate.h"


struct cmdu_buff *agent_gen_ap_autoconfig_search(struct agent *a,
		struct wifi_radio_element *radio, uint8_t profile)
{
	struct cmdu_buff *frm = NULL;
	int ret = 0;
	uint8_t band = 0;
	uint16_t mid = 0;
	uint8_t origin[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x13};


	frm = cmdu_alloc_simple(CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	CMDU_SET_RELAY_MCAST(frm->cdata);

	ret = agent_gen_al_mac(a, frm, a->almac);
	if (ret)
		goto out;

	ret = agent_gen_searched_role(a, frm, IEEE80211_ROLE_REGISTRAR);
	if (ret)
		goto out;

	band = wifi_band_to_ieee1905band(radio->band);
	trace("radio band = %d, band = %d\n", radio->band, band);

	ret = agent_gen_autoconf_freq_band(a, frm, band);
	if (ret)
		goto out;

	ret = agent_gen_supported_service(a, frm, SUPPORTED_SERVICE_MULTIAP_AGENT);
	if (ret)
		goto out;

	ret = agent_gen_searched_service(a, frm, SEARCHED_SERVICE_MULTIAP_CONTROLLER);
	if (ret)
		goto out;

	ret = agent_gen_map_profile(a, frm, a->cfg.map_profile);
	if (ret)
		goto out;

#if (EASYMESH_VERSION > 2)
	if (a->cfg.map_profile > 2) {
		ret = agent_gen_dpp_chirp(a, frm);
		if (ret)
			goto out;
	}
#endif

	memcpy(frm->origin, origin, 6);
	cmdu_put_eom(frm);

	dbg("%s:%d: radio = %s\n", __func__, __LINE__, radio->name);
	return frm;
out:
	cmdu_free(frm);
	return NULL;
}

struct cmdu_buff *agent_gen_ap_autoconfig_wsc(struct agent *a, struct cmdu_buff *rx_cmdu,
		struct wifi_radio_element *radio)
{
	trace("agent: %s: --->\n", __func__);
	struct cmdu_buff *frm = NULL;
	uint16_t mid = 0;
	int ret = 0;


	frm = cmdu_alloc_simple(CMDU_TYPE_AP_AUTOCONFIGURATION_WSC, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(frm->origin, rx_cmdu->origin, 6);

	ret = agent_gen_wsc(a, frm, radio);
	if (ret)
		goto out;

	ret = agent_gen_ap_radio_adv_cap(a, frm, radio);
	if (ret)
		goto out;

	ret = agent_gen_ap_radio_basic_cap(a, frm, radio);
	if (ret)
		goto out;

	ret = agent_gen_profile2_ap_cap(a, frm);
	if (ret)
		goto out;

	trace("build ap autoconfig wsc!\n");
	cmdu_put_eom(frm);

	return frm;
out:
	cmdu_free(frm);
	return NULL;
}

struct cmdu_buff *agent_gen_ap_metrics_response(struct agent *a,
		struct cmdu_buff *rx_cmdu, struct node *n)
{
	struct cmdu_buff *frm;
	int ret;
	int i = 0, j = 0;
	uint16_t mid = 0;
	struct tlv *tv[2][16] = {0};

	ret = map_cmdu_parse_tlvs(rx_cmdu, tv, 2, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return NULL;
	}

	if (!tv[0][0])
		return NULL;

	mid = cmdu_get_mid(rx_cmdu);

	frm = cmdu_alloc_simple(CMDU_AP_METRICS_RESPONSE, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(frm->origin, rx_cmdu->origin, 6);

	/* AP Radio Identifier TLV */
	while (tv[1][i]) {
		int radio_index;
		struct tlv_ap_radio_identifier *tmp =
			(struct tlv_ap_radio_identifier *) tv[1][i++]->data;

		radio_index = get_radio_index(a, tmp->radio);
		if (radio_index != -1) {
// #ifdef PROFILE2
			/* Radio Metrics TLV */
			ret = agent_gen_radio_metrics(a, frm, radio_index);
			if (ret)
				goto out;
// #endif
		}
	}

	/* AP Metric Query TLV */
	if (tv[0][0]) {
		struct wifi_radio_element *radio;
		struct wifi_bss_element *bss;
		struct tlv_ap_metric_query *tmp =
			(struct tlv_ap_metric_query *) tv[0][0]->data;

		for (j = 0; j < tmp->num_bss; j++) {
			int radio_index;
			int bss_index;
			struct sta *s;
			struct netif_fh *fh;
			struct agent_config_radio *rcfg;

			bss_index = get_radio_and_bss_index(a,
					tmp->bss[j].bssid,
					&radio_index);

			if (bss_index == -1)
				continue;

			radio = a->radios + radio_index;
			bss = radio->bsslist + bss_index;

			/* AP Metrics TLV */
			ret = agent_gen_ap_metrics(a, frm,
					radio_index, bss_index);
			if (ret)
				goto out;

// #ifdef PROFILE2
			/* AP Extended Metrics TLV */
			ret = agent_gen_ap_ext_metrics(a, frm,
					radio_index, bss_index);
			if (ret)
				goto out;
// #endif

			fh = wifi_get_netif_by_bssid(a, bss->bssid);
			if (fh == NULL)
				continue;

			rcfg = get_agent_config_radio(&a->cfg, fh->cfg->device);
			if (!rcfg)
				return NULL;

			list_for_each_entry(s, &fh->stalist, list) {
				if (rcfg->include_sta_stats) {
					/* Associated STA Traffic Stats TLV */
					ret = agent_gen_assoc_sta_traffic_stats(a, frm, s->macaddr, s);
					if (ret)
						goto out;
				}

				if (rcfg->include_sta_metric) {
					/* Associated STA Link Metrics TLV */
					ret = agent_gen_assoc_sta_link_metrics(a, frm, s, bss->bssid);
					if (ret)
						goto out;
// #ifdef PROFILE2
					/* Associated STA Extended Link Metrics TLV */
					ret = agent_gen_assoc_sta_ext_link_metric(a, frm, s, bss->bssid);
					if (ret)
						goto out;
// #endif
				}

#if (EASYMESH_VERSION > 2)
				if (rcfg->include_wifi6_sta_status &&
				    a->cfg.map_profile > 2) {
					/* Associated Wi-Fi 6 STA Status Report TLV */
					ret = agent_gen_assoc_wifi6_sta_status_report(a, frm, s);
					if (ret)
						goto out;
				}
#endif

			}
		}
	}

	cmdu_put_eom(frm);

	return frm;
out:
	cmdu_free(frm);
	return NULL;
}

struct cmdu_buff *agent_gen_assoc_sta_metric_response_per_intf(
		struct agent *a, char *ifname)
{
	uint16_t mid = 0;
	struct cmdu_buff *frm;
	struct wifi_radio_element *radio;
	int i, ret;

	frm = cmdu_alloc_simple(CMDU_ASSOC_STA_LINK_METRICS_RESPONSE, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(frm->origin, a->cntlr_almac, 6);

	radio = wifi_ifname_to_radio_element(a, ifname);
	if (!radio)
		goto error;

	for (i = 0; i < radio->num_bss; i++) {
		struct sta *s = NULL;
		struct netif_fh *fh;
		struct wifi_bss_element *bss;

		bss = radio->bsslist + i;
		fh = wifi_get_netif_by_bssid(a, bss->bssid);
		if (!fh)
			continue;

		list_for_each_entry(s, &fh->stalist, list) {

			ret = agent_gen_assoc_sta_link_metrics(a, frm,
					s, bss->bssid);
			if (ret)
				goto error;

// #ifdef PROFILE2
			ret = agent_gen_assoc_sta_ext_link_metric(a, frm,
					s, bss->bssid);
			if (ret)
				goto error;
// #endif
		}

	}

	cmdu_put_eom(frm);

	return frm;
error:
	cmdu_free(frm);

	return NULL;
}

struct cmdu_buff *agent_gen_assoc_sta_metric_responsex(struct agent *a,
		uint8_t *origin, struct sta *s, struct netif_fh *fh)
{
	uint16_t mid = 0;
	struct cmdu_buff *frm;
	int ret;

	frm = cmdu_alloc_simple(CMDU_ASSOC_STA_LINK_METRICS_RESPONSE, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	if (s) {
		/* Associated STA Link Metrics TLV */
		ret = agent_gen_assoc_sta_link_metrics(a, frm, s, fh->bssid);
		if (ret)
			goto error;

// #ifdef PROFILE2
		/* Associated STA Extended Link Metrics TLV */
		ret = agent_gen_assoc_sta_ext_link_metric(a, frm, s, fh->bssid);
		if (ret)
			goto error;
// #endif
	} else {
		uint8_t reason_code = 0x00;
		struct tlv *t;
		struct tlv_assoc_sta_link_metrics *data;

		/* Associated STA Link Metrics TLV */
		t = cmdu_reserve_tlv(frm, 20);
		if (!t)
			goto error;

		t->type = MAP_TLV_ASSOCIATED_STA_LINK_METRICS;
		t->len = sizeof(*data);

		data = (struct tlv_assoc_sta_link_metrics *) t->data;
		/* Reported BSS for STA */
		data->num_bss = 0;
		ret = cmdu_put_tlv(frm, t);
		if (ret) {
			dbg("%s: error: cmdu_put_tlv()\n", __func__);
			goto error;
		}

		/* Error Code TLV */
		reason_code = 0x02;	/* STA not associated with any BSS */
		ret = agent_gen_tlv_error_code(a, frm, data->macaddr,
				reason_code);
		if (ret)
			goto error;
	}

	cmdu_put_eom(frm);
	memcpy(frm->origin, origin, 6);
	return frm;
error:
	cmdu_free(frm);
	return NULL;
}

struct cmdu_buff *agent_gen_assoc_sta_metric_response(
		struct agent *a, struct cmdu_buff *rx_cmdu, struct node *n)
{
	uint16_t mid = 0;
	struct tlv *tv0;
	struct tlv_sta_mac *query;
	struct cmdu_buff *frm;
	struct tlv *tv[1][16];
	struct netif_fh *fh;
	struct sta *s;
	bool is_sta_found = false;
	int ret;

	ret = map_cmdu_parse_tlvs(rx_cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return NULL;
	}

	if (!tv[0][0])
		return NULL;

	mid = cmdu_get_mid(rx_cmdu);

	frm = cmdu_alloc_simple(CMDU_ASSOC_STA_LINK_METRICS_RESPONSE, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(frm->origin, rx_cmdu->origin, 6);

	tv0 = tv[0][0];
	query = (struct tlv_sta_mac *) tv0->data;
	list_for_each_entry(fh, &a->fhlist, list) {
		list_for_each_entry(s, &fh->stalist, list) {
			if (hwaddr_equal(query->macaddr, s->macaddr)) {
				is_sta_found = true;
				break;
			}
		}
		if (is_sta_found)
			break;
	}

	if (is_sta_found) {
		/* Associated STA Link Metrics TLV */
		ret = agent_gen_assoc_sta_link_metrics(a, frm, s, fh->bssid);
		if (ret)
			goto error;

// #ifdef PROFILE2
		/* Associated STA Extended Link Metrics TLV */
		ret = agent_gen_assoc_sta_ext_link_metric(a, frm, s, fh->bssid);
		if (ret)
			goto error;
// #endif
	} else {
		uint8_t reason_code = 0x00;
		struct tlv *t;
		struct tlv_assoc_sta_link_metrics *data;

		/* Associated STA Link Metrics TLV */
		t = cmdu_reserve_tlv(frm, 20);
		if (!t)
			goto error;

		t->type = MAP_TLV_ASSOCIATED_STA_LINK_METRICS;
		t->len = sizeof(*data);

		data = (struct tlv_assoc_sta_link_metrics *) t->data;
		memcpy(data->macaddr, query->macaddr, 6);
		/* Reported BSS for STA */
		data->num_bss = 0;
		ret = cmdu_put_tlv(frm, t);
		if (ret) {
			dbg("%s: error: cmdu_put_tlv()\n", __func__);
			goto error;
		}

		/* Error Code TLV */
		reason_code = 0x02;	/* STA not associated with any BSS */
		ret = agent_gen_tlv_error_code(a, frm,
				query->macaddr, reason_code);
		if (ret)
			goto error;
	}

	cmdu_put_eom(frm);

	return frm;
error:
	cmdu_free(frm);

	return NULL;
}

struct cmdu_buff *agent_gen_beacon_metrics_query(struct agent *a,
			uint8_t *agent_mac, uint8_t *sta_addr, uint8_t opclass,
			uint8_t channel, uint8_t *bssid,
			uint8_t reporting_detail, char *ssid,
			uint8_t num_report, struct sta_channel_report *report,
			uint8_t num_element, uint8_t *element)
{
	struct cmdu_buff *frm = NULL;
	int ret = 0;
	uint16_t mid = 0;

	trace("agent: %s: --->\n", __func__);

	if (!agent_mac || !sta_addr || !bssid)
		return NULL;

	frm = cmdu_alloc_simple(CMDU_BEACON_METRICS_QUERY, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	/* Beacon metrics query TLV */
	ret = agent_gen_tlv_beacon_metrics_query(a, frm,
			sta_addr, opclass, channel, bssid,
			reporting_detail, ssid, num_report,
			report, num_element, element);

	if (ret)
		goto fail;

	/* destination agent */
	memcpy(frm->origin, agent_mac, 6);

	cmdu_put_eom(frm);

	return frm;
fail:
	cmdu_free(frm);
	return NULL;
}

struct cmdu_buff *agent_gen_cmdu_beacon_metrics_resp(struct agent *a,
			uint8_t *sta_addr, uint8_t report_elems_nr,
			uint8_t *report_elem, uint16_t elem_len)
{
	struct cmdu_buff *frm = NULL;
	uint8_t *tlv = NULL;
	uint16_t mid = 0;
	uint8_t origin[6] = { 0 };
	uint32_t t_len = 0;

	/* Since no excess allocation (1500 octets in cmdu_alloc_simple)
	 * and cmdu_put_tlv is not used - one must specify the exact size.
	 * I.e. must manually add +3: +1 for type and +2 for length.
	 */
	t_len = sizeof(struct tlv_beacon_metrics_resp) + elem_len + 3;

	tlv = (uint8_t *) calloc(1, t_len);

	if (!tlv)
		return NULL;

	if (agent_gen_tlv_beacon_metrics_resp(
					a, tlv, sta_addr,
					report_elems_nr,
					report_elem,
					elem_len))
		goto out;

	frm = cmdu_alloc_custom(CMDU_BEACON_METRICS_RESPONSE,
				&mid, NULL, origin, tlv, t_len);

	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		goto out;
	}

	/* destination controller */
	memcpy(frm->origin, a->cntlr_almac, 6);

	cmdu_put_eom(frm);
out:
	if (tlv)
		free(tlv);
	return frm;
}

struct cmdu_buff *agent_gen_unassoc_sta_metric_query(struct agent *a,
		uint8_t *origin, uint8_t opclass,
		uint8_t num_metrics, struct unassoc_sta_metric *metrics)
{
	int ret;
	uint16_t mid = 0;
	struct cmdu_buff *frm;

	/* TODO: A Multi-AP Agent shall not send an Unassociated
	 * STA Link Metrics Query message to a Multi-AP Agent that
	 * does not indicate support for Unassociated STA Link
	 * Metrics in the AP Capability TLV.
	 */

	frm = cmdu_alloc_simple(CMDU_UNASSOC_STA_LINK_METRIC_QUERY, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(frm->origin, origin, 6);

	/* Unassociated STA link metrics query TLV */
	ret = agent_gen_tlv_unassoc_sta_lm_query(a, frm,
			opclass, num_metrics, metrics);

	if (ret)
		goto out;

	cmdu_put_eom(frm);
	return frm;

out:
	return NULL;
}

struct cmdu_buff *agent_gen_tunneled_msg(struct agent *a, uint8_t protocol,
		uint8_t *sta, int frame_len, uint8_t *frame_body)
{
	int ret;
	struct cmdu_buff *cmdu;
	uint16_t mid = 0;

	/* TODO: check profile type
	 * return NULL,in case of PROFILE-1
	 * #ifdef PROFILE1
	 * return NULL;
	 * #endif
	 */

	if (!sta && !frame_body)
		return NULL;

	cmdu = cmdu_alloc_simple(CMDU_TUNNELED, &mid);
	if (!cmdu) {
		err("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(cmdu->origin, a->cntlr_almac, 6);

	/* Source Info TLV */
	ret = agent_gen_source_info(a, cmdu, sta);
	if (ret)
		goto error;

	/* Tunneled message type TLV */
	ret = agent_gen_tunnel_msg_type(a, cmdu, protocol);
	if (ret)
		goto error;

	/* Tunneled TLV */
	ret = agent_gen_tunneled(a, cmdu, frame_len, frame_body);
	if (ret)
		goto error;

	cmdu_put_eom(cmdu);

	return cmdu;

error:
	cmdu_free(cmdu);

	return NULL;
}


struct cmdu_buff *agent_gen_vendor_specific_cmdu(struct agent *a,
		uint8_t *origin, uint8_t depth)
{
	return NULL;
//	struct tlv_vendor_specific *p;
//	struct cmdu_cstruct *cmdu;
//	int tlv_index = 0;
//
//	cmdu = calloc(1, sizeof(struct cmdu_cstruct));
//	if (!cmdu)
//		return NULL;
//
//	cmdu->message_type = CMDU_TYPE_VENDOR_SPECIFIC;
//	memcpy(cmdu->origin, origin, 6);
//	strncpy(cmdu->intf_name, a->cfg.al_bridge, IFNAMESIZE - 1);
//
//	p = agent_gen_vendor_specific_tlv(a, depth);
//	if (!p)
//		goto error;
//
//	cmdu->num_tlvs++;
//	cmdu->tlvs = (uint8_t **)calloc(cmdu->num_tlvs,
//			sizeof(uint8_t *));
//	cmdu->tlvs[tlv_index++] = (uint8_t *)p;
//	return cmdu;
//error:
//	map_free_cmdu(cmdu);
//	return NULL;
}

static int agent_gen_ch_scan_response_all(struct agent *a, struct cmdu_buff *cmdu,
		struct wifi_netdev *ndev, uint8_t status)
{
	int i, j, ret;
	struct wifi_scanres_element *sl;
	struct wifi_scanres_opclass_element *op;
	struct wifi_scanres_channel_element *ch;
	int num_tlv = 0;

	if (!a || !cmdu || !ndev || !ndev->re)
		return -1;

	if (!ndev->re->scanlist) {
		dbg("|%s:%d| missing scanlist\n", __func__, __LINE__);
		return -1;
	}

	sl = ndev->re->scanlist;
	for (i = 0; i < sl->num_opclass_scanned; i++) {
		op = sl->opclass_scanlist + i;

		if (op->bandwidth != 20)
			continue;

		for (j = 0; j < op->num_channels_scanned; j++) {
			ch = op->channel_scanlist + j;

			ret = agent_gen_ch_scan_response_tlv(a, cmdu,
					ndev->re->macaddr, op->opclass, ch, status);
			if (ret)
				return ret;

			dbg("|%s:%d| Added Channel Scan Result TLV.\n",
			    __func__, __LINE__);
			num_tlv++;
		}
	}

	if (!num_tlv) {
		dbg("|%s:%d| No Scan Result TLV added.\n",
		    __func__, __LINE__);
		return -1;
	}

	/* TODO: use scan cache */

	/* Currently scanlist contains all supported opclasses so the
	 * requirement for 'Requested Channels Scan - Stored' to report
	 * all opc/ch combinations listed in Channel Scan Caps is met
	 * but when moving to scan cache, this will no longer be true
	 * and some opc/ch combinations may be missing. TODO: revisit
	 */

	return 0;
}

static int agent_gen_ch_scan_response_opc(struct agent *a,
		struct cmdu_buff *cmdu, struct wifi_netdev *ndev,
		struct wifi_scan_request_opclass *req_opc, uint8_t status)
{
	int ci, i, j, ret;
	struct wifi_scanres_element *sl;
	struct wifi_scanres_opclass_element *op;
	struct wifi_scanres_channel_element *ch;
	uint8_t channels[128];
	int num_chan;
	int num_tlv = 0;

	if (!a || !cmdu || !ndev || !ndev->re || !req_opc)
		return -1;

	trace("|%s:%d| response_opc id %d channels %d\n",
	      __func__, __LINE__, req_opc->classid, req_opc->num_channel);

	/* No Channels specified in the request */
	if (req_opc->num_channel == 0) {
		/* Report all supported channels in Operating Class */
		num_chan = ARRAY_SIZE(channels);
		ret = wifi_opclass_get_supported_ctrl_channels(&ndev->re->opclass,
					req_opc->classid,
					channels,
					&num_chan);
		if (ret)
			return -1;
	}
	/* Number and list of Channels specified in the request */
	else {
		/* Report for channels from the request */
		num_chan = (req_opc->num_channel < ARRAY_SIZE(channels) ?
					req_opc->num_channel : ARRAY_SIZE(channels));
		memcpy(channels, req_opc->channel, num_chan);
	}

	for (ci = 0; ci < num_chan ; ci++) {

		dbg("|%s:%d| Add Channel Scan Result TLV, op: %u, ch: %u\n",
		    __func__, __LINE__, req_opc->classid, channels[ci]);

		/* Scan failed: add Scan Status only */
		if (status != CH_SCAN_STATUS_SUCCESS) {
			struct wifi_scanres_channel_element ch_elem;

			ch_elem.channel = channels[ci];
			ret = agent_gen_ch_scan_response_tlv(a, cmdu, ndev->re->macaddr,
					req_opc->classid, &ch_elem, status);
			if (ret)
				return ret;

			dbg("|%s:%d| Added Channel Scan Result TLV.\n",
			    __func__, __LINE__);
			num_tlv++;

			continue;
		}

		/* Scan succesful: add full Channel Scan Result TLV */
		if (!ndev->re->scanlist) {
			dbg("|%s:%d| missing scanlist\n", __func__, __LINE__);
			return -1;
		}
		sl = ndev->re->scanlist;

		for (i = 0; i < sl->num_opclass_scanned; i++) {
			op = sl->opclass_scanlist + i;

			for (j = 0; j < op->num_channels_scanned; j++) {
				int k;
				ch = op->channel_scanlist + j;
				trace("scan opclass %d channel %d num_neighbors %d\n",
				    op->opclass, ch->channel, ch->num_neighbors);
				for (k = 0; k < ch->num_neighbors; k++) {
					struct wifi_scanres_neighbor_element *nbr = ch->nbrlist + k;
					trace("trace \tneigh " MACFMT " ssid %s\n", MAC2STR(nbr->bssid), nbr->ssid);
				}
			}

			if (req_opc->classid != op->opclass) {
				trace("skip opclass %d\n", op->opclass);
				continue;
			}

			for (j = 0; j < op->num_channels_scanned; j++) {
				ch = op->channel_scanlist + j;

				if (ch->channel != channels[ci])
					continue;

				ret = agent_gen_ch_scan_response_tlv(a, cmdu,
						ndev->re->macaddr,
						op->opclass, ch, status);
				if (ret)
					return ret;

				dbg("|%s:%d| Added Channel Scan Result TLV.\n",
				    __func__, __LINE__);
				num_tlv++;
			}
		}
	}

	if (!num_tlv) {
		dbg("|%s:%d| No Scan Result TLV added.\n",
		    __func__, __LINE__);
		return -1;
	}

	return 0;
}

struct cmdu_buff *agent_gen_independent_ch_scan_response(struct agent *a,
		struct wifi_netdev *ndev)
{
	struct cmdu_buff *cmdu_data;
	int ret;

	trace("%s --->\n", __func__);

	cmdu_data = cmdu_alloc_frame(CH_SCAN_RESP_MAX_BYTES);
	if (!cmdu_data) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	cmdu_set_type(cmdu_data, CMDU_CHANNEL_SCAN_REPORT);
	memcpy(cmdu_data->origin, a->cntlr_almac, 6);

	ret = agent_gen_timestamp_tlv(a, cmdu_data);
	if (ret)
		goto error; /* err */

	dbg("|%s:%d| added MAP_TLV_TIMESTAMP\n", __func__, __LINE__);

	ret = agent_gen_ch_scan_response_all(a, cmdu_data, ndev,
			CH_SCAN_STATUS_SUCCESS);

	if (ret)
		goto error; /* err */

	cmdu_put_eom(cmdu_data);
	return cmdu_data;

error:
	dbg("|%s:%d| failed to build cmdu!\n", __func__, __LINE__);
	cmdu_free(cmdu_data);

	return NULL;
}

struct cmdu_buff *agent_gen_ch_scan_response_radio(struct agent *a,
		struct wifi_netdev *ndev,
		struct wifi_scan_request_radio *req, uint8_t status)
{
	trace("%s --->\n", __func__);

	int i, ret;
	struct cmdu_buff *cmdu_data; /* The response cmdu */

	if (WARN_ON(!req))
		return NULL;

	if (WARN_ON(!ndev))
		return NULL;

	/* Allocate the cmdu */
	cmdu_data = cmdu_alloc_frame(CH_SCAN_RESP_MAX_BYTES);
	if (!cmdu_data) {
		trace("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	/* Define the cmdu */
	cmdu_set_type(cmdu_data, CMDU_CHANNEL_SCAN_REPORT);

	cmdu_set_mid(cmdu_data, req->mid);

	memcpy(cmdu_data->origin, a->cntlr_almac, 6);

	/* Define the TLVs */
	/* Timestamp TLV */
	ret = agent_gen_timestamp_tlv(a, cmdu_data);
	if (ret)
		goto free_cmdu; /* err */

	trace("|%s:%d| Added Timestamp TLV\n", __func__, __LINE__);

	/* Opclass not provided or fresh_scan == 0 */
	if (req->num_opclass == 0) {
		//	|| !(req->mode & SCAN_REQUEST_FRESH_SCAN) // redundant
		/* Include all stored results for this radio */
		ret = agent_gen_ch_scan_response_all(a, cmdu_data, ndev, status);
		/* return: */
		if (ret)
			goto free_cmdu; /* err */
		goto put_tlv; /* OK */
	}

	/* One or more opclasses were listed in the request */
	for (i = 0; i < req->num_opclass; i++) {
		/* Include results for opclass given in request */
		ret = agent_gen_ch_scan_response_opc(a, cmdu_data, ndev,
						&req->opclass[i],
						status);
		if (ret)
			goto free_cmdu; /* err */
	}

put_tlv:
	cmdu_put_eom(cmdu_data);
	return cmdu_data;
free_cmdu:
	dbg("|%s:%d| failed to build cmdu!\n", __func__, __LINE__);
	cmdu_free(cmdu_data);
	return NULL;
}

struct cmdu_buff *agent_gen_ap_caps_query(struct agent *a, uint8_t *origin)
{
	uint16_t mid = 0;
	struct cmdu_buff *resp;

	/* Allocate the cmdu_data structure */
	resp = cmdu_alloc_simple(CMDU_AP_CAPABILITY_QUERY, &mid);
	if (!resp) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(resp->origin, origin, 6);
	cmdu_put_eom(resp);
	return resp;
}

struct cmdu_buff *agent_gen_ap_caps_response(struct agent *a,
		struct cmdu_buff *rec_cmdu)
{
	int i, ret;
	uint16_t mid = 0;
	struct cmdu_buff *resp;
	struct wifi_radio_element *radio;

	mid = cmdu_get_mid(rec_cmdu);
	resp = cmdu_alloc_simple(CMDU_AP_CAPABILITY_REPORT, &mid);
	if (!resp) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}
	memcpy(resp->origin, rec_cmdu->origin, 6);

	/* AP Capability TLV */
	ret = agent_gen_ap_caps(a, resp);
	if (ret)
		goto error;

	/* AP Radio Basic Capabilities TLV */
	for (i = 0; i < a->num_radios; i++) {
		radio = a->radios + i;
		ret = agent_gen_ap_radio_basic_cap(a, resp, radio);
		if (ret)
			goto error;
	}

	/* AP HT Capabilities TLV */
	for (i = 0; i < a->num_radios; i++)
		agent_gen_ap_ht_caps(a, resp, i);

	/* AP VHT Capabilities TLV */
	for (i = 0; i < a->num_radios; i++)
		agent_gen_ap_vht_caps(a, resp, i);

	/* AP HE Capabilities TLV */
	for (i = 0; i < a->num_radios; i++)
		agent_gen_ap_he_caps(a, resp, i);

	if (a->cfg.map_profile >= 2) {
		/* Channel Scan Capabilities TLV */
		ret = agent_gen_ch_scan_cap(a, resp);
		if (ret)
			goto error;

		/* CAC Capabilities TLV */
		ret = agent_gen_cac_cap(a, resp);
		if (ret)
			goto error;

		/* Profile-2 AP Capability TLV */
		ret = agent_gen_profile2_ap_cap(a, resp);
		if (ret)
			goto error;

		/* Metric Collection Interval TLV */
		ret = agent_gen_metric_collection_interval(a, resp);
		if (ret)
			goto error;

#if (EASYMESH_VERSION > 2)
		if (a->cfg.map_profile > 2) {
			/* AP Wi-Fi 6 Capabilities TLV */
			for (i = 0; i < a->num_radios; i++) {
				ret = agent_gen_ap_wifi6_caps(a, resp, a->radios + i);
				if (ret)
					goto error;
			}

			/* Device 1905 Layer Security Capability TLV */
			ret = agent_gen_device_1905_layer_security_cap(a, resp);
			if (ret)
				goto error;

			/*  Device Inventory TLV */
			ret = agent_gen_device_inventory(a, resp);
			if (ret)
				goto error;
		}
#endif
	}

	cmdu_put_eom(resp);

	return resp;

error:
	cmdu_free(resp);

	return NULL;
}

struct cmdu_buff *agent_gen_bk_caps_response(struct agent *a,
		struct cmdu_buff *cmdu)
{
	struct cmdu_buff *cmdu_data;
	uint32_t i;
	uint16_t mid;
	int ret;

	/* Allocate and define the cmdu */
	mid = cmdu_get_mid(cmdu);
	cmdu_data = cmdu_alloc_simple(CMDU_BACKHAUL_STA_CAPABILITY_REPORT, &mid);
	if (!cmdu_data) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(cmdu_data->origin, cmdu->origin, 6);

	/* Define the TLVs */
	for (i = 0; i < a->num_radios; i++) {
		/* Backhaul STA radio capabilities TLV */
		ret = agent_gen_bk_sta_radio_cap_tlv(a, i, cmdu_data);
		if (ret)
			goto error;
		trace("|%s:%d| Added MAP_TLV_BACKHAUL_STA_RADIO_CAPABILITY\n", __func__, __LINE__);
	}

	cmdu_put_eom(cmdu_data);
	return cmdu_data;
error:
	cmdu_free(cmdu_data);
	return NULL;
}

struct cmdu_buff *agent_gen_topology_notification(struct agent *agent,
		uint8_t *mac, uint8_t *bssid, uint8_t assoc_event)
{

	struct cmdu_buff *frm = NULL;
	int ret = 0;
	uint16_t mid = 0;
	uint8_t origin[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x13};


	frm = cmdu_alloc_simple(CMDU_TYPE_TOPOLOGY_NOTIFICATION, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	CMDU_SET_RELAY_MCAST(frm->cdata);

	ret = agent_gen_al_mac(agent, frm, agent->almac);
	if (ret)
		goto out;

	/* Client Association Event TLV */
	ret = agent_gen_client_assoc_event_tlv(agent, frm, mac, bssid,
			assoc_event);
	if (ret)
		goto out;

	memcpy(frm->origin, origin, 6);
	cmdu_put_eom(frm);
	return frm;
out:
	cmdu_free(frm);
	return NULL;
}

struct cmdu_buff *agent_gen_client_disassoc(struct agent *a,
		uint8_t *mac, uint8_t *bssid, uint16_t reason_code)
{
	uint16_t mid = 0;
	int ret;
	struct cmdu_buff *cmdu;
	struct sta *s;

	cmdu = cmdu_alloc_simple(CMDU_CLIENT_DISASSOCIATION_STATS, &mid);
	if (!cmdu) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(cmdu->origin, a->cntlr_almac, 6);


	/* STA MAC Address TLV */
	ret = agent_gen_sta_mac(a, cmdu, mac);
	if (ret)
		goto error;

	/* Reason Code TLV */
	ret = agent_gen_reason_code(a, cmdu, reason_code);
	if (ret)
		goto error;

	/* Authorized STA Traffic Stats TLV */
	s = find_sta_by_mac(a, mac); /* NOTE: can be NULL */
	ret = agent_gen_assoc_sta_traffic_stats(a, cmdu, mac, s);
	if (ret)
		goto error;

	cmdu_put_eom(cmdu);

	return cmdu;
error:
	cmdu_free(cmdu);

	return NULL;
}

struct cmdu_buff *agent_gen_topology_query(struct agent *a, uint8_t *origin)
{
	struct cmdu_buff *resp;
	uint16_t mid = 0;
	int ret = 0;

	resp = cmdu_alloc_simple(CMDU_TYPE_TOPOLOGY_QUERY, &mid);
	if (!resp) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	ret = agent_gen_map_profile(a, resp, a->cfg.map_profile);
	if (!ret)
		goto error;

	memcpy(resp->origin, origin, 6);
	cmdu_put_eom(resp);
	return resp;
error:
	cmdu_free(resp);
	return NULL;
}

struct cmdu_buff *agent_gen_topology_response(struct agent *a, uint8_t *origin,
	uint16_t mid)
{
	struct cmdu_buff *resp = NULL, *ext = NULL;
	int ret;

	/* query i1905d base CMDU */
	resp = ieee1905_ubus_buildcmdu(a->ubus_ctx, CMDU_TYPE_TOPOLOGY_RESPONSE);
	if (!resp) {
		dbg("No response from stack when generating 0x%04x\n",
				CMDU_TYPE_TOPOLOGY_RESPONSE);
		return NULL;
	}

	ext = cmdu_realloc(resp, 2000);
	if (!ext)
		goto error;

	resp = ext;

	/* Supported Service */
	ret = agent_gen_supported_service(a, resp,
			(!memcmp(a->almac, a->cntlr_almac, 6) ?
			SUPPORTED_SERVICE_MULTIAP_CONTROLLER :
			SUPPORTED_SERVICE_MULTIAP_AGENT));
	if (ret)
		goto error;

	/* AP Operational BSS */
	ret = agent_gen_ap_oper_bss_tlv(a, resp);
	if (ret)
		goto error;

	/* Associated Clients */
	ret = agent_gen_assoc_client_tlv(a, resp);
	if (ret)
		goto error;

#ifdef EASYMESH_VENDOR_EXT
	/* Vendor Specific tlv added to get the sta link metrics in host.devices*/
	ret = agent_gen_vendor_specific_bbbs_tlv(a, resp);
	if (ret)
		goto error;
#endif /*EASYMESH_VENDOR_EXT*/

#if (EASYMESH_VERSION > 2)
	if (a->cfg.map_profile > 2) {
		/* BSS Configuration Report TLV*/
		ret = agent_gen_bss_config_report_tlv(a, resp);
		if (ret)
			goto error;
	}
#endif

	/* Multi-AP profile */
	ret = agent_gen_map_profile(a, resp, a->cfg.map_profile);
	if (ret)
		goto error;

	cmdu_set_mid(resp, mid);
	memcpy(resp->origin, origin, 6);
	cmdu_put_eom(resp);
	return resp;
error:
	cmdu_free(resp);
	return NULL;
}

struct cmdu_buff *agent_gen_cmdu_1905_ack(
		struct agent *a, uint8_t *origin, uint16_t mid,
		struct sta_error_response *sta_resp, uint32_t sta_count)
{
	trace("agent: %s: --->\n", __func__);
	struct cmdu_buff *frm = NULL;
	int j;

	frm = cmdu_alloc_simple(CMDU_1905_ACK, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(frm->origin, origin, 6);

	/* Error Code TLV 17.2.36 */
	for (j = 0; j < sta_count; j++) {
		if (agent_gen_tlv_error_code(a, frm,
				sta_resp[j].sta_mac, sta_resp[j].response))
			continue;

	}

	cmdu_put_eom(frm);
	return frm;
}

struct cmdu_buff *agent_gen_cmdu_backhaul_steer_resp(struct agent *a,
		uint8_t *target_bssid, uint8_t *macaddr, uint16_t mid)
{
	trace("agent: %s: --->\n", __func__);
	struct cmdu_buff *frm = NULL;
	int ret = 0;


	frm = cmdu_alloc_simple(CMDU_BACKHAUL_STEER_RESPONSE, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	ret = agent_gen_tlv_backhaul_steer_resp(a, frm, target_bssid, macaddr);
	if (ret)
		goto out;

	cmdu_put_eom(frm);

	return frm;
out:
	cmdu_free(frm);
	return NULL;
}

struct cmdu_buff *agent_gen_channel_preference_report(struct agent *a,
		struct cmdu_buff *rx_cmdu)
{
	uint16_t mid = 0;
	int i, ret;
	struct cmdu_buff *frm;

	if (rx_cmdu)
		mid = cmdu_get_mid(rx_cmdu);

	frm = cmdu_alloc_simple(CMDU_CHANNEL_PREFERENCE_REPORT, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	if (rx_cmdu)
		memcpy(frm->origin, rx_cmdu->origin, 6);
	else
		memcpy(frm->origin, a->cntlr_almac, 6);

	for (i = 0; i < a->num_radios; i++) {
		/* Channel Preference TLV */
		ret = agent_gen_channel_pref(a, frm, i);
		if (ret)
			goto error;
	}

#if 0
	/*
	 * Disable while not required, before better understand of this.
	 * Seems today we fill it wrong.
	 */
	for (i = 0; i < a->num_radios; i++) {
		/* Radio Operation Restriction TLV */
		ret = agent_gen_radio_oper_restrict(a, frm, i);
		if (ret)
			goto error;
	}
#endif

//#ifdef PROFILE2
	/* CAC Completion Report TLV */
	ret = agent_gen_cac_complete_report(a, frm);
	if (ret)
		goto error;

	/* CAC Status Report TLV */
	ret = agent_gen_cac_status_report(a, frm);
	if (ret)
		goto error;
//#endif

	cmdu_put_eom(frm);
	return frm;

error:
	cmdu_free(frm);
	return NULL;
}

struct cmdu_buff *agent_gen_association_status_notify(struct agent *a,
		int num_data, void *data)
{
	uint16_t mid = 0;
	int ret;
	struct cmdu_buff *frm;

	trace("%s: %d\n", __func__, __LINE__);
	frm = cmdu_alloc_simple(CMDU_ASSOCIATION_STATUS_NOTIFICATION, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	/* send notifiy to Multi-AP Controller
	 * and all the other Multi-AP Agent (TODO)
	 */
	memcpy(frm->origin, a->cfg.cntlr_almac, 6);

	ret = agent_gen_assoc_status_notif(a, frm, num_data, data);
	if (ret)
		goto error;

	cmdu_put_eom(frm);

	return frm;
error:
	cmdu_free(frm);

	return NULL;
}

struct cmdu_buff *agent_gen_oper_channel_response(struct agent *a,
		struct wifi_radio_element *radio,
		uint32_t channel, uint32_t bandwidth, bool all)
{
	uint32_t j;
	uint16_t mid = 0;
	struct cmdu_buff *cmdu;
	int ret;

	cmdu = cmdu_alloc_simple(CMDU_OPERATING_CHANNEL_REPORT, &mid);
	if (!cmdu) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	if (all == 1) {
		/* Operating Channel Report TLV 17.2.17 */
		for (j = 0; j < a->num_radios; j++) {
			struct wifi_radio_element *r = a->radios + j;
			uint32_t chan = r->current_channel;
			uint32_t op_class = r->current_opclass;
			ret = agent_gen_oper_channel_report(a, cmdu, r, chan, 0, op_class);
			if (ret)
				goto error;
		}
	} else {
		ret = agent_gen_oper_channel_report(a, cmdu, radio, channel, bandwidth, 0);
		if (ret)
			goto error;
	}

	/* destination controller */
	memcpy(cmdu->origin, a->cntlr_almac, 6);

	cmdu_put_eom(cmdu);
	return cmdu;

error:
	cmdu_free(cmdu);
	return NULL;
}

struct cmdu_buff *agent_gen_higher_layer_data(struct agent *a, uint8_t *addr,
		uint8_t proto, uint8_t *data, int len)
{
	struct cmdu_buff *frm;
	int ret;

	/* HLD payload with 1 byte proto + tlv header + eom */
	frm = cmdu_alloc_frame(len + 1 + 2*TLV_HLEN);
	if (!frm)
		return NULL;
	cmdu_set_type(frm, CMDU_HIGHER_LAYER_DATA);
	//cmdu_set_mid(frm, 0); /* dynamicly assigned */

	/* Agent send to orgin */
	memcpy(frm->origin, addr, 6);

	ret = agent_gen_tlv_higher_layer_data(a, frm, proto, data, len);
	if (ret)
		goto error;

	cmdu_put_eom(frm);
	return frm;

error:
	cmdu_free(frm);
	return NULL;
}

struct cmdu_buff *agent_gen_sta_caps_response(struct agent *a,
		struct cmdu_buff *rx_cmdu, struct node *n)
{
	uint8_t result_code = 0x00;
	uint8_t reason_code = 0x00;
	uint16_t mid = 0;
	int ret;
	struct cmdu_buff *resp;
	struct sta *s = NULL;
	struct tlv_client_info *tmp = NULL;
	struct tlv *tv[1][16];

	/* parse received CMDU */
	ret = map_cmdu_parse_tlvs(rx_cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return NULL;
	}

	if (!tv[0][0])
		return NULL;

	mid = cmdu_get_mid(rx_cmdu);
	resp = cmdu_alloc_simple(CMDU_CLIENT_CAPABILITY_REPORT, &mid);
	if (!resp) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(resp->origin, rx_cmdu->origin, 6);

	tmp = (struct tlv_client_info *)tv[0][0]->data;

	/* Client Info TLV */
	ret = agent_gen_client_info(a, resp, tmp->macaddr, tmp->bssid);
	if (ret)
		goto error;

	s = find_sta_by_mac(a, tmp->macaddr);
	if (s && (s->assoc_frame)) {
		/* sta is associated */
		trace("sta associated\n");

		/* Client Capability Report TLV */
		ret = agent_gen_client_cap_report(a, resp,
				result_code, s);
		if (ret)
			goto error;

	} else {
		result_code = 0x01;

		if (s) {
			/* assoc frame is not available */
			trace("no assoc frame for sta " MACFMT "\n",
					MAC2STR(tmp->macaddr));
			reason_code = 0x03;
		} else {
			/* sta is not associated with any BSS*/
			trace("sta not associated\n");
			reason_code = 0x02;
		}

		/* Client Capability Report TLV */
		ret = agent_gen_client_cap_report(a, resp,
				result_code, NULL);
		if (ret)
			goto error;

		/* Error Code TLV */
		ret = agent_gen_tlv_error_code(a, resp,
				tmp->macaddr, reason_code);
		if (ret)
			goto error;
	}

	cmdu_put_eom(resp);

	return resp;
error:
	cmdu_free(resp);

	return NULL;
}

struct cmdu_buff *agent_gen_topology_discovery(struct agent *a)
{
	struct cmdu_buff *frm = NULL;
	uint16_t mid = 0;
	uint8_t origin[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x13};
	int ret = 0;

	frm = cmdu_alloc_simple(CMDU_TYPE_TOPOLOGY_DISCOVERY, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	ret = agent_gen_al_mac(a, frm, a->almac);
	if (ret)
		goto out;

	ret = agent_gen_mac(a, frm, a->almac);
	if (ret)
		goto out;

	memcpy(frm->origin, origin, 6);
	cmdu_put_eom(frm);

	return frm;
out:
	cmdu_free(frm);
	return NULL;
}

struct cmdu_buff *agent_gen_failed_connection(struct agent *a,
		uint8_t *sta, int status_code, int reason_code)
{
	uint16_t mid = 0;
	int ret;
	struct cmdu_buff *frm = NULL;

	frm = cmdu_alloc_simple(CMDU_FAILED_CONNECTION, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(frm->origin, a->cntlr_almac, 6);

	ret = agent_gen_sta_mac(a, frm, sta);
	if (ret)
		goto out;

	ret = agent_gen_status_code(a, frm, status_code);
	if (ret)
		goto out;

	if (status_code == 0) {
		ret = agent_gen_reason_code(a, frm, reason_code);
		if (ret)
			goto out;
	}

	cmdu_put_eom(frm);

	return frm;

out:
	cmdu_free(frm);
	return NULL;
}

#if (EASYMESH_VERSION > 2)
struct cmdu_buff *agent_gen_bss_configuration_request(struct agent *a)
{
	struct cmdu_buff *req_cmdu;
	uint16_t mid = 0;
	int i;

	req_cmdu = cmdu_alloc_simple(CMDU_BSS_CONFIG_REQUEST, &mid);
	if (!req_cmdu) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	/*  One Multi-AP Profile TLV */
	if (agent_gen_map_profile(a, req_cmdu, a->cfg.map_profile)) {
		dbg("%s: agent_gen_map_profile failed.\n", __func__);
		goto out;
	}

	/* One SupportedService TLV */
	if (agent_gen_supported_service(a, req_cmdu, SUPPORTED_SERVICE_MULTIAP_AGENT)) {
		dbg("%s: agent_gen_supported_service failed.\n", __func__);
		goto out;
	}

	/*  One AKM Suite Capabilities TLV */
	if (agent_gen_akm_suite_cap(a, req_cmdu)) {
		dbg("%s: agent_gen_akm_suite_cap failed.\n", __func__);
		goto out;
	}

	/* One or more AP Radio Basic Capabilities TLV */
	for (i = 0; i < a->num_radios; ++i) {
		if (agent_gen_ap_radio_basic_cap(a, req_cmdu, a->radios + i)) {
			dbg("%s: agent_gen_ap_radio_basic_cap failed.\n", __func__);
			goto out;
		}
	}

	/* Zero or more Backhaul STA Radio Capabilities TLV */
	for (i = 0; i < a->num_radios; ++i) {
		if (agent_gen_bk_sta_radio_cap_tlv(a, i, req_cmdu)) {
			dbg("%s: agent_gen_bk_sta_radio_cap_tlv failed.\n", __func__);
			goto out;
		}
	}

	/* One Profile-2 AP Capability TLV */
	if (agent_gen_profile2_ap_cap(a, req_cmdu)) {
		dbg("%s: agent_gen_profile2_ap_cap failed.\n", __func__);
		goto out;
	}

	/* One or more AP Radio Advanced Capabilities TLV */
	for (i = 0; i < a->num_radios; ++i) {
		if (agent_gen_ap_radio_adv_cap(a, req_cmdu, a->radios + i)) {
			dbg("%s: agent_gen_ap_radio_adv_cap failed.\n", __func__);
			goto out;
		}
	}

	/* One or more JSON encoded DPP Configuration Request Object attributes */
	if (agent_gen_conf_req_object_atrributes(a, req_cmdu)) {
		dbg("%s: agent_gen_conf_req_object_atrributes failed.\n", __func__);
		goto out;
	}

	if (cmdu_put_eom(req_cmdu)) {
		dbg("%s: cmdu_put_eom failed.\n", __func__);
		goto out;
	}

	return req_cmdu;

out:
	cmdu_free(req_cmdu);
	return NULL;
}

struct cmdu_buff *agent_gen_bss_configuration_result(struct agent *a)
{
	struct cmdu_buff *result_cmdu;
	uint16_t mid = 0;

	result_cmdu = cmdu_alloc_simple(CMDU_BSS_CONFIG_RESULT, &mid);
	if (!result_cmdu) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	/* One BSS Configuration Report TLV */
	if (agent_gen_bss_config_report_tlv(a, result_cmdu)) {
		dbg("%s: agent_gen_bss_config_report_tlv failed.\n", __func__);

		cmdu_free(result_cmdu);
		return NULL;
	}

	return result_cmdu;
}

struct cmdu_buff *agent_gen_dpp_bootstrapping_uri_notification(
		struct agent *a, uint8_t *radio_id, uint8_t *bssid,
		uint8_t *bksta, char *dpp_uri, int uri_len)
{
	int ret;
	uint16_t mid = 0;
	struct cmdu_buff *frm = NULL;

	frm = cmdu_alloc_simple(CMDU_DPP_BOOTSTRAPING_URI, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(frm->origin, a->cntlr_almac, 6);
	ret = agent_gen_dpp_bootstrapping_uri_notif(a, frm, radio_id,
			bssid, bksta, dpp_uri, uri_len);
	if (ret)
		goto out;

	cmdu_put_eom(frm);

	return frm;
out:
	cmdu_free(frm);
	return NULL;
}
#endif // EASYMESH_VERSION > 2
