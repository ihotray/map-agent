/*
 * agent_ubus_dbg.c - for testing purpose only
 *
 * Copyright (C) 2022 IOPSYS Software Solutions AB. All rights reserved.
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
#include "wifi.h"
#include <map_module.h>
#include <easymesh.h>
#include <i1905_wsc.h>
#include <cntlrsync.h>

#include "timer.h"
#include "utils/utils.h"
#include "utils/debug.h"
#include "config.h"
#include "nl.h"
#include "agent.h"
#include "agent_map.h"
#include "agent_ubus.h"
#include "agent_cmdu.h"
#include "agent_ubus.h"

#define OBJECT_INVALID	((uint32_t)-1)

#ifndef MAP_AGENT_DISABLE_UBUS_DBG

static int wifi_ubus_scan_req(struct agent *a, const char *radio, const char *ssid)
{
	struct scan_param_ex param = {};
	int res = 0;
	int i;

	if (ssid) {
		param.flag |= WIFI_SCAN_REQ_SSID;
		param.num_ssid = 1;

		strncpy(param.ssid[0], ssid, sizeof(param.ssid[0]) - 1);
	}

	if (radio)
		return wifi_scan(radio, &param, 0, NULL, 0, NULL);

	for (i = 0; i < ARRAY_SIZE(a->radios); i++)
		res |= wifi_scan(a->radios[i].name, &param, 0, NULL, 0, NULL);

	return res;
}

static char * opclass_dfs(enum wifi_radio_opclass_dfs dfs)
{
	switch (dfs) {
	case WIFI_RADIO_OPCLASS_CHANNEL_DFS_USABLE:
		return "usable";
	case WIFI_RADIO_OPCLASS_CHANNEL_DFS_AVAILABLE:
		return "available";
	case WIFI_RADIO_OPCLASS_CHANNEL_DFS_NOP:
		return "nop";
	case WIFI_RADIO_OPCLASS_CHANNEL_DFS_CAC:
		return "cac";
	default:
		break;
	}

	return "unknown";
}

static int opclass_dump(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct agent *agent = container_of(obj, struct agent, obj_dbg);
	struct wifi_radio_element *re;
	struct wifi_radio_opclass *opclass;
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *chan;
	void *a, *aa, *aaa, *t, *tt, *ttt;
	struct blob_buf bb = {};
	int i, j, k;

	blob_buf_init(&bb, 0);
	a = blobmsg_open_array(&bb, "radios");
	for (i = 0; i < agent->num_radios; i++) {
		re = &agent->radios[i];
		opclass = &re->opclass;

		t = blobmsg_open_table(&bb, "");
		blobmsg_add_string(&bb, "name", re->name);

		aa = blobmsg_open_array(&bb, "entries");
		for (j = 0; j < opclass->entry_num; j++) {
			entry = &opclass->entry[j];

			tt = blobmsg_open_table(&bb, "");
			blobmsg_add_u32(&bb, "id", entry->id);
			blobmsg_add_u32(&bb, "bw", entry->bandwidth);

			aaa = blobmsg_open_array(&bb, "channels");
			for (k = 0; k < entry->channel_num; k++) {
				chan = &entry->channel[k];

				ttt = blobmsg_open_table(&bb, "");

				blobmsg_add_u32(&bb, "channel", chan->channel);
				blobmsg_add_u32(&bb, "pref",  (chan->preference & CHANNEL_PREF_MASK) >> 4);

				if (chan->dfs != WIFI_RADIO_OPCLASS_CHANNEL_DFS_NONE) {
					blobmsg_add_string(&bb, "dfs", opclass_dfs(chan->dfs));
					blobmsg_add_u32(&bb, "cac_time", chan->cac_time);
					blobmsg_add_u32(&bb, "nop_time", chan->nop_time);
				}

				blobmsg_close_table(&bb, ttt);
			}
			blobmsg_close_array(&bb, aaa);
			blobmsg_close_table(&bb, tt);
		}
		blobmsg_close_array(&bb, aa);
		blobmsg_close_table(&bb, t);
	}
	blobmsg_close_array(&bb, a);

        ubus_send_reply(ctx, req, bb.head);
        blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

enum {
	PREF_CHANNELS_RADIO,
	PREF_CHANNELS_MODE,
	_PREF_CHANNELS_MAX
};

static const struct blobmsg_policy pref_channels_params[_PREF_CHANNELS_MAX] = {
	[PREF_CHANNELS_RADIO] = { .name = "radio", .type = BLOBMSG_TYPE_STRING },
	[PREF_CHANNELS_MODE] = { .name = "mode", .type = BLOBMSG_TYPE_INT32 },
};

static int pref_channels(struct ubus_context *ctx, struct ubus_object *obj,
			 struct ubus_request_data *req, const char *method,
			 struct blob_attr *msg)
{
	struct blob_attr *tb[_PREF_CHANNELS_MAX];
	struct agent *a = container_of(obj, struct agent, obj_dbg);
	const char *radio;
	int mode = 0;

	blobmsg_parse(pref_channels_params, _PREF_CHANNELS_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (!tb[PREF_CHANNELS_RADIO])
		return UBUS_STATUS_UNKNOWN_ERROR;

	if (tb[PREF_CHANNELS_MODE])
		mode = blobmsg_get_u32(tb[PREF_CHANNELS_MODE]);

	radio = blobmsg_data(tb[PREF_CHANNELS_RADIO]);

	switch (mode) {
	/* Play with scan and get fresh results after scan */
	case 0:
		agent_set_post_scan_action_pref(a, radio, true);
		if (wifi_ubus_scan_req(a, radio, NULL))
			return UBUS_STATUS_UNKNOWN_ERROR;
		break;

	/* Run direct call - could be old score */
	case 1:
		if (wifi_radio_update_opclass_preferences(a, radio, true))
			return UBUS_STATUS_UNKNOWN_ERROR;
		break;
	default:
		return UBUS_STATUS_UNKNOWN_ERROR;
	}


	return UBUS_STATUS_OK;
}

enum {
	DBG_WIFI_AP_STATUS_IFNAME,
	_DBG_WIFI_AP_STATUS_MAX
};

static const struct blobmsg_policy dbg_wifi_ap_status_params[_DBG_WIFI_AP_STATUS_MAX] = {
	[DBG_WIFI_AP_STATUS_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
};
static int dbg_wifi_ap_status(struct ubus_context *ctx, struct ubus_object *obj,
			      struct ubus_request_data *req, const char *method,
			      struct blob_attr *msg)
{
	struct blob_attr *tb[_DBG_WIFI_AP_STATUS_MAX];
	struct wifi_ap_status ap_status = {};
	char bssidstr[18] = {};
	struct blob_buf bb = {};
	const char *ifname;
	int ret;

	blobmsg_parse(dbg_wifi_ap_status_params, _DBG_WIFI_AP_STATUS_MAX, tb,
		      blob_data(msg), blob_len(msg));

	if (!tb[DBG_WIFI_AP_STATUS_IFNAME])
		return UBUS_STATUS_UNKNOWN_ERROR;

	ifname = blobmsg_get_string(tb[DBG_WIFI_AP_STATUS_IFNAME]);

	ret = wifi_ap_status(ifname, &ap_status);
	if (ret)
		return UBUS_STATUS_UNKNOWN_ERROR;

	blob_buf_init(&bb, 0);
	hwaddr_ntoa(ap_status.ap.bss.bssid, bssidstr);
	blobmsg_add_string(&bb, "ssid", (char *) ap_status.ap.bss.ssid);
	blobmsg_add_string(&bb, "bssid", bssidstr);
	blobmsg_add_u32(&bb, "channel", ap_status.ap.bss.channel);
	blobmsg_add_u32(&bb, "utilization", ap_status.ap.bss.load.utilization);

        ubus_send_reply(ctx, req, bb.head);
        blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

enum {
	DBG_WIFI_RADIO_SCANRESULTS_RADIO,
	DBG_WIFI_RADIO_SCANRESULTS_RADIO_MAC,
	_DBG_WIFI_RADIO_SCANRESULTS_MAX
};

static const struct blobmsg_policy dbg_wifi_radio_scanresults_params[_DBG_WIFI_RADIO_SCANRESULTS_MAX] = {
	[DBG_WIFI_RADIO_SCANRESULTS_RADIO] = {
		.name = "radio",
		.type = BLOBMSG_TYPE_STRING
	},
	[DBG_WIFI_RADIO_SCANRESULTS_RADIO_MAC] = {
		.name = "radio_mac",
		.type = BLOBMSG_TYPE_STRING
	},
};

static int dbg_wifi_radio_scanresults(struct ubus_context *ctx, struct ubus_object *obj,
				      struct ubus_request_data *req, const char *method,
				      struct blob_attr *msg)
{
	struct agent *agent = container_of(obj, struct agent, obj_dbg);
	struct wifi_radio_element *re = NULL;
	struct blob_attr *tb[_DBG_WIFI_RADIO_SCANRESULTS_MAX];
	struct wifi_bss bss[128];
	char bssidstr[18] = {};
	char mac_str[18] = {};
	uint8_t radio_mac[6] = {0};
	int bss_num = ARRAY_SIZE(bss);
	struct blob_buf bb = {};
	char *radio;
	int bandwidth;
	void *t, *a, *b;
	int i, j, ret;

	blobmsg_parse(dbg_wifi_radio_scanresults_params, _DBG_WIFI_RADIO_SCANRESULTS_MAX, tb,
		      blob_data(msg), blob_len(msg));

	if (tb[DBG_WIFI_RADIO_SCANRESULTS_RADIO]) {
		radio = blobmsg_get_string(tb[DBG_WIFI_RADIO_SCANRESULTS_RADIO]);
		re = wifi_ifname_to_radio_element(agent, radio);
		if (!re) {
			dbg("failed to get radio by name\n");
			return UBUS_STATUS_UNKNOWN_ERROR;
		}
	} else if (tb[DBG_WIFI_RADIO_SCANRESULTS_RADIO_MAC]) {
		strncpy(mac_str,
				blobmsg_data(tb[DBG_WIFI_RADIO_SCANRESULTS_RADIO_MAC]),
							 sizeof(mac_str) - 1);

		if (!hwaddr_aton(mac_str, radio_mac)) {
			dbg("wrongly formated radio MAC\n");
			return UBUS_STATUS_UNKNOWN_ERROR;
		}

		re = wifi_get_radio_by_mac(agent, radio_mac);
		if (!re) {
			dbg("failed to get radio by MAC\n");
			return UBUS_STATUS_UNKNOWN_ERROR;
		}
	}

	blob_buf_init(&bb, 0);

	b = blobmsg_open_array(&bb, "radios");

	for (i = 0; i < agent->num_radios; i++) {
		char macaddrstr[18] = {0};
		struct wifi_radio_element *c_re = NULL;
		void *b1;

		c_re = &agent->radios[i];

		if (re && re != c_re)
			/* other radio requested */
			continue;

		b1 = blobmsg_open_table(&bb, "");

		hwaddr_ntoa(c_re->macaddr, macaddrstr);
		blobmsg_add_string(&bb, "macaddr", macaddrstr);
		bss_num = ARRAY_SIZE(bss);
		ret = wifi_get_scan_results(c_re->name, bss, &bss_num);
		if (ret) {
			dbg("failed to get scan results for radio %s\n", c_re->name);
			return UBUS_STATUS_UNKNOWN_ERROR;
		}

		a = blobmsg_open_array(&bb, "accesspoints");
		for (j = 0; j < bss_num; j++) {
			hwaddr_ntoa(bss[j].bssid, bssidstr);
			bandwidth = wifi_bw_to_bw(bss[j].curr_bw);

			t = blobmsg_open_table(&bb, "");
			blobmsg_add_string(&bb, "ssid", (char *) bss[j].ssid);
			blobmsg_add_string(&bb, "bssid", bssidstr);
			blobmsg_add_u32(&bb, "channel", bss[j].channel);
			blobmsg_add_u32(&bb, "bandwidth", bandwidth);
			blobmsg_add_u32(&bb, "rssi", bss[j].rssi);
			blobmsg_add_u32(&bb, "load_stas", bss[j].load.sta_count);
			blobmsg_add_u32(&bb, "load_utilization",
					bss[j].load.utilization);
			blobmsg_close_table(&bb, t);
		}
		blobmsg_close_array(&bb, a); /* accesspoints */
		blobmsg_close_table(&bb, b1);
	}

	blobmsg_close_array(&bb, b); /* radios */

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

enum {
	DBG_SCAN_CACHE_DUMP_RADIO_NAME,
	DBG_SCAN_CACHE_DUMP_RADIO_MAC,
	_DBG_SCAN_CACHE_DUMP_MAX
};

static const struct blobmsg_policy dbg_scan_cache_dump_params[_DBG_SCAN_CACHE_DUMP_MAX] = {
	[DBG_SCAN_CACHE_DUMP_RADIO_NAME] = {
		.name = "radio",
		.type = BLOBMSG_TYPE_STRING
	},
	[DBG_SCAN_CACHE_DUMP_RADIO_MAC] = {
		.name = "radio_mac",
		.type = BLOBMSG_TYPE_STRING
	},
};

static int dbg_scancache_dump(struct ubus_context *ctx, struct ubus_object *obj,
				      struct ubus_request_data *req, const char *method,
				      struct blob_attr *msg)
{
	struct agent *agent = container_of(obj, struct agent, obj_dbg);
	struct wifi_radio_element *re = NULL;
	struct blob_attr *tb[_DBG_WIFI_RADIO_SCANRESULTS_MAX];
	char mac_str[18] = {};
	uint8_t radio_mac[6] = {0};
	struct blob_buf bb = {};
	char *radio;
	void *a, *b;
	int i, j;

	blobmsg_parse(dbg_wifi_radio_scanresults_params, _DBG_WIFI_RADIO_SCANRESULTS_MAX,
		      tb, blob_data(msg), blob_len(msg));

	if (tb[DBG_SCAN_CACHE_DUMP_RADIO_NAME]) {
		radio = blobmsg_get_string(tb[DBG_WIFI_RADIO_SCANRESULTS_RADIO]);
		re = wifi_ifname_to_radio_element(agent, radio);
		if (!re) {
			dbg("failed to get radio by name\n");
			return UBUS_STATUS_UNKNOWN_ERROR;
		}
	} else if (tb[DBG_SCAN_CACHE_DUMP_RADIO_MAC]) {
		strncpy(mac_str,
				blobmsg_data(tb[DBG_WIFI_RADIO_SCANRESULTS_RADIO_MAC]),
							 sizeof(mac_str) - 1);

		if (!hwaddr_aton(mac_str, radio_mac)) {
			dbg("wrongly formated radio MAC\n");
			return UBUS_STATUS_UNKNOWN_ERROR;
		}

		re = wifi_get_radio_by_mac(agent, radio_mac);
		if (!re) {
			dbg("failed to get radio by MAC\n");
			return UBUS_STATUS_UNKNOWN_ERROR;
		}
	}

	blob_buf_init(&bb, 0);

	b = blobmsg_open_array(&bb, "radios");

	for (i = 0; i < agent->num_radios; i++) {
		char macaddrstr[18] = {0};
		struct wifi_radio_element *c_re = NULL;
		void *b1;

		c_re = &agent->radios[i];

		if (re && re != c_re)
			/* other radio requested */
			continue;

		b1 = blobmsg_open_table(&bb, "");

		hwaddr_ntoa(c_re->macaddr, macaddrstr);
		blobmsg_add_string(&bb, "macaddr", macaddrstr);

		a = blobmsg_open_array(&bb, "entries");
		for (j = 0; j < c_re->scanresults.entry_num; j++) {
			struct wifi_scanresults_entry *entry;
			struct wifi_bss *bss;
			char bssidstr[18] = {};
			int bandwidth;
			void *b2;

			entry = &c_re->scanresults.entry[j];
			bss = &entry->bss;

			b2 = blobmsg_open_table(&bb, "");

			hwaddr_ntoa(bss->bssid, bssidstr);
			blobmsg_add_string(&bb, "bssid", bssidstr);

			blobmsg_add_u32(&bb, "opclass_HT20", entry->opclass);
			blobmsg_add_u32(&bb, "channel", bss->channel);
			blobmsg_add_string(&bb, "ssid", (char *) bss->ssid);
			bandwidth = wifi_bw_to_bw(bss->curr_bw);
			blobmsg_add_u32(&bb, "bandwidth", bandwidth);
			blobmsg_add_u32(&bb, "rssi", bss->rssi);
			blobmsg_add_u32(&bb, "load_stas", bss->load.sta_count);
			blobmsg_add_u32(&bb, "load_utilization",
					bss->load.utilization);

			blobmsg_add_u32(&bb, "age",
					timestamp_elapsed_sec(&entry->tsp));
			blobmsg_add_u32(&bb, "expired", entry->expired);

			blobmsg_close_table(&bb, b2);
		}
		blobmsg_close_array(&bb, a); /* accesspoints */
		blobmsg_close_table(&bb, b1);
	}

	blobmsg_close_array(&bb, b); /* radios */

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

enum {
	DBG_WIFI_CHAN_SWITCH_IFNAME,
	DBG_WIFI_CHAN_SWITCH_CHAN,
	DBG_WIFI_CHAN_SWITCH_BW,
	DBG_WIFI_CHAN_SWITCH_COUNT,
	_DBG_WIFI_CHAN_SWITCH_MAX
};

static const struct blobmsg_policy dbg_wifi_chan_switch_params[_DBG_WIFI_CHAN_SWITCH_MAX] = {
	[DBG_WIFI_CHAN_SWITCH_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[DBG_WIFI_CHAN_SWITCH_CHAN] = { .name = "channel", .type = BLOBMSG_TYPE_INT32},
	[DBG_WIFI_CHAN_SWITCH_BW] = { .name = "bandwidth", .type = BLOBMSG_TYPE_INT32},
	[DBG_WIFI_CHAN_SWITCH_COUNT] = { .name = "count", .type = BLOBMSG_TYPE_INT32},
};

static int dbg_wifi_chan_switch(struct ubus_context *ctx, struct ubus_object *obj,
				struct ubus_request_data *req, const char *method,
				struct blob_attr *msg)
{
	struct blob_attr *tb[_DBG_WIFI_CHAN_SWITCH_MAX];
	struct chan_switch_param param = {};
	const char *ifname;
	int channel, bw;
	int count = 5;

	blobmsg_parse(dbg_wifi_chan_switch_params, _DBG_WIFI_CHAN_SWITCH_MAX, tb,
		      blob_data(msg), blob_len(msg));

	if (!tb[DBG_WIFI_CHAN_SWITCH_IFNAME])
		return UBUS_STATUS_UNKNOWN_ERROR;

	if (!tb[DBG_WIFI_CHAN_SWITCH_CHAN])
		return UBUS_STATUS_UNKNOWN_ERROR;

	if (!tb[DBG_WIFI_CHAN_SWITCH_BW])
		return UBUS_STATUS_UNKNOWN_ERROR;

	if (tb[DBG_WIFI_CHAN_SWITCH_COUNT])
		count = blobmsg_get_u32(tb[DBG_WIFI_CHAN_SWITCH_COUNT]);

	ifname = blobmsg_get_string(tb[DBG_WIFI_AP_STATUS_IFNAME]);
	channel = blobmsg_get_u32(tb[DBG_WIFI_CHAN_SWITCH_CHAN]);
	bw = blobmsg_get_u32(tb[DBG_WIFI_CHAN_SWITCH_BW]);

	param.freq = c2f(channel);
	param.bandwidth = bw;
	param.count = count;

	return wifi_chan_switch(ifname, &param);
}

enum {
	DBG_WIFI_AP_ASSOCLIST_IFNAME,
	_DBG_WIFI_AP_ASSOCLIST_MAX
};

static const struct blobmsg_policy dbg_wifi_ap_assoclist_params[_DBG_WIFI_AP_ASSOCLIST_MAX] = {
	[DBG_WIFI_AP_ASSOCLIST_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
};

static int dbg_wifi_ap_assoclist(struct ubus_context *ctx, struct ubus_object *obj,
				 struct ubus_request_data *req, const char *method,
				 struct blob_attr *msg)
{
	struct blob_buf bb = {};
	struct blob_attr *tb[_DBG_WIFI_AP_ASSOCLIST_MAX];
	uint8_t sta[128 * 6] = {};
	int num_sta = 128;
	const char *ifname;
	void *a, *t;
	int ret, i;

	blobmsg_parse(dbg_wifi_ap_assoclist_params, _DBG_WIFI_AP_ASSOCLIST_MAX, tb,
		      blob_data(msg), blob_len(msg));

	if (!tb[DBG_WIFI_AP_ASSOCLIST_IFNAME])
		return UBUS_STATUS_UNKNOWN_ERROR;

	ifname = blobmsg_get_string(tb[DBG_WIFI_AP_ASSOCLIST_IFNAME]);

	ret = wifi_get_assoclist(ifname, sta, &num_sta);
	if (ret)
		return UBUS_STATUS_UNKNOWN_ERROR;

	blob_buf_init(&bb, 0);
	a = blobmsg_open_array(&bb, "assoclist");
	for (i = 0; i < num_sta; i++) {
		char sta_macaddr[18] = {};

		hwaddr_ntoa(&sta[i * 6], sta_macaddr);
		t = blobmsg_open_table(&bb, "");
		blobmsg_add_string(&bb, "macaddr", sta_macaddr);
		blobmsg_close_table(&bb, t);
	}
	blobmsg_close_array(&bb, a);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

enum {
	DBG_WIFI_LIST_NEIGHBOR_IFNAME,
	_DBG_WIFI_LIST_NEIGHBOR_MAX
};

static const struct blobmsg_policy dbg_wifi_list_neighbor_params[_DBG_WIFI_LIST_NEIGHBOR_MAX] = {
	[DBG_WIFI_LIST_NEIGHBOR_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
};

static int dbg_wifi_list_neighbor(struct ubus_context *ctx, struct ubus_object *obj,
				 struct ubus_request_data *req, const char *method,
				 struct blob_attr *msg)
{
	struct blob_buf bb = {};
	struct blob_attr *tb[_DBG_WIFI_LIST_NEIGHBOR_MAX];
	struct nbr nbr[64] = {};
	int num_nbr = ARRAY_SIZE(nbr);
	const char *ifname;
	void *a, *t;
	int ret, i;

	blobmsg_parse(dbg_wifi_list_neighbor_params, _DBG_WIFI_LIST_NEIGHBOR_MAX, tb,
		      blob_data(msg), blob_len(msg));

	if (!tb[DBG_WIFI_LIST_NEIGHBOR_IFNAME])
		return UBUS_STATUS_UNKNOWN_ERROR;

	ifname = blobmsg_get_string(tb[DBG_WIFI_LIST_NEIGHBOR_IFNAME]);

	ret = wifi_get_neighbor_list(ifname, nbr, &num_nbr);
	if (ret)
		return UBUS_STATUS_UNKNOWN_ERROR;

	blob_buf_init(&bb, 0);
	a = blobmsg_open_array(&bb, "neighbors");
	for (i = 0; i < num_nbr; i++) {
		char bssid_str[18] = {};

		hwaddr_ntoa(nbr[i].bssid, bssid_str);
		t = blobmsg_open_table(&bb, "");
		blobmsg_add_string(&bb, "bssid", bssid_str);
		blobmsg_add_u32(&bb, "bssid_info", nbr[i].bssid_info);
		blobmsg_add_u32(&bb, "regulatory", nbr[i].reg);
		blobmsg_add_u32(&bb, "channel", nbr[i].channel);
		blobmsg_add_u32(&bb, "phy", nbr[i].phy);
		blobmsg_close_table(&bb, t);
	}
	blobmsg_close_array(&bb, a);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

enum {
	DBG_WIFI_GET_STATION_IFNAME,
	DBG_WIFI_GET_STATION_ADDR,
	_DBG_WIFI_GET_STATION_MAX
};

static const struct blobmsg_policy dbg_wifi_get_station_params[_DBG_WIFI_GET_STATION_MAX] = {
	[DBG_WIFI_GET_STATION_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[DBG_WIFI_GET_STATION_ADDR] = { .name = "sta", .type = BLOBMSG_TYPE_STRING },
};

static int dbg_wifi_get_station(struct ubus_context *ctx, struct ubus_object *obj,
				struct ubus_request_data *req, const char *method,
				struct blob_attr *msg)
{
	struct blob_buf bb = {};
	struct blob_attr *tb[_DBG_WIFI_GET_STATION_MAX];
	struct wifi_sta stas[64] = {};
	int num_stas = ARRAY_SIZE(stas);
	const char *ifname;
	const char *sta_str = NULL;
	uint8_t sta[6];
	void *a, *t, *aa;
	int ret, i, j;

	blobmsg_parse(dbg_wifi_get_station_params, _DBG_WIFI_GET_STATION_MAX, tb,
		      blob_data(msg), blob_len(msg));

	if (!tb[DBG_WIFI_GET_STATION_IFNAME])
		return UBUS_STATUS_UNKNOWN_ERROR;

	ifname = blobmsg_get_string(tb[DBG_WIFI_GET_STATION_IFNAME]);

	if (tb[DBG_WIFI_GET_STATION_ADDR]) {
		sta_str = blobmsg_get_string(tb[DBG_WIFI_GET_STATION_ADDR]);
		hwaddr_aton(sta_str, sta);
	}

	ret = wifi_get_stations(ifname, stas, &num_stas);
	if (ret)
		return UBUS_STATUS_UNKNOWN_ERROR;

	blob_buf_init(&bb, 0);
	a = blobmsg_open_array(&bb, "stations");
	for (i = 0; i < num_stas; i++) {
		char mac_str[18] = {};

		hwaddr_ntoa(stas[i].macaddr, mac_str);
		t = blobmsg_open_table(&bb, "");
		blobmsg_add_string(&bb, "macaddr", mac_str);
		aa = blobmsg_open_array(&bb, "rssi_per_antenna");
		for (j = 0; j < ARRAY_SIZE(stas[i].rssi); j++)
			blobmsg_add_u32(&bb, "", stas[i].rssi[j]);
		blobmsg_close_array(&bb, aa);
		blobmsg_close_table(&bb, t);
	}
	blobmsg_close_array(&bb, a);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

enum {
	DBG_WIFI_BSTA_STATUS_IFNAME,
	_DBG_WIFI_BSTA_STATUS_MAX
};

static const struct blobmsg_policy dbg_wifi_bsta_status_params[_DBG_WIFI_BSTA_STATUS_MAX] = {
	[DBG_WIFI_BSTA_STATUS_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
};
static int dbg_wifi_bsta_status(struct ubus_context *ctx, struct ubus_object *obj,
				struct ubus_request_data *req, const char *method,
				struct blob_attr *msg)
{
	struct blob_attr *tb[_DBG_WIFI_BSTA_STATUS_MAX];
	struct wifi_bsta_status bsta_status = {};
	char bssidstr[18] = {};
	char macaddrstr[18] = {};
	struct blob_buf bb = {};
	const char *ifname;
	int ret;

	blobmsg_parse(dbg_wifi_bsta_status_params, _DBG_WIFI_BSTA_STATUS_MAX, tb,
		      blob_data(msg), blob_len(msg));

	if (!tb[DBG_WIFI_BSTA_STATUS_IFNAME])
		return UBUS_STATUS_UNKNOWN_ERROR;

	ifname = blobmsg_get_string(tb[DBG_WIFI_BSTA_STATUS_IFNAME]);

	ret = wifi_bsta_status(ifname, &bsta_status);
	if (ret)
		return UBUS_STATUS_UNKNOWN_ERROR;

	blob_buf_init(&bb, 0);
	hwaddr_ntoa(bsta_status.sta.bssid, bssidstr);
	hwaddr_ntoa(bsta_status.sta.macaddr, macaddrstr);
	blobmsg_add_string(&bb, "ssid", (char *) bsta_status.ssid);
	blobmsg_add_string(&bb, "bssid", bssidstr);
	blobmsg_add_string(&bb, "macaddr", bssidstr);
	blobmsg_add_u32(&bb, "channel", bsta_status.channel);
	blobmsg_add_u32(&bb, "bandwidth", wifi_bw_to_bw(bsta_status.bandwidth));
	blobmsg_add_u32(&bb, "frequency", bsta_status.frequency);
	blobmsg_add_u8(&bb, "4addr", bsta_status.mode4addr);

        ubus_send_reply(ctx, req, bb.head);
        blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

int agent_publish_dbg_object(struct agent *a, const char *objname)
{
	struct ubus_method m[] = {
		UBUS_METHOD("pref_channels", pref_channels, pref_channels_params),
		UBUS_METHOD("wifi_ap_info", dbg_wifi_ap_status, dbg_wifi_ap_status_params),
		UBUS_METHOD("wifi_radio_scanresults", dbg_wifi_radio_scanresults, dbg_wifi_radio_scanresults_params),
		UBUS_METHOD("scancache_dump", dbg_scancache_dump, dbg_scan_cache_dump_params),
		UBUS_METHOD("wifi_chan_switch", dbg_wifi_chan_switch, dbg_wifi_chan_switch_params),
		UBUS_METHOD("wifi_ap_assoclist", dbg_wifi_ap_assoclist, dbg_wifi_ap_assoclist_params),
		UBUS_METHOD("wifi_list_neighbor", dbg_wifi_list_neighbor, dbg_wifi_list_neighbor_params),
		UBUS_METHOD("wifi_get_station", dbg_wifi_get_station, dbg_wifi_get_station_params),
		UBUS_METHOD("wifi_bsta_info", dbg_wifi_bsta_status, dbg_wifi_bsta_status_params),
		UBUS_METHOD_NOARG("opclass", opclass_dump),
	};
	int num_methods = ARRAY_SIZE(m);
	struct ubus_object_type *obj_type;
	struct ubus_method *obj_methods;
	struct ubus_object *obj;
	int ret;


	obj = &a->obj_dbg;
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

void agent_remove_dbg_object(struct agent *a)
{
	if (a->ubus_ctx && a->obj_dbg.id != OBJECT_INVALID) {
		ubus_remove_object(a->ubus_ctx, &a->obj_dbg);
		free(a->obj_dbg.type);
		free((void *) a->obj_dbg.methods);
	}
}
#else
int agent_publish_dbg_object(struct agent *a, const char *objname)
{
	return 0;
}

void agent_remove_dbg_object(struct agent *a)
{
	return;
}
#endif
