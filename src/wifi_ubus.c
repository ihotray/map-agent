/*
 * wifi_ubus.c - wifimngr ubus interface
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

#include <easy/easy.h>
#include "wifi.h"
#include <map_module.h>
#include <easymesh.h>

#include "utils/utils.h"
#include "utils/debug.h"

int wifi_ubus_scan(struct ubus_context *ubus_ctx, const char *radio,
		   struct scan_param_ex *param,
		   int num_opclass, uint8_t *opclass,
		   int num_channel, uint8_t *channel)
{
	struct blob_buf bb = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s] %s num_ssid %d num_freq %d num_opclass %d num_channel %d\n",
		  radio, __func__,
		  param->num_ssid, param->num_freq,
		  num_opclass, num_channel);

	for (id = 0; id < num_opclass; id++)
		trace("\topclass: %d\n", opclass[id]);

	/* Get id from radio name */
	snprintf(name, sizeof(name), "wifi.radio.%s", radio);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);

	/* TODO add/check param->bssid */

	/* array of ssids */
	if (param->num_ssid) {
		void *a;
		int i;

		a = blobmsg_open_array(&bb, "ssid");
		for (i = 0; i < param->num_ssid; i++) {
			if (strlen(param->ssid[i])) {
				trace("[%s] %s add ssid %s\n", radio, __func__,
					  param->ssid[i]);
				blobmsg_add_string(&bb, "", param->ssid[i]);
			}
		}
		blobmsg_close_array(&bb, a);
	}

	/* array of opclasses */
	if (num_opclass) {
		void *a;
		int i;

		a = blobmsg_open_array(&bb, "opclass");
		for (i = 0; i < num_opclass; i++)
			blobmsg_add_u32(&bb, NULL, opclass[i]);
		blobmsg_close_array(&bb, a);
	}

	/* array of channels */
	if (num_channel) {
		void *a;
		int i;

		a = blobmsg_open_array(&bb, "channel");
		for (i = 0; i < num_channel; i++)
			blobmsg_add_u32(&bb, NULL, channel[i]);
		blobmsg_close_array(&bb, a);
	}

	ret = ubus_invoke(ubus_ctx, id, "scan_ex", bb.head, NULL, NULL, 30 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", radio, __func__, ret);
	return ret;
}

int wifi_ubus_ap_set_state(struct ubus_context *ubus_ctx, const char *ifname, bool up)
{
	struct blob_buf bb = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s] %s %s", ifname, __func__, up ? "up" : "down");

	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
        ret = ubus_lookup_id(ubus_ctx, name, &id);
        if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	ret = ubus_invoke(ubus_ctx, id, up ? "up" : "down",
			  bb.head, NULL, NULL, 20 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;
}

int wifi_ubus_start_cac(struct ubus_context *ubus_ctx, const char *radio, int channel,
			enum wifi_bw bw, enum wifi_cac_method method)
{
	struct blob_buf bb = {};
	int bandwidth;
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s] %s %d/%d method %d\n", radio, __func__,
	      channel, bw, method);

	switch (bw) {
	case BW20:
		bandwidth = 20;
		break;
	case BW40:
		bandwidth = 40;
		break;
	case BW80:
		bandwidth = 80;
		break;
	case BW160:
		bandwidth = 160;
		break;
	default:
		bandwidth = 20;
		break;
	}

	/* Get id from radio name */
	snprintf(name, sizeof(name), "wifi.radio.%s", radio);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	/* Setup required params */
	blob_buf_init(&bb, 0);
	blobmsg_add_u32(&bb, "channel", channel);
	blobmsg_add_u32(&bb, "bandwidth", bandwidth);
	blobmsg_add_u32(&bb, "method", method);

	ret = ubus_invoke(ubus_ctx, id, "start_cac", bb.head, NULL, NULL, 30 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", radio, __func__, ret);
	return ret;
}

int wifi_ubus_stop_cac(struct ubus_context *ubus_ctx, const char *radio)
{
	struct blob_buf bb = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s] %s\n", radio, __func__);

	/* Get id from radio name */
	snprintf(name, sizeof(name), "wifi.radio.%s", radio);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	ret = ubus_invoke(ubus_ctx, id, "stop_cac", bb.head, NULL, NULL, 30 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", radio, __func__, ret);
	return ret;
}

int wifi_ubus_del_neighbor(struct ubus_context *ubus_ctx, const char *ifname, uint8_t *bssid)
{
	struct blob_buf bb = {};
	char bssidstr[18] = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	hwaddr_ntoa(bssid, bssidstr);
	trace("[%s] %s %s\n", ifname, __func__, bssidstr);

	/* Get id from ap name */
	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, "bssid", bssidstr);
	ret = ubus_invoke(ubus_ctx, id, "del_neighbor", bb.head,
			  NULL, NULL, 20 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;
}

int wifi_ubus_add_neighbor(struct ubus_context *ubus_ctx, const char *ifname,
			   struct nbr *nbr)
{
	struct blob_buf bb = {};
	char bssidstr[18] = {};
	char bssid_infostr[12] = {};
	char name[256] = {};
	uint32_t id;
	int ret = 0;

	hwaddr_ntoa(nbr->bssid, bssidstr);
	snprintf(bssid_infostr, sizeof(bssid_infostr), "%u", nbr->bssid_info);

	trace("[%s]: %s %s channel %d bssidinfo %s\n",
	      ifname, __func__, bssidstr, nbr->channel, bssid_infostr);

	/* Get id from ap name */
	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, "bssid", bssidstr);
	blobmsg_add_u32(&bb, "channel", nbr->channel);
	blobmsg_add_string(&bb, "bssid_info", bssid_infostr);
	blobmsg_add_u32(&bb, "reg", nbr->reg);
	blobmsg_add_u32(&bb, "phy", nbr->phy);
	ret = ubus_invoke(ubus_ctx, id, "add_neighbor", bb.head,
			  NULL, NULL, 20 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;
}

struct list_neighbor_ctx {
	struct nbr *nbr;
	int num;
	int max;
	int status;
};

static void wifi_ubus_list_neighbor_cb(struct ubus_request *req,
				       int type,
				       struct blob_attr *msg)
{
	struct list_neighbor_ctx *ctx = req->priv;
        static const struct blobmsg_policy list_neighbor_policy[] = {
                [0] = { .name = "neighbors", .type = BLOBMSG_TYPE_ARRAY },
	};
	struct blob_attr *tb[ARRAY_SIZE(list_neighbor_policy)];
	struct blob_attr *cur;
	struct nbr *nbr;
	int num, rem;

	ctx->num = 0;
	num = 0;

	blobmsg_parse(list_neighbor_policy, ARRAY_SIZE(list_neighbor_policy),
		      tb, blob_data(msg), blob_len(msg));

	if (!tb[0]) {
		ctx->status = -1;
		return;
	}

	blobmsg_for_each_attr(cur, tb[0], rem) {
		static const struct blobmsg_policy neighbor_policy[] = {
			[0] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING },
			[1] = { .name = "bss_info", .type = BLOBMSG_TYPE_INT32 },
			[2] = { .name = "regulatory", .type = BLOBMSG_TYPE_INT32 },
			[3] = { .name = "channel", .type = BLOBMSG_TYPE_INT32 },
			[4] = { .name = "phy", .type = BLOBMSG_TYPE_INT32 },
		};
		struct blob_attr *neighbor_tb[ARRAY_SIZE(neighbor_policy)];

		if (WARN_ON(num >= ctx->max))
			break;

		blobmsg_parse(neighbor_policy, ARRAY_SIZE(neighbor_policy), neighbor_tb,
			      blobmsg_data(cur), blobmsg_data_len(cur));

		if (!neighbor_tb[0] || !neighbor_tb[1] || !neighbor_tb[2] || !neighbor_tb[3] || !neighbor_tb[4])
			continue;

		nbr = &ctx->nbr[num];

		hwaddr_aton(blobmsg_get_string(neighbor_tb[0]), nbr->bssid);
		nbr->bssid_info = blobmsg_get_u32(neighbor_tb[1]);
		nbr->reg = blobmsg_get_u32(neighbor_tb[2]);
		nbr->channel = blobmsg_get_u32(neighbor_tb[3]);
		nbr->phy = blobmsg_get_u32(neighbor_tb[4]);

		num++;
	}

	ctx->status = 0;
	ctx->num = num;
}

int wifi_ubus_list_neighbor(struct ubus_context *ubus_ctx, const char *ifname,
			    struct nbr *nbr, int *nbr_num)
{
	struct blob_buf bb = {};
	struct list_neighbor_ctx ctx = {
		.nbr = nbr,
		.max = *nbr_num,
		.num = 0,
		.status = -1,
	};
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s]: %s\n", ifname, __func__);

	/* Get id from ap name */
	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	ret = ubus_invoke(ubus_ctx, id, "list_neighbor", bb.head,
			  wifi_ubus_list_neighbor_cb, &ctx, 20 * 1000);
	blob_buf_free(&bb);

	if (ctx.status)
		ret = ctx.status;

	*nbr_num = ctx.num;
out:
	trace("[%s]: %s ret %d num %d\n", ifname, __func__, ret, *nbr_num);
	return ret;
}

int wifi_ubus_monitor_add_del(struct ubus_context *ubus_ctx, const char *ifname,
			      uint8_t *macaddr, bool add)
{
	struct blob_buf bb = {};
	char macaddrstr[18] = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	hwaddr_ntoa(macaddr, macaddrstr);
	trace("[%s] %s %s %s\n", ifname, __func__, macaddrstr, add ? "add" : "del");

	/* Get id from ap name */
	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, "sta", macaddrstr);
	ret = ubus_invoke(ubus_ctx, id, add ? "monitor_add" : "monitor_del",
			  bb.head, NULL, NULL, 20 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;
}

int wifi_ubus_monitor_add(struct ubus_context *ubus_ctx, const char *ifname, uint8_t *macaddr)
{
	return wifi_ubus_monitor_add_del(ubus_ctx, ifname, macaddr, true);
}

int wifi_ubus_monitor_del(struct ubus_context *ubus_ctx, const char *ifname, uint8_t *macaddr)
{
	return wifi_ubus_monitor_add_del(ubus_ctx, ifname, macaddr, false);
}

struct monitor_get_ctx {
	struct wifi_monsta *monsta;
	int status;
};

static void wifi_ubus_monitor_get_cb(struct ubus_request *req,
				     int type,
				     struct blob_attr *msg)
{
	struct monitor_get_ctx *ctx = req->priv;
        static const struct blobmsg_policy monitor_get_policy[] = {
                [0] = { .name = "sta", .type = BLOBMSG_TYPE_TABLE },
	};
	struct blob_attr *tb[ARRAY_SIZE(monitor_get_policy)];
	static const struct blobmsg_policy attr_policy[] = {
		[0] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "seen", .type = BLOBMSG_TYPE_INT32 },
		[2] = { .name = "rssi_avg", .type = BLOBMSG_TYPE_INT32 },
		[3] = { .name = "rssi", .type = BLOBMSG_TYPE_ARRAY },
	};
	struct blob_attr *attr_data[ARRAY_SIZE(attr_policy)];
	static struct blobmsg_policy rssi_policy[] = {
		{ .type = BLOBMSG_TYPE_INT32 },
		{ .type = BLOBMSG_TYPE_INT32 },
		{ .type = BLOBMSG_TYPE_INT32 },
		{ .type = BLOBMSG_TYPE_INT32 },
	};
	struct blob_attr *rssi[ARRAY_SIZE(rssi_policy)];
	struct wifi_monsta *monsta;

	blobmsg_parse(monitor_get_policy, ARRAY_SIZE(monitor_get_policy),
		      tb, blob_data(msg), blob_len(msg));

	if (!tb[0]) {
		ctx->status = -1;
		return;
	}

	blobmsg_parse(attr_policy, ARRAY_SIZE(attr_policy),
		      attr_data, blobmsg_data(tb[0]), blobmsg_data_len(tb[0]));

	if (!attr_data[0] || !attr_data[1] || !attr_data[2] || !attr_data[3]) {
		ctx->status = -1;
		return;
	}

	monsta = ctx->monsta;

	hwaddr_aton(blobmsg_get_string(attr_data[0]), monsta->macaddr);
	monsta->last_seen = blobmsg_get_u32(attr_data[1]);
	monsta->rssi_avg = blobmsg_get_u32(attr_data[2]);

	blobmsg_parse_array(rssi_policy, ARRAY_SIZE(rssi_policy), rssi,
			    blobmsg_data(attr_data[3]), blobmsg_data_len(attr_data[3]));

	if (!rssi[0] || !rssi[1] || !rssi[2] || !rssi[3]) {
		ctx->status = -1;
		return;
	}

	monsta->rssi[0] = blobmsg_get_u32(rssi[0]);
	monsta->rssi[1] = blobmsg_get_u32(rssi[1]);
	monsta->rssi[2] = blobmsg_get_u32(rssi[2]);
	monsta->rssi[3] = blobmsg_get_u32(rssi[3]);

	ctx->status = 0;
}

int wifi_ubus_monitor_get(struct ubus_context *ubus_ctx, const char *ifname,
			  uint8_t *macaddr, struct wifi_monsta *monsta)
{
	struct blob_buf bb = {};
	struct monitor_get_ctx ctx = {
		.monsta = monsta,
		.status = -1,
	};
	char macaddrstr[18] = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	hwaddr_ntoa(macaddr, macaddrstr);
	trace("[%s] %s " MACFMT "\n", ifname, __func__, MAC2STR(macaddr));

	/* Get id from ap name */
	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, "sta", macaddrstr);
	ret = ubus_invoke(ubus_ctx, id, "monitor_get", bb.head,
			  wifi_ubus_monitor_get_cb, &ctx, 20 * 1000);
	blob_buf_free(&bb);

	if (ctx.status)
		ret = ctx.status;

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;

}

/* opclass preferences context */
struct opclass_preferences_ctx
{
	const char *radio;
	struct wifi_radio_opclass *opclass;
};

static uint8_t opclass_preferences_recalc_score(uint32_t score)
{
	uint8_t pref;

	/* Unknown/not supported */
	if (score == 255)
		pref = 14;
	else if (score > 100)
		pref = 14;
	else
		pref = (score * 14) / 100;

	/* preference = 0 - only when not supported by HW */
	if (!pref && score)
		pref = 1;

	return pref;
}

static enum wifi_radio_opclass_dfs opclass_preferences_get_dfs(const char *dfs_state)
{
	if (!dfs_state)
		return WIFI_RADIO_OPCLASS_CHANNEL_DFS_NONE;

	if (!strcmp(dfs_state, "usable"))
		return WIFI_RADIO_OPCLASS_CHANNEL_DFS_USABLE;
	else if (!strcmp(dfs_state, "available"))
		return WIFI_RADIO_OPCLASS_CHANNEL_DFS_AVAILABLE;
	else if (!strcmp(dfs_state, "unavailable"))
		return WIFI_RADIO_OPCLASS_CHANNEL_DFS_NOP;
	else if (!strcmp(dfs_state, "cac"))
		return WIFI_RADIO_OPCLASS_CHANNEL_DFS_CAC;

	return WIFI_RADIO_OPCLASS_CHANNEL_DFS_NONE;
}

static uint8_t opclass_preferences_get_reason(enum wifi_radio_opclass_dfs dfs)
{
	switch (dfs) {
		case (WIFI_RADIO_OPCLASS_CHANNEL_DFS_NONE):
			return CHANNEL_PREF_REASON_UNSPEC;
		case (WIFI_RADIO_OPCLASS_CHANNEL_DFS_USABLE):
			return CHANNEL_PREF_REASON_DFS_USABLE;
		case (WIFI_RADIO_OPCLASS_CHANNEL_DFS_AVAILABLE):
			return CHANNEL_PREF_REASON_DFS_AVAILABLE;
		case (WIFI_RADIO_OPCLASS_CHANNEL_DFS_NOP):
			return CHANNEL_PREF_REASON_DFS_NOP;
		case (WIFI_RADIO_OPCLASS_CHANNEL_DFS_CAC):
			return CHANNEL_PREF_REASON_DFS_USABLE;
		default:
			break;
	}

	return CHANNEL_PREF_REASON_UNSPEC;
}

static void wifi_ubus_opclass_preferences_cb(struct ubus_request *req,
					     int type,
					     struct blob_attr *msg)
{
	struct opclass_preferences_ctx *ctx = req->priv;
        static const struct blobmsg_policy pref_opclass_policy[] = {
                [0] = { .name = "pref_opclass", .type = BLOBMSG_TYPE_ARRAY },
	};
	struct blob_attr *tb[ARRAY_SIZE(pref_opclass_policy)];
	struct blob_attr *pref_opclass;
	struct blob_attr *cur;
	struct wifi_radio_opclass *opclass;
	int rem;
	int k;

	trace("[%s] %s\n", ctx->radio, __func__);

	/* Prepare result buffer */
	opclass = ctx->opclass;
	wifi_opclass_reset(opclass);

	blobmsg_parse(pref_opclass_policy, ARRAY_SIZE(pref_opclass_policy), tb, blob_data(msg), blob_len(msg));
	pref_opclass = tb[0];
	if (!pref_opclass)
		return;

	blobmsg_for_each_attr(cur, pref_opclass, rem) {
		static const struct blobmsg_policy attr_policy[] = {
			[0] = { .name = "opclass", .type = BLOBMSG_TYPE_INT32 },
			[1] = { .name = "bandwidth", .type = BLOBMSG_TYPE_INT32 },
			[2] = { .name = "txpower", .type = BLOBMSG_TYPE_INT32 },
			[3] = { .name = "channels", .type = BLOBMSG_TYPE_ARRAY },
		};
		struct blob_attr *attr_data[ARRAY_SIZE(attr_policy)];
		struct blob_attr *cur_chan;
		struct blob_attr *ctrl_chan;
		struct wifi_radio_opclass_entry entry = {};
		int rem_ctrl_chan;
		int rem_chan;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE)
			continue;

		blobmsg_parse(attr_policy, ARRAY_SIZE(attr_policy),
			      attr_data, blobmsg_data(cur), blobmsg_data_len(cur));

		if (!attr_data[0] || !attr_data[1] || !attr_data[2] || !attr_data[3])
			continue;

		trace("[%s] %s %u txpower %u bandwidth %u\n", ctx->radio, __func__, blobmsg_get_u32(attr_data[0]),
		      blobmsg_get_u32(attr_data[2]), blobmsg_get_u32(attr_data[1]));

		entry.id = (uint8_t) blobmsg_get_u32(attr_data[0]);
		entry.bandwidth = blobmsg_get_u32(attr_data[1]);;
		entry.max_txpower = (uint8_t) blobmsg_get_u32(attr_data[2]);

		blobmsg_for_each_attr(cur_chan, attr_data[3], rem_chan) {
			static const struct blobmsg_policy chan_policy[] = {
				[0] = { .name = "channel", .type = BLOBMSG_TYPE_INT32 },
				[1] = { .name = "score", .type = BLOBMSG_TYPE_INT32 },
				[2] = { .name = "dfs", .type = BLOBMSG_TYPE_INT32 },
				[3] = { .name = "dfs_state", .type = BLOBMSG_TYPE_STRING },
				[4] = { .name = "cac_time", .type = BLOBMSG_TYPE_INT32 },
				[5] = { .name = "nop_time", .type = BLOBMSG_TYPE_INT32 },
				[6] = { .name = "ctrl_channels", .type = BLOBMSG_TYPE_ARRAY },
			};
			struct blob_attr *chan_data[ARRAY_SIZE(chan_policy)];
			struct wifi_radio_opclass_channel channel = {};
			uint8_t score;

			if (blobmsg_type(cur_chan) != BLOBMSG_TYPE_TABLE)
				continue;

			blobmsg_parse(chan_policy, ARRAY_SIZE(chan_policy),
				      chan_data, blobmsg_data(cur_chan), blobmsg_data_len(cur_chan));

			if (!chan_data[0] ||  !chan_data[1] || ! chan_data[2])
				continue;

			score = opclass_preferences_recalc_score(blobmsg_get_u32(chan_data[1]));
			trace("[%s] %s chan %u score %u (%u) dfs %u dfs_state %s\n",
			      ctx->radio,
			      __func__,
			      chan_data[0] ? blobmsg_get_u32(chan_data[0]) : 0,
			      chan_data[1] ? blobmsg_get_u32(chan_data[1]) : 0,
			      score,
			      chan_data[2] ? blobmsg_get_u32(chan_data[2]) : 0,
			      chan_data[3] ? blobmsg_get_string(chan_data[3]) : "none");

			channel.channel = (uint8_t) blobmsg_get_u32(chan_data[0]);
			channel.preference = score << 4;
			channel.dfs = WIFI_RADIO_OPCLASS_CHANNEL_DFS_NONE;

			if (chan_data[3]) {
				channel.dfs = opclass_preferences_get_dfs(blobmsg_get_string(chan_data[3]));
				channel.preference |= opclass_preferences_get_reason(channel.dfs);
			}
			if (chan_data[4])
				channel.cac_time = blobmsg_get_u32(chan_data[4]);
			if (chan_data[5])
				channel.nop_time = blobmsg_get_u32(chan_data[5]);

			if (chan_data[6]) {
				k = 0;
				blobmsg_for_each_attr(ctrl_chan, chan_data[6], rem_ctrl_chan) {
					if (k >= ARRAY_SIZE(channel.ctrl_channels))
						break;
					trace("channel %d ctrl[%d]: %d\n", blobmsg_get_u32(chan_data[0]), k, blobmsg_get_u32(ctrl_chan));
					channel.ctrl_channels[k] = blobmsg_get_u32(ctrl_chan);
					k++;
				}
			}

			if (WARN_ON(wifi_opclass_add_channel(&entry, &channel)))
				break;
		}

		if (WARN_ON(wifi_opclass_add_entry(opclass, &entry)))
			break;
	}
}

int wifi_ubus_opclass_preferences(struct ubus_context *ubus_ctx, const char *radio,
				  struct wifi_radio_opclass *opclass)
{
	struct opclass_preferences_ctx ctx = {
			.radio = radio,
			.opclass = opclass,
	};
	struct blob_buf bb = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s] %s\n", radio, __func__);

	/* Get id from radio name */
	snprintf(name, sizeof(name), "wifi.radio.%s", radio);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	ret = ubus_invoke(ubus_ctx, id, "opclass_preferences", bb.head,
			  wifi_ubus_opclass_preferences_cb, &ctx,
			  20 * 1000);

	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", radio, __func__, ret);
	return ret;
}

struct radio_status_ctx {
	const char *radio;
	struct wifi_radio_status *radio_status;
	int status;
};

static void wifi_ubus_radio_status_cb(struct ubus_request *req,
				      int type,
				      struct blob_attr *msg)
{
	struct radio_status_ctx *ctx = req->priv;
        static const struct blobmsg_policy radio_status_policy[] = {
                [0] = { .name = "opclass", .type = BLOBMSG_TYPE_INT32 },
                [1] = { .name = "channel", .type = BLOBMSG_TYPE_INT32 },
                [2] = { .name = "bandwidth", .type = BLOBMSG_TYPE_INT32 },
		/* TODO add more fields if required */
	};
	struct blob_attr *tb[ARRAY_SIZE(radio_status_policy)];
	struct wifi_radio_status *status = ctx->radio_status;

	blobmsg_parse(radio_status_policy, ARRAY_SIZE(radio_status_policy),
		      tb, blob_data(msg), blob_len(msg));

	if (!tb[0] || !tb[1] || !tb[2]) {
		ctx->status = -1;
		return;
	}

	status->info.channel = blobmsg_get_u32(tb[1]);
	status->info.curr_bw = bw_to_wifi_bw(blobmsg_get_u32(tb[2]));

	status->channel = blobmsg_get_u32(tb[1]);
	status->bandwidth = blobmsg_get_u32(tb[2]);
	status->opclass = blobmsg_get_u32(tb[0]);

	ctx->status = 0;
}

int wifi_ubus_radio_status(struct ubus_context *ubus_ctx, const char *radio,
			   struct wifi_radio_status *status)
{
	struct radio_status_ctx ctx = {
		.radio = radio,
		.radio_status = status,
		.status = -1,
	};
	struct blob_buf bb = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s] %s\n", radio, __func__);

	/* Get id from radio name */
	snprintf(name, sizeof(name), "wifi.radio.%s", radio);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	ret = ubus_invoke(ubus_ctx, id, "status", bb.head,
			  wifi_ubus_radio_status_cb, &ctx,
			  20 * 1000);
	blob_buf_free(&bb);

	if (ctx.status)
		ret = ctx.status;

out:
	trace("[%s] %s ret %d ctx status %d\n", radio, __func__, ret, ctx.status);
	return ret;
}

int wifi_ubus_disconnect_sta(struct ubus_context *ubus_ctx, const char *ifname,
			     uint8_t *macaddr, uint16_t reason)
{
	struct blob_buf bb = {};
	char name[256] = {};
	char macstr[18] = {};
	uint32_t id;
	int ret;

	snprintf(macstr, sizeof(macstr), MACFMT, MAC2STR(macaddr));
	trace("[%s] %s " MACFMT "\n", ifname, __func__, MAC2STR(macaddr));

	/* Get id from ap name */
	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	/* Setup required params */
	blobmsg_add_string(&bb, "sta", macstr);
	blobmsg_add_u32(&bb, "reason", reason);

	ret = ubus_invoke(ubus_ctx, id, "disconnect", bb.head, NULL, NULL, 10 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;
}

int wifi_ubus_restrict_sta(struct ubus_context *ubus_ctx, const char *ifname,
			   uint8_t *macaddr, int enable)
{
	struct blob_buf bb = {};
	char name[256] = {};
	char macstr[18] = {};
	uint32_t id;
	int ret;
	void *t;

	snprintf(macstr, sizeof(macstr), MACFMT, MAC2STR(macaddr));
	trace("[%s] restrict sta " MACFMT " %s\n",
		  ifname, MAC2STR(macaddr), enable ? "enable" : "disable");

	/* Get id from ap name */
	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	/* Setup required params */
	blob_buf_init(&bb, 0);
	t = blobmsg_open_array(&bb, "client");
	blobmsg_add_string(&bb, "", macstr);
	blobmsg_close_array(&bb, t);
	blobmsg_add_u32(&bb, "enable", enable);

	ret = ubus_invoke(ubus_ctx, id, "assoc_control", bb.head, NULL, NULL, 10 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;
}


int wifi_ubus_req_btm(struct ubus_context *ubus_ctx, const char *ifname, uint8_t *macaddr,
		      int bsss_nr, uint8_t *bsss, struct wifi_btmreq *req)
{
	struct blob_buf bb = {};
	char name[256] = {};
	char macstr[18] = {};
	uint32_t id;
	void *a;
	int ret;
	int i;

	snprintf(macstr, sizeof(macstr), MACFMT, MAC2STR(macaddr));
	trace("[%s] %s sta %s\n", name, __func__, macstr);

	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, "client", macstr);

	a = blobmsg_open_array(&bb, "bssid");
	for (i = 0; i < bsss_nr; i++) {
		hwaddr_ntoa(&bsss[i * 6], macstr);
		blobmsg_add_string(&bb, "", macstr);
	}
	blobmsg_close_array(&bb, a);

	blobmsg_add_u32(&bb, "mode", req->mode);
	blobmsg_add_u32(&bb, "disassoc_tmo", req->disassoc_tmo);
	blobmsg_add_u32(&bb, "vlidity_int", req->validity_int);
	blobmsg_add_u32(&bb, "bssterm_dur", req->bssterm_dur);
	if (req->mbo.valid) {
		blobmsg_add_u32(&bb, "mbo_reason", req->mbo.reason);
		blobmsg_add_u32(&bb, "mbo_cell_pref", req->mbo.cell_pref);
		blobmsg_add_u32(&bb, "mbo_reassoc_delay", req->mbo.reassoc_delay);
	}

	ret = ubus_invoke(ubus_ctx, id, "request_btm", bb.head,
			  NULL, NULL, 20 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;
}

int wifi_ubus_request_transition(struct ubus_context *ubus_ctx, const char *ifname, uint8_t *macaddr,
				 uint8_t bss_num, uint8_t *bss, int validity_int)
{
	struct blob_buf bb = {};
	char name[256] = {};
	char macstr[18] = {};
	uint8_t *bssid;
	uint32_t id;
	uint8_t mode = 0;
	int ret;
	void *t;
	int i;

	snprintf(macstr, sizeof(macstr), MACFMT, MAC2STR(macaddr));
	trace("[%s] %s %s\n", ifname, __func__, macstr);

	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, "client", macstr);
	t = blobmsg_open_array(&bb, "bssid");
	for (i = 0; i < bss_num; i++) {
		bssid = &bss[i * 6];
		snprintf(macstr, sizeof(macstr), MACFMT, MAC2STR(bssid));
		blobmsg_add_string(&bb, "", macstr);
	}
	blobmsg_close_array(&bb, t);

	if (validity_int)
		blobmsg_add_u32(&bb, "validity_int", validity_int);

	/* Preferred Candidate List Included */
	mode |= WIFI_BTMREQ_PREF_INC;
	/* Inform client of imminent disassociation */
	mode |= WIFI_BTMREQ_DISASSOC_IMM;
	blobmsg_add_u32(&bb, "mode", mode);

	ret = ubus_invoke(ubus_ctx, id, "request_btm", bb.head,
			  NULL, NULL, 20 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;
}

int wifi_ubus_add_vendor_ie(struct ubus_context *ubus_ctx, const char *ifname, int mgmt,
			    char *oui, char *data)
{
	struct blob_buf bb = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s] %s\n", ifname, __func__);

	/* Get id from ap name */
	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	/* Setup required params */
	blob_buf_init(&bb, 0);
	blobmsg_add_u32(&bb, "mgmt", mgmt);
	blobmsg_add_string(&bb, "oui", oui);
	blobmsg_add_string(&bb, "data", data);

	ret = ubus_invoke(ubus_ctx, id, "add_vendor_ie", bb.head, NULL, NULL, 10 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;
}

int wifi_ubus_del_vendor_ie(struct ubus_context *ubus_ctx, const char *ifname, int mgmt,
			    char *oui, char *data)
{
	struct blob_buf bb = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s] %s\n", ifname, __func__);

	/* Get id from ap name */
	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	/* Setup required params */
	blob_buf_init(&bb, 0);
	blobmsg_add_u32(&bb, "mgmt", mgmt);
	blobmsg_add_string(&bb, "oui", oui);
	if (data)
		blobmsg_add_string(&bb, "data", data);

	ret = ubus_invoke(ubus_ctx, id, "del_vendor_ie", bb.head, NULL, NULL, 10 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;
}

struct sta_4addr_ctx {
	bool enable;
	int status;
};

static void wifi_ubus_get_4addr_cb(struct ubus_request *req,
				   int type,
				   struct blob_attr *msg)
{
	struct sta_4addr_ctx *ctx = req->priv;
        static const struct blobmsg_policy sta_4addr_policy[] = {
                [0] = { .name = "enable", .type = BLOBMSG_TYPE_BOOL },
	};
	struct blob_attr *tb[ARRAY_SIZE(sta_4addr_policy)];

	blobmsg_parse(sta_4addr_policy, ARRAY_SIZE(sta_4addr_policy),
		      tb, blob_data(msg), blob_len(msg));

	if (!tb[0]) {
		ctx->status = -1;
		return;
	}

	ctx->enable = blobmsg_get_bool(tb[0]);
	ctx->status = 0;
}

int wifi_ubus_get_4addr(struct ubus_context *ubus_ctx, const char *ifname, bool *enable)
{
	struct blob_buf bb = {};
	char name[256] = {};
	uint32_t id;
	struct sta_4addr_ctx ctx = {};
	int ret;

	trace("[%s] %s\n", ifname, __func__);

	/* Get id from backhaul name */
	snprintf(name, sizeof(name), "wifi.backhaul.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	ret = ubus_invoke(ubus_ctx, id, "4addr", bb.head,
			  wifi_ubus_get_4addr_cb, &ctx, 10 * 1000);
	blob_buf_free(&bb);

	if (ret || ctx.status)
		goto out;

	*enable = ctx.enable;

out:
	trace("[%s] %s ret %d enable %d\n", ifname, __func__, ret, *enable);
	return ret;
}

int wifi_ubus_set_4addr(struct ubus_context *ubus_ctx, const char *ifname, bool enable)
{
	struct blob_buf bb = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s] %s %d\n", ifname, __func__, enable);

	/* Get id from backhaul name */
	snprintf(name, sizeof(name), "wifi.backhaul.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	blobmsg_add_u32(&bb, "enable", enable);

	ret = ubus_invoke(ubus_ctx, id, "4addr", bb.head, NULL, NULL, 10 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;
}

struct ap_status_ctx {
	const char *ifname;
	struct wifi_ap_status *ap_status;
	int status;
};

static void parse_dot11n(struct blob_attr *arg, struct wifi_caps_element *caps)
{
	int supp_mcs = 0;
	struct blob_attr *tb[4];
	static const struct blobmsg_policy ap_attr[4] = {
		[0] = { .name = "dot11n_sgi20", .type = BLOBMSG_TYPE_BOOL },
		[1] = { .name = "dot11n_sgi40", .type = BLOBMSG_TYPE_BOOL },
		[2] = { .name = "dot11n_40", .type = BLOBMSG_TYPE_BOOL },
		[3] = { .name = "dot11n_supp_max_mcs", .type = BLOBMSG_TYPE_INT32 }
	};

	blobmsg_parse(ap_attr, 4, tb, blobmsg_data(arg), blobmsg_data_len(arg));

	// TODO: cleaner way?
	supp_mcs = blobmsg_get_u32(tb[3]);
	supp_mcs = supp_mcs/8;
	caps->ht |= (supp_mcs & 0x3) << 6;
	caps->ht |= (supp_mcs & 0x3) << 4;
	caps->ht |= ((blobmsg_get_bool(tb[0]) ? 1 : 0) << 3);
	caps->ht |= ((blobmsg_get_bool(tb[1]) ? 1 : 0) << 2);
	caps->ht |= ((blobmsg_get_bool(tb[2]) ? 1 : 0) << 1);
}

#define VHT_CAP_MAX_MCS	8
static void parse_dot11ac_mcs(uint8_t *supp_mcs, int mcs, int nss)
{
	int i;
	int octel;
	int shift;
	const uint8_t mask[4] = {0xfc, 0xf3, 0xcf, 0x3f};
	int nss_cnt = min(nss, VHT_CAP_MAX_MCS);

	for (i = 0; i < nss_cnt; i++) {
		octel = (2 * i) / 8;
		shift = (2 * i) % 8;

		if (mcs == 9)
			supp_mcs[octel] &= (mask[i%4] | (0x02 << shift));
		else if (mcs == 8)
			supp_mcs[octel] &= (mask[i%4] | (0x01 << shift));
		else if (mcs == 7)
			supp_mcs[octel] &= (mask[i%4] | (0x00 << shift));
	}
}

static void parse_dot11ac(struct blob_attr *arg, struct wifi_caps_element *caps)
{
	int tx_mcs = 0, tx_nss = 0;
	int rx_mcs = 0, rx_nss = 0;
	uint8_t tx_supp_mcs[2] = {0xff, 0xff};
	uint8_t rx_supp_mcs[2] = {0xff, 0xff};
	static const struct blobmsg_policy attr[] = {
		[0] = { .name = "dot11ac_sgi80", .type = BLOBMSG_TYPE_BOOL },
		[1] = { .name = "dot11ac_sgi160", .type = BLOBMSG_TYPE_BOOL },
		[2] = { .name = "dot11ac_8080", .type = BLOBMSG_TYPE_BOOL },
		[3] = { .name = "dot11ac_160", .type = BLOBMSG_TYPE_BOOL },
		[4] = { .name = "dot11ac_su_beamformer", .type = BLOBMSG_TYPE_BOOL },
		[5] = { .name = "dot11ac_mu_beamformer", .type = BLOBMSG_TYPE_BOOL },
		[6] = { .name = "dot11ac_supp_max_rx_mcs", .type = BLOBMSG_TYPE_INT32 },
		[7] = { .name = "dot11ac_supp_max_rx_nss", .type = BLOBMSG_TYPE_INT32 },
		[8] = { .name = "dot11ac_supp_max_tx_mcs", .type = BLOBMSG_TYPE_INT32 },
		[9] = { .name = "dot11ac_supp_max_tx_nss", .type = BLOBMSG_TYPE_INT32 },
	};
	struct blob_attr *tb[ARRAY_SIZE(attr)];

	blobmsg_parse(attr, ARRAY_SIZE(attr), tb, blobmsg_data(arg), blobmsg_data_len(arg));

	rx_mcs = blobmsg_get_u32(tb[6]);
	rx_nss = blobmsg_get_u32(tb[7]);
	tx_mcs = blobmsg_get_u32(tb[8]);
	tx_nss = blobmsg_get_u32(tb[9]);
	caps->vht[4] |= ((blobmsg_get_bool(tb[0]) ? 1 : 0) << 1);
	caps->vht[4] |= ((blobmsg_get_bool(tb[1]) ? 1 : 0) << 0);
	caps->vht[5] |= ((blobmsg_get_bool(tb[2]) ? 1 : 0) << 7);
	caps->vht[5] |= ((blobmsg_get_bool(tb[3]) ? 1 : 0) << 6);
	caps->vht[5] |= ((blobmsg_get_bool(tb[4]) ? 1 : 0) << 5);
	caps->vht[5] |= ((blobmsg_get_bool(tb[5]) ? 1 : 0) << 4);

	caps->vht[4] |= ((tx_nss - 1) & 0x07) << 5;
	caps->vht[4] |= ((rx_nss - 1) & 0x07) << 2;

	parse_dot11ac_mcs(tx_supp_mcs, tx_mcs, tx_nss);
	memcpy(&caps->vht[0], tx_supp_mcs, 2);
	parse_dot11ac_mcs(rx_supp_mcs, rx_mcs, rx_nss);
	memcpy(&caps->vht[2], rx_supp_mcs, 2);
}

#define HE_CAP_MAX_MCS	8
static void parse_dot11ax_mcs(uint8_t *he, int *he_mcs_len, int mcs,
			int nss, int *max_nss)
{
	int i;
	int octel;
	int shift;
	int offset = 1 + *he_mcs_len;
	uint8_t supp_mcs[2] = {0xff, 0xff};
	const uint8_t mask[4] = {0xfc, 0xf3, 0xcf, 0x3f};
	int nss_cnt = min(nss, HE_CAP_MAX_MCS);

	for (i = 0; i < nss_cnt; i++) {
		octel = (2 * i) / 8;
		shift = (2 * i) % 8;

		if (mcs == 11)
			supp_mcs[octel] &= (mask[i%4] | (0x02 << shift));
		else if (mcs == 9)
			supp_mcs[octel] &= (mask[i%4] | (0x01 << shift));
		else if (mcs == 7)
			supp_mcs[octel] &= (mask[i%4] | (0x00 << shift));
	}

	memcpy(he + offset, supp_mcs, 2);
	*he_mcs_len += 2;
	*max_nss = max(*max_nss, nss);
}

static void parse_dot11ax(struct blob_attr *arg, struct wifi_caps_element *caps)
{
	int max_rx_nss = 0;
	int max_tx_nss = 0;
	int mcs_len = 0;
	int offset = 0;
	static const struct blobmsg_policy attr[26] = {
		[0] = { .name = "dot11ax_5g_160_and_8080", .type = BLOBMSG_TYPE_BOOL },
		[1] = { .name = "dot11ax_5g_160", .type = BLOBMSG_TYPE_BOOL },
		[2] = { .name = "dot11ax_su_beamformer", .type = BLOBMSG_TYPE_BOOL },
		[3] = { .name = "dot11ax_mu_beamformer", .type = BLOBMSG_TYPE_BOOL },
		[4] = { .name = "dot11ax_ul_mumimo_full", .type = BLOBMSG_TYPE_BOOL },
		[5] = { .name = "dot11ax_ofdma_ra", .type = BLOBMSG_TYPE_BOOL },
		[6] = { .name = "dot11ax_supp_max_rx_mcs_20", .type = BLOBMSG_TYPE_INT32 },
		[7] = { .name = "dot11ax_supp_max_rx_nss_20", .type = BLOBMSG_TYPE_INT32 },
		[8] = { .name = "dot11ax_supp_max_tx_mcs_20", .type = BLOBMSG_TYPE_INT32 },
		[9] = { .name = "dot11ax_supp_max_tx_nss_20", .type = BLOBMSG_TYPE_INT32 },
		[10] = { .name = "dot11ax_supp_max_rx_nss_40", .type = BLOBMSG_TYPE_INT32 },
		[11] = { .name = "dot11ax_supp_max_rx_mcs_40", .type = BLOBMSG_TYPE_INT32 },
		[12] = { .name = "dot11ax_supp_max_tx_mcs_40", .type = BLOBMSG_TYPE_INT32 },
		[13] = { .name = "dot11ax_supp_max_tx_nss_40", .type = BLOBMSG_TYPE_INT32 },
		[14] = { .name = "dot11ax_supp_max_rx_mcs_80", .type = BLOBMSG_TYPE_INT32 },
		[15] = { .name = "dot11ax_supp_max_rx_nss_80", .type = BLOBMSG_TYPE_INT32 },
		[16] = { .name = "dot11ax_supp_max_tx_mcs_80", .type = BLOBMSG_TYPE_INT32 },
		[17] = { .name = "dot11ax_supp_max_tx_nss_80", .type = BLOBMSG_TYPE_INT32 },
		[18] = { .name = "dot11ax_supp_max_rx_mcs_160", .type = BLOBMSG_TYPE_INT32 },
		[19] = { .name = "dot11ax_supp_max_rx_nss_160", .type = BLOBMSG_TYPE_INT32 },
		[20] = { .name = "dot11ax_supp_max_tx_nss_160", .type = BLOBMSG_TYPE_INT32 },
		[21] = { .name = "dot11ax_supp_max_tx_mcs_160", .type = BLOBMSG_TYPE_INT32 },
		[22] = { .name = "dot11ax_supp_max_rx_mcs_8080", .type = BLOBMSG_TYPE_INT32 },
		[23] = { .name = "dot11ax_supp_max_rx_nss_8080", .type = BLOBMSG_TYPE_INT32 },
		[24] = { .name = "dot11ax_supp_max_tx_mcs_8080", .type = BLOBMSG_TYPE_INT32 },
		[25] = { .name = "dot11ax_supp_max_tx_nss_8080", .type = BLOBMSG_TYPE_INT32 },
	};
	struct blob_attr *tb[ARRAY_SIZE(attr)];

	blobmsg_parse(attr, ARRAY_SIZE(attr), tb, blobmsg_data(arg), blobmsg_data_len(arg));

	if (tb[6])
		parse_dot11ax_mcs(caps->he, &mcs_len,
				blobmsg_get_u32(tb[6]),
				blobmsg_get_u32(tb[7]), &max_rx_nss);
	else if (tb[11])
		parse_dot11ax_mcs(caps->he, &mcs_len,
				blobmsg_get_u32(tb[11]),
				blobmsg_get_u32(tb[10]), &max_rx_nss);
	else if (tb[14])
		parse_dot11ax_mcs(caps->he, &mcs_len,
				blobmsg_get_u32(tb[14]),
				blobmsg_get_u32(tb[15]), &max_rx_nss);

	if (tb[8])
		parse_dot11ax_mcs(caps->he, &mcs_len,
				blobmsg_get_u32(tb[8]),
				blobmsg_get_u32(tb[9]), &max_tx_nss);
	else if (tb[12])
		parse_dot11ax_mcs(caps->he, &mcs_len,
				blobmsg_get_u32(tb[12]),
				blobmsg_get_u32(tb[13]), &max_tx_nss);
	else if (tb[16])
		parse_dot11ax_mcs(caps->he, &mcs_len,
				blobmsg_get_u32(tb[16]),
				blobmsg_get_u32(tb[17]), &max_tx_nss);

	if (tb[18])
		parse_dot11ax_mcs(caps->he, &mcs_len,
				blobmsg_get_u32(tb[18]),
				blobmsg_get_u32(tb[19]), &max_rx_nss);

	if (tb[21])
		parse_dot11ax_mcs(caps->he, &mcs_len,
				blobmsg_get_u32(tb[21]),
				blobmsg_get_u32(tb[20]), &max_tx_nss);

	if (tb[22])
		parse_dot11ax_mcs(caps->he, &mcs_len,
				blobmsg_get_u32(tb[22]),
				blobmsg_get_u32(tb[24]), &max_rx_nss);

	if (tb[24])
		parse_dot11ax_mcs(caps->he, &mcs_len,
				blobmsg_get_u32(tb[24]),
				blobmsg_get_u32(tb[25]), &max_tx_nss);

	caps->he[0] = mcs_len;
	offset = 1 + mcs_len;
	caps->he[offset] |= (((max_tx_nss - 1) & 0x07) << 5);
	caps->he[offset] |= (((max_rx_nss - 1) & 0x07) << 2);
	caps->he[offset] |= ((blobmsg_get_bool(tb[0]) ? 1 : 0) << 1);
	caps->he[offset] |= ((blobmsg_get_bool(tb[1]) ? 1 : 0) << 0);

	offset++;
	caps->he[offset] |= ((blobmsg_get_bool(tb[2]) ? 1 : 0) << 7);
	caps->he[offset] |= ((blobmsg_get_bool(tb[3]) ? 1 : 0) << 6);
	caps->he[offset] |= ((blobmsg_get_bool(tb[4]) ? 1 : 0) << 5);
	caps->he[offset] |= ((blobmsg_get_bool(tb[5]) ? 1 : 0) << 4);
	caps->he[offset] |= ((blobmsg_get_bool(tb[5]) ? 1 : 0) << 3);
	caps->he[offset] |= ((blobmsg_get_bool(tb[5]) ? 1 : 0) << 2);
	caps->he[offset] |= ((blobmsg_get_bool(tb[5]) ? 1 : 0) << 1);
}

static void wifi_ubus_wifi_caps_element(struct blob_attr *msg,
					struct wifi_caps_element *caps)
{
		struct blob_attr *data[4];
		static const struct blobmsg_policy cap_attr[4] = {
			[0] = { .name = "dot11n", .type = BLOBMSG_TYPE_TABLE },
			[1] = { .name = "dot11ac", .type = BLOBMSG_TYPE_TABLE },
			[2] = { .name = "wmm", .type = BLOBMSG_TYPE_BOOL },
			[3] = { .name = "dot11ax", .type = BLOBMSG_TYPE_TABLE }
		};

		blobmsg_parse(cap_attr, 4, data, blobmsg_data(msg),
				blobmsg_data_len(msg));

		if (data[0])
			parse_dot11n(data[0], caps);
		if (data[1])
			parse_dot11ac(data[1], caps);
		if (data[2])
			caps->wmm = blobmsg_get_bool(data[2]);
		if (data[3])
			parse_dot11ax(data[3], caps);
}

static void wifi_ubus_ap_status_cb(struct ubus_request *req,
				   int type,
				   struct blob_attr *msg)
{
	struct ap_status_ctx *ctx = req->priv;
        static const struct blobmsg_policy ap_status_policy[] = {
                [0] = { .name = "channel", .type = BLOBMSG_TYPE_INT32 },
                [1] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING },
                [2] = { .name = "ssid", .type = BLOBMSG_TYPE_STRING },
                [3] = { .name = "utilization", .type = BLOBMSG_TYPE_INT32 },
                [4] = { .name = "capabilities", .type = BLOBMSG_TYPE_TABLE },
                [5] = { .name = "standard", .type = BLOBMSG_TYPE_STRING },
                [6] = { .name = "bandwidth", .type = BLOBMSG_TYPE_INT32 },
                [7] = { .name = "status", .type = BLOBMSG_TYPE_STRING },
                [8] = { .name = "num_stations", .type = BLOBMSG_TYPE_INT32 },
                [9] = { .name = "enabled", .type = BLOBMSG_TYPE_BOOL },
		[10] = { .name = "encryption", .type = BLOBMSG_TYPE_STRING },
		[11] = { .name = "hidden", .type = BLOBMSG_TYPE_INT32 },
		/* TODO add more fields if required */
	};
	struct blob_attr *tb[ARRAY_SIZE(ap_status_policy)];
	struct wifi_caps_element *caps;
	struct wifi_ap *ap;

	blobmsg_parse(ap_status_policy, ARRAY_SIZE(ap_status_policy),
		      tb, blob_data(msg), blob_len(msg));

	if (!tb[0] || !tb[1] || !tb[2] || !tb[3] || !tb[4] || !tb[5] ||
	    !tb[6] || !tb[7] || !tb[8] || !tb[9] || !tb[10] || !tb[11]) {
		ctx->status = -1;
		return;
	}

	ap = &ctx->ap_status->ap;
	caps = &ctx->ap_status->caps;

	ap->bss.channel = blobmsg_get_u32(tb[0]);
	if (hwaddr_aton(blobmsg_get_string(tb[1]), ap->bss.bssid) == NULL) {
		ctx->status = -1;
		return;
	}
	strncpy((char *) &ap->bss.ssid[0], blobmsg_get_string(tb[2]), sizeof(ap->bss.ssid));

	ap->bss.load.utilization = blobmsg_get_u32(tb[3]);
	ap->bss.load.sta_count = blobmsg_get_u32(tb[8]);

	wifi_ubus_wifi_caps_element(tb[4], caps);
	ap->enabled = blobmsg_get_u32(tb[9]);

	ctx->status = 0;
}

int wifi_ubus_ap_status(struct ubus_context *ubus_ctx, const char *ifname,
			struct wifi_ap_status *ap_status)
{
	struct ap_status_ctx ctx = {
		.ifname = ifname,
		.ap_status = ap_status,
		.status = -1,
	};
	struct blob_buf bb = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s] %s\n", ifname, __func__);

	/* Get id from radio name */
	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	ret = ubus_invoke(ubus_ctx, id, "status", bb.head,
			  wifi_ubus_ap_status_cb, &ctx,
			  20 * 1000);
	blob_buf_free(&bb);

	if (ctx.status)
		ret = ctx.status;

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;
}

struct radio_scanresults_ctx {
	const char *radio;
	struct wifi_bss *bss;
	int num;
	int max;
	int status;
};

static void wifi_ubus_radio_scanresults_cb(struct ubus_request *req,
					   int type,
					   struct blob_attr *msg)
{
	struct wifi_bss *bss;
	struct radio_scanresults_ctx *ctx = req->priv;
        static const struct blobmsg_policy radio_scanresults_policy[] = {
                [0] = { .name = "accesspoints", .type = BLOBMSG_TYPE_ARRAY },
	};
	struct blob_attr *tb[ARRAY_SIZE(radio_scanresults_policy)];
	struct blob_attr *cur;
	int rem, num;

	blobmsg_parse(radio_scanresults_policy, ARRAY_SIZE(radio_scanresults_policy),
		      tb, blob_data(msg), blob_len(msg));

	num = 0;
	ctx->num = 0;

	if (!tb[0]) {
		ctx->status = -1;
		return;
	}

	blobmsg_for_each_attr(cur, tb[0], rem) {
                static const struct blobmsg_policy bss_policy[] = {
                        [0] = { .name = "ssid", .type = BLOBMSG_TYPE_STRING },
                        [1] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING },
                        [2] = { .name = "channel", .type = BLOBMSG_TYPE_INT32 },
                        [3] = { .name = "bandwidth", .type = BLOBMSG_TYPE_INT32 },
                        [4] = { .name = "rssi", .type = BLOBMSG_TYPE_INT32 },
                        [5] = { .name = "load_stas", .type = BLOBMSG_TYPE_INT32 },
                        [6] = { .name = "load_utilization", .type = BLOBMSG_TYPE_INT32 }
                };
                struct blob_attr *bss_tb[ARRAY_SIZE(bss_policy)];

		if (WARN_ON(num >= ctx->max))
			break;

		blobmsg_parse(bss_policy, ARRAY_SIZE(bss_policy), bss_tb,
			      blobmsg_data(cur), blobmsg_data_len(cur));

		if (!bss_tb[0] || !bss_tb[1] || !bss_tb[2] || !bss_tb[3] || !bss_tb[4] || !bss_tb[5] || !bss_tb[6])
			continue;

		bss = &ctx->bss[num];

		strncpy((char *) bss->ssid, blobmsg_get_string(bss_tb[0]), sizeof(bss->ssid));
		hwaddr_aton(blobmsg_get_string(bss_tb[1]), bss->bssid);
		bss->channel = blobmsg_get_u32(bss_tb[2]);

		switch (blobmsg_get_u32(bss_tb[3])) {
		case 20:
			bss->curr_bw = BW20;
			break;
		case 40:
			bss->curr_bw = BW40;
			break;
		case 80:
			bss->curr_bw = BW80;
			break;
		case 160:
			bss->curr_bw = BW160;
			break;
		case 8080:
			bss->curr_bw = BW8080;
			break;
		default:
			bss->curr_bw = BW20;
			break;
		}
		bss->rssi = blobmsg_get_u32(bss_tb[4]);
		bss->load.sta_count = blobmsg_get_u32(bss_tb[5]);
		bss->load.utilization = blobmsg_get_u32(bss_tb[6]);

		num++;
	}

	ctx->num = num;
	ctx->status = 0;
}

int wifi_ubus_radio_scanresults(struct ubus_context *ubus_ctx, const char *radio,
				struct wifi_bss *bss, int *num)
{
	struct radio_scanresults_ctx ctx = {
		.radio = radio,
		.bss = bss,
		.num = 0,
		.max = *num,
		.status = -1,
	};
	struct blob_buf bb = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s] %s\n", radio, __func__);

	/* Get id from radio name */
	snprintf(name, sizeof(name), "wifi.radio.%s", radio);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	ret = ubus_invoke(ubus_ctx, id, "scanresults", bb.head,
			  wifi_ubus_radio_scanresults_cb, &ctx,
			  20 * 1000);
	blob_buf_free(&bb);

	if (ctx.status)
		ret = ctx.status;

	*num = ctx.num;

out:
	trace("[%s] %s ret %d num %d max %d\n", radio, __func__, ret, *num, ctx.max);
	return ret;
}

int wifi_ubus_chan_switch(struct ubus_context *ubus_ctx, const char *ifname,
			  struct chan_switch_param *param)
{
	struct blob_buf bb = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s] %s chan %d bw %d\n", ifname, __func__, param->freq, param->bandwidth);

	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);

	blobmsg_add_u32(&bb, "freq", param->freq);
	blobmsg_add_u32(&bb, "bw", param->bandwidth);
	blobmsg_add_u32(&bb, "count", param->count);

	if (param->cf1)
		blobmsg_add_u32(&bb, "cf1", param->cf1);
	if (param->cf2)
		blobmsg_add_u32(&bb, "cf2", param->cf2);
	if (param->sec_chan_offset)
		blobmsg_add_u32(&bb, "sec_chan_offset", param->sec_chan_offset);

	blobmsg_add_u8(&bb, "ht", param->ht);
	blobmsg_add_u8(&bb, "vht", param->vht);
	blobmsg_add_u8(&bb, "he", param->he);

	ret = ubus_invoke(ubus_ctx, id, "chan_switch", bb.head,
			  NULL, NULL, 20 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;
}

struct ap_assoclist_ctx {
	const char *ifname;
	uint8_t *sta;
	int num;
	int max;
	int status;
};

static void wifi_ubus_ap_assoclist_cb(struct ubus_request *req,
				      int type,
				      struct blob_attr *msg)
{
	struct ap_assoclist_ctx *ctx = req->priv;
	static const struct blobmsg_policy assoclist_policy[] = {
		[0] = { .name="assoclist", .type = BLOBMSG_TYPE_ARRAY },
	};
	struct blob_attr *tb[ARRAY_SIZE(assoclist_policy)];
	struct blob_attr *cur;
	int num = 0;
	int rem;

	blobmsg_parse(assoclist_policy, ARRAY_SIZE(assoclist_policy),
		      tb, blob_data(msg), blob_len(msg));

	if (!tb[0]) {
		ctx->status = -1;
		return;
	}

	blobmsg_for_each_attr(cur, tb[0], rem) {
		static const struct blobmsg_policy attr_policy[] = {
			[0] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING},
		};
		struct blob_attr *attr_data[ARRAY_SIZE(attr_policy)];

		blobmsg_parse(attr_policy, ARRAY_SIZE(attr_policy),
			      attr_data, blobmsg_data(cur), blobmsg_data_len(cur));

		if (!attr_data[0])
			continue;

		if (WARN_ON(num >= ctx->max))
			break;

		hwaddr_aton(blobmsg_get_string(attr_data[0]), &ctx->sta[num * 6]);
		num++;
	}

	ctx->num = num;
	ctx->status = 0;
}

int wifi_ubus_get_assoclist(struct ubus_context *ubus_ctx, const char *ifname,
			   uint8_t *sta, int *num)
{
	struct blob_buf bb = { 0 };
	char name[256] = {};
	struct ap_assoclist_ctx ctx = {
		.ifname = ifname,
		.sta = sta,
		.num = 0,
		.max = *num,
		.status = -1
	};
	uint32_t id;
	int ret;

	trace("[%s] %s\n", ifname, __func__);

	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	ret = ubus_invoke(ubus_ctx, id, "assoclist", bb.head,
			  wifi_ubus_ap_assoclist_cb, &ctx, 20 * 1000);
	blob_buf_free(&bb);

	*num = ctx.num;
out:
	trace("[%s] %s ret %d num %d\n", ifname, __func__, ret, *num);
	return ret;
}

int wifi_ubus_req_neighbor(struct ubus_context *ubus_ctx, const char *ifname,
			   uint8_t *sta, struct wifi_request_neighbor_param *param)
{
	char client_macstr[18] = { 0 };
	char bssid_macstr[18] = { 0 };
	struct blob_buf bb = { 0 };
	char objname[32] = {0};
	char ssid_str[33] = {0};
	uint32_t id;
	uint8_t *pos;
	int i, j, ret = -1;

	trace("[%s]: %s\n", ifname, __func__);

	blob_buf_init(&bb, 0);

	if (!sta)
		goto out;

	snprintf(objname, 31, "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, objname, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	hwaddr_ntoa(sta, client_macstr);
	blobmsg_add_string(&bb, "client", client_macstr);

	if (param->opclass)
		blobmsg_add_u32(&bb, "opclass", param->opclass);

	if (param->channel)
		blobmsg_add_u32(&bb, "channel", param->channel);

	if (param->bssid) {
		hwaddr_ntoa(param->bssid, bssid_macstr);
		blobmsg_add_string(&bb, "bssid", bssid_macstr);
	}

	/* TODO: revisit */
	/* Set mode to PASSIVE/100ms explicitly */
	blobmsg_add_string(&bb, "mode", "passive");
	blobmsg_add_u32(&bb, "duration", 100);

	if (param->reporting_detail)
		blobmsg_add_u32(&bb, "reporting_detail", param->reporting_detail);

	if (param->ssid_len && param->ssid) {
		if (param->ssid_len > 32) {
			trace("[%s:%d] ssid too long\n", __func__, __LINE__);
			goto out;
		}
		snprintf(ssid_str, 33, "%s", param->ssid);
		blobmsg_add_string(&bb, "ssid", ssid_str);
	}

	/* If the value of the Number of AP Channel Reports field (h)
	 * in the query is greater than zero and the value of the
	 * Channel Number field in the query is 255, then h AP Channel
	 * Report subelements shall be included in the 802.11 Beacon
	 * request, each containing the specified Operating Class and
	 * Channel List.
	 */
	if (param->num_report && param->channel == 255) {
		void *aa, *t, *b;

		dbg("|%s:%d| adding AP Channel Reports\n",
				__func__, __LINE__);

		aa = blobmsg_open_array(&bb, "channel_report");
		pos = param->report;
		for (i = 0; i < param->num_report; i++) {
			struct ap_channel_report *rep =
					(struct ap_channel_report *) pos;

			t = blobmsg_open_table(&bb, "");
			blobmsg_add_u32(&bb, "opclass", rep->opclass);
			b = blobmsg_open_array(&bb, "channels");
			for (j = 0; j < (rep->len - 1); j++)
				blobmsg_add_u32(&bb, NULL, rep->channel[j]);
			blobmsg_close_array(&bb, b);
			blobmsg_close_table(&bb, t);
			pos += 1 + rep->len;
		}
		blobmsg_close_array(&bb, aa);
	}

	if (param->num_element) {
		void *c;

		dbg("|%s:%d| adding Element IDs\n",
				__func__, __LINE__);

		c = blobmsg_open_array(&bb, "request_element");
		pos = param->element;
		for (i = 0; i < param->num_element; i++) {
			blobmsg_add_u32(&bb, NULL, *pos);
			pos += 1;
		}
		blobmsg_close_array(&bb, c);
	}

	dbg("|%s:%d| ubus call request_neighbor on %s\n",
		__func__, __LINE__, ifname);

	ret = ubus_invoke(ubus_ctx, id, "request_neighbor", bb.head,
		NULL, NULL, 20 * 1000);

	if (ret) {
		trace("[%s:%d] ubus call failed for %s send, ret = %d\n",
			__func__, __LINE__, objname, ret);
		goto out;
	}

out:
	blob_buf_free(&bb);

	trace("[%s]: %s ret %d\n", ifname, __func__, ret);
	return ret;
}

struct get_stas_ctx {
	const char *ifname;
	uint8_t *sta_addr;
	struct wifi_sta *sta;
	int num;
	int max;
	int status;
};

static int wifi_ubus_get_sta_caps(struct blob_attr *msg,
				  struct wifi_caps *caps)
{
	/* TODO fill caps */
	return 0;
}

static int wifi_ubus_get_sta_rssi(struct blob_attr *msg,
				  int8_t *rssi, int max)
{
	static const struct blobmsg_policy rssi_policy[] = {
		{ .type = BLOBMSG_TYPE_INT32 },
		{ .type = BLOBMSG_TYPE_INT32 },
		{ .type = BLOBMSG_TYPE_INT32 },
		{ .type = BLOBMSG_TYPE_INT32 },
	};
	struct blob_attr *tb[ARRAY_SIZE(rssi_policy)];

	blobmsg_parse_array(rssi_policy, ARRAY_SIZE(rssi_policy), tb,
			    blobmsg_data(msg), blobmsg_data_len(msg));

	if (!tb[0] || !tb[1] || !tb[2] || !tb[3])
		return -1;

	if (max < 4)
		return -1;

	rssi[0] = blobmsg_get_u32(tb[0]);
	rssi[1] = blobmsg_get_u32(tb[1]);
	rssi[2] = blobmsg_get_u32(tb[2]);
	rssi[3] = blobmsg_get_u32(tb[3]);

	return 0;
}

static int wifi_ubus_get_sta_rate(struct blob_attr *msg,
				  struct wifi_rate *rate)
{
	static const struct blobmsg_policy rate_policy[] = {
		[0] = { .name = "rate", .type = BLOBMSG_TYPE_INT32 },
		[1] = { .name = "mcs", .type = BLOBMSG_TYPE_INT32 },
		[2] = { .name = "bandwidth", .type = BLOBMSG_TYPE_INT32 },
		[3] = { .name = "sgi", .type = BLOBMSG_TYPE_INT32 },
		[4] = { .name = "nss", .type = BLOBMSG_TYPE_INT32 },
		[5] = { .name = "phy", .type = BLOBMSG_TYPE_INT32 },
	};
	struct blob_attr *tb[ARRAY_SIZE(rate_policy)];

	blobmsg_parse(rate_policy, ARRAY_SIZE(rate_policy), tb,
		      blobmsg_data(msg), blobmsg_data_len(msg));

	if (!tb[0] || !tb[1] || !tb[2] || !tb[3] || !tb[4] || !tb[5])
		return -1;

	rate->rate = blobmsg_get_u32(tb[0]);
	rate->m.mcs = blobmsg_get_u32(tb[1]);
	rate->m.bw = bw_to_wifi_bw(blobmsg_get_u32(tb[2]));
	rate->m.sgi = blobmsg_get_u32(tb[3]);
	rate->m.nss = blobmsg_get_u32(tb[4]);
	rate->phy = blobmsg_get_u32(tb[5]);

	return 0;
}


static int wifi_ubus_get_sta_stats(struct blob_attr *msg,
				   struct wifi_sta_stats *stats)
{
	static const struct blobmsg_policy stats_policy[] = {
		[0] = { .name = "tx_total_pkts", .type = BLOBMSG_TYPE_INT64 },
		[1] = { .name = "tx_total_bytes", .type = BLOBMSG_TYPE_INT64 },
		[2] = { .name = "tx_failures", .type = BLOBMSG_TYPE_INT64 },
		[3] = { .name = "tx_pkts_retries", .type = BLOBMSG_TYPE_INT64 },
		[4] = { .name = "rx_data_pkts", .type = BLOBMSG_TYPE_INT64 },
		[5] = { .name = "rx_data_bytes", .type = BLOBMSG_TYPE_INT64 },
		[6] = { .name = "rx_failures", .type = BLOBMSG_TYPE_INT64 },
		[7] = { .name = "tx_rate_latest", .type = BLOBMSG_TYPE_TABLE },
		[8] = { .name = "rx_rate_latest", .type = BLOBMSG_TYPE_TABLE },
	};
	struct blob_attr *tb[ARRAY_SIZE(stats_policy)];

	blobmsg_parse(stats_policy, ARRAY_SIZE(stats_policy), tb,
		      blobmsg_data(msg), blobmsg_data_len(msg));

	if (!tb[0] || !tb[1] || !tb[2] || !tb[3] || !tb[4]
			   || !tb[5] || !tb[6] || !tb[7] || !tb[8])
		return -1;

	stats->tx_pkts = blobmsg_get_u64(tb[0]);
	stats->tx_bytes = blobmsg_get_u64(tb[1]);
	stats->tx_fail_pkts = blobmsg_get_u64(tb[2]);
	stats->tx_retry_pkts = blobmsg_get_u64(tb[3]);

	stats->rx_pkts = blobmsg_get_u64(tb[4]);
	stats->rx_bytes = blobmsg_get_u64(tb[5]);
	stats->rx_fail_pkts = blobmsg_get_u64(tb[6]);

	wifi_ubus_get_sta_rate(tb[7], &stats->tx_rate);
	wifi_ubus_get_sta_rate(tb[8], &stats->rx_rate);

	return 0;
}

static void wifi_ubus_get_stas_cb(struct ubus_request *req,
				  int type,
				  struct blob_attr *msg)
{
	struct get_stas_ctx *ctx = req->priv;
        static const struct blobmsg_policy get_stations_policy[] = {
                [0] = { .name = "stations", .type = BLOBMSG_TYPE_ARRAY },
	};
	struct blob_attr *tb[ARRAY_SIZE(get_stations_policy)];
	char sta_addr_str[18] = {};
	struct wifi_sta *sta;
	struct blob_attr *cur;
	int num, rem;

	ctx->num = 0;
	num = 0;

	if (ctx->sta_addr)
		hwaddr_ntoa(ctx->sta_addr, sta_addr_str);

	blobmsg_parse(get_stations_policy, ARRAY_SIZE(get_stations_policy),
		      tb, blob_data(msg), blob_len(msg));

	if (!tb[0]) {
		ctx->status = -1;
		return;
	}

	blobmsg_for_each_attr(cur, tb[0], rem) {
		static const struct blobmsg_policy sta_policy[] = {
			[0] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
			[1] = { .name = "channel", .type = BLOBMSG_TYPE_INT32 },
			[2] = { .name = "rssi", .type = BLOBMSG_TYPE_INT32 },
			[3] = { .name = "stats", .type = BLOBMSG_TYPE_TABLE },
			[4] = { .name = "in_network", .type = BLOBMSG_TYPE_INT64 },
			[5] = { .name = "tx_airtime", .type = BLOBMSG_TYPE_INT32 },
			[6] = { .name = "rx_airtime", .type = BLOBMSG_TYPE_INT32 },
			[7] = { .name = "nss", .type = BLOBMSG_TYPE_INT32 },
			[8] = { .name = "bandwidth", .type = BLOBMSG_TYPE_INT32 },
			[9] = { .name = "capabilities", .type = BLOBMSG_TYPE_TABLE },
			[10] = { .name = "maxrate", .type = BLOBMSG_TYPE_INT32 },
			[11] = { .name = "rssi_per_antenna", .type = BLOBMSG_TYPE_ARRAY },
		};
		struct blob_attr *sta_tb[ARRAY_SIZE(sta_policy)];

		blobmsg_parse(sta_policy, ARRAY_SIZE(sta_policy), sta_tb,
			      blobmsg_data(cur), blobmsg_data_len(cur));

		if (!sta_tb[0] || !sta_tb[1] || !sta_tb[2])
			continue;

		if (ctx->sta_addr && strcmp(blobmsg_get_string(sta_tb[0]), sta_addr_str))
			continue;

		if (WARN_ON(num >= ctx->max))
			break;

		sta = &ctx->sta[num];

		hwaddr_aton(blobmsg_get_string(sta_tb[0]), sta->macaddr);
		sta->rssi_avg = blobmsg_get_u32(sta_tb[2]);

		sta->conn_time = blobmsg_get_u64(sta_tb[4]);
		sta->tx_airtime = blobmsg_get_u32(sta_tb[5]);
		sta->rx_airtime = blobmsg_get_u32(sta_tb[6]);

		wifi_ubus_get_sta_rssi(sta_tb[11], sta->rssi, sizeof(sta->rssi));
		wifi_ubus_get_sta_caps(sta_tb[9], &sta->caps);
		wifi_ubus_get_sta_stats(sta_tb[3], &sta->stats);

		num++;

		/* Single station requested */
		if (ctx->sta_addr)
			break;
	}

	ctx->num = num;
	ctx->status = 0;
}

static int wifi_ubus_get_stas(struct ubus_context *ubus_ctx, const char *ifname,
			      uint8_t *sta_addr, struct wifi_sta *sta, int *num)
{
	struct get_stas_ctx ctx = {
		.ifname = ifname,
		.sta = sta,
		.max = *num,
		.num = 0,
		.status = -1,
	};
	struct blob_buf bb = {};
	char sta_addr_str[18] = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s] %s\n", ifname, __func__);

	*num = 0;

	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);

	if (sta_addr) {
		hwaddr_ntoa(sta_addr, sta_addr_str);
		blobmsg_add_string(&bb, "sta", sta_addr_str);
	}

	ret = ubus_invoke(ubus_ctx, id, "stations", bb.head,
			  wifi_ubus_get_stas_cb, &ctx,
			  20 * 1000);

	blob_buf_free(&bb);

	if (ctx.status)
		ret = ctx.status;

	*num = ctx.num;
out:
	trace("[%s] %s ret %d (num %d)\n", ifname, __func__, ret, *num);
	return ret;
}

int wifi_ubus_get_stations(struct ubus_context *ubus_ctx, const char *ifname,
			   struct wifi_sta *sta, int *num)
{
	return wifi_ubus_get_stas(ubus_ctx, ifname, NULL, sta, num);
}

int wifi_ubus_get_station(struct ubus_context *ubus_ctx, const char *ifname,
			  uint8_t *sta_addr, struct wifi_sta *sta)
{
	int num = 1;

	return wifi_ubus_get_stas(ubus_ctx, ifname, sta_addr, sta, &num);
}

int wifi_ubus_sta_disconnect_ap(struct ubus_context *ubus_ctx, const char *ifname,
				uint32_t reason)
{
	struct blob_buf bb = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s] %s\n", ifname, __func__);

	snprintf(name, sizeof(name), "wifi.backhaul.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	if (reason)
		blobmsg_add_u32(&bb, "reason", reason);

	ret = ubus_invoke(ubus_ctx, id, "disconnect", bb.head, NULL, NULL, 20 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;
}

static int wifi_ubus_subscribe_unsubscribe_frame(struct ubus_context *ubus_ctx,
						 const char *ifname,
						 uint8_t type, uint8_t stype,
						 bool subscribe)
{
	struct blob_buf bb = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s] %s\n", ifname, __func__);

	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	blobmsg_add_u32(&bb, "type", type);
	blobmsg_add_u32(&bb, "stype", stype);
	ret = ubus_invoke(ubus_ctx, id, subscribe ? "subscribe_frame" : "unsubscribe_frame",
			  bb.head, NULL, NULL, 20 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;
}

int wifi_ubus_subscribe_frame(struct ubus_context *ubus_ctx, const char *ifname,
			      uint8_t type, uint8_t stype)
{
	return wifi_ubus_subscribe_unsubscribe_frame(ubus_ctx, ifname, type, stype, true);
}

int wifi_ubus_unsubscribe_frame(struct ubus_context *ubus_ctx, const char *ifname,
				uint8_t type, uint8_t stype)
{
	return wifi_ubus_subscribe_unsubscribe_frame(ubus_ctx, ifname, type, stype, false);
}

struct ap_stats_ctx {
	struct wifi_ap_stats *stats;
	int status;
};

static void wifi_ubus_ap_stats_cb(struct ubus_request *req,
				  int type,
				  struct blob_attr *msg)
{
	struct ap_stats_ctx *ctx = req->priv;
	static const struct blobmsg_policy stats_policy[] = {
		[0] = { .name = "tx_bytes", .type = BLOBMSG_TYPE_INT64 },
		[1] = { .name = "tx_packets", .type = BLOBMSG_TYPE_INT64 },
		[2] = { .name = "tx_unicast_packets", .type = BLOBMSG_TYPE_INT64 },
		[3] = { .name = "tx_multicast_packets", .type = BLOBMSG_TYPE_INT64 },
		[4] = { .name = "tx_broadcast_packets", .type = BLOBMSG_TYPE_INT64 },
		[5] = { .name = "tx_error_packets", .type = BLOBMSG_TYPE_INT64 },
		[6] = { .name = "tx_retrans_packets", .type = BLOBMSG_TYPE_INT64 },
		[7] = { .name = "tx_retrans_fail_packets", .type = BLOBMSG_TYPE_INT64 },
		[8] = { .name = "tx_retry_packets", .type = BLOBMSG_TYPE_INT64 },
		[9] = { .name = "tx_multi_retry_packets", .type = BLOBMSG_TYPE_INT64 },
		[10] = { .name = "tx_dropped_packets", .type = BLOBMSG_TYPE_INT64 },
		[11] = { .name = "ack_fail_packets", .type = BLOBMSG_TYPE_INT64 },
		[12] = { .name = "aggregate_packets", .type = BLOBMSG_TYPE_INT64 },
		[13] = { .name = "rx_bytes", .type = BLOBMSG_TYPE_INT64 },
		[14] = { .name = "rx_packets", .type = BLOBMSG_TYPE_INT64 },
		[15] = { .name = "rx_unicast_packets", .type = BLOBMSG_TYPE_INT64 },
		[16] = { .name = "rx_multicast_packets", .type = BLOBMSG_TYPE_INT64 },
		[17] = { .name = "rx_broadcast_packets", .type = BLOBMSG_TYPE_INT64 },
		[18] = { .name = "rx_error_packets", .type = BLOBMSG_TYPE_INT64 },
		[19] = { .name = "rx_dropped_packets", .type = BLOBMSG_TYPE_INT64 },
		[20] = { .name = "rx_unknown_packets", .type = BLOBMSG_TYPE_INT64 },
	};
	struct blob_attr *tb[ARRAY_SIZE(stats_policy)];
	struct wifi_ap_stats *stats;
	int i;

	blobmsg_parse(stats_policy, ARRAY_SIZE(stats_policy), tb,
		      blobmsg_data(msg), blobmsg_data_len(msg));

	for (i = 0; i < ARRAY_SIZE(stats_policy); i++) {
		if (!tb[i]) {
			ctx->status = -1;
			return;
		}
	}

	stats = ctx->stats;

	stats->tx_bytes = blobmsg_get_u64(tb[1]);
	stats->tx_pkts = blobmsg_get_u64(tb[2]);
	stats->tx_ucast_pkts = blobmsg_get_u64(tb[3]);
	stats->tx_mcast_pkts = blobmsg_get_u64(tb[4]);
	stats->tx_bcast_pkts = blobmsg_get_u64(tb[5]);
	stats->tx_err_pkts = blobmsg_get_u64(tb[6]);
	stats->tx_rtx_pkts = blobmsg_get_u64(tb[7]);
	stats->tx_retry_pkts = blobmsg_get_u64(tb[8]);
	stats->tx_mretry_pkts = blobmsg_get_u64(tb[9]);
	stats->tx_dropped_pkts = blobmsg_get_u64(tb[10]);
	stats->ack_fail_pkts = blobmsg_get_u64(tb[11]);
	stats->aggr_pkts = blobmsg_get_u64(tb[12]);

	stats->rx_bytes = blobmsg_get_u64(tb[13]);
	stats->rx_pkts = blobmsg_get_u64(tb[14]);
	stats->rx_ucast_pkts = blobmsg_get_u64(tb[15]);
	stats->rx_mcast_pkts = blobmsg_get_u64(tb[16]);
	stats->rx_bcast_pkts = blobmsg_get_u64(tb[17]);
	stats->rx_err_pkts = blobmsg_get_u64(tb[18]);
	stats->rx_dropped_pkts = blobmsg_get_u64(tb[19]);
	stats->rx_unknown_pkts = blobmsg_get_u64(tb[20]);

	ctx->status = 0;
}

int wifi_ubus_ap_stats(struct ubus_context *ubus_ctx, const char *ifname,
		       struct wifi_ap_stats *stats)
{
	struct ap_stats_ctx ctx = {
		.stats = stats,
		.status = -1,
	};
	struct blob_buf bb = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s] %s\n", ifname, __func__);

	snprintf(name, sizeof(name), "wifi.ap.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	ret = ubus_invoke(ubus_ctx, id, "stats", bb.head,
			  wifi_ubus_ap_stats_cb, &ctx, 20 * 1000);
	blob_buf_free(&bb);

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;
}

struct bsta_status_ctx {
	const char *ifname;
	struct wifi_bsta_status *bsta_status;
	int status;
};

static void wifi_ubus_bsta_status_cb(struct ubus_request *req,
				     int type,
				     struct blob_attr *msg)
{
	struct bsta_status_ctx *ctx = req->priv;
        static const struct blobmsg_policy bsta_status_policy[] = {
		[0] = { .name = "status", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "channel", .type = BLOBMSG_TYPE_INT32 },
		[2] = { .name = "bandwidth", .type = BLOBMSG_TYPE_INT32 },
		[3] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
		[4] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING },
		[5] = { .name = "ssid", .type = BLOBMSG_TYPE_STRING },
		[6] = { .name = "4addr", .type = BLOBMSG_TYPE_BOOL },
		[7] = { .name = "frequency", .type = BLOBMSG_TYPE_INT32 },
		/* TODO add more fields if required */
	};
	struct blob_attr *tb[ARRAY_SIZE(bsta_status_policy)];
	struct wifi_bsta_status *status;

	trace("[%s] %s\n", ctx->ifname, __func__);

	blobmsg_parse(bsta_status_policy, ARRAY_SIZE(bsta_status_policy),
		      tb, blob_data(msg), blob_len(msg));

	if (!tb[0] || !tb[3] || !tb[6]) {
		ctx->status = -1;
		return;
	}

	status = ctx->bsta_status;

	status->mode4addr = blobmsg_get_u8(tb[6]);
	if (hwaddr_aton(blobmsg_get_string(tb[3]), status->sta.macaddr) == NULL) {
		ctx->status = -1;
		return;
	}

	if (tb[1])
		status->channel = blobmsg_get_u32(tb[1]);
	if (tb[2])
		status->bandwidth = bw_to_wifi_bw(blobmsg_get_u32(tb[2]));
	if (tb[4]) {
		if (hwaddr_aton(blobmsg_get_string(tb[4]), status->sta.bssid) == NULL) {
			ctx->status = -1;
			return;
		}
	}
	if (tb[5])
		strncpy((char *) &status->ssid[0], blobmsg_get_string(tb[5]), sizeof(status->ssid));
	if (tb[7])
		status->frequency = blobmsg_get_u32(tb[7]);

	ctx->status = 0;
}

int wifi_ubus_bsta_status(struct ubus_context *ubus_ctx, const char *ifname,
			  struct wifi_bsta_status *bsta_status)
{
	struct bsta_status_ctx ctx = {
		.ifname = ifname,
		.bsta_status = bsta_status,
		.status = -1,
	};
	struct blob_buf bb = {};
	char name[256] = {};
	uint32_t id;
	int ret;

	trace("[%s] %s\n", ifname, __func__);

	/* Get id from backhaul name */
	snprintf(name, sizeof(name), "wifi.backhaul.%s", ifname);
	ret = ubus_lookup_id(ubus_ctx, name, &id);
	if (ret != UBUS_STATUS_OK)
		goto out;

	blob_buf_init(&bb, 0);
	ret = ubus_invoke(ubus_ctx, id, "status", bb.head,
			  wifi_ubus_bsta_status_cb, &ctx,
			  20 * 1000);
	blob_buf_free(&bb);

	if (ctx.status)
		ret = ctx.status;

out:
	trace("[%s] %s ret %d\n", ifname, __func__, ret);
	return ret;
}
