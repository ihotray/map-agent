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
#include "wifi_ubus.h"

int wifi_add_neighbor(const char *ifname, struct nbr *nbr)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_add_neighbor(ctx, ifname, nbr);

	ubus_free(ctx);
	return ret;
}

int wifi_get_neighbor_list(const char *ifname, struct nbr *nbrs, int *nr)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_list_neighbor(ctx, ifname, nbrs, nr);

	ubus_free(ctx);
	return ret;
}

int wifi_del_neighbor(const char *ifname, unsigned char *bssid)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_del_neighbor(ctx, ifname, bssid);

	ubus_free(ctx);
	return ret;
}

int wifi_start_cac(const char *name, int channel, enum wifi_bw bw,
		   enum wifi_cac_method method)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_start_cac(ctx, name, channel, bw, method);

	ubus_free(ctx);
	return ret;
}

int wifi_stop_cac(const char *name)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_stop_cac(ctx, name);

	ubus_free(ctx);
	return ret;
}

int wifi_scan(const char *name, struct scan_param_ex *param,
	      int num_opclass, uint8_t *opclass,
	      int num_channel, uint8_t *channel)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_scan(ctx, name, param,
			     num_opclass, opclass,
			     num_channel, channel);

	ubus_free(ctx);
	return ret;
}

int wifi_get_scan_results(const char *name, struct wifi_bss *bsss, int *num)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_radio_scanresults(ctx, name, bsss, num);

	ubus_free(ctx);
	return ret;
}

int wifi_set_4addr(const char *ifname, bool enable)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_set_4addr(ctx, ifname, enable);

	ubus_free(ctx);
	return ret;
}

int wifi_get_4addr(const char *ifname, bool *enabled)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_get_4addr(ctx, ifname, enabled);

	ubus_free(ctx);
	return ret;
}

int wifi_get_4addr_parent(const char *ifname, char *parent)
{
	return -1;
}

int wifi_ap_set_state(const char *ifname, bool up)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_ap_set_state(ctx, ifname, up);

	ubus_free(ctx);
	return ret;
}

int wifi_monitor_sta(const char *ifname, uint8_t *sta, struct wifi_monsta_config *cfg)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_monitor_add_del(ctx, ifname, sta, cfg->enable);

	ubus_free(ctx);
	return ret;
}

int wifi_monitor_sta_add(const char *ifname, uint8_t *sta)
{
	struct wifi_monsta_config cfg = {
		.enable = true,
	};

	return wifi_monitor_sta(ifname, sta, &cfg);
}

int wifi_monitor_sta_del(const char *ifname, uint8_t *sta)
{
	struct wifi_monsta_config cfg = {
		.enable = false,
	};

	return wifi_monitor_sta(ifname, sta, &cfg);
}

int wifi_get_monitor_sta(const char *ifname, uint8_t *sta, struct wifi_monsta *mon)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_monitor_get(ctx, ifname, sta, mon);

	ubus_free(ctx);
	return ret;
}

int wifi_chan_switch(const char *ifname, struct chan_switch_param *param)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_chan_switch(ctx, ifname, param);

	ubus_free(ctx);
	return ret;
}

int wifi_restrict_sta(const char *ifname, uint8_t *sta, int enable)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_restrict_sta(ctx, ifname, sta, enable);

	ubus_free(ctx);
	return ret;
}

int wifi_ap_status(const char *ifname, struct wifi_ap_status *ap_status)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_ap_status(ctx, ifname, ap_status);

	ubus_free(ctx);
	return ret;
}

int wifi_bsta_status(const char *ifname, struct wifi_bsta_status *bsta_status)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_bsta_status(ctx, ifname, bsta_status);

	ubus_free(ctx);
	return ret;
}

int wifi_get_assoclist(const char *ifname, uint8_t *stas, int *num_stas)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_get_assoclist(ctx, ifname, stas, num_stas);

	ubus_free(ctx);
	return ret;
}

int wifi_disconnect_sta(const char *ifname, uint8_t *sta, uint16_t reason)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_disconnect_sta(ctx, ifname, sta, reason);

	ubus_free(ctx);
	return ret;
}

int wifi_req_bss_transition(const char *ifname, unsigned char *sta,
			    int bsss_nr, unsigned char *bsss,
			    unsigned int tmo)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_request_transition(ctx, ifname, sta, bsss_nr, bsss, tmo);

	ubus_free(ctx);
	return ret;
}

int wifi_radio_status(const char *name, struct wifi_radio_status *status)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_radio_status(ctx, name, status);

	ubus_free(ctx);
	return ret;
}

int wifi_req_btm(const char *ifname, uint8_t *sta, int bsss_nr, uint8_t *bsss,
		 struct wifi_btmreq *req)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_req_btm(ctx, ifname, sta, bsss_nr, bsss, req);

	ubus_free(ctx);
	return ret;
}

int wifi_req_neighbor(const char *ifname, uint8_t *sta,
		      struct wifi_request_neighbor_param *param)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_req_neighbor(ctx, ifname, sta, param);

	ubus_free(ctx);
	return ret;
}

int wifi_add_vendor_ie(const char *ifname, int mgmt, char *oui, char *data)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_add_vendor_ie(ctx, ifname, mgmt, oui, data);

	ubus_free(ctx);
	return ret;
}

int wifi_del_vendor_ie(const char *ifname, int mgmt, char *oui, char *data)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_del_vendor_ie(ctx, ifname, mgmt, oui, data);

	ubus_free(ctx);
	return ret;
}

int wifi_opclass_preferences(const char *radio,
			     struct wifi_radio_opclass *opclass)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_opclass_preferences(ctx, radio, opclass);

	ubus_free(ctx);
	return ret;
}

int wifi_get_stations(const char *ifname, struct wifi_sta *sta, int *num)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_get_stations(ctx, ifname, sta, num);

	ubus_free(ctx);
	return ret;
}

int wifi_get_station(const char *ifname, uint8_t *sta_addr, struct wifi_sta *sta)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_get_station(ctx, ifname, sta_addr, sta);

	ubus_free(ctx);
	return ret;
}

int wifi_sta_disconnect_ap(const char *ifname, uint32_t reason)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_sta_disconnect_ap(ctx, ifname, reason);

	ubus_free(ctx);
	return ret;
}

int wifi_subscribe_frame(const char *ifname, uint8_t type, uint8_t stype)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_subscribe_frame(ctx, ifname, type, stype);

	ubus_free(ctx);
	return ret;
}

int wifi_unsubscribe_frame(const char *ifname, uint8_t type, uint8_t stype)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_unsubscribe_frame(ctx, ifname, type, stype);

	ubus_free(ctx);
	return ret;
}

int wifi_ap_stats(const char *ifname, struct wifi_ap_stats *stats)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	int ret;

	ret = wifi_ubus_ap_stats(ctx, ifname, stats);

	ubus_free(ctx);
	return ret;
}

int c2f(int chan)
{
	int freq = 0;

	if (chan >= 1 && chan <= 13)
		freq = 2407 + chan * 5;
	if (chan == 14)
		freq = 2484;
	if (chan >= 36)
		freq = 5000 + chan * 5;

	return freq;
}

uint32_t wifi_bw_to_bw(enum wifi_bw bw)
{
	uint32_t bandwidth;

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
	case BW8080:
		bandwidth = 8080;
		break;
	default:
		bandwidth = 20;
		break;
	}

	return bandwidth;
}

enum wifi_bw bw_to_wifi_bw(uint32_t bandwidth)
{
	enum wifi_bw wifi_bw = BW20;

	switch (bandwidth) {
	case 20:
		wifi_bw = BW20;
		break;
	case 40:
		wifi_bw = BW40;
		break;
	case 80:
		wifi_bw = BW80;
		break;
	case 160:
		wifi_bw = BW160;
		break;
	case 8080:
		wifi_bw = BW8080;
		break;
	default:
		wifi_bw = BW20;
		break;
	}

	return wifi_bw;
}
