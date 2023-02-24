/*
 * wifi_ubus.h - wifimngr ubus interface
 *
 * Copyright (C) 2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 */

#ifndef WIFI_UBUS_H
#define WIFI_UBUS_H

#include "wifidefs.h"

int wifi_ubus_scan(struct ubus_context *ubus_ctx, const char *radio,
		   struct scan_param_ex *param,
		   int num_opclass, uint8_t *opclass,
		   int num_channel, uint8_t *channel);
int wifi_ubus_ap_set_state(struct ubus_context *ubus_ctx, const char *name, bool up);

int wifi_ubus_start_cac(struct ubus_context *ubus_ctx, const char *radio,
			int channel, enum wifi_bw bw, enum wifi_cac_method method);
int wifi_ubus_stop_cac(struct ubus_context *ubus_ctx, const char *radio);
int wifi_ubus_del_neighbor(struct ubus_context *ubus_ctx, const char *ifname, uint8_t *bssid);
int wifi_ubus_add_neighbor(struct ubus_context *ubus_ctx, const char *ifname, struct nbr *nbr);
int wifi_ubus_list_neighbor(struct ubus_context *ubus_ctx, const char *ifname,
			    struct nbr *nbr, int *nbr_num);

int wifi_ubus_opclass_preferences(struct ubus_context *ubus_ctx, const char *radio,
				  struct wifi_radio_opclass *opclass);
int wifi_ubus_radio_status(struct ubus_context *ubus_ctx, const char *radio,
			   struct wifi_radio_status *status);
int wifi_ubus_disconnect_sta(struct ubus_context *ubus_ctx, const char *ifname,
			     uint8_t *macaddr, uint16_t reason);
int wifi_ubus_restrict_sta(struct ubus_context *ubus_ctx, const char *ifname,
			   uint8_t *macaddr, int enable);

int wifi_ubus_req_btm(struct ubus_context *ubus_ctx, const char *name, uint8_t *macaddr,
		      int bsss_nr, uint8_t *bsss, struct wifi_btmreq *req);
int wifi_ubus_request_transition(struct ubus_context *ubus_ctx, const char *ifname, uint8_t *macaddr,
				 uint8_t bss_num, uint8_t *bss, int timeout);
int wifi_ubus_add_vendor_ie(struct ubus_context *ubus_ctx, const char *ifname, int mgmt,
			    char *oui, char *data);
int wifi_ubus_del_vendor_ie(struct ubus_context *ubus_ctx, const char *ifname, int mgmt,
			    char *oui, char *data);
int wifi_ubus_get_4addr(struct ubus_context *ubus_ctx, const char *ifname, bool *enable);
int wifi_ubus_set_4addr(struct ubus_context *ubus_ctx, const char *ifname, bool enable);

int wifi_ubus_ap_status(struct ubus_context *ubus_ctx, const char *ifname, struct wifi_ap_status *ap_status);
int wifi_ubus_radio_scanresults(struct ubus_context *ubus_ctx, const char *radio,
				struct wifi_bss *bss, int *num);

int wifi_ubus_monitor_add_del(struct ubus_context *ubus_ctx, const char *ifname,
			      uint8_t *macaddr, bool add);
int wifi_ubus_monitor_add(struct ubus_context *ubus_ctx, const char *ifname, uint8_t *macaddr);
int wifi_ubus_monitor_del(struct ubus_context *ubus_ctx, const char *ifname, uint8_t *macaddr);
int wifi_ubus_monitor_get(struct ubus_context *ubus_ctx, const char *ifname,
			  uint8_t *macaddr, struct wifi_monsta *monsta);

int wifi_ubus_chan_switch(struct ubus_context *ubus_ctx, const char *ifname,
			  struct chan_switch_param *param);
int wifi_ubus_get_assoclist(struct ubus_context *ubus_ctx, const char *ifname,
			    uint8_t *sta, int *num);
int wifi_ubus_req_neighbor(struct ubus_context *ubus_ctx, const char *ifname,
			   uint8_t *sta, struct wifi_request_neighbor_param *param);
int wifi_ubus_get_stations(struct ubus_context *ubus_ctx, const char *ifname,
			   struct wifi_sta *sta, int *num);
int wifi_ubus_get_station(struct ubus_context *ubus_ctx, const char *ifname,
			  uint8_t *sta_addr, struct wifi_sta *sta);
int wifi_ubus_sta_disconnect_ap(struct ubus_context *ubus_ctx, const char *ifname,
				uint32_t reason);
int wifi_ubus_subscribe_frame(struct ubus_context *ubus_ctx, const char *ifname,
			      uint8_t type, uint8_t stype);
int wifi_ubus_unsubscribe_frame(struct ubus_context *ubus_ctx, const char *ifname,
				uint8_t type, uint8_t stype);
int wifi_ubus_ap_stats(struct ubus_context *ubus_ctx, const char *ifname,
		       struct wifi_ap_stats *stats);
int wifi_ubus_bsta_status(struct ubus_context *ubus_ctx, const char *ifname,
			  struct wifi_bsta_status *bsta_status);
#endif /* WIFI_UBUS_H */
