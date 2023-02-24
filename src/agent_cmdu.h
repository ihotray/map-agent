/*
 * agent_cmdu.h - cmdu building function declarations
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: jakob.olsson@iopsys.eu
 *
 */

#ifndef MAPAGENT_CMDU_H
#define MAPAGENT_CMDU_H

struct cmdu_buff *agent_gen_ap_autoconfig_search(struct agent *a,
		struct wifi_radio_element *radio, uint8_t profile);
struct cmdu_buff *agent_gen_ap_metrics_response(struct agent *a,
		struct cmdu_buff *rec_cmdu, struct node *n);
struct cmdu_buff *agent_gen_assoc_sta_metric_response_per_intf(
		struct agent *a, char *ifname);
struct cmdu_buff *agent_gen_assoc_sta_metric_response(
		struct agent *a, struct cmdu_buff *rec_cmdu, struct node *n);
struct cmdu_buff *agent_gen_beacon_metrics_query(struct agent *a,
		uint8_t *agent_mac, uint8_t *sta_addr, uint8_t opclass,
		uint8_t channel, uint8_t *bssid,
		uint8_t reporting_detail, char *ssid,
		uint8_t num_report, struct sta_channel_report *report,
		uint8_t num_element, uint8_t *element);
struct cmdu_buff *agent_gen_cmdu_beacon_metrics_resp(struct agent *a,
		uint8_t *sta_addr, uint8_t report_elems_nr,
		uint8_t *report_elem, uint16_t elem_len);
struct cmdu_buff *agent_gen_unassoc_sta_metric_query(struct agent *a,
		uint8_t *origin, uint8_t opclass,
		uint8_t num_metrics, struct unassoc_sta_metric *metrics);
struct cmdu_buff *agent_gen_tunneled_msg(struct agent *a, uint8_t protocol,
		uint8_t *sta, int frame_len, uint8_t *frame_body);
struct cmdu_buff *agent_gen_vendor_specific_cmdu(struct agent *a, uint8_t *origin, uint8_t depth);
struct cmdu_buff *agent_gen_independent_ch_scan_response(struct agent *a,
		struct wifi_netdev *ndev);
struct cmdu_buff *agent_gen_ch_scan_response_radio(struct agent *a,
		struct wifi_netdev *ndev,
		struct wifi_scan_request_radio *req, uint8_t status);
struct cmdu_buff *agent_gen_ap_caps_query(struct agent *a, uint8_t *origin);
struct cmdu_buff *agent_gen_ap_caps_response(struct agent *a,
		struct cmdu_buff *rec_cmdu);
struct cmdu_buff *agent_gen_bk_caps_response(struct agent *a,
		struct cmdu_buff *cmdu);
struct cmdu_buff *agent_gen_topology_notification (struct agent *agent,
		uint8_t *mac, uint8_t *bssid, uint8_t assoc_event);
struct cmdu_buff *agent_gen_ap_autoconfig_wsc(struct agent *a, struct cmdu_buff *rx_cmdu,
		struct wifi_radio_element *radio);
struct cmdu_buff *agent_gen_cmdu_1905_ack(
		struct agent *a, uint8_t *origin, uint16_t mid,
		struct sta_error_response *sta_resp, uint32_t sta_count);
struct cmdu_buff *agent_gen_cmdu_backhaul_steer_resp(struct agent *a,
		uint8_t *target_bssid, uint8_t *macaddr, uint16_t mid);
struct cmdu_buff *agent_gen_topology_query(struct agent *a, uint8_t *origin);
struct cmdu_buff *agent_gen_topology_response(struct agent *a, uint8_t *origin,
		uint16_t mid);

struct cmdu_buff *agent_gen_client_disassoc(struct agent *a,
					    uint8_t *mac, uint8_t *bssid, uint16_t reason);
struct cmdu_buff *agent_gen_channel_preference_report(struct agent *a,
		struct cmdu_buff *rx_cmdu);
struct cmdu_buff *agent_gen_association_status_notify(struct agent *a,
		int num_data, void *data);
struct cmdu_buff *agent_gen_sta_caps_response(struct agent *a,
		struct cmdu_buff *rx_cmdu, struct node *n);

struct cmdu_buff *agent_gen_higher_layer_data(struct agent *a, uint8_t *addr,
		uint8_t proto, uint8_t *data, int len);
struct cmdu_buff *agent_gen_assoc_sta_metric_responsex(struct agent *a,
		uint8_t *origin, struct sta *s, struct netif_fh *fh);
struct cmdu_buff *agent_gen_oper_channel_response(struct agent *a,
		struct wifi_radio_element *radio, uint32_t channel,
		uint32_t bandwidth, bool all);
struct cmdu_buff *agent_gen_topology_discovery(struct agent *a);
struct cmdu_buff *agent_gen_failed_connection(struct agent *a,
		uint8_t *sta, int status_code, int reason_code);
#if (EASYMESH_VERSION > 2)
struct cmdu_buff *agent_gen_bss_configuration_request(struct agent *a);
struct cmdu_buff *agent_gen_bss_configuration_result(struct agent *a);
struct cmdu_buff *agent_gen_dpp_bootstrapping_uri_notification(
		struct agent *a, uint8_t *radio_id, uint8_t *bssid,
		uint8_t *bksta, char *dpp_uri, int uri_len);
#endif

#endif /* MAPAGENT_CMDU_H */
