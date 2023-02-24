/*
 * agent_tlv.h - tlv building function declarations
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: jakob.olsson@iopsys.eu
 *
 */

#ifndef MAPAGENT_TLV_H
#define MAPAGENT_TLV_H

#define VENDOR_SPECIFIC_TYPE_DEPTH 0x0a

#define BUF_PUT_BE64(b, v)      buf_put_be64((uint8_t *)&(b), v)

#ifdef EASYMESH_VENDOR_EXT
struct tlv_vendor_bbss {
	uint8_t oui[3];
	uint8_t num_radios;
	struct __attribute__((packed)) radio {
		uint8_t radio_id[6];
		uint8_t num_bbss;
		struct __attribute__((packed)) backhaul_bss {
			uint8_t bssid[6];
		} bbss[];
	} radios[];
} __attribute__((packed));
#endif

int get_radio_index(struct agent *a, uint8_t *mac);
int get_bss_index(struct wifi_radio_element *radio, uint8_t *bssid);
int get_radio_and_bss_index(struct agent *a, uint8_t *bssid, int *radio_index);
uint8_t rssi_to_rcpi(int rssi);
int agent_gen_ap_ht_caps(struct agent *a,
		struct cmdu_buff *cmdu, uint32_t radio_index);
int agent_gen_ap_he_caps(struct agent *a,
		struct cmdu_buff *cmdu, uint32_t radio_index);
int agent_gen_ap_caps(struct agent *a,
		struct cmdu_buff *cmdu);
int agent_gen_ap_radio_basic_cap(struct agent *a,
		struct cmdu_buff *frm, struct wifi_radio_element *radio);
int agent_gen_ap_vht_caps(struct agent *a,
		struct cmdu_buff *cmdu, uint32_t radio_index);
int agent_gen_profile2_ap_cap(struct agent *a, struct cmdu_buff *frm);
int agent_gen_ap_radio_adv_cap(struct agent *a,
		struct cmdu_buff *cmdu, struct wifi_radio_element *radio);
int agent_gen_wsc(struct agent *a, struct cmdu_buff *cmdu,
		struct wifi_radio_element *radio);
int agent_gen_ch_scan_cap(struct agent *a, struct cmdu_buff *cmdu);
int agent_gen_oper_channel_report(struct agent *a,
		struct cmdu_buff *frm, struct wifi_radio_element *radio,
		uint32_t channel, uint32_t bw, uint32_t opclass);
int agent_gen_channel_selection_resp(struct agent *a,
		struct cmdu_buff *cmdu, uint8_t *radio_recvd, uint8_t reason_code);
int agent_gen_cac_cap(struct agent *a, struct cmdu_buff *cmdu);
int agent_gen_metric_collection_interval(struct agent *a, struct cmdu_buff *cmdu);
int agent_gen_channel_pref (struct agent *a,
		struct cmdu_buff *frm, int radio_index);
int agent_gen_radio_oper_restrict(struct agent *a,
		struct cmdu_buff *frm, int radio_index);
int agent_gen_cac_complete_report(struct agent *a, struct cmdu_buff *frm);
int agent_gen_cac_status_report(struct agent *a, struct cmdu_buff *frm);
int agent_gen_tlv_error_code(struct agent *a,
	struct cmdu_buff *cmdu, uint8_t *macaddr, uint8_t reason_code);
int agent_gen_steer_btm_report(struct agent *a, struct cmdu_buff *frm,
		uint8_t *target_bssid, uint8_t *src_bssid,
		uint8_t *sta, uint8_t status_code);
int agent_gen_al_mac(struct agent *a, struct cmdu_buff *frm, uint8_t *macaddr);
int agent_gen_mac(struct agent *a, struct cmdu_buff *frm, uint8_t *macaddr);
int agent_gen_tlv_unassoc_sta_lm_query(struct agent *a,
		struct cmdu_buff *frm, uint8_t opclass,
		uint8_t num_metrics, struct unassoc_sta_metric *metrics);
int agent_gen_tlv_unassoc_sta_lm_report(struct agent *a, struct cmdu_buff *frm,
		uint8_t opclass, struct wifi_radio_element *radio);
int agent_gen_tlv_beacon_metrics_query(struct agent *a,
		struct cmdu_buff *frm, uint8_t *sta_addr,
		uint8_t opclass, uint8_t channel,
		uint8_t *bssid, uint8_t reporting_detail, char *ssid,
		uint8_t num_report, struct sta_channel_report *report,
		uint8_t num_element, const uint8_t *element);
int agent_gen_tlv_beacon_metrics_resp(struct agent *a, uint8_t *tlv,
		uint8_t *sta_addr, uint8_t report_elems_nr,
		uint8_t *report_elem, uint16_t elem_len);
int agent_gen_supported_service(struct agent *a, struct cmdu_buff *frm, uint8_t service);
int agent_gen_searched_service(struct agent *a, struct cmdu_buff *frm, uint8_t service);
int agent_gen_map_profile(struct agent *a, struct cmdu_buff *frm, uint8_t profile);
int agent_gen_autoconf_freq_band(struct agent *a, struct cmdu_buff *frm,
		uint8_t band);
int agent_gen_searched_role(struct agent *a, struct cmdu_buff *frm,
		uint8_t role);
int agent_gen_radio_metrics(struct agent *a, struct cmdu_buff *frm,
		int radio_index);
int agent_gen_ap_metrics(struct agent *a, struct cmdu_buff *frm,
		int radio_index, int bss_index);
int agent_gen_ap_ext_metrics(struct agent *a, struct cmdu_buff *frm,
		int radio_index, int bss_index);
int agent_gen_assoc_sta_traffic_stats(struct agent *a,
		struct cmdu_buff *frm, uint8_t *mac, struct sta *s);
int agent_gen_assoc_sta_link_metrics(struct agent *a,
		struct cmdu_buff *frm, struct sta *s, uint8_t *bssid);
int agent_gen_assoc_sta_ext_link_metric(struct agent *a,
		struct cmdu_buff *frm, struct sta *s, uint8_t *bssid);
int agent_gen_ap_radio_identifier(struct agent *a,
		struct cmdu_buff *frm, uint8_t *radio_id);
int agent_gen_ap_metric_query(struct agent *a, struct cmdu_buff *frm,
		int num_bss, uint8_t *bsslist);
int agent_gen_source_info(struct agent *a,
		struct cmdu_buff *frm, uint8_t *mac);
int agent_gen_tunnel_msg_type(struct agent *a,
		struct cmdu_buff *frm, uint8_t protocol);
int agent_gen_tunneled(struct agent *a, struct cmdu_buff *frm,
		int frame_len, uint8_t *frame_body);
struct tlv_vendor_specific *agent_gen_vendor_specific_tlv(struct agent *a, uint8_t depth);
#ifdef EASYMESH_VENDOR_EXT
int agent_gen_vendor_specific_bbbs_tlv(struct agent *a, struct cmdu_buff *frm);
#endif
int agent_gen_timestamp_tlv(struct agent *agent, struct cmdu_buff *frm);
int agent_gen_ch_scan_response_tlv(struct agent *a, struct cmdu_buff *cmdu,
		uint8_t *radio_mac, uint8_t opclass_id,
		struct wifi_scanres_channel_element *ch, uint8_t status);
int agent_gen_bk_sta_radio_cap_tlv(struct agent *a, uint32_t radio_index, struct cmdu_buff *cmdu);
int agent_gen_client_assoc_event_tlv(struct agent *agent, struct cmdu_buff *frm,
		uint8_t *mac, uint8_t *bssid, uint8_t assoc_event);
int agent_gen_sta_mac(struct agent *agent,
		struct cmdu_buff *frm, uint8_t *mac);
int agent_gen_reason_code(struct agent *agent,
		struct cmdu_buff *frm, uint16_t reason_code);
int agent_gen_tlv_backhaul_steer_resp(struct agent *a, struct cmdu_buff *frm,
		uint8_t *target_bssid, uint8_t *macaddr);
int agent_gen_ap_oper_bss_tlv(struct agent *a, struct cmdu_buff *frm);
int agent_gen_assoc_client_tlv(struct agent *a, struct cmdu_buff *frm);
int agent_gen_assoc_status_notif(struct agent *a, struct cmdu_buff *frm,
		int num_data, void *data);
int agent_gen_tlv_higher_layer_data(struct agent *a, struct cmdu_buff *frm,
		uint8_t proto, uint8_t *data, int len);
int agent_gen_client_info(struct agent *a, struct cmdu_buff *frm,
		uint8_t *sta, uint8_t *bssid);
int agent_gen_client_cap_report(struct agent *a, struct cmdu_buff *frm,
		uint8_t result, struct sta *s);
int agent_gen_vendor_specific_sta_linkmetric_tlv(struct agent *a, struct cmdu_buff *frm);
int agent_gen_status_code(struct agent *a, struct cmdu_buff *frm, int status_code);
#if (EASYMESH_VERSION > 2)
int agent_gen_bss_config_report_tlv(struct agent *a, struct cmdu_buff *frm);
int agent_gen_akm_suite_cap(struct agent *a, struct cmdu_buff *frm);
int agent_gen_conf_req_object_atrributes(struct agent *a, struct cmdu_buff *frm);
#endif


/* Policy config related functions */
int agent_fill_steering_policy(struct agent *a,
		struct tlv_steering_policy *p,
		struct uci_context *ctx, struct uci_package *pkg);
int agent_fill_metric_report_policy(struct agent *a,
		struct tlv_metric_report_policy *p,
		struct uci_context *ctx, struct uci_package *pkg);
int agent_fill_8021q_setting(struct agent *a, uint16_t pvid, uint8_t pcp);
int agent_fill_8021q_setting_from_tlv(struct agent *a,
		struct tlv_default_8021q_settings *p);
int agent_clear_traffic_sep(struct agent *a);
int agent_fill_traffic_sep_policy(struct agent *a,
		struct tlv_traffic_sep_policy *p);
int agent_fill_ch_scan_rep_policy(struct agent *a,
		struct tlv_channel_scan_report_policy *p,
		struct uci_context *ctx, struct uci_package *pkg);
int agent_fill_unsuccess_assoc_policy(struct agent *a,
		struct tlv_unsuccess_assoc_policy *p,
		struct uci_context *ctx, struct uci_package *pkg);
int agent_fill_backhaul_bss_config(struct agent *a,
		struct tlv_bbss_config *p,
		struct uci_context *ctx, struct uci_package *pkg);
int agent_fill_backhaul_bss_config_all(struct agent *a,
		struct tlv_bbss_config *p,
		struct uci_context *ctx, struct uci_package *pkg);

#if (EASYMESH_VERSION > 2)
int agent_gen_device_1905_layer_security_cap(struct agent *a,
		struct cmdu_buff *frm);
int agent_gen_device_inventory(struct agent *a, struct cmdu_buff *frm);
int agent_gen_dpp_chirp(struct agent *a, struct cmdu_buff *frm);
int agent_gen_assoc_wifi6_sta_status_report(struct agent *a,
		struct cmdu_buff *frm, struct sta *s);
int agent_gen_dpp_bootstrapping_uri_notif(struct agent *a,
		struct cmdu_buff *frm, uint8_t *radio_id, uint8_t *bssid,
		uint8_t *bksta, char *dpp_uri, int uri_len);
#endif

#endif /* MAPAGENT_TLV_H */
