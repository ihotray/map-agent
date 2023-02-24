
#ifndef AGENT_MAP_H
#define AGENT_MAP_H

#define RCPI_THRESHOLD_TIMER	(5 * 1000)
#define RADIO_STATS_TIMER	(1 * 1000)

struct channel_response;

/** enum bssid informatino field - bit-flags */
enum bssid_information {
	BSSID_INFO_REACHABILITY_B0,
	BSSID_INFO_REACHABILITY_B1,
	BSSID_INFO_SECURITY,
	BSSID_INFO_KEY_SCOPE,

	BSSID_INFO_CAP_SPECTRUM_MGMT,
	BSSID_INFO_CAP_WMM,
	BSSID_INFO_CAP_APSD,
	BSSID_INFO_CAP_RADIO_MEAS,
	BSSID_INFO_CAP_DELAYED_BA,
	BSSID_INFO_CAP_IMMEDIATE_BA,

	BSSID_INFO_MOBILITY_DOMAIN,
	BSSID_INFO_HT,
	BSSID_INFO_VHT,
	BSSID_INFO_FMT,

	BSSID_INFO_AFTER_LAST,
	BSSID_INFO_MAX = BSSID_INFO_AFTER_LAST - 1
};

#define agent_bssid_info_set(b, f) ((b) |= (1 << (f)))

uint8_t *extract_tlv_by_type(struct cmdu_buff *cmdu, uint8_t tlv_type);

extern bool is_cmdu_for_us(struct agent *a, uint16_t type);

extern int agent_handle_map_cmd(struct agent *a, char *data, int len);

int agent_handle_map_event(struct agent *a, uint16_t cmdutype, uint16_t mid,
	char *rxif, uint8_t *src, uint8_t *origin, uint8_t *tlvs, int len);
int handle_wifi_radio_scan_finished(struct agent *a,
		struct wifi_netdev *ndev);
int agent_get_highest_preference(struct wifi_radio_element *radio,
		uint32_t op_class_id, uint32_t *channel,
		uint32_t *opclass_to_move);
int agent_channel_switch(struct agent *a, uint8_t *radio_id, int channel,
		int opclass);
int agent_set_channel_preference_to_default(struct wifi_radio_element *radio);

uint16_t agent_send_cmdu(struct agent *a, struct cmdu_buff *cmdu);
int agent_send_cmdu_ubus(struct agent *a, struct cmdu_buff *cmdu);
int send_channel_sel_response(void *agent, struct cmdu_buff *cmdu,
		struct channel_response *rec_cmdu, uint32_t channel_response_nr);
int agent_fill_radio_max_preference(void *agent,
		struct channel_response *channel_resp, uint32_t *channel_response_nr);
int agent_process_channel_pref_tlv(void *agent, struct tlv_channel_pref  *p,
		struct channel_response *channel_resp,
		uint32_t *channel_response_nr);
int agent_process_unassoc_sta_lm_query_tlv(struct agent *a,
		struct tlv_unassoc_sta_link_metrics_query *query,
		struct cmdu_buff *cmdu);
int send_steer_btm_report(void *agent, uint8_t *origin, const char *intf_name,
		uint8_t *target_bssid, uint8_t *src_bssid,
		uint8_t *sta, uint8_t status_code);
int send_beacon_metrics_response(void *agent, uint8_t *sta_addr,
		uint8_t report_elems_nr, uint8_t *report_elem,
		uint16_t elem_len);
int send_topology_query(void *agent, uint8_t *origin);
int send_sta_steer_complete(void *agent, uint8_t *origin, const char *intf_name);
#if (EASYMESH_VERSION > 2)
int send_bss_configuration_request(struct agent *agent);
#endif
uint16_t agent_send_cmdu_unish(struct agent *a, struct cmdu_buff *cmdu);
int send_1905_acknowledge(void *agent, uint8_t *origin, uint16_t mid,
		struct sta_error_response *sta_resp, uint32_t sta_count);
int send_failed_connection_msg(void *agent, uint8_t *sta, int status_code, int reason_code);


//int agent_prepare_traffic_separation(struct agent *a);
int agent_apply_traffic_separation(struct agent *a);
int agent_disable_traffic_separation(struct agent *a);

void update_neighbors_from_scanlist(struct agent *a, struct wifi_radio_element *re);
int wifi_radio_update_opclass_preferences(struct agent *a, const char *radio, bool send_report);
int wifi_radio_scan_req_all(struct agent *a, const char *radio);
#if (EASYMESH_VERSION > 2)
int handle_agent_list(void *agent, struct cmdu_buff *cmdu, struct node *n);
#endif
int agent_set_link_profile(struct agent *a, struct node *n,
			   struct cmdu_buff *cmdu);
struct tlv_channel_scan_request *alloc_channel_scan_req(struct cmdu_buff *req_cmdu,
		uint8_t map_profile);

#endif /* AGENT_MAP_H */
