
#ifndef	CMDU_VALIDATE
#define CMDU_VALIDATE

bool validate_channel_scan_request(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile);
bool validate_topology_response(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile);
bool validate_ap_autoconfig_wsc(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile);
bool validate_ap_autoconfig_search(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile);
bool validate_ap_autoconfig_response(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile);
bool validate_ap_autoconfig_renew(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile);
bool validate_ap_caps_report(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile);

#if (EASYMESH_VERSION > 2)
/**
 * @enum enum bss_configuration_response_tlvs_order
 * @brief specifies order of output TLVs and max. number of different TLVs
 *		for validate_bss_configuration_response function.
 */
enum bss_configuration_response_tlvs_order {
	BSS_CFG_RESP_BSS_CONFIG_RESPONSE_IDX, // 0
	BSS_CFG_RESP_DEFAULT_8021Q_SETTINGS_IDX,
	BSS_CFG_RESP_TRAFFIC_SEPARATION_POLICY_IDX,

	BSS_CFG_RESP_MAX_NUMBER_OF_TLV_TYPES
};

bool validate_bss_configuration_response(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile);
bool validate_agent_list(struct cmdu_buff *cmdu, struct tlv *tv[][16], size_t tv_size, uint8_t profile);
#endif /* EASYMESH_VERSION > 2 */

#endif	/* CMDU_VALIDATE */
