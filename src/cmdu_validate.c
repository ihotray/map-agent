#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <json-c/json.h>

#include <easymesh.h>
#include <1905_tlvs.h>
#include <cmdu.h>
#include <map_module.h>

#include "cmdu_validate.h"
#include "utils/debug.h"

bool validate_channel_scan_request(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile)
{
	int ret = 0;

	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));

		return false;
	}

	if (!tv[0][0]) {
		dbg("%s: No CHANNEL_SCAN_REQ_TLV received!!\n", __func__);
		return false;
	}

	if (tv[0][0]) {
		int i, j;
		int offset = 0;
		int num_radio = 0;
		uint8_t *t = NULL;
		uint16_t tlv_len = tlv_length(tv[0][0]);

		t = (uint8_t *)tv[0][0]->data;
		if (!t)
			return false;

		/* offset within provided minlen(2) */
		offset += 1;	/* mode */
		num_radio = t[offset];
		offset += 1;	/* num radio */

		for (i = 0; i < num_radio; i++) {
			int num_opclass = 0;

			if ((offset + 6 + 1) > tlv_len)
				return false;

			offset += 6;	/* radio id */
			num_opclass = t[offset];
			offset += 1;	/* num opclass */

			for (j = 0; j < num_opclass; j++) {
				int num_ch = 0;

				if ((offset + 1 + 1) > tlv_len)
					return false;

				offset += 1;	/* class id */
				num_ch = t[offset];
				offset += 1;	/* num_channel */

				if ((offset + num_ch) > tlv_len)
					return false;

				offset += num_ch;	/* channels */
			}
		}
	}

	return true;
}

bool validate_topology_response(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile)
{
	int ret = 0;

	trace("%s |" MACFMT "|CMDU: topology response\n",
			__func__, MAC2STR(cmdu->origin));

	ret = map_cmdu_parse_tlvs(cmdu, tv, 12, profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));

		return false;
	}

	if (!tv[7][0])
		return false;

	/* MAP_TLV_AP_OPERATIONAL_BSS */
	if (tv[7][0]) {
		struct tlv_ap_oper_bss *tlv;
		uint8_t *tv_data;
		uint16_t tlv_len = 0;
		int i, offset = 0;

		tlv_len = tlv_length(tv[7][0]);
		if (!tlv_len)
			return false;

		tlv = (struct tlv_ap_oper_bss *)tv[7][0]->data;
		if (!tlv)
			return false;

		tv_data = (uint8_t *)tlv;

		/* num_radio (1 byte) */
		if (offset + 1 > tlv_len)
			return false;

		offset += 1;

		for (i = 0; i < tlv->num_radio; i++) {
			uint8_t num_bss = 0;
			int j;

			/* macaddr (6 bytes) */
			if (offset + 6 > tlv_len)
				return false;

			offset += 6;

			/* num_bss (1 byte) */
			if (offset + 1 > tlv_len)
				return false;

			memcpy(&num_bss, &tv_data[offset], 1);

			offset += 1;

			for (j = 0; j < num_bss; j++) {
				uint8_t ssidlen = 0;

				/* macaddr (6 bytes) */
				if (offset + 6 > tlv_len)
					return false;

				offset += 6;

				/* ssidlen (1 byte) */
				if (offset + 1 > tlv_len)
					return false;

				memcpy(&ssidlen, &tv_data[offset], 1);

				offset += 1;

				/* ssid (ssidlen bytes) */
				if (offset + ssidlen > tlv_len)
					return false;

				offset += ssidlen;
			}
		}
	}

	return true;
}

#define ATTR_MSG_TYPE	(0x1022)
#define MSG_TYPE_M2		(0x05)
static int validate_wsc_m2(uint8_t *m2, uint16_t m2_size)
{
	uint8_t *data;
	uint8_t *m2_end;
	bool ret = -1;

	if (!m2 || !m2_size)
		return -1;

	data = m2;
	m2_end = m2 + m2_size;

	while (labs(data - m2) < m2_size - 4) {
		uint16_t attr_type;
		uint16_t attr_len;

		attr_type = buf_get_be16(data);
		data += 2;
		attr_len = buf_get_be16(data);
		data += 2;

		if (data + attr_len > m2_end) {
			dbg("%s: parse_wsc_m2 failed\n", __func__);
			ret = -1;
			break;
		}

		if (attr_type == ATTR_MSG_TYPE) {
			if (attr_len != 1) {
				ret = -1;
				break;
			}
			if (*data == MSG_TYPE_M2)
				ret = 0;
		}

		data += attr_len;
	}

	/* true if msg type is M2 & data never goes OOB */
	return ret;
}

/* Check WSC TLV (containing M2) */
static int check_wsc_tlv(struct tlv *t)
{
	uint8_t *tv_data;
	uint16_t tlv_len;

	if (!t)
		return -1;

	tlv_len = tlv_length(t);
	if (!tlv_len)
		return -1;

	tv_data = (uint8_t *)t->data;
	if (!tv_data)
		return -1;

	return validate_wsc_m2(tv_data, tlv_len);
}

static int check_serialized_tlv(struct tlv *t, uint16_t len)
{
	uint8_t *tv_data;
	uint16_t tlv_len;

	if (!t)
		return -1;

	tlv_len = tlv_length(t);

	if (tlv_len != len)
		return -1;

	tv_data = (uint8_t *)t->data;
	if (!tv_data)
		return -1;

	return 0;
}

/* Check 1905.1 AL MAC address type TLV */
static int check_al_mac_addr_type_tlv(struct tlv *t)
{
	/* macaddr (6 bytes) */
	return check_serialized_tlv(t, 6);
}

/* Check AP Radio Indentifier TLV */
static int check_ap_radio_dentifier_tlv(struct tlv *t)
{
	/* bssid (6 bytes) */
	return check_serialized_tlv(t, 6);
}

/* Check Default 802.1Q Settings TLV */
static int check_default_11q_settings_tlv(struct tlv *t)
{
	/* pvid + pcp (3 bytes) */
	return check_serialized_tlv(t,
				sizeof(struct tlv_default_8021q_settings));
}

/* Check SupportedFreqBand TLV */
static int check_supported_band_tlv(struct tlv *t)
{
	/* band (1 byte) */
	return check_serialized_tlv(t,
				sizeof(struct tlv_supported_band));
}

/* Check SupportedRole TLV */
static int check_supported_role_tlv(struct tlv *t)
{
	/* role (1 byte) */
	return check_serialized_tlv(t,
				sizeof(struct tlv_supported_role));
}

/* Check AP Capability TLV */
static int check_ap_capability_tlv(struct tlv *t)
{
	/* cap (1 byte) */
	return check_serialized_tlv(t,
				sizeof(struct tlv_ap_cap));
}

/* Check Profile-2 AP Capability TLV */
static int check_profile2_ap_capability_tlv(struct tlv *t)
{
	/* reserved(2) + unit(1) + max_vids(1 byte) */
	return check_serialized_tlv(t,
				sizeof(struct tlv_profile2_ap_cap));
}

/* Check Metric Collection Interval TLV */
static int check_metric_collection_interval_tlv(struct tlv *t)
{
	/* interval (4 bytes) */
	return check_serialized_tlv(t,
				sizeof(struct tlv_metric_collection_int));
}

/* Check APHTCapabilities TLV */
static int check_ap_ht_capability_tlv(struct tlv *t)
{
	/* radio (6 bytes) + cap (1 byte) */
	return check_serialized_tlv(t,
				sizeof(struct tlv_ap_ht_cap));
}

/* Check APVHTCapabilities TLV */
static int check_ap_vht_capability_tlv(struct tlv *t)
{
	/* radio (6) + rx (2) + tx (2) + cap (2 bytes) */
	return check_serialized_tlv(t,
				sizeof(struct tlv_ap_vht_cap));
}

/* Check Traffic Separation Policy TLV */
static int check_traffic_separation_policy_tlv(struct tlv *t)
{
	int i, offset = 0;
	uint8_t num_ssid;
	uint8_t *tv_data;
	uint16_t tlv_len;

	if (!t)
		return -1;

	tlv_len = tlv_length(t);
	/* at least 1 byte: num_ssid */
	if (tlv_len < 1)
		return -1;

	tv_data = (uint8_t *)t->data;
	if (!tv_data)
		return -1;

	num_ssid = tv_data[offset++];

	for (i = 0; i < num_ssid; i++) {
		int ssid_len;

		/* ssid_len (1 byte) */
		if (offset + 1 > tlv_len)
			return -1;
		ssid_len = tv_data[offset++];

		/* ssid (ssid_len bytes) */
		if (offset + ssid_len > tlv_len)
			return -1;
		offset += ssid_len;

		/* vid (2 bytes) */
		if (offset + 2 > tlv_len)
			return -1;
		offset += 2;
	}

	return 0;
}

/* AP Radio Basic Capabilities TLV */
static int check_ap_radio_basic_caps_tlv(struct tlv *t)
{
	int i, offset = 0;
	uint8_t num_opclass;
	uint8_t *tv_data;
	uint16_t tlv_len;

	if (!t)
		return -1;

	tlv_len = tlv_length(t);
	/* at least 1 byte: num_ssid */
	if (tlv_len < 1)
		return -1;

	tv_data = (uint8_t *)t->data;
	if (!tv_data)
		return -1;

	/* radio (6 bytes) */
	if (offset + 6 > tlv_len)
		return -1;
	offset += 6;

	/* max_bssnum (1 byte) */
	if (offset + 1 > tlv_len)
		return -1;
	offset += 1;

	/* num_opclass (1 byte) */
	if (offset + 1 > tlv_len)
		return -1;
	num_opclass = tv_data[offset++];

	for (i = 0; i < num_opclass; i++) {
		int num_nonop_channel;

		/* classid (1 byte) */
		if (offset + 1 > tlv_len)
			return -1;
		offset += 1;

		/* max_txpower (1 byte) */
		if (offset + 1 > tlv_len)
			return -1;
		offset += 1;

		/* num_nonop_channel (1 byte) */
		if (offset + 1 > tlv_len)
			return -1;
		num_nonop_channel = tv_data[offset++];

		/* nonop_channel[] (num_nonop_channel bytes) */
		if (offset + num_nonop_channel > tlv_len)
			return -1;
		offset += num_nonop_channel;
	}

	return 0;
}

/* Check AP HE Capabilities TLV */
static int check_ap_he_capability_tlv(struct tlv *t)
{
	int offset = 0;
	uint8_t len;
	uint8_t *tv_data;
	uint16_t tlv_len;

	if (!t)
		return -1;

	tlv_len = tlv_length(t);
	/* at least 1 byte: num_ssid */
	if (tlv_len < 1)
		return -1;

	tv_data = (uint8_t *)t->data;
	if (!tv_data)
		return -1;

	/* radio (6 bytes) */
	if (offset + 6 > tlv_len)
		return -1;
	offset += 6;

	/* len (1 byte) */
	if (offset + 1 > tlv_len)
		return -1;
	len = tv_data[offset++];

	/* mcs[] (len bytes) */
	if (offset + len > tlv_len)
		return -1;
	offset += len;

	/* caps (2 bytes) */
	if (offset + 2 > tlv_len)
		return -1;

	return 0;
}

/* Check Channel Scan Capability TLV */
static int check_channel_scan_capability_tlv(struct tlv *t)
{
	int i, j, offset = 0;
	uint8_t num_radio;
	uint8_t *tv_data;
	uint16_t tlv_len;

	if (!t)
		return -1;

	tlv_len = tlv_length(t);
	/* at least 1 byte: num_ssid */
	if (tlv_len < 1)
		return -1;

	tv_data = (uint8_t *)t->data;
	if (!tv_data)
		return -1;

	/* num_radio (1 byte) */
	if (offset + 1 > tlv_len)
		return -1;
	num_radio = tv_data[offset++];

	for (i = 0; i < num_radio; i++) {
		int num_opclass;

		/* radio (6 bytes) */
		if (offset + 6 > tlv_len)
			return -1;
		offset += 6;

		/* cap (1) + min_scan_interval (4 bytes) */
		if (offset + 5 > tlv_len)
			return -1;
		offset += 5;

		/* num_opclass (1 byte) */
		if (offset + 1 > tlv_len)
			return -1;
		num_opclass = tv_data[offset++];

		for (j = 0; j < num_opclass; j++) {
			int num_channel;

			/* classid (1 byte) */
			if (offset + 1 > tlv_len)
				return -1;
			offset += 1;

			/* num_channel (1 byte) */
			if (offset + 1 > tlv_len)
				return -1;
			num_channel = tv_data[offset++];

			/* channel[] (num_channel) */
			if (offset + num_channel > tlv_len)
				return -1;
			offset += num_channel;
		} /* for j */
	} /* for i */

	return 0;
}

/* Check Channel Scan Capability TLV */
static int check_cac_capability_tlv(struct tlv *t)
{
	int i, j, k, offset = 0;
	uint8_t num_radio;
	uint8_t *tv_data;
	uint16_t tlv_len;

	if (!t)
		return -1;

	tlv_len = tlv_length(t);
	/* at least 1 byte: num_ssid */
	if (tlv_len < 1)
		return -1;

	tv_data = (uint8_t *)t->data;
	if (!tv_data)
		return -1;

	/* country (2 bytes) */
	if (offset + 2 > tlv_len)
		return -1;
	offset += 2;

	/* num_radio (1 byte) */
	if (offset + 1 > tlv_len)
		return -1;
	num_radio = tv_data[offset++];

	for (i = 0; i < num_radio; i++) {
		int num_cac;

		/* radio (6 bytes) */
		if (offset + 6 > tlv_len)
			return -1;
		offset += 6;

		/* num_cac (1 byte) */
		if (offset + 1 > tlv_len)
			return -1;
		num_cac = tv_data[offset++];

		for (j = 0; j < num_cac; j++) {
			int num_opclass;

			/* supp_method (1) + duration (3 bytes) */
			if (offset + 4 > tlv_len)
				return -1;
			offset += 4;

			/* num_opclass (1 byte) */
			if (offset + 1 > tlv_len)
				return -1;
			num_opclass = tv_data[offset++];

			for (k = 0; k < num_opclass; k++) {
				int num_channel;

				/* classid (1 byte) */
				if (offset + 1 > tlv_len)
					return -1;
				offset += 1;

				/* num_channel (1 byte) */
				if (offset + 1 > tlv_len)
					return -1;
				num_channel = tv_data[offset++];

				/* channel[] (num_channel) */
				if (offset + num_channel > tlv_len)
					return -1;
				offset += num_channel;
			} /* for k */
		} /* for j */
	} /* for i */

	return 0;
}

/* Check service TLV */
static int check_service_tlv(struct tlv *t)
{
	int offset = 0;
	uint8_t num_services;
	uint8_t *tv_data;
	uint16_t tlv_len;

	if (!t)
		return -1;

	tlv_len = tlv_length(t);
	/* at least 1 byte: num_services */
	if (tlv_len < 1)
		return -1;

	tv_data = (uint8_t *)t->data;
	if (!tv_data)
		return -1;

	num_services = tv_data[offset++];

	/* services (num_services bytes) */
	if (offset + num_services > tlv_len)
		return -1;

	return 0;
}

/* Check SupportedService TLV */
static int check_supported_service_tlv(struct tlv *t)
{
	return check_service_tlv(t);
}

/* Check SearchedService TLV */
static int check_searched_service_tlv(struct tlv *t)
{
	return check_service_tlv(t);
}

#if (EASYMESH_VERSION > 2)
static int check_bss_config_response_tlv(struct tlv *t)
{
	const uint16_t tlv_len = tlv_length(t);
	json_tokener *tok;
	json_object *jsobj;
	int result;

	if (!t->data)
		return -1;

	if (!t->len)
		return -1;

	/* Check whether TLV is valid JSON object */
	tok = json_tokener_new();
	if (!tok)
		return -1;

	result = 0;
	jsobj = json_tokener_parse_ex(tok, (const char *)t->data, tlv_len);
	if (!jsobj || !json_object_is_type(jsobj, json_type_object))
		result = -1;

	json_tokener_free(tok);

	return result;
}
#endif /* EASYMESH_VERSION > 2 */

bool validate_ap_autoconfig_wsc(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile)
{
	struct tlv_policy a_policy[] = {
		[0] = { .type = MAP_TLV_AP_RADIO_IDENTIFIER,
				.present = TLV_PRESENT_ONE,
				.minlen = 6, /* bssid */
				.maxlen = 6,
		},
		[1] = { .type = TLV_TYPE_WSC,
				.present = TLV_PRESENT_MORE,
		},
		[2] = { .type = MAP_TLV_DEFAULT_8021Q_SETTINGS,
				.present = TLV_PRESENT_OPTIONAL_ONE,
				.minlen = 3, /* tlv_default_8021q_settings */
		},
		[3] = { .type = MAP_TLV_TRAFFIC_SEPARATION_POLICY,
				.present = TLV_PRESENT_OPTIONAL_ONE,
				.minlen = 1, /* tlv_traffic_sep_policy: num_ssid */
		}
	};
	int num = 0;
	int ret;

	trace("%s |" MACFMT "|CMDU: ap autoconfig WSC\n",
	      __func__, MAC2STR(cmdu->origin));

	ret = cmdu_parse_tlvs(cmdu, tv, a_policy, 4);
	if (ret) {
		dbg("%s: parse_tlv failed\n", __func__);
		return false;
	}

	if (!tv[0][0] || !tv[1][0]) {
		dbg("%s: Missing one or more mandatory TLV!\n", __func__);
		return false;
	}

	/* Parse AP Radio Identifier TLV */
	if (check_ap_radio_dentifier_tlv(tv[0][0]))
		return false;

	/* Parse WSC TLVs (containing M2) */
	while (tv[1][num]) {
		if (check_wsc_tlv(tv[1][num]))
			return false;
		num++;
	}

	/* Parse Default 802.1Q Settings TLV */
	if (tv[2][0] && check_default_11q_settings_tlv(tv[2][0]))
		return false;

	/* Parse Traffic Separation Policy TLV */
	if (tv[3][0] && check_traffic_separation_policy_tlv(tv[3][0]))
		return false;

	return true;
}

/* 0: 1905.1 AL MAC address type TLV
 * 1: SearchedRole TLV
 * 2: AutoconfigFreqBand TLV
 * 3: SupportedService TLV
 * 4: SearchedService TLV
 * 5: MultiAP Profile TLV
 **/
bool validate_ap_autoconfig_search(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile)
{
	int ret;

	trace("%s |" MACFMT "|CMDU: ap autoconfig search\n",
		  __func__, MAC2STR(cmdu->origin));

	ret = map_cmdu_parse_tlvs(cmdu, tv, 7, profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));

		return false;
	}

	if (tv[3][0] && check_supported_service_tlv(tv[3][0]))
		return false;

	if (tv[4][0] && check_searched_service_tlv(tv[4][0]))
		return false;

	return true;
}

/* 0: SupportedRole TLV
 * 1: SupportedFreqBand TLV
 * 2: SupportedService TLV
 * 3: MultiAP Profile TLV
 **/
bool validate_ap_autoconfig_response(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile)
{
	int ret;

	trace("%s |" MACFMT "|CMDU: ap autoconfig response\n",
		  __func__, MAC2STR(cmdu->origin));

	ret = map_cmdu_parse_tlvs(cmdu, tv, 7, profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));

		return false;
	}

	if (tv[2][0] && check_supported_service_tlv(tv[2][0]))
		return false;

	return true;
}

bool validate_ap_autoconfig_renew(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile)
{

	int ret;

	trace("%s |" MACFMT "|CMDU: ap autoconfig renew\n",
		  __func__, MAC2STR(cmdu->origin));

	ret = map_cmdu_parse_tlvs(cmdu, tv, 3, profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));

		return false;
	}

	if (!tv[0][0] || !tv[1][0] || !tv[2][0]) {
		dbg("%s: Missing one or more mandatory TLV!\n", __func__);
		return false;
	}

	/* Parse 1905.1 AL MAC address type TLV */
	if (check_al_mac_addr_type_tlv(tv[0][0]))
		return false;

	/* Parse SupportedRole TLV */
	if (check_supported_role_tlv(tv[1][0]))
		return false;

	/* Parse SupportedFreqBand TLV */
	if (check_supported_band_tlv(tv[2][0]))
		return false;

	return true;
}

bool validate_ap_caps_report(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile)
{
	int ret = 0;
	int num = 0;

	trace("%s |" MACFMT "|CMDU: ap caps report\n",
			__func__, MAC2STR(cmdu->origin));

	ret = map_cmdu_parse_tlvs(cmdu, tv, 13, profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));

		return false;
	}

	if (!tv[0][0] || !tv[1][0] || !tv[5][0] || !tv[6][0] || !tv[7][0] || !tv[8][0]) {
		dbg("%s: Missing one or more mandatory TLV!\n", __func__);
		return false;
	}

	/* Parse one AP Capability TLV */
	if (check_ap_capability_tlv(tv[0][0]))
		return false;

	/* Parse one or more AP Radio Basic Capabilities TLV */
	num = 0;
	while (tv[1][num]) {
		if (check_ap_radio_basic_caps_tlv(tv[1][num]))
			return false;
		num++;
	}

	/* Parse zero or more AP HT Capabilities TLV */
	num = 0;
	while (tv[2][num]) {
		if (check_ap_ht_capability_tlv(tv[2][num]))
			return false;
		num++;
	}

	/* Parse zero or more AP VHT Capabilities TLV */
	num = 0;
	while (tv[3][num]) {
		if (check_ap_vht_capability_tlv(tv[3][num]))
			return false;
		num++;
	}

	/* Parse zero or more AP HE Capabilities TLV */
	num = 0;
	while (tv[4][num]) {
		if (check_ap_he_capability_tlv(tv[4][num]))
			return false;
		num++;
	}

	/* Parse one Channel Scan Capabilities TLV */
	if (check_channel_scan_capability_tlv(tv[5][0]))
		return false;

	/* Parse one CAC Capabilities TLV */
	if (check_cac_capability_tlv(tv[6][0]))
		return false;

	/* Parse one Profile-2 AP Capabilities TLV */
	if (check_profile2_ap_capability_tlv(tv[7][0]))
		return false;

	/* Parse one Metric Collection Interval TLV */
	if (check_metric_collection_interval_tlv(tv[8][0]))
		return false;

	return true;
}

#if (EASYMESH_VERSION > 2)
bool validate_bss_configuration_response(struct cmdu_buff *cmdu, struct tlv *tlvs[][16], uint8_t profile)
{
	const int easymesh_rev = profile;
	int i;
	struct tlv *tlv;
	const int max_num_of_tlvs = 16;

	if (map_cmdu_parse_tlvs(cmdu, tlvs, BSS_CFG_RESP_MAX_NUMBER_OF_TLV_TYPES, easymesh_rev)) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return false;
	}

	i = 0;
	while ((i < max_num_of_tlvs) && tlvs[BSS_CFG_RESP_BSS_CONFIG_RESPONSE_IDX][i]) {
		if (check_bss_config_response_tlv(tlvs[BSS_CFG_RESP_BSS_CONFIG_RESPONSE_IDX][i]))
			return false;
		++i;
	}

	/* Check optional TLVs if present */
	tlv = tlvs[BSS_CFG_RESP_DEFAULT_8021Q_SETTINGS_IDX][0];
	if (tlv && check_default_11q_settings_tlv(tlv))
		return false;

	tlv = tlvs[BSS_CFG_RESP_TRAFFIC_SEPARATION_POLICY_IDX][0];
	if (tlv && check_traffic_separation_policy_tlv(tlv))
		return false;

	return true;
}

bool validate_agent_list(struct cmdu_buff *cmdu, struct tlv *tlvs[][16], size_t tlvs_size, uint8_t profile)
{
	int ret = map_cmdu_parse_tlvs(cmdu, tlvs, tlvs_size, profile);

	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return false;
	}

	if (tlvs[0][0]) {
		int i;
		int offset = 0;
		int num_agent = 0;
		uint8_t *t = NULL;
		uint16_t tlv_len = tlv_length(tlvs[0][0]);

		t = (uint8_t *)tlvs[0][0]->data;
		if (!t)
			return false;

		num_agent = t[offset];
		offset += 1; /* num agent */

		for (i = 0; i < num_agent; i++) {
			/* 8 bytes = al macaddr (6 byte) + profile (1 byte) + security (1 byte)*/
			offset += 8;
			if (offset > tlv_len)
				return false;
		}
	}

        return true;
}
#endif /* EASYMESH_VERSION > 2 */
