/*
 * agent_tlv.c - tlv building functions
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

#include <timer_impl.h>
#include <cmdu.h>
#include <1905_tlvs.h>
#include <i1905_wsc.h>
#include <easymesh.h>
#include <bufutil.h>

#include <uci.h>
#include <map_module.h>

//#include "map_module.h"
#include "utils/utils.h"
#include "utils/debug.h"
#include "utils/liblist.h"
#include "utils/1905_ubus.h"
#include "steer_rules.h"
#include "config.h"
#include "nl.h"
#include "agent.h"
#include "agent_tlv.h"
#include "agent_map.h"

#define AP_COLLECTION_INTERVAL (10 * 1000)

int agent_gen_ap_ht_caps(struct agent *a,
		struct cmdu_buff *cmdu, uint32_t radio_index)
{
	int ret;
	struct tlv *t;
	struct tlv_ap_ht_cap *data;
	struct wifi_radio_element *radio;
	struct netif_fh *fh;

	t = cmdu_reserve_tlv(cmdu, 20);
	if (!t)
		return -1;

	t->type = MAP_TLV_AP_HT_CAPABILITIES;
	t->len = sizeof(*data);
	data = (struct tlv_ap_ht_cap *)t->data;
	radio = a->radios + radio_index;
	fh = wifi_radio_to_ap(a, radio->name);
	if (!fh)
		return -1;

	memcpy(data->radio, radio->macaddr, 6);
	memcpy(&data->cap, &fh->caps.ht, 1);

	ret = cmdu_put_tlv(cmdu, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_ap_he_caps(struct agent *a,
		struct cmdu_buff *cmdu, uint32_t radio_index)
{
	int ret;
	int offset = 0;
	int index, mcs_len;
	struct tlv *t;
	struct wifi_radio_element *radio;
	struct netif_fh *fh;

	t = cmdu_reserve_tlv(cmdu, 40);
	if (!t)
		return -1;

	t->type = MAP_TLV_AP_HE_CAPABILITIES;

	radio = a->radios + radio_index;
	fh = wifi_radio_to_ap(a, radio->name);
	if (!fh)
		return -1;

	memcpy(&t->data[offset], radio->macaddr, 6);
	offset += 6;
	t->data[offset++] = fh->caps.he[0];
	mcs_len = fh->caps.he[0];

	if (mcs_len > 0)
		memcpy(&t->data[offset], &fh->caps.he[1], mcs_len);

	offset += mcs_len;
	index = 1 + mcs_len;
	memcpy(&t->data[offset], &fh->caps.he[index], 2);

	t->len = offset + 2;

	ret = cmdu_put_tlv(cmdu, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

#if (EASYMESH_VERSION > 2)
int agent_gen_ap_wifi6_caps(struct agent *a,
		struct cmdu_buff *cmdu, struct wifi_radio_element *radio)
{
	struct tlv *t;
	struct netif_fh *fh;
	int offset = 0;
	struct tlv_ap_wifi6_caps *caps_data;
	struct wifi6_agent_role *role_data;
	struct wifi6_agent_role_other_caps *role_other_caps_data;
	uint8_t mcs_len = 0;
	const struct wifi_wifi6_capabilities *src_wifi6_caps = NULL;

	t = cmdu_reserve_tlv(cmdu, 48);
	if (!t)
		return -1;

	t->type = MAP_TLV_AP_WIFI6_CAPS;
	caps_data = (struct tlv_ap_wifi6_caps *) t->data;

	memcpy(caps_data->ruid, radio->macaddr, sizeof(caps_data->ruid));
	offset += sizeof(caps_data->ruid);

	/* TODO: Currenlty only caps for AGENT_ROLE_AP are populated. */
	/* Decide whether/how caps for backhaul STA role shall be provided. */
	caps_data->num_roles = 1;
	offset += sizeof(caps_data->num_roles);

	fh = wifi_radio_to_ap(a, radio->name);
	if (!fh)
		return -1;

	src_wifi6_caps = &fh->caps.wifi6;

	role_data = (struct wifi6_agent_role *)(t->data + offset);

	role_data->caps |= AGENT_ROLE_AP << 6;
	role_data->caps |= src_wifi6_caps->he160 ? HE160_SUPPORTED : 0;
	role_data->caps |= src_wifi6_caps->he8080 ? HE8080_SUPPORTED : 0;

	mcs_len = src_wifi6_caps->mcs_nss_len;
	role_data->caps |= mcs_len & MCS_NSS_LEN_MASK;

	offset += sizeof(role_data->caps);

	if (mcs_len > 0)
		memcpy(role_data->mcs_nss_12, src_wifi6_caps->mcs_nss_12, mcs_len);

	offset += mcs_len;

	role_other_caps_data =
		(struct wifi6_agent_role_other_caps *)(t->data + offset);

	role_other_caps_data->beamform_caps |= src_wifi6_caps->su_beamformer ? SU_BEAMFORMER_SUPPORTED : 0;
	role_other_caps_data->beamform_caps |= src_wifi6_caps->su_beamformee ? SU_BEAMFORMEE_SUPPORTED : 0;
	role_other_caps_data->beamform_caps |= src_wifi6_caps->mu_beamformer ? MU_B_FORMER_STATUS_SUPPORTED : 0;
	role_other_caps_data->beamform_caps |= src_wifi6_caps->beamformee_le80 ? B_FORMEE_STS_LE_80_SUPPORTED : 0;
	role_other_caps_data->beamform_caps |= src_wifi6_caps->beamformee_gt80 ? B_FORMEE_STS_GT_80_SUPPORTED : 0;
	role_other_caps_data->beamform_caps |= src_wifi6_caps->ul_mumimo ? UL_MU_MIMO_SUPPORTED : 0;
	role_other_caps_data->beamform_caps |= src_wifi6_caps->ul_ofdma ? UL_OFDMA_SUPPORTED : 0;
	role_other_caps_data->beamform_caps |= src_wifi6_caps->dl_ofdma ? DL_OFDMA_SUPPORTED : 0;

	role_other_caps_data->max_mu_mimo_users |=
		(src_wifi6_caps->max_dl_mumimo << 4) & MAX_NUM_USRS_DL_MU_MIMO_MASK;
	role_other_caps_data->max_mu_mimo_users |=
		(src_wifi6_caps->max_ul_mumimo << 0) & MAX_NUM_USRS_UL_MU_MIMO_MASK;

	role_other_caps_data->max_dl_ofdma_users = src_wifi6_caps->max_dl_ofdma;
	role_other_caps_data->max_ul_ofdma_users = src_wifi6_caps->max_ul_ofdma;

	role_other_caps_data->other_caps |= src_wifi6_caps->rts ? RTS_SUPPORTED : 0;
	role_other_caps_data->other_caps |= src_wifi6_caps->mu_rts ? MU_RTS_SUPPORTED : 0;
	role_other_caps_data->other_caps |= src_wifi6_caps->multi_bssid ? MULTI_BSSID_SUPPORTED : 0;
	role_other_caps_data->other_caps |= src_wifi6_caps->mu_edca ? MU_EDCA_SUPPORTED : 0;
	role_other_caps_data->other_caps |= src_wifi6_caps->twt_requester ? TWT_REQUESTER_SUPPORTED : 0;
	role_other_caps_data->other_caps |= src_wifi6_caps->twt_responder ? TWT_RESPONDER_SUPPORTED : 0;
	role_other_caps_data->other_caps |= src_wifi6_caps->spatial_reuse ? SPATIAL_REUSE_SUPPORTED : 0;
	role_other_caps_data->other_caps |= src_wifi6_caps->anticipated_ch_usage ? ACU_SUPPORTED : 0;


	offset += sizeof(struct wifi6_agent_role_other_caps);
	t->len = offset;

	if (cmdu_put_tlv(cmdu, t)) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}
#endif /* EASYMESH_VERSION > 2 */

int agent_gen_ap_caps(struct agent *a,
		struct cmdu_buff *cmdu)
{
	int ret;
	struct tlv *t;
	struct tlv_ap_cap *data;

	t = cmdu_reserve_tlv(cmdu, 20);
	if (!t)
		return -1;

	t->type = MAP_TLV_AP_CAPABILITY;
	t->len = sizeof(*data);
	data = (struct tlv_ap_cap *)t->data;
	/* Support Agent-initiated RCPI-based Steering */
	data->cap |= AGENT_SUPPORTS_RCPI_STEER;
	/* Support Unassociated STA Link Metrics reporting on
	 * the channels its BSSs are currently operating on.
	 */
	/* TODO: use UCI config */
	data->cap |= UNASSOC_STA_REPORTING_ONCHAN;

	ret = cmdu_put_tlv(cmdu, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;

//	struct tlv_ap_cap *p;
//
//	p = (struct tlv_ap_cap *)calloc(1,
//			sizeof(struct tlv_ap_cap));
//	if (!p)
//		return NULL;
//
//	p->tlv_type = MAP_TLV_AP_CAPABILITY;
//	p->op_ch_metric_reporting = 0;
//	p->non_op_ch_metric_reporting = 0;
//	p->agent_init_rcpi_steering = 1;
//
//	return p;
}

int agent_gen_ap_radio_basic_cap(struct agent *a,
		struct cmdu_buff *frm, struct wifi_radio_element *radio)
{
	struct wifi_radio_opclass *opclass;
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *channel;
	struct tlv *t;
	uint8_t *data;
	int i, j, offset;

	opclass = &radio->opclass;
	offset = 0;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_AP_RADIO_BASIC_CAPABILITIES;

	data = (uint8_t *) t->data;
	memcpy(&data[offset], radio->macaddr, 6);
	offset += 6;

	data[offset] = 16; /* TODO: dummy: max BSS per radio */
	offset += 1;

	data[offset] = wifi_opclass_num_supported(opclass); /* k */
	offset += 1;

	for (i = 0; i < opclass->entry_num; i++) {
		entry = &opclass->entry[i];

		/* Skip unsupported opclasses */
		if (!wifi_opclass_id_supported(opclass, entry->id))
			continue;

		data[offset] = entry->id;
		offset += 1;
		data[offset] = entry->max_txpower;
		offset += 1;

		data[offset] = wifi_opclass_id_num_channels_unsupported(opclass, entry->id);	/* m */
		offset += 1;

		for (j = 0; j < entry->channel_num; j++) {
			channel = &entry->channel[j];

			if (wifi_opclass_id_channel_supported(opclass, entry->id, channel->channel))
				continue;

			data[offset] = channel->channel;
			offset += 1;
		}
	}

	t->len = offset;

	if (cmdu_put_tlv(frm, t)) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_ap_vht_caps(struct agent *a,
		struct cmdu_buff *cmdu, uint32_t radio_index)
{
	int ret;
	struct tlv *t;
	struct tlv_ap_vht_cap *data;
	struct wifi_radio_element *radio;
	struct netif_fh *fh;

	t = cmdu_reserve_tlv(cmdu, 30);
	if (!t)
		return -1;

	t->type = MAP_TLV_AP_VHT_CAPABILITIES;
	t->len = sizeof(*data);
	data = (struct tlv_ap_vht_cap *)t->data;
	radio = a->radios + radio_index;
	fh = wifi_radio_to_ap(a, radio->name);
	if (!fh)
		return -1;

	memcpy(data->radio, radio->macaddr, 6);
	data->tx_mcs_supported = BUF_GET_BE16(fh->caps.vht[0]);
	data->rx_mcs_supported = BUF_GET_BE16(fh->caps.vht[2]);
	memcpy(data->cap, &fh->caps.vht[4], 2);

	ret = cmdu_put_tlv(cmdu, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_profile2_ap_cap(struct agent *a, struct cmdu_buff *frm)
{
	struct tlv *t;
	struct tlv_profile2_ap_cap *data;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_PROFILE2_AP_CAPABILITY;
	t->len = 4;

	data = (struct tlv_profile2_ap_cap *) t->data;
#if (EASYMESH_VERSION > 2)
	data->caps |= STATS_UNIT_BYTE;
#else
	data->unit = STATS_UNIT_BYTE;
#endif
	data->max_vids = (uint8_t) 255;

	if (cmdu_put_tlv(frm, t)) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_ap_radio_adv_cap(struct agent *a,
		struct cmdu_buff *frm, struct wifi_radio_element *radio)
{
	struct tlv *t;
	struct tlv_ap_radio_adv_cap *data;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_AP_RADIO_ADV_CAPABILITY;
	t->len = 7;

	data = (struct tlv_ap_radio_adv_cap *) t->data;
	memcpy(data->radio, radio->macaddr, 6);
#if 0 /* Today don't support R1 agents in TS network */
	if (a->cfg.map_profile == 0x02)
		data->cap |= RADIO_CAP_COMBINED_P1P2;
#endif
	if (!hwaddr_is_zero(radio->bksta.macaddr) && radio->num_bss > 0)
		data->cap |= RADIO_CAP_COMBINED_FHBK;

	if (cmdu_put_tlv(frm, t)) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_wsc(struct agent *a, struct cmdu_buff *frm,
		struct wifi_radio_element *radio)
{
	struct tlv *t;
	uint8_t *m1;
	uint16_t m1_size = 0;
	struct wsc_key *key;
	struct wps_credential wps = {0};
	int ret;
	struct agent_config_radio *rcfg;

	rcfg = get_agent_config_radio(&a->cfg, radio->name);
	if (!rcfg) {
		dbg("|%s:%d| radio config not found for %s\n", __func__,
		    __LINE__, radio->name);
		return -1;
	}

	wps.auth_type = rcfg->encryption;
	wps.band = radio->band;
	memcpy(wps.macaddr, a->almac, 6);
	strncpy(wps.manufacturer, radio->manufacturer, 64);
	strncpy(wps.model_name, radio->model_name, 32);
	strncpy(wps.device_name, radio->device_name, 32);
	memcpy(wps.model_number, radio->model_number, 32);
	memcpy(wps.serial_number, radio->serial_number, 32);
	memcpy(wps.uuid, radio->uuid, 16);

	ret = wsc_build_m1(&wps, &m1, &m1_size, (void *)&key);
	if (ret)
		return -1;

	t = cmdu_reserve_tlv(frm, 1024);
	if (!t)
		goto error;

	t->type = TLV_TYPE_WSC;
	t->len = m1_size;
	memcpy(t->data, m1, m1_size);

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		goto error;
	}

	agent_free_wsc_data(&radio->autconfig);

	radio->autconfig.m1_frame = m1;
	radio->autconfig.m1_size = m1_size;
	radio->autconfig.key = key;

	dbg("size = %d\n", m1_size);
	return 0;
error:
	if (m1)
		free(m1);
	if (key) {
		if (key->key)
			free(key->key);

		free(key);
	}
	return -1;
}

int agent_gen_ch_scan_cap(struct agent *a, struct cmdu_buff *cmdu)
{
	trace("%s ---->\n", __func__);
	struct wifi_radio_element *radio;
	struct wifi_radio_opclass *opclass;
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *channel;
	int channels_supported;
	struct tlv *t;
	uint8_t cap = 0x00;
	int i, j, k;
	int offset = 0;
	int ret;

	if (a->num_radios <= 0)
		return -1;

	t = cmdu_reserve_tlv(cmdu, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_CHANNEL_SCAN_CAPABILITY;
	t->data[offset++] = a->num_radios;

	/* cap */
	if (a->cfg.scan_on_boot_only)
		cap |= SCAN_CAP_ON_BOOT_ONLY; /* On Boot Only field */
		/* If the "On boot only" bit is set to one,
		 * the Scan Impact field shall be set to 0x00.
		 */
	else
		cap |= SCAN_CAP_IMPACT; /* Scan Impact field */
		/* 0x03: Radio unavailable for >= 2 seconds) */

	for (i = 0; i < a->num_radios; i++) {

		radio = &a->radios[i];
		opclass = &radio->opclass;

		memcpy(&t->data[offset], radio->macaddr, 6);			/* radio */
		offset += 6;
		t->data[offset++] = cap;				/* cap */
		/* Minimum Scan Interval */
		BUF_PUT_BE32(t->data[offset], MIN_SCAN_ITV_SEC);
		offset += 4;

		t->data[offset++] = wifi_opclass_num_supported(opclass);	/* m */

		for (j = 0; j < opclass->entry_num; j++) {
			entry = &opclass->entry[j];

			if (!wifi_opclass_id_supported(opclass, entry->id))
				continue;

			t->data[offset++] = entry->id;				/* classid */

			/* All channels supported? */
			if (wifi_opclass_id_all_channels_supported(opclass, entry->id)) {
				t->data[offset++] = 0;				/* k = 0 */
				continue;
			}

			channels_supported = wifi_opclass_id_num_channels_supported(opclass, entry->id);
			t->data[offset++] = channels_supported;
			for (k = 0; k < entry->channel_num; k++) {
				channel = &entry->channel[k];
				if (!wifi_opclass_id_channel_supported(opclass, entry->id, channel->channel))
					continue;
				t->data[offset++] = channel->channel;	/* k */
			}
		}
	}

	/* update the tlv length */
	t->len = offset;

	ret = cmdu_put_tlv(cmdu, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

static inline void put_duration_data(uint8_t *buf, uint32_t val)
{
	/* ignore val MSB data */
	buf[0] = (val >> 16) & 0x0ff;
	buf[1] = (val >> 8) & 0xff;
	buf[2] = val & 0xff;
}

static int agent_num_dfs_radios(struct agent *a)
{
	struct wifi_radio_element *radio;
	int num = 0;
	int i;

	for (i = 0; i < a->num_radios; i++) {
		radio = &a->radios[i];

		if (wifi_opclass_dfs_supported(&radio->opclass))
			num++;
	}

	return num;
}

int agent_gen_cac_cap(struct agent *a, struct cmdu_buff *cmdu)
{
	int i, j, k, l;
	int ret;
	int offset = 0;
	struct tlv *t;
	struct tlv_cac_cap *data;
	struct wifi_radio_element *radio;
	struct wifi_radio_opclass *opclass;
	struct wifi_radio_opclass_entry *entry;

	t = cmdu_reserve_tlv(cmdu, 512);
	if (!t)
		return -1;

	t->type = MAP_TLV_CAC_CAPABILITY;
	data = (struct tlv_cac_cap *)t->data;

	memcpy(data->country, a->radios[0].country_code, 2);

	data->num_radio = agent_num_dfs_radios(a);
	offset = sizeof(*data);
	for (i = 0; i < a->num_radios; i++) {
		struct cac_cap_radio *r =
			(struct cac_cap_radio *)&t->data[offset];

		radio = a->radios + i;
		opclass = &radio->opclass;

		if (!wifi_opclass_dfs_supported(opclass))
			continue;

		memcpy(r->radio, radio->macaddr, 6);
		r->num_cac = 1;
		offset += sizeof(*r);
		for (j = 0; j < r->num_cac; j++) {
			struct cac_cap_cac *c =
				(struct cac_cap_cac *)&t->data[offset];
			uint32_t cac_time = 60;

			c->supp_method |= CAC_METHOD_CONTINUOUS_CAC;
			/* TODO/revisit for putting data in duration buffer, 3 byte */
			put_duration_data(c->duration, cac_time);
			c->num_opclass = wifi_opclass_dfs_num(opclass);
			offset += sizeof(*c);
			for (k = 0; k < opclass->entry_num; k++) {
				entry = &opclass->entry[k];
				struct cac_cap_opclass *op =
					(struct cac_cap_opclass *)&t->data[offset];
				int num = 0;

				if (!wifi_opclass_id_dfs_supported(opclass, entry->id))
					continue;

				op->classid = entry->id;
				op->num_channel = wifi_opclass_id_dfs_num(opclass, entry->id);
				offset += sizeof(*op) + op->num_channel;

				for (l = 0; l < entry->channel_num; l++) {
					if (!wifi_opclass_is_channel_supported(&entry->channel[l]))
						continue;
					if (!wifi_opclass_is_dfs_channel(&entry->channel[l]))
						continue;

					op->channel[num] = entry->channel[l].channel;
					if (entry->channel[l].cac_time > cac_time)
						cac_time = entry->channel[l].cac_time;
					put_duration_data(c->duration, cac_time);
					num++;
				}
			}
		}
	}

	/* update the tlv length */
	t->len = offset;

	ret = cmdu_put_tlv(cmdu, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

#define AP_COLLECTION_INTERVAL	(10 * 1000)
int agent_gen_metric_collection_interval(struct agent *a, struct cmdu_buff *cmdu)
{
	int ret;
	struct tlv *t;
	struct tlv_metric_collection_int *data;

	t = cmdu_reserve_tlv(cmdu, 20);
	if (!t)
		return -1;

	t->type = MAP_TLV_METRIC_COLLECTION_INTERVAL;
	t->len = sizeof(*data);
	data = (struct tlv_metric_collection_int *)t->data;
	BUF_PUT_BE32(data->interval, AP_COLLECTION_INTERVAL);

	ret = cmdu_put_tlv(cmdu, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_oper_channel_report(struct agent *a,
	struct cmdu_buff *frm, struct wifi_radio_element *radio,
	uint32_t channel, uint32_t bw, uint32_t opclass)
{
	int j;
	int ret, offset = 0;
	int num_opclass = 1;
	uint8_t txpower = 0;
	struct tlv *t;

	t = cmdu_reserve_tlv(frm, 100);
	if (!t)
		return -1;

	t->type = MAP_TLV_OPERATING_CHANNEL_REPORT;
	memcpy(&t->data[offset], radio->macaddr, 6);
	offset += 6;
	t->data[offset++] = num_opclass;	/* num opclass */
	for (j = 0; j < num_opclass; j++) {
		if (opclass == 0) {
			uint32_t op_class = wifi_opclass_find_id_from_channel(
							&radio->opclass, channel, bw);
			if (op_class == 0)
				return -1;
			t->data[offset++] = op_class;
		} else {
			t->data[offset++] = opclass;
		}
		t->data[offset++] = (uint8_t) channel;
	}

	/* current transmit power is the (operating class tx power) *
	 *	(current_tx_power_percent)/100
	 */
	for (j = 0; j < radio->opclass.entry_num; j++) {
		if (radio->opclass.entry[j].id == radio->current_opclass) {
			txpower = (radio->opclass.entry[j].max_txpower *
				   radio->current_txpower_percent) / 100;
			break;
		}
	}

	t->data[offset++] = txpower;

	t->len = offset;
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_channel_selection_resp(struct agent *a, struct cmdu_buff *frm,
		uint8_t *radio_recvd, uint8_t reason_code)
{
	int ret;
	struct tlv *t;
	struct tlv_channel_selection_resp *data;

	t = cmdu_reserve_tlv(frm, 30);
	if (!t)
		return -1;

	t->type = MAP_TLV_CHANNEL_SELECTION_RESPONSE;
	t->len = sizeof(*data);
	data = (struct tlv_channel_selection_resp *)t->data;

	memcpy(data->radio, radio_recvd, 6);
	data->response = reason_code;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_channel_pref(struct agent *a, struct cmdu_buff *frm,
		int radio_index)
{
	int ret, offset = 0;
	int i, j;
	struct tlv *t;
	struct wifi_radio_element *radio = a->radios + radio_index;
	struct wifi_radio_opclass *opclass;
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *channel;
	int opclass_num_offset;
	int opclass_num;

	/* Get opclass preferences from lower layer */
	WARN_ON(wifi_radio_update_opclass_preferences(a, radio->name, false));

	opclass = &radio->opclass;
	opclass_num = 0;

	t = cmdu_reserve_tlv(frm, 1024);
	if (!t)
		return -1;

	t->type = MAP_TLV_CHANNEL_PREFERENCE;
	memcpy(&t->data[offset], radio->macaddr, 6);				/* radio id */
	offset += 6;

	opclass_num_offset = offset;
	t->data[offset++] = 0;							/* m */

	for (i = 0; i < opclass->entry_num; i++) {
		entry = &opclass->entry[i];
		uint8_t preference;

		if (wifi_opclass_id_same_preference(&radio->opclass, entry->id, &preference)) {
			t->data[offset++] = entry->id;
			t->data[offset++] = 0;					/* k */
			t->data[offset++] = preference;
			opclass_num++;
			continue;
		}

		for (j = 0; j < entry->channel_num; j++) {
			channel = &entry->channel[j];

			/* skip max pref for non-DFS channels */
			if (wifi_opclass_max_preference(channel->preference) &&
			    channel->dfs == WIFI_RADIO_OPCLASS_CHANNEL_DFS_NONE)
				continue;

			t->data[offset++] = entry->id;
			t->data[offset++] = 1;					/* k */
			t->data[offset++] = channel->channel;
			t->data[offset++] = channel->preference;

			opclass_num++;
		}
	}

	t->data[opclass_num_offset] = opclass_num;				/* m */

	t->len = offset;
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_radio_oper_restrict(struct agent *a,
		struct cmdu_buff *frm, int radio_index)
{
	int ret, offset = 0, opclass_num_offset;
	int i, j;
	struct tlv *t;
	struct wifi_radio_element *radio;
	struct wifi_radio_opclass *opclass;
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *channel;
	int opclass_num;

	radio = &a->radios[radio_index];
	opclass = &radio->opclass;
	opclass_num = 0;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_RADIO_OPERATION_RESTRICTION;

	memcpy(&t->data[offset], radio->macaddr, 6);	/* radio id */
	offset += 6;
	opclass_num_offset = offset;
	t->data[offset++] = 0;				/* m */

	for (i = 0; i < opclass->entry_num; i++) {
		entry = &opclass->entry[i];

		if (wifi_opclass_id_all_channels_supported(opclass, entry->id))
			continue;

		t->data[offset++] = entry->id;
		t->data[offset++] = wifi_opclass_id_num_channels_unsupported(opclass, entry->id);	/* k */

		for (j = 0; j < entry->channel_num; j++) {
			channel = &entry->channel[j];

			if (wifi_opclass_id_channel_supported(opclass, entry->id, channel->channel))
				continue;

			t->data[offset++] = channel->channel;
			t->data[offset++] = 0;	/* Freq separation */
		}

		opclass_num++;
	}

	t->data[opclass_num_offset] = opclass_num;
	t->len = offset;
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_cac_complete_report(struct agent *a, struct cmdu_buff *frm)
{
	int ret, offset = 0;
	int i;
	struct tlv *t;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_CAC_COMPLETION_REPORT;

	t->data[offset++] = a->num_radios;	/* num radio */
	for (i = 0; i < a->num_radios; i++) {
		struct wifi_radio_element *radio = a->radios + i;

		memcpy(&t->data[offset], radio->macaddr, 6);	/* radio id */
		offset += 6;
		t->data[offset++] = 0x01;	/* TODO dummy value; op class */
		t->data[offset++] = 0x01;	/* TODO dummy value; channel */

		/* TODO harcoded value; cac completion status */
		t->data[offset++] = CAC_COMP_REPORT_STATUS_OTHER;
		t->data[offset++] = 0;	/* TODO harcoded value; num_pairs */
	}

	t->len = offset;
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_cac_status_report(struct agent *a, struct cmdu_buff *frm)
{
	struct wifi_radio_element *radio;
	struct wifi_radio_opclass *opclass;
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *chan;

	int ret, offset = 0;
	struct tlv *t;
	uint8_t *num_ptr;
	uint8_t num;
	uint32_t time;
	int i, j, r;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_CAC_STATUS_REPORT;

	/* CAC available */
	num = 0;
	num_ptr = &t->data[offset];
	t->data[offset++] = num;

	for (r = 0; r < a->num_radios; r++) {
		radio = &a->radios[r];
		opclass = &radio->opclass;

		if (!wifi_opclass_dfs_supported(opclass))
			continue;

		for (i = 0; i < opclass->entry_num; i++) {
			entry = &opclass->entry[i];

			for (j = 0; j < entry->channel_num; j++) {
				chan = &entry->channel[j];

				if (!wifi_opclass_is_channel_supported(chan))
					continue;
				if (!wifi_opclass_is_dfs_channel(chan))
					continue;
				if (!wifi_opclass_is_channel_dfs_available(chan))
					continue;

				t->data[offset++] = entry->id;
				t->data[offset++] = chan->channel;

				time = 60;
				BUF_PUT_BE16(t->data[offset], time);
				offset += 2;
				num++;
			}
		}
	}
	*num_ptr = num;

	/* NOP */
	num = 0;
	num_ptr = &t->data[offset];
	t->data[offset++] = num;

	for (r = 0; r < a->num_radios; r++) {
		radio = &a->radios[r];
		opclass = &radio->opclass;

		if (!wifi_opclass_dfs_supported(opclass))
			continue;

		for (i = 0; i < opclass->entry_num; i++) {
			entry = &opclass->entry[i];

			for (j = 0; j < entry->channel_num; j++) {
				chan = &entry->channel[j];

				if (!wifi_opclass_is_channel_supported(chan))
					continue;
				if (!wifi_opclass_is_dfs_channel(chan))
					continue;
				if (!wifi_opclass_is_channel_dfs_nop(chan))
					continue;

				t->data[offset++] = entry->id;
				t->data[offset++] = chan->channel;

				time = wifi_opclass_channel_dfs_nop_time(chan);
				BUF_PUT_BE16(t->data[offset], time);
				offset += 2;
				num++;
			}
		}
	}
	*num_ptr = num;

	/* CAC ongoing */
	num = 0;
	num_ptr = &t->data[offset];
	t->data[offset++] = 0;

	for (r = 0; r < a->num_radios; r++) {
		radio = &a->radios[r];
		opclass = &radio->opclass;

		if (!wifi_opclass_dfs_supported(opclass))
			continue;

		for (i = 0; i < opclass->entry_num; i++) {
			entry = &opclass->entry[i];

			for (j = 0; j < entry->channel_num; j++) {
				chan = &entry->channel[j];

				if (!wifi_opclass_is_channel_supported(chan))
					continue;
				if (!wifi_opclass_is_dfs_channel(chan))
					continue;
				if (!wifi_opclass_is_channel_dfs_cac(chan))
					continue;

				t->data[offset++] = entry->id;
				t->data[offset++] = chan->channel;

				time = wifi_opclass_channel_dfs_cac_time(chan);

				/* TODO fix it PUT_BE24 */
				BUF_PUT_BE16(t->data[offset], time);
				offset += 3;
				num++;
			}
		}
	}
	*num_ptr = num;

	t->len = offset;
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_tlv_error_code(struct agent *a, struct cmdu_buff *frm,
			     uint8_t *macaddr, uint8_t reason_code)
{
	struct tlv *t;
	struct tlv_error_code *data;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_ERROR_CODE;
	t->len = 7;

	data = (struct tlv_error_code *)t->data;
	data->reason = reason_code;

	if (macaddr)
		memcpy(data->macaddr, macaddr, 6);

	if (cmdu_put_tlv(frm, t)) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_mac(struct agent *a, struct cmdu_buff *frm, uint8_t *macaddr)
{
	struct tlv *t;
	struct tlv_macaddr *data;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = TLV_TYPE_MAC_ADDRESS_TYPE;
	t->len = 6;

	data = (struct tlv_macaddr *) t->data;
	memcpy(data->macaddr, macaddr, 6);

	if (cmdu_put_tlv(frm, t)) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_al_mac(struct agent *a, struct cmdu_buff *frm, uint8_t *macaddr)
{
	struct tlv *t;
	struct tlv_aladdr *data;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = TLV_TYPE_AL_MAC_ADDRESS_TYPE;
	t->len = 6;

	data = (struct tlv_aladdr *) t->data;
	memcpy(data->macaddr, macaddr, 6);

	if (cmdu_put_tlv(frm, t)) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}


int agent_gen_supported_service(struct agent *a, struct cmdu_buff *frm, uint8_t service)
{
	struct tlv *t;
	int ret;

	t = cmdu_reserve_tlv(frm, 128);
	if (!t)
		return -1;

	t->type = MAP_TLV_SUPPORTED_SERVICE;
	t->len = 2;
	t->data[0] = 0x1;
	t->data[1] = service;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_searched_service(struct agent *a, struct cmdu_buff *frm, uint8_t service)
{
	struct tlv *t;
	int ret;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_SEARCHED_SERVICE;
	t->len = 2;
	t->data[0] = 0x1;
	t->data[1] = service;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_map_profile(struct agent *a, struct cmdu_buff *frm, uint8_t profile)
{
	struct tlv *t;
	struct tlv_map_profile *data;
	int ret;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_MULTIAP_PROFILE;
	t->len = 1;
	data = (struct tlv_map_profile *) t->data;
	data->profile = profile;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_tlv_beacon_metrics_query(struct agent *a,
		struct cmdu_buff *frm, uint8_t *sta_addr,
		uint8_t opclass, uint8_t channel,
		uint8_t *bssid, uint8_t reporting_detail, char *ssid,
		uint8_t num_report, struct sta_channel_report *report,
		uint8_t num_element, const uint8_t *element)
{
	struct tlv *t;
	struct tlv_beacon_metrics_query *data;
	uint8_t *data_p;
	struct ssid_query *ssidq;
	size_t ssid_len = strlen(ssid);
	int i, ret;

	/* TODO: check size */
	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = MAP_TLV_BEACON_METRICS_QUERY;
	/* It will be increased later for variable params */
	t->len = sizeof(struct tlv_beacon_metrics_query);

	/* Note: this cast holds only till 'reporting_detail' field */
	data = (struct tlv_beacon_metrics_query *) t->data;

	memcpy(data->sta_macaddr, sta_addr, 6);
	data->opclass = opclass;
	data->channel = channel;
	memcpy(data->bssid, bssid, 6);
	data->reporting_detail = reporting_detail;

	/* Flexible array in the middle of the struct - cast to ssid_query */
	ssidq = (struct ssid_query *) &data->ssid;
	ssidq->ssidlen = ssid_len;
	memcpy(ssidq->ssid, ssid, ssid_len);

	t->len += ssid_len;

	/* No more direct use of tlv_beacon_metrics_query structure layout
	 * from here on: data->num_report doesn't point to num_report anymore!
	 * From now on just use the data pointer to pack the data manually.
	 */
	data_p = &(ssidq->ssidlen) + 1 + ssid_len;

	/* Channel reports */
	if (num_report && report) {
		/* data->num_report */
		*data_p = num_report;
		data_p++;

		/* data->report */
		/* -1: one report always counted for in sizeof query struct */
		t->len += (num_report - 1) * sizeof(struct ap_channel_report);

		for (i = 0; i < num_report; i++) {
			struct ap_channel_report *ch_rep =
					(struct ap_channel_report *) data_p;
			int num_channel = report[i].num_channel;

			ch_rep->opclass = report[i].opclass;
			/* opclass + channel[] */
			ch_rep->len = 1 + num_channel;
			memcpy(ch_rep->channel, report[i].channel, num_channel);

			/* Increase t->len by number of channels */
			t->len += num_channel;
			/* (len + opclass) + channel[] */
			data_p += 2 + num_channel;
		}
	}

	/* Request elements */
	if (reporting_detail == 1 && num_element) {
		/* data->num_element */
		*data_p = num_element;
		/* num_element already counted for in len */
		data_p++;

		if (element) {
			/* data->element */
			t->len += num_element;
			for (i = 0; i < num_element; i++) {
				*data_p = element[i];
				data_p++;
			}
		}
	}

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_tlv_unassoc_sta_lm_query(struct agent *a,
		struct cmdu_buff *frm, uint8_t opclass,
		uint8_t num_metrics, struct unassoc_sta_metric *metrics)
{
	int ret, i, j, num_sta;
	struct tlv *t;
	struct tlv_unassoc_sta_link_metrics_query *data;

	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = MAP_TLV_UNASSOCIATED_STA_LINK_METRICS_QUERY;
	t->len = sizeof(struct tlv_unassoc_sta_link_metrics_query);

	data = (struct tlv_unassoc_sta_link_metrics_query *) t->data;
	data->opclass = opclass;
	data->num_channel = num_metrics;

	for (i = 0; i < num_metrics; i++) {
		t->len += 2; /* two bytes: channel & num_sta */

		data->ch[i].channel = metrics[i].channel;
		num_sta = metrics[i].num_sta;

		if (num_sta > MAX_UNASSOC_STAMACS) {
			dbg("%s: error: num_sta (%d) greater than %d\n",
				__func__, num_sta, MAX_UNASSOC_STAMACS);
			num_sta = MAX_UNASSOC_STAMACS;
		}

		t->len += (num_sta * 6); /* six bytes: macaddr */

		data->ch[i].num_sta = num_sta;
		for (j = 0; j < num_sta; j++)
			memcpy(data->ch[i].sta[j].macaddr,
			       metrics[i].sta[j].macaddr, 6);
	}

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_tlv_unassoc_sta_lm_report(struct agent *a,
	struct cmdu_buff *frm, uint8_t opclass,
	struct wifi_radio_element *radio)
{
	int ret;
	int offset = 0;
	struct tlv *t;
	struct tlv_unassoc_sta_link_metrics_resp *data;
	int i;
	struct timespec now;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_UNASSOCIATED_STA_LINK_METRICS_RESPONSE;
	data = (struct tlv_unassoc_sta_link_metrics_resp *)t->data;
	data->opclass = opclass;
	data->num_sta = 0; //radio->num_unassoc_sta;

	offset = sizeof(*data);

	timestamp_update(&now);

	for (i = 0; i < radio->num_unassoc_sta; i++) {
		struct wifi_unassoc_sta_element *sta_elem =
				&radio->unassoc_stalist[i];
		struct unassoc_sta_link_metrics_sta *s =
				(struct unassoc_sta_link_metrics_sta *)&t->data[offset];

		if (sta_elem->meas.opclass == opclass &&
				sta_elem->meas.rssi &&
				sta_elem->meas.rcpi != 255) {

			memcpy(s->macaddr, sta_elem->macaddr, 6);
			s->channel = sta_elem->meas.channel;
			BUF_PUT_BE32(s->time_delta, timestamp_diff_ms(now,
					sta_elem->meas.timestamp));
			s->ul_rcpi = sta_elem->meas.rcpi;

			offset += sizeof(*s);
			data->num_sta++;

			/* Get rid of the measurement data after sending resp */
			memset(&sta_elem->meas, 0, sizeof(struct wifi_sta_measurement));
		}
	}

	t->len = offset;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_tlv_beacon_metrics_resp(struct agent *a,
		uint8_t *tlv, uint8_t *sta_addr,
		uint8_t report_elems_nr, uint8_t *report_elem,
		uint16_t elem_len)
{
	struct tlv_beacon_metrics_resp *data;
	struct tlv *t = (struct tlv *) tlv;
	uint16_t len = sizeof(struct tlv_beacon_metrics_resp) + elem_len;

	if (!t)
		return -1;

	t->type = MAP_TLV_BEACON_METRICS_RESPONSE;
	buf_put_be16((uint8_t *)&t->len, len); /* swap */
	data = (struct tlv_beacon_metrics_resp *) t->data;

	memcpy(data->sta_macaddr, sta_addr, 6);
	//data->reserved = 0;
	data->num_element = report_elems_nr;

	if (report_elems_nr) {
		memcpy(data->element, report_elem, elem_len);
	}

	return 0;
}

int agent_gen_steer_btm_report(struct agent *a, struct cmdu_buff *frm,
		uint8_t *target_bssid, uint8_t *src_bssid,
		uint8_t *sta, uint8_t status_code)
{
	int ret;
	struct tlv *t;
	struct tlv_steer_btm_report *data;

	t = cmdu_reserve_tlv(frm, 40);
	if (!t)
		return -1;

	t->type = MAP_TLV_STEERING_BTM_REPORT;
	t->len = sizeof(*data);
	data = (struct tlv_steer_btm_report *)t->data;

	memcpy(data->bssid, src_bssid, 6);
	memcpy(data->sta_macaddr, sta, 6);
	data->status = status_code;
	if (status_code == 0x00)
		memcpy(data->target_bssid, target_bssid, 6);

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

/**
 * band -
 *	0x00 2.4GHz
 *	0x01 5GHz
 *	0x02 60GHz
 */
int agent_gen_autoconf_freq_band(struct agent *a, struct cmdu_buff *frm,
		uint8_t band)
{
	struct tlv *t;
	struct tlv_autoconfig_band *data;
	int ret;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = TLV_TYPE_AUTOCONFIG_FREQ_BAND;
	t->len = 1;
	data = (struct tlv_autoconfig_band *) t->data;
	data->band = band;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_searched_role(struct agent *a, struct cmdu_buff *frm,
		uint8_t role)
{
	struct tlv *t;
	struct tlv_searched_role *data;
	int ret;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = TLV_TYPE_SEARCHED_ROLE;
	t->len = 1;
	data = (struct tlv_searched_role *) t->data;
	data->role = role;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_radio_metrics(struct agent *a, struct cmdu_buff *frm,
		int radio_index)
{
	int ret;
	struct tlv *t;
	struct tlv_radio_metrics *data;
	struct wifi_radio_element *radio = a->radios + radio_index;
	int total = 0;

	t = cmdu_reserve_tlv(frm, 30);
	if (!t)
		return -1;

	t->type = MAP_TLV_RADIO_METRICS;
	t->len = sizeof(*data);
	data = (struct tlv_radio_metrics *) t->data;

	memcpy(data->radio, radio->macaddr, 6);
	data->noise = radio->anpi;
	data->transmit = radio->tx_utilization;
	data->receive_self = radio->rx_utilization;
	data->receive_other = radio->other_utilization;

	total = data->transmit + data->receive_self +
		data->receive_other;

	/* total airtime should not exceed 255 */
	if (total > 255) {
		float r = (float) 255 / (float) total;

		data->transmit *= r;
		data->receive_self *= r;
		data->receive_other *= r;
	}

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_ap_metrics(struct agent *a, struct cmdu_buff *frm,
		int radio_index, int bss_index)
{
	int ret;
	int copy_index = 0;
	struct tlv *t;
	struct tlv_ap_metrics *data;
	struct wifi_radio_element *radio = a->radios + radio_index;
	struct wifi_bss_element *bss = radio->bsslist + bss_index;
	struct netif_fh *fh;
	struct sta *s = NULL;
	uint16_t num_sta = 0;

	t = cmdu_reserve_tlv(frm, 64);
	if (!t)
		return -1;

	t->type = MAP_TLV_AP_METRICS;
	t->len = sizeof(*data);
	data = (struct tlv_ap_metrics *) t->data;

	memcpy(data->bssid, bss->bssid, 6);
	data->channel_utilization = radio->total_utilization;;
	fh = wifi_get_netif_by_bssid(a, bss->bssid);
	if (!fh)
		return -1;

	list_for_each_entry(s, &fh->stalist, list)
		num_sta++;

	BUF_PUT_BE16(data->num_station, num_sta);
	data->esp_ac = ESP_AC_BE;
	memcpy(data->esp_be, bss->est_wmm_be, 3);

	if (bss->is_ac_bk) {
		data->esp_ac |= ESP_AC_BK;
		memcpy(data->esp + copy_index, bss->est_wmm_bk, 3);
		copy_index += 3;
	}

	if (bss->is_ac_vo) {
		data->esp_ac |= ESP_AC_VO;
		memcpy(data->esp + copy_index, bss->est_wmm_vo, 3);
		copy_index += 3;
	}

	if (bss->is_ac_vi) {
		data->esp_ac |= ESP_AC_VI;
		memcpy(data->esp + copy_index, bss->est_wmm_vi, 3);
		copy_index += 3;
	}

	t->len += copy_index;
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_ap_ext_metrics(struct agent *a, struct cmdu_buff *frm,
		int radio_index, int bss_index)
{
	int ret;
	struct tlv *t;
	struct tlv_ap_ext_metrics *data;
	struct wifi_radio_element *radio = a->radios + radio_index;
	struct wifi_bss_element *bss = radio->bsslist + bss_index;

	t = cmdu_reserve_tlv(frm, 64);
	if (!t)
		return -1;

	t->type = MAP_TLV_AP_EXTENDED_METRICS;
	t->len = sizeof(*data);
	data = (struct tlv_ap_ext_metrics *) t->data;

	memcpy(data->bssid, bss->bssid, 6);
	BUF_PUT_BE32(data->tx_bytes_ucast, bss->tx_ucast_bytes);
	BUF_PUT_BE32(data->rx_bytes_ucast, bss->rx_ucast_bytes);
	BUF_PUT_BE32(data->tx_bytes_mcast, bss->tx_mcast_bytes);
	BUF_PUT_BE32(data->rx_bytes_mcast, bss->rx_mcast_bytes);
	BUF_PUT_BE32(data->tx_bytes_bcast, bss->tx_bcast_bytes);
	BUF_PUT_BE32(data->rx_bytes_bcast, bss->rx_bcast_bytes);

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_assoc_sta_traffic_stats(struct agent *a,
		struct cmdu_buff *frm, uint8_t *mac, struct sta *s)
{
	int ret;
	struct tlv *t;
	struct tlv_assoc_sta_traffic_stats *data;

	t = cmdu_reserve_tlv(frm, 64);
	if (!t)
		return -1;

	t->type = MAP_TLV_ASSOCIATED_STA_TRAFFIC_STATS;
	t->len = sizeof(*data);
	data = (struct tlv_assoc_sta_traffic_stats *) t->data;

	memcpy(data->macaddr, mac, 6);

	if (s) {
		BUF_PUT_BE32(data->tx_bytes, s->tx_bytes);
		BUF_PUT_BE32(data->rx_bytes, s->rx_bytes);
		BUF_PUT_BE32(data->tx_packets, s->tx_pkts);
		BUF_PUT_BE32(data->rx_packets, s->rx_pkts);
		BUF_PUT_BE32(data->tx_err_packets, s->tx_fail_pkts);
		BUF_PUT_BE32(data->rx_err_packets, s->rx_fail_pkts);
		//TODO:FIXME. align this field
		BUF_PUT_BE32(data->rtx_packets, 0);
	} else {
		memset(data + 6, 0, 58);
	}

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_assoc_sta_link_metrics(struct agent *a,
		struct cmdu_buff *frm, struct sta *s, uint8_t *bssid)
{
	int ret, i;
	int offset = 0;
	struct tlv *t;
	struct tlv_assoc_sta_link_metrics *data;
	struct timespec curr_ts;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	timestamp_update(&curr_ts);
	t->type = MAP_TLV_ASSOCIATED_STA_LINK_METRICS;
	data = (struct tlv_assoc_sta_link_metrics *) t->data;
	memcpy(data->macaddr, s->macaddr, 6);
	data->num_bss = 1;
	offset = sizeof(*data);

	for (i = 0; i < data->num_bss; i++) {
		struct assoc_sta_link_metrics_bss *b =
			(struct assoc_sta_link_metrics_bss *)&t->data[offset];

		memcpy(b->bssid, bssid, 6);
		BUF_PUT_BE32(b->time_delta,
				timestamp_diff_ms(curr_ts, s->last_update));
		BUF_PUT_BE32(b->dl_thput, s->rx_thput);
		BUF_PUT_BE32(b->ul_thput, s->tx_thput);
		b->ul_rcpi = rssi_to_rcpi(s->rssi[0]);
		offset += sizeof(*b);
	}

	t->len = offset;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_assoc_sta_ext_link_metric(struct agent *a,
		struct cmdu_buff *frm, struct sta *s, uint8_t *bssid)
{
	int ret, i;
	int offset = 0;
	struct tlv *t;
	struct tlv_sta_ext_link_metric *data;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_ASSOCIATED_STA_EXT_LINK_METRICS;
	data = (struct tlv_sta_ext_link_metric *) t->data;
	memcpy(data->macaddr, s->macaddr, 6);
	data->num_bss = 1;
	offset = sizeof(*data);

	for (i = 0; i < data->num_bss; i++) {
		struct sta_ext_link_metric_bss *b =
			(struct sta_ext_link_metric_bss *)&t->data[offset];

		memcpy(b->bssid, bssid, 6);
		BUF_PUT_BE32(b->dl_rate, s->rx_rate);
		BUF_PUT_BE32(b->ul_rate, s->tx_rate);
		BUF_PUT_BE32(b->rx_util, s->rx_airtime);
		BUF_PUT_BE32(b->tx_util, s->tx_airtime);
		offset += sizeof(*b);
	}

	t->len = offset;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_ap_radio_identifier(struct agent *a,
		struct cmdu_buff *frm, uint8_t *radio_id)
{
	int ret;
	struct tlv *t;
	struct tlv_ap_radio_identifier *data;

	t = cmdu_reserve_tlv(frm, 20);
	if (!t)
		return -1;

	t->type = MAP_TLV_AP_RADIO_IDENTIFIER;
	t->len = sizeof(*data);
	data = (struct tlv_ap_radio_identifier *) t->data;
	memcpy(data->radio, radio_id, 6);

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_ap_metric_query(struct agent *a, struct cmdu_buff *frm,
		int num_bss, uint8_t *bsslist)
{
	int i, ret;
	struct tlv *t;
	struct tlv_ap_metric_query *data;

	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = MAP_TLV_AP_METRIC_QUERY;
	t->len = sizeof(*data) + (6 * num_bss);
	data = (struct tlv_ap_metric_query *) t->data;

	data->num_bss = num_bss;
	for (i = 0; i < data->num_bss; i++)
		memcpy(data->bss[i].bssid, &bsslist[i * 6], 6);

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_source_info(struct agent *a,
		struct cmdu_buff *frm, uint8_t *mac)
{
	int ret;
	struct tlv *t;
	struct tlv_source_info *data;

	if (!mac)
		return -1;

	t = cmdu_reserve_tlv(frm, 20);
	if (!t)
		return -1;

	t->type = MAP_TLV_SOURCE_INFO;
	t->len = sizeof(*data);
	data = (struct tlv_source_info *) t->data;

	memcpy(data->macaddr, mac, 6);

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_tunnel_msg_type(struct agent *a,
		struct cmdu_buff *frm, uint8_t protocol)
{
	int ret;
	struct tlv *t;
	struct tlv_tunnel_msg_type *data;

	t = cmdu_reserve_tlv(frm, 20);
	if (!t)
		return -1;

	t->type = MAP_TLV_TUNNELED_MSG_TYPE;
	t->len = sizeof(*data);
	data = (struct tlv_tunnel_msg_type *) t->data;

	data->type = protocol;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_tunneled(struct agent *a, struct cmdu_buff *frm,
		int frame_len, uint8_t *frame_body)
{
	int ret;
	struct tlv *t;
	struct tlv_tunneled *data;

	if ((!frame_body) || (frame_len <= 0))
		return -1;

	t = cmdu_reserve_tlv(frm, 1024);
	if (!t)
		return -1;

	t->type = MAP_TLV_TUNNELED;
	t->len = frame_len;
	data = (struct tlv_tunneled *) t->data;

	memcpy(data->frame, frame_body, frame_len);

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int fill_steering_policy_from_tlv(struct agent *a,
		struct tlv_steering_policy *p,
		struct uci_context *ctx, struct uci_package *pkg,
		int skip_offset)
{
	int ret, i, offset = 0;
	int num_radio;
	struct uci_element *e;
	struct uci_ptr ptr;
	char buf[64] = {0};
	uint8_t *data = (uint8_t *)p;

	offset = skip_offset;
	num_radio = data[offset++];
	for (i = 0; i < num_radio; i++) {
		int k;
		int radio_index;
		uint8_t steer_policy;
		uint8_t util_threshold;
		uint8_t rcpi_threshold;
		struct wifi_radio_element *radio;
		uint8_t radio_id[6] = {0};

		memcpy(radio_id, data + offset, 6);
		offset += 6;
		steer_policy = data[offset++];
		util_threshold = data[offset++];
		rcpi_threshold = data[offset++];

		radio_index = get_radio_index(a, radio_id);
		if (radio_index == -1)
			continue;

		radio = a->radios + radio_index;

		/* add the configuration in each radio section for specific radio */
		for (k = 0; k < WIFI_DEVICE_MAX_NUM; k++) {
			uci_foreach_element(&pkg->sections, e) {
				struct uci_section *s = uci_to_section(e);

				if (strcmp(s->type, "radio"))
					continue;

				snprintf(buf, sizeof(buf) - 1, "%s.%s.device",
						pkg->e.name, s->e.name);
				ret = uci_lookup_ptr(ctx, &ptr, buf, true);
				if (ptr.value && (ret != UCI_OK)) {
					fprintf(stderr, "value not found\n");
					continue;
				}

				if (strncmp(ptr.o->v.string, radio->name, 16))
					continue;

				/* Add the policy config params */
				snprintf(buf, sizeof(buf) - 1,
						"%s.%s.steer_policy=%d",
						pkg->e.name, s->e.name,
						steer_policy);
				ret = uci_lookup_ptr(ctx, &ptr, buf, true);
				if (ret != UCI_OK)
					return -1;

				uci_set(ctx, &ptr);
				uci_save(ctx, ptr.p);

				snprintf(buf, sizeof(buf) - 1,
						"%s.%s.util_threshold=%d",
						pkg->e.name, s->e.name,
						util_threshold);
				ret = uci_lookup_ptr(ctx, &ptr, buf, true);
				if (ret != UCI_OK)
					return -1;

				uci_set(ctx, &ptr);
				uci_save(ctx, ptr.p);

				snprintf(buf, sizeof(buf) - 1,
						"%s.%s.rcpi_threshold=%d",
						pkg->e.name, s->e.name,
						rcpi_threshold);
				ret = uci_lookup_ptr(ctx, &ptr, buf, true);
				if (ret != UCI_OK)
					return -1;

				uci_set(ctx, &ptr);
				uci_save(ctx, ptr.p);

				break;
			}
		}
	}

	return 0;
}

/* for tlv_steering_policy:
 * num_radios = 1 && radio_id == 'ff:ff:ff:ff:ff:ff'
 * Means the config need to apply for all ap section;
 */
int fill_steering_policy_all(struct agent *a,
		struct tlv_steering_policy *p,
		struct uci_context *ctx, struct uci_package *pkg,
		int skip_offset)
{
	int ret, offset = 0;
	struct uci_element *e;
	struct uci_ptr ptr = {0};
	char buf[64] = {0};
	uint8_t *data = (uint8_t *)p;
	uint8_t steer_policy;
	uint8_t util_threshold;
	uint8_t rcpi_threshold;

	/* add the configuration in each iface section */
	offset = skip_offset + 1 + 6;
	steer_policy = data[offset++];
	util_threshold = data[offset++];
	rcpi_threshold = data[offset++];

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (strcmp(s->type, "radio"))
			continue;

		/* Add the policy config params */
		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf) - 1,
				"%s.%s.steer_policy=%d",
				pkg->e.name, s->e.name,
				steer_policy);
		ret = uci_lookup_ptr(ctx, &ptr, buf, true);
		if (ret != UCI_OK)
			return -1;

		uci_set(ctx, &ptr);
		uci_save(ctx, ptr.p);

		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf) - 1,
				"%s.%s.util_threshold=%d",
				pkg->e.name, s->e.name,
				util_threshold);
		ret = uci_lookup_ptr(ctx, &ptr, buf, true);
		if (ret != UCI_OK)
			return -1;

		uci_set(ctx, &ptr);
		uci_save(ctx, ptr.p);

		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf) - 1,
				"%s.%s.rcpi_threshold=%d",
				pkg->e.name, s->e.name,
				rcpi_threshold);
		ret = uci_lookup_ptr(ctx, &ptr, buf, true);
		if (ret != UCI_OK)
			return -1;

		uci_set(ctx, &ptr);
		uci_save(ctx, ptr.p);
	}

	return 0;
}

int agent_fill_steering_policy(struct agent *a,
		struct tlv_steering_policy *p,
		struct uci_context *ctx, struct uci_package *pkg)
{
	int ret, i, num_radio;
	int offset = 0, skip_offset;
	int local_disallowed_sta_nr;
	int btm_disallowed_sta_nr;
	struct uci_element *e;
	struct uci_ptr ptr;
	char buf[64] = {0};
	char addr[18] = {0};
	uint8_t mac[6] = {0};
	uint8_t radio_id[6] = {0};
	uint8_t *data = (uint8_t *)p;
	uint8_t generic_id[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	/* Add exclude list & btm exclude list in 'policy' section */
	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (strcmp(s->type, "policy"))
			continue;

		/* steer_exclude */
		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf),
				 "%s.%s.%s", pkg->e.name,
				 s->e.name, "steer_exclude");

		/* empty current UCI steer_exclude list first */
		ret = uci_lookup_ptr(ctx, &ptr, buf, true);
		if (ret != UCI_OK ||
				!(ptr.flags & UCI_LOOKUP_DONE))
			return -1;

		if (ptr.flags & UCI_LOOKUP_COMPLETE) {
			/* steer_exclude list found - remove */
			if (uci_delete(ctx, &ptr) == UCI_OK)
				uci_save(ctx, pkg);
		}

		/* add entries to steer_exclude UCI list */
		local_disallowed_sta_nr = data[offset++];
		for (i = 0; i < local_disallowed_sta_nr; i++) {
			memset(addr, 0, sizeof(addr));
			memset(mac, 0, sizeof(mac));
			memcpy(mac, data + offset, 6);
			offset += 6;
			hwaddr_ntoa(mac, addr);

			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf),
					"%s.%s.steer_exclude=%s",
					pkg->e.name, s->e.name, addr);

			ret = uci_lookup_ptr(ctx, &ptr, buf, true);
			if (ret != UCI_OK ||
					!(ptr.flags & UCI_LOOKUP_DONE))
				return -1;

			if (uci_add_list(ctx, &ptr) == UCI_OK)
				uci_save(ctx, ptr.p);
		}

		/* steer_exclude_btm */
		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf),
				 "%s.%s.%s", pkg->e.name,
				 s->e.name, "steer_exclude_btm");

		/* empty current UCI steer_exclude_btm list first */
		ret = uci_lookup_ptr(ctx, &ptr, buf, true);
		if (ret != UCI_OK ||
				!(ptr.flags & UCI_LOOKUP_DONE))
			return -1;

		if (ptr.flags & UCI_LOOKUP_COMPLETE) {
			/* steer_exclude_btm list found - remove */
			if (uci_delete(ctx, &ptr) == UCI_OK)
				uci_save(ctx, pkg);
		}

		/* add entries to steer_exclude_btm UCI list */
		btm_disallowed_sta_nr = data[offset++];
		for (i = 0; i < btm_disallowed_sta_nr; i++) {
			memset(addr, 0, sizeof(addr));
			memset(mac, 0, sizeof(mac));
			memcpy(mac, data + offset, 6);
			offset += 6;
			hwaddr_ntoa(mac, addr);

			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf),
					"%s.%s.steer_exclude_btm=%s",
					pkg->e.name, s->e.name, addr);

			ret = uci_lookup_ptr(ctx, &ptr, buf, true);
			if (ret != UCI_OK ||
					!(ptr.flags & UCI_LOOKUP_DONE))
				return -1;

			if (uci_add_list(ctx, &ptr) == UCI_OK)
				uci_save(ctx, ptr.p);
		}

		break;
	}

	skip_offset = offset;
	num_radio = data[offset++];
	memcpy(radio_id, data + offset, 6);
	if ((num_radio == 1) &&
			!memcmp(radio_id, generic_id, 6)) {
		fill_steering_policy_all(a, p, ctx, pkg, skip_offset);
	} else
		fill_steering_policy_from_tlv(a, p, ctx, pkg, skip_offset);

	return 0;
}

int add_metric_report_policy_config(struct uci_context *ctx,
		struct uci_package *pkg, struct uci_section *s,
		uint8_t rcpi_threshold, uint8_t rcpi_hysteresis,
		uint8_t util_threshold, uint8_t include)
{
	int ret;
	char buf[64] = {0};
	struct uci_ptr ptr;

	/* Add the policy config params */
	snprintf(buf, sizeof(buf) - 1,
			"%s.%s.report_rcpi_threshold=%d",
			pkg->e.name, s->e.name,
			rcpi_threshold);
	ret = uci_lookup_ptr(ctx, &ptr, buf, true);
	if (ret != UCI_OK)
		return -1;

	uci_set(ctx, &ptr);
	uci_save(ctx, ptr.p);

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1,
			"%s.%s.rcpi_hysteresis_margin=%d",
			pkg->e.name, s->e.name,
			rcpi_hysteresis);
	ret = uci_lookup_ptr(ctx, &ptr, buf, true);
	if (ret != UCI_OK)
		return -1;

	uci_set(ctx, &ptr);
	uci_save(ctx, ptr.p);

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1,
			"%s.%s.report_util_threshold=%d",
			pkg->e.name, s->e.name,
			util_threshold);
	ret = uci_lookup_ptr(ctx, &ptr, buf, true);
	if (ret != UCI_OK)
		return -1;

	uci_set(ctx, &ptr);
	uci_save(ctx, ptr.p);

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1,
			"%s.%s.include_sta_stats=%d",
			pkg->e.name, s->e.name,
			(!!(include & INCLUDE_STA_STATS) ? 1 : 0));
	ret = uci_lookup_ptr(ctx, &ptr, buf, true);
	if (ret != UCI_OK)
		return -1;

	uci_set(ctx, &ptr);
	uci_save(ctx, ptr.p);

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1,
			"%s.%s.include_sta_metric=%d",
			pkg->e.name, s->e.name,
			(!!(include & INCLUDE_STA_LINK_METRICS) ? 1 : 0));
	ret = uci_lookup_ptr(ctx, &ptr, buf, true);
	if (ret != UCI_OK)
		return -1;

	uci_set(ctx, &ptr);
	uci_save(ctx, ptr.p);

#if (EASYMESH_VERSION > 2)
	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1,
			"%s.%s.include_wifi6_sta_status=%d",
			pkg->e.name, s->e.name,
			(!!(include & INCLUDE_STA_STATUS_REPORT) ? 1 : 0));
	ret = uci_lookup_ptr(ctx, &ptr, buf, true);
	if (ret != UCI_OK)
		return -1;

	uci_set(ctx, &ptr);
	uci_save(ctx, ptr.p);
#endif

	return 0;
}

int fill_metric_report_policy_from_tlv(struct agent *a,
		struct tlv_metric_report_policy *p, struct uci_context *ctx,
		struct uci_package *pkg)
{
	int ret, i;
	int offset = 0;
	int num_radio;
	struct uci_element *e;
	struct uci_ptr ptr;
	char buf[64] = {0};
	uint8_t *data = (uint8_t *)p;

	offset = 1;
	num_radio = data[offset++];
	/* Add radio specific params in ap section */
	for (i = 0; i < num_radio; i++) {
		int k;
		int radio_index;
		uint8_t rcpi_threshold;
		uint8_t rcpi_hysteresis;
		uint8_t util_threshold;
		uint8_t include;
		uint8_t radio_id[6] = {0};
		struct wifi_radio_element *radio;

		memcpy(radio_id, data + offset, 6);
		offset += 6;
		rcpi_threshold = data[offset++];
		rcpi_hysteresis = data[offset++];
		util_threshold = data[offset++];
		include = data[offset++];

		radio_index = get_radio_index(a, radio_id);
		if (radio_index == -1)
			continue;

		radio = a->radios + radio_index;

		/* add configuration in each iface section for specific radio */
		for (k = 0; k < WIFI_DEVICE_MAX_NUM; k++) {
			uci_foreach_element(&pkg->sections, e) {
				struct uci_section *s = uci_to_section(e);

				if (strcmp(s->type, "radio"))
					continue;

				memset(buf, 0, sizeof(buf));
				snprintf(buf, sizeof(buf) - 1, "%s.%s.device",
						pkg->e.name, s->e.name);
				ret = uci_lookup_ptr(ctx, &ptr, buf, true);
				if (ptr.value && (ret != UCI_OK)) {
					fprintf(stderr, "value not found\n");
					continue;
				}

				if (strncmp(ptr.o->v.string, radio->name, 16))
					continue;

				add_metric_report_policy_config(ctx, pkg, s,
						rcpi_threshold, rcpi_hysteresis,
						util_threshold, include);

				break;
			}
		}

	}

	return 0;
}

/* for metric_reporting_policy_tlv:
 * num_radio = 1 && radio_id == ff:ff:ff:ff:ff:ff;
 * config need to apply on all ap section.
 */
int fill_metric_report_policy_all(struct agent *a,
		struct tlv_metric_report_policy *p, struct uci_context *ctx,
		struct uci_package *pkg)
{
	int offset = 0;
	struct uci_element *e;
	uint8_t *data = (uint8_t *)p;
	uint8_t rcpi_threshold;
	uint8_t rcpi_hysteresis;
	uint8_t util_threshold;
	uint8_t include;

	offset = 1 + 1 + 6;
	rcpi_threshold = data[offset++];
	rcpi_hysteresis = data[offset++];
	util_threshold = data[offset++];
	include = data[offset++];

	/* add configuration in each iface section */
	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (strcmp(s->type, "radio"))
			continue;

		add_metric_report_policy_config(ctx, pkg, s,
				rcpi_threshold, rcpi_hysteresis,
				util_threshold, include);
	}

	return 0;
}


int agent_fill_metric_report_policy(struct agent *a,
		struct tlv_metric_report_policy *p, struct uci_context *ctx,
		struct uci_package *pkg)
{
	int ret, offset = 0;
	int num_radio;
	uint8_t radio_id[6] = {0};
	struct uci_element *e;
	struct uci_ptr ptr;
	char buf[64] = {0};
	bool is_section_found = false;
	uint8_t *data = (uint8_t *)p;
	struct uci_section *s;
	uint8_t generic_id[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	uci_foreach_element(&pkg->sections, e) {
		s = uci_to_section(e);

		if (!strcmp(s->type, "policy")) {
			is_section_found = true;
			break;
		}
	}

	if (!is_section_found) {
		s = NULL;

		/* add a new section 'policy' */
		ret = uci_add_section(ctx, pkg, "policy", &s);
		if (ret != UCI_OK)
			return -1;

		uci_save(ctx, pkg);
	}

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1,
			"%s.%s.report_interval=%d",
			pkg->e.name, s->e.name, data[offset++]);
	ret = uci_lookup_ptr(ctx, &ptr, buf, true);
	if (ret != UCI_OK)
		return -1;

	uci_set(ctx, &ptr);
	uci_save(ctx, ptr.p);

	num_radio = data[offset++];
	memcpy(radio_id, data + offset, 6);
	if ((num_radio == 1) &&
			!memcmp(radio_id, generic_id, 6)) {
		fill_metric_report_policy_all(a, p, ctx, pkg);
	} else
		fill_metric_report_policy_from_tlv(a, p, ctx, pkg);

	return 0;
}

int agent_fill_8021q_setting(struct agent *a, uint16_t pvid, uint8_t pcp)
{
	int ret;
	struct uci_element *e;
	struct uci_ptr ptr;
	char buf[64] = {0};
	struct uci_section *s;
	bool is_section_found = false;
	struct uci_context *ctx;
	struct uci_package *pkg;

	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	if (uci_load(ctx, "mapagent", &pkg)) {
		uci_free_context(ctx);
		return -1;
	}

	uci_foreach_element(&pkg->sections, e) {
		s = uci_to_section(e);

		if (!strcmp(s->type, "policy")) {
			is_section_found = true;
			break;
		}
	}

	if (!is_section_found) {
		s = NULL;

		/* add a new section 'policy' */
		ret = uci_add_section(ctx, pkg, "policy", &s);
		if (ret != UCI_OK)
			return -1;

		uci_save(ctx, pkg);
	}

	dbg("Received Primary VID %u\n", pvid);

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1, "%s.%s.pvid=%d",
			pkg->e.name, s->e.name,
			pvid);
	ret = uci_lookup_ptr(ctx, &ptr, buf, true);
	if (ret != UCI_OK)
		return -1;

	uci_set(ctx, &ptr);
	uci_save(ctx, ptr.p);

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "%d", pvid);
	set_value_by_string("ieee1905", "ieee1905", "primary_vid", buf, UCI_TYPE_STRING);
	ieee1905_ubus_set_vid(a->ubus_ctx, a->pvid);

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1, "%s.%s.pcp_default=%d",
			pkg->e.name, s->e.name,
			(pcp & PCP_MASK) >> 5);
	ret = uci_lookup_ptr(ctx, &ptr, buf, true);
	if (ret != UCI_OK)
		return -1;

	uci_set(ctx, &ptr);
	uci_save(ctx, ptr.p);

	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return 0;
}

int agent_fill_8021q_setting_from_tlv(struct agent *a,
		struct tlv_default_8021q_settings *p)
{
	uint16_t pvid = BUF_GET_BE16(p->pvid);;
	uint8_t pcp = p->pcp;

	return agent_fill_8021q_setting(a, pvid, pcp);
}

int agent_clear_traffic_sep(struct agent *a)
{
	bool reload = false;

	/* if pvid was previously enabled, disable and wake nl */
	if (a->cfg.pcfg) {
		int pvid = a->cfg.pcfg->pvid;

		if ((pvid < TS_VID_INVALID) && (pvid > 0))
			reload = true;
	}

	uci_clear_traffic_sep(&a->cfg);

	if (reload)
		nl_check_vlan(a, true);

	return 0;
}

int agent_fill_traffic_sep_policy(struct agent *a,
		struct tlv_traffic_sep_policy *p)
{
	int ret, i;
	int offset = 0;
	int num_ssid;
	uint8_t *data = (uint8_t *)p;
	struct uci_element *e;
	struct uci_ptr ptr;
	char buf[64];
	struct uci_context *ctx;
	struct uci_package *pkg;

	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	if (uci_load(ctx, "mapagent", &pkg)) {
		uci_free_context(ctx);
		return -1;
	}

	num_ssid = data[offset++];
	for (i = 0; i < num_ssid; i++) {
		int ssid_len;
		uint16_t vid;
		char ssid[32] = {0};

		ssid_len = data[offset++];
		memcpy(ssid, data + offset, ssid_len);
		offset += ssid_len;
		vid = BUF_GET_BE16(data[offset]);
		offset += 2;

		uci_foreach_element(&pkg->sections, e) {
			struct uci_element *e1;
			struct uci_section *s = uci_to_section(e);
			char section_ssid[32] = {0};
			uint8_t maxlen = 0;

			if (strcmp(s->type, "ap"))
				continue;

			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf) - 1, "%s.%s.ssid",
					pkg->e.name, s->e.name);
			ret = uci_lookup_ptr(ctx, &ptr, buf, true);
			if (ret != UCI_OK)
				return -1;


			e1 = ptr.last;
			if (e1->type == UCI_TYPE_OPTION)
				strncpy(section_ssid, ptr.o->v.string, 31);


			maxlen = (strlen(section_ssid) > ssid_len ?
					strlen(section_ssid) : ssid_len);

			if (strncmp(section_ssid, ssid, maxlen))
				continue;

			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf) - 1, "%s.%s.vid=%d",
					pkg->e.name, s->e.name,
					vid);
			ret = uci_lookup_ptr(ctx, &ptr, buf, true);
			if (ret != UCI_OK)
				return -1;

			uci_set(ctx, &ptr);
			uci_save(ctx, ptr.p);

			/* if guest isolation is set, set isolate for guest VIDs */
			if (a->cfg.guest_isolation) {
				char ifname[16] = {0};

				if (strcmp(s->type, "ap"))
					continue;

				if (vid == a->cfg.pcfg->pvid)
					continue;

				memset(buf, 0, sizeof(buf));
				snprintf(buf, sizeof(buf) - 1, "%s.%s.ifname",
						pkg->e.name, s->e.name);
				ret = uci_lookup_ptr(ctx, &ptr, buf, true);
				if (ret != UCI_OK)
					continue;

				if (ptr.last->type != UCI_TYPE_OPTION)
					continue;

				strncpy(ifname, ptr.o->v.string, 16);

				uci_set_wireless_interface_option("wireless",
								  "wifi-iface",
								  "ifname",
								  ifname,
								  "isolate",
								  "1");
			}
		}
	}

	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return 0;
}

int agent_fill_ch_scan_rep_policy(struct agent *a,
		struct tlv_channel_scan_report_policy *p, struct uci_context *ctx,
		struct uci_package *pkg)
{
	int ret;
	struct uci_element *e;
	struct uci_ptr ptr;
	char buf[64] = {0};
	bool is_section_found = false;
	struct uci_section *s;

	uci_foreach_element(&pkg->sections, e) {
		s = uci_to_section(e);

		if (!strcmp(s->type, "policy")) {
			is_section_found = true;
			break;
		}
	}

	if (!is_section_found) {
		s = NULL;

		/* add a new section 'policy' */
		ret = uci_add_section(ctx, pkg, "policy", &s);
		if (ret != UCI_OK)
			return -1;

		uci_save(ctx, pkg);
	}

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1, "%s.%s.report_scan=%d",
			pkg->e.name, s->e.name,
			!!(p->report & REPORT_CHANNEL_SCANS) ? 1 : 0);
	ret = uci_lookup_ptr(ctx, &ptr, buf, true);
	if (ret != UCI_OK)
		return -1;

	uci_set(ctx, &ptr);
	uci_save(ctx, ptr.p);

	return 0;
}

int agent_fill_unsuccess_assoc_policy(struct agent *a,
		struct tlv_unsuccess_assoc_policy *p, struct uci_context *ctx,
		struct uci_package *pkg)
{
	int ret;
	struct uci_element *e;
	struct uci_ptr ptr;
	char buf[64] = {0};
	bool is_section_found = false;
	struct uci_section *s;

	uci_foreach_element(&pkg->sections, e) {
		s = uci_to_section(e);

		if (!strcmp(s->type, "policy")) {
			is_section_found = true;
			break;
		}
	}

	if (!is_section_found) {
		s = NULL;

		/* add a new section 'policy' */
		ret = uci_add_section(ctx, pkg, "policy", &s);
		if (ret != UCI_OK)
			return -1;

		uci_save(ctx, pkg);
	}

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1,
			"%s.%s.report_sta_assocfails=%d",
			pkg->e.name, s->e.name,
			!!(p->report & UNSUCCESSFUL_ASSOC_REPORT) ? 1 : 0);
	ret = uci_lookup_ptr(ctx, &ptr, buf, true);
	if (ret != UCI_OK)
		return -1;

	uci_set(ctx, &ptr);
	uci_save(ctx, ptr.p);

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1,
			"%s.%s.report_sta_assocfails_rate=%d",
			pkg->e.name, s->e.name,
			BUF_GET_BE32(p->max_report_rate));
	ret = uci_lookup_ptr(ctx, &ptr, buf, true);
	if (ret != UCI_OK)
		return -1;

	uci_set(ctx, &ptr);
	uci_save(ctx, ptr.p);

	return 0;
}

int agent_fill_backhaul_bss_config(struct agent *a,
		struct tlv_bbss_config *p, struct uci_context *ctx,
		struct uci_package *pkg)
{
	struct netif_fh *fh;
	struct uci_element *e;
	struct uci_ptr ptr;
	int ret;
	bool is_bksec_found = false;
	struct uci_section *s;
	char buf[64] = {0};

	fh = wifi_get_netif_by_bssid(a, p->bssid);
	if (fh == NULL)
		return -1;

	uci_foreach_element(&pkg->sections, e) {
		struct uci_element *e1;
		char section_ifname[16] = {0};

		s = uci_to_section(e);
		if (strcmp(s->type, "bsta"))
			continue;

		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf) - 1, "%s.%s.ifname",
				pkg->e.name, s->e.name);
		ret = uci_lookup_ptr(ctx, &ptr, buf, true);
		if (ptr.value && (ret != UCI_OK))
			return -1;

		e1 = ptr.last;
		if (e1->type == UCI_TYPE_OPTION)
			strncpy(section_ifname, ptr.o->v.string, 15);

		if (!strcmp(section_ifname, fh->name)) {
			is_bksec_found = true;
			break;
		}
	}

	if (!is_bksec_found) {
		s = NULL;

		/* Add a new 'bsta section' */
		ret = uci_add_section(ctx, pkg, "bsta", &s);
		if (ret != UCI_OK)
			return -1;

		uci_save(ctx, pkg);
	}

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1, "%s.%s.ifname=%s",
			pkg->e.name, s->e.name, fh->name);
	ret = uci_lookup_ptr(ctx, &ptr, buf, true);
	if (ret != UCI_OK)
		return -1;

	uci_set(ctx, &ptr);
	uci_save(ctx, ptr.p);

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1,
			"%s.%s.disallow_bsta_p1=%d",
			pkg->e.name, s->e.name,
			!!(p->config & BBSS_CONFIG_P1_BSTA_DISALLOWED) ? 1 : 0);
	ret = uci_lookup_ptr(ctx, &ptr, buf, true);
	if (ret != UCI_OK)
		return -1;

	uci_set(ctx, &ptr);
	uci_save(ctx, ptr.p);

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1,
			"%s.%s.disallow_bsta_p2=%d",
			pkg->e.name, s->e.name,
			!!(p->config & BBSS_CONFIG_P2_BSTA_DISALLOWED) ? 1 : 0);
	ret = uci_lookup_ptr(ctx, &ptr, buf, true);
	if (ret != UCI_OK)
		return -1;

	uci_set(ctx, &ptr);
	uci_save(ctx, ptr.p);

	return 0;
}

/* for backhaul_bss_config_tlv:
 * if p->bssid == ff:ff:ff:ff:ff:ff;
 * config need to apply on all bsta section.
 */
int agent_fill_backhaul_bss_config_all(struct agent *a,
		struct tlv_bbss_config *p, struct uci_context *ctx,
		struct uci_package *pkg)
{
	struct netif_fh *fh;
	struct uci_element *e;
	struct uci_ptr ptr;
	int ret;
	char buf[64] = {0};

	fh = wifi_get_netif_by_bssid(a, p->bssid);
	if (fh == NULL)
		return -1;

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s;

		s = uci_to_section(e);
		if (strcmp(s->type, "bsta"))
			continue;

		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf) - 1,
				"%s.%s.disallow_bsta_p1=%d",
				pkg->e.name, s->e.name,
				!!(p->config & BBSS_CONFIG_P1_BSTA_DISALLOWED) ? 1 : 0);
		ret = uci_lookup_ptr(ctx, &ptr, buf, true);
		if (ret != UCI_OK)
			return -1;

		uci_set(ctx, &ptr);
		uci_save(ctx, ptr.p);

		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf) - 1,
				"%s.%s.disallow_bsta_p2=%d",
				pkg->e.name, s->e.name,
				!!(p->config & BBSS_CONFIG_P2_BSTA_DISALLOWED) ? 1 : 0);
		ret = uci_lookup_ptr(ctx, &ptr, buf, true);
		if (ret != UCI_OK)
			return -1;

		uci_set(ctx, &ptr);
		uci_save(ctx, ptr.p);
	}

	return 0;
}

struct tlv_vendor_specific *agent_gen_vendor_specific_tlv(struct agent *a, uint8_t depth)
{
	return NULL;
//	struct tlv_vendor_specific *p;
//
//	p = calloc(1, sizeof(*p));
//	if (!p)
//		return NULL;
//
//	p->tlv_type = TLV_TYPE_VENDOR_SPECIFIC;
//	/* IOPSYS vendor oui */
//	p->vendor_oui[0] = 0x00;
//	p->vendor_oui[1] = 0x22;
//	p->vendor_oui[2] = 0x07;
//
//	p->m_nr = 1 + 1 + 2 + 1; // number of tlvs, type, len, val
//	p->m = calloc(1, p->m_nr);
//	if (!p->m)
//		goto error;
//
//	p->m[0] = 0x01;
//	p->m[1] = VENDOR_SPECIFIC_TYPE_DEPTH;
//	p->m[3] = 1;
//	p->m[4] = depth;
//
//	return p;
//error:
//	free(p);
//	return NULL;
}
#ifdef EASYMESH_VENDOR_EXT
int agent_gen_vendor_specific_bbbs_tlv(struct agent *a, struct cmdu_buff *frm)
{
	struct tlv *t;
	struct tlv_vendor_bbss *data;
	int i, ret;
	int offset = 0;
	uint8_t oui2[3];

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = TLV_TYPE_VENDOR_SPECIFIC;

	data = (struct tlv_vendor_bbss *) t->data;
	/* TODO: use the same vendor oui-type instead of a new oui2 here */
	memcpy(oui2, EASYMESH_VENDOR_EXT_OUI, 3);
	oui2[2]++;

	memcpy(data->oui, oui2, 3);
	offset += 3;
	data->num_radios = a->num_radios;
	offset += 1;

	for (i = 0; i < a->num_radios; i++) {
		int j;
		bool found = false;
		struct wifi_radio_element *r = &a->radios[i];

		memcpy(&t->data[offset], r->macaddr, 6);
		offset += 6;
		for (j = 0; j < a->radios[i].num_bss; j++) {
			struct netif_fh *fh;

			fh = wifi_get_netif_by_bssid(a, r->bsslist[j].bssid);
			if (!fh)
				continue;

			if (!(fh->cfg->multi_ap & 0x01))
				continue;

			/* TODO: currently assume at most one bbss per radio */
			t->data[offset] = 1;
			offset += 1;

			memcpy(&t->data[offset], fh->bssid, 6);
			offset += 6;
			found = true;
			break; /* TODO: currently assume at most one bbss per radio */
		}
		if (!found) {
			t->data[offset] = 0;
			offset += 1;
		}
	}

	t->len = offset;
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		err("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}
#endif /*EASYMESH_VENDOR_EXT*/

char *get_timestamp_old(time_t *t, char **tbuf)
{
	char tmpbuf[64] = {0};
	struct tm res;
	char sign;
	long toff, toff_hour, toff_min;
	const time_t now = time(t);

	//if (!tbuf)
	//        return NULL;

	/* E.g. "2019-02-11T06:42:31.23039-08:00" */

	localtime_r(&now, &res);
	tzset();
	toff = timezone;
	sign = toff > 0 ? '-' : '+';
	toff *= -1L;

	toff_hour = toff / 3600;
	toff_min = (toff % 3600) / 60;

	snprintf(tmpbuf, 63, "%04d-%02d-%02dT%02d:%02d:%02d%c%02ld:%02ld",
		 res.tm_year + 1900, res.tm_mon + 1, res.tm_mday,
		 res.tm_hour, res.tm_min, res.tm_sec,
		 sign, toff_hour, toff_min);

	if (!*tbuf) {
		*tbuf = calloc(1, strlen(tmpbuf) + 1);
		if (!*tbuf)
			return NULL;
	}

	snprintf(*tbuf, strlen(tmpbuf) + 1, "%s", tmpbuf);
	return *tbuf;
}

char *get_timestamp(time_t *t, char *tbuf)
{
	char tmpbuf[64] = {0};
	struct tm res;
	char sign;
	long int toff, toff_hour, toff_min;
	const time_t now = time(t);

	if (!tbuf)
			return NULL;

	/* E.g. "2019-02-11T06:42:31.23039-08:00" */

	localtime_r(&now, &res);
	tzset();
	toff = timezone;
	sign = toff > 0 ? '-' : '+';
	toff *= -1L;

	toff_hour = toff / 3600;
	toff_min = (toff % 3600) / 60;

	snprintf(tmpbuf, 63, "%04d-%02d-%02dT%02d:%02d:%02d%c%02ld:%02ld",
		 res.tm_year + 1900, res.tm_mon + 1, res.tm_mday,
		 res.tm_hour, res.tm_min, res.tm_sec,
		 sign, toff_hour, toff_min);

	snprintf(tbuf, 64, "%s", tmpbuf);
	return tbuf;
}

int agent_gen_timestamp_tlv(struct agent *agent, struct cmdu_buff *frm)
{
	int ret;
	struct tlv *t;
	char tsp[TIMESTAMP_TLV_MAX_LEN] = {0};
	struct tlv_timestamp *data;
	/* Allocate the TLV of the cmdu_data */
	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	/* Define the TLV */
	t->type = MAP_TLV_TIMESTAMP;
	data = (struct tlv_timestamp *) t->data;
	get_timestamp(NULL, tsp);
	data->len = strlen(tsp);
	memcpy(data->timestamp, (uint8_t *)tsp, data->len);
	t->len = sizeof(*data) + data->len;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}
	return 0;
}

/* Updates Scan Result TLV's NumberOfNeighbors */
void scan_result_tlv_update_num_nbr(struct tlv *t, uint32_t num_nbr)
{
	uint8_t status;
	uint8_t ts_len;
	int offset = 0;

	offset += 6; /* RUID */
	offset += 1; /* opclass */
	offset += 1; /* channel */
	status = t->data[offset];
	offset += 1; /* status code */

	/* Nothing to update */
	if (status != CH_SCAN_STATUS_SUCCESS)
		return;

	ts_len = t->data[offset];
	offset += 1; /* timestamp len */
	offset += ts_len; /* timestamp */
	offset += 1; /* utilization */
	offset += 1; /* noise */
	/* num neighbors */
	BUF_PUT_BE16(t->data[offset], num_nbr);
}

/* Reserves reserve_len bytes for scan response TLV and fills in repeatable data */
struct tlv *cmdu_reserve_scan_response_tlv(struct cmdu_buff *cmdu,
		int reserve_len, char *tsp, uint8_t *radio_mac, uint8_t opclass_id,
		struct wifi_scanres_channel_element *ch, uint8_t status, int *offset)
{
	trace("%s ---->\n", __func__);

	struct tlv *t;
	*offset = 0;

	t = cmdu_reserve_tlv(cmdu, reserve_len);
	if (!t)
		return NULL;

	t->type = MAP_TLV_CHANNEL_SCAN_RES;
	memcpy(&t->data[*offset], radio_mac, 6);
	*offset += 6;
	t->data[*offset] = opclass_id;	/* opclass */
	*offset += 1;
	t->data[*offset] = ch->channel;	/* channel */
	*offset += 1;
	t->data[*offset] = status;		/* status code */
	*offset += 1;

	/* Put (non-success) status code only */
	if (status != CH_SCAN_STATUS_SUCCESS)
		return t;

	t->data[*offset] = strlen(ch->tsp) + 1;		/* timestamp len */
	*offset += 1;
	memcpy(&t->data[*offset], ch->tsp, strlen(ch->tsp));	/* timestamp */
	*offset += strlen(ch->tsp);
	t->data[*offset] = '\0';
	*offset += 1;
	t->data[*offset] = ch->utilization;	/* utilization */
	*offset += 1;
	t->data[*offset] = ch->anpi;		/* noise */
	*offset += 1;
	/* num neighbors */
	BUF_PUT_BE16(t->data[*offset], ch->num_neighbors);
	*offset += 2;

	return t;
}

/* Puts Channel Scan Response TLV(s) into CMDU. Splits neighbors evenly
 * between TLVs so that TLV is always less than CH_SCAN_RESP_MAX_DATALEN.
 */
int agent_gen_ch_scan_response_tlv(struct agent *a, struct cmdu_buff *cmdu,
			uint8_t *radio_mac, uint8_t opclass_id,
			struct wifi_scanres_channel_element *ch, uint8_t status)
{
	trace("%s ---->\n", __func__);

	char tsp[32] = {0};
	struct tlv *t;
	uint8_t bssload_elem_pres = CH_SCAN_RESULT_BSSLOAD_PRESENT;
	int i, ret, offset = 0;
	int reserve_len = CH_SCAN_RESP_TLV_MAX_LEN;
	/* TODO/FIXME
	 * add the total scan duration for active scan
	 */
	uint32_t scan_duration = 0;
	uint32_t num_nbr = 0;

	trace("\t INFO: radio " MACFMT ", channel %d\n",
		  MAC2STR(radio_mac), ch->channel);

	get_timestamp(NULL, tsp);
	memcpy(ch->tsp, tsp, strlen(tsp));
	t = cmdu_reserve_scan_response_tlv(cmdu, reserve_len,
				tsp, radio_mac, opclass_id, ch, status, &offset);
	if (!t)
		return -1;

	/* Put (non-success) status code only */
	if (status != CH_SCAN_STATUS_SUCCESS)
		goto put_tlv;

	for (i = 0; i < ch->num_neighbors; i++) {
		char bw_str[16] = {0};
		struct wifi_scanres_neighbor_element *nbr = ch->nbrlist + i;

		snprintf(bw_str, 15, "%u", nbr->bw);

		/* Check if nbr data will fit within TLV limits */
		if ((offset + 18 + strlen(nbr->ssid) + strlen(bw_str)) >= reserve_len) {
			/* Always add scan duration and scan type to TLV */
			BUF_PUT_BE32(t->data[offset], scan_duration);
			offset += 4;
			t->data[offset++] = SCAN_RESULT_SCAN_TYPE;

			/* Update the TLV length */
			t->len = offset;
			/* Update NumberOfNeighbors */
			if (num_nbr != ch->num_neighbors)
				scan_result_tlv_update_num_nbr(t, num_nbr);
			/* Put intermediate TLV into CMDU ... */
			ret = cmdu_put_tlv(cmdu, t);
			if (ret) {
				fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
				return -1;
			}

			/* ... and start over */
			t = cmdu_reserve_scan_response_tlv(cmdu,
						reserve_len,
						tsp,
						radio_mac,
						opclass_id,
						ch,
						status,
						&offset);
			if (!t)
				return -1;
			num_nbr = 0;
		}

		memcpy(&t->data[offset], nbr->bssid, 6);	/* bssid */
		offset += 6;
		t->data[offset++] = strlen(nbr->ssid);		/* ssid len */
		/* ssid */
		memcpy(&t->data[offset], nbr->ssid, strlen(nbr->ssid));
		offset += strlen(nbr->ssid);
		t->data[offset++] = rssi_to_rcpi(nbr->rssi);	/* rcpi */

		t->data[offset++] = strlen(bw_str); //+ 1;		/* BW length */
		memcpy(&t->data[offset], bw_str, strlen(bw_str));
		/* NOTE: It is not a real string terminated with EOS null */
		offset += strlen(bw_str);
		//t->data[offset++] = '\0';
		t->data[offset++] = bssload_elem_pres;		/* BSS load element */

		if (bssload_elem_pres & CH_SCAN_RESULT_BSSLOAD_PRESENT) {
			t->data[offset++] = nbr->utilization;			/* channel utilization */
			BUF_PUT_BE16(t->data[offset], nbr->num_stations);	/* station count */
			offset += 2;
		}
		num_nbr++;
	}

	BUF_PUT_BE32(t->data[offset], scan_duration);	/* scan duration */
	offset += 4;
	t->data[offset++] = SCAN_RESULT_SCAN_TYPE;	/* scan type */

put_tlv:
	/* update the tlv length */
	t->len = offset;
	/* Update NumberOfNeighbors */
	if (num_nbr != ch->num_neighbors)
		scan_result_tlv_update_num_nbr(t, num_nbr);
	ret = cmdu_put_tlv(cmdu, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_bk_sta_radio_cap_tlv(struct agent *a, uint32_t radio_index, struct cmdu_buff *cmdu)
{
	struct wifi_radio_element *radio = a->radios + radio_index;
	struct tlv *t;
	struct tlv_bsta_radio_cap *p;
	struct netif_bk *bk = NULL;
	struct wifi_radio_element *bk_radio;
	int ret;

	/* Allocate the TLV of the cmdu_data */
	t = cmdu_reserve_tlv(cmdu, 256);
	if (!t)
		return -1;

	/* Define the TLV */
	t->type = MAP_TLV_BACKHAUL_STA_RADIO_CAPABILITY;
	t->len = 7;
	p = (struct tlv_bsta_radio_cap *) t->data;
	memcpy(p->radio, radio->macaddr, 6);
	p->macaddr_included = 0;
	list_for_each_entry(bk, &a->bklist, list) {
		if (hwaddr_is_zero(bk->bssid))
			continue;

		bk_radio = wifi_ifname_to_radio_element(a,
				bk->cfg->name);
		if (!bk_radio)
			continue;

		if (!strcmp(radio->name, bk_radio->name)) {
			memcpy(p->macaddr, bk->bssid, 6);
			p->macaddr_included = BSTA_MACADDRESS_INCLUDED;
			t->len += 6;
			break;
		}
	}

	ret = cmdu_put_tlv(cmdu, t);
	if (ret) {
		trace("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_client_assoc_event_tlv(struct agent *agent, struct cmdu_buff *frm,
		uint8_t *mac, uint8_t *bssid, uint8_t assoc_event)
{
	struct tlv *t;
	struct tlv_client_assoc_event *data;
	int ret;

	t = cmdu_reserve_tlv(frm, 128);
	if (!t)
		return -1;

	t->type = MAP_TLV_CLIENT_ASSOCIATION_EVENT;
	t->len = 13;
	data = (struct tlv_client_assoc_event *) t->data;

	memcpy(data->macaddr, mac, 6);
	memcpy(data->bssid, bssid, 6);
	if (assoc_event == 0x01)
		data->event = 1 << 7;
	else
		data->event = 0;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_sta_mac(struct agent *agent,
		struct cmdu_buff *frm, uint8_t *mac)
{
	int ret;
	struct tlv *t;
	struct tlv_sta_mac *data;

	t = cmdu_reserve_tlv(frm, 20);
	if (!t)
		return -1;

	t->type = MAP_TLV_STA_MAC_ADDRESS;
	t->len = sizeof(*data);
	data = (struct tlv_sta_mac *) t->data;

	memcpy(data->macaddr, mac, 6);
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_reason_code(struct agent *agent,
		struct cmdu_buff *frm, uint16_t reason_code)
{
	int ret;
	struct tlv *t;
	struct tlv_reason_code *data;

	t = cmdu_reserve_tlv(frm, 20);
	if (!t)
		return -1;

	t->type = MAP_TLV_REASON_CODE;
	t->len = sizeof(*data);
	data = (struct tlv_reason_code *) t->data;

	BUF_PUT_BE16(data->code, reason_code);
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_ap_oper_bss_tlv(struct agent *a,
		struct cmdu_buff *frm)
{
	struct tlv *t;
	struct tlv_ap_oper_bss *data;
	int ret, i = 0;
	uint8_t *ptr;

	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = MAP_TLV_AP_OPERATIONAL_BSS;
	t->len = 1;

	ptr = t->data;
	data = (struct tlv_ap_oper_bss *)t->data;

	data->num_radio = (uint8_t) a->num_radios;
	ptr += 1;

	for (i = 0; i < a->num_radios; i++) {
		int j;
		uint8_t *num_bss;
		/* radio mac */
		memcpy(ptr, a->radios[i].macaddr, 6);
		ptr += 6;
		t->len += 6;

		/* num_bss */
		num_bss = ptr;
		*num_bss = 0;
		ptr += 1;
		t->len += 1;

		for (j = 0; j < a->radios[i].num_bss; j++) {
			/* only report BSS in PWR_ON or PWR_SAVE mode */
			if (a->radios[i].bsslist[j].enabled) {
				int len;

				(*num_bss)++;

				len = strlen(a->radios[i].bsslist[j].ssid);

				/* iface bssid */
				memcpy(ptr, a->radios[i].bsslist[j].bssid, 6);
				ptr += 6;
				t->len += 6;

				/* ssid len */
				memcpy(ptr, &len, 1);
				ptr += 1;
				t->len += 1;

				/* ssid */
				memcpy(ptr, a->radios[i].bsslist[j].ssid, len);
				ptr += len;
				t->len += len;
			}
		}
	}

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		err("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_assoc_client_tlv(struct agent *a, struct cmdu_buff *frm)
{
	struct tlv *t;
	struct tlv_assoc_client *data;
	int i, ret;
	int offset = 0;

	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = MAP_TLV_ASSOCIATED_CLIENTS;
	t->len = 1;

	data = (struct tlv_assoc_client *) t->data;
	offset += 1;
	data->num_bss = 0;

	for (i = 0; i < a->num_radios; i++) {
		int j;

		for (j = 0; j < a->radios[i].num_bss; j++) {

			if (!a->radios[i].bsslist[j].enabled)
				continue;

			data->num_bss++;
			/* bssid */
			memcpy(&data[offset], a->radios[i].bsslist[j].bssid, 6);
			offset += 6;

#if 1 /* TODO: replace with stalist when ready for use */
			{
				struct netif_fh *fh;
				struct sta *s;
				uint16_t num_sta = 0;

				fh = wifi_get_netif_by_bssid(a, a->radios[i].bsslist[j].bssid);
				if (!fh)
					continue;

				list_for_each_entry(s, &fh->stalist, list)
					num_sta++;

				/* num_client */
				BUF_PUT_BE16(data[offset], num_sta);
				offset += 2;


				list_for_each_entry(s, &fh->stalist, list) {
					uint16_t conntime = 0;

					/* macaddr */
					memcpy(&data[offset], s->macaddr, 6);
					offset += 6;

					conntime = ((s->connected_ms / 1000) > 0xFFFF)
						? 0xFFFF
						: (s->connected_ms / 1000) & 0xFFFF;

					/* conntime */
					BUF_PUT_BE16(data[offset], conntime);

					offset += 2;
				}
			}
#endif
#if 0
			p->bss[idx + j].clients =
				calloc(a->radios[i].bsslist[j].num_stations,
				       sizeof(*p->bss[idx + j].clients));
			if (!p->bss[idx + j].clients)
				return NULL;

			p->bss[idx + j].assoc_clients_nr =
				a->radios[i].bsslist[j].num_stations;

			for (k = 0; k < p->bss[idx + j].assoc_clients_nr; k++) {
				memcpy(p->bss[idx + j].clients[k].client_addr,
				       a->radios[i].bsslist[j].stalist[k].macaddr,
				       sizeof(p->bss[idx + j].clients[k].client_addr));

				/* Note: cap at 0xFFFF, see above */
				p->bss[idx + j].clients[k].uptime =
					a->radios[i].bsslist[j].stalist[k].conn_time;
			}
#endif
		}
	}
	t->len = offset;
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		err("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_tlv_backhaul_steer_resp(struct agent *a, struct cmdu_buff *frm,
		uint8_t *target_bssid, uint8_t *macaddr)
{
	struct tlv *t;
	struct tlv_backhaul_steer_resp *data;
	int ret;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_BACKHAUL_STEERING_RESPONSE;
	t->len = 13;
	data = (struct tlv_backhaul_steer_resp *) t->data;

	memcpy(data->target_bssid, target_bssid, 6);
	memcpy(data->macaddr, macaddr, 6);
	data->result = 0x0; /* default success */

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_assoc_status_notif(struct agent *a, struct cmdu_buff *frm,
		int num_data, void *data)
{
	int i, ret;
	int offset = 0;
	struct tlv *t;
	struct bss_data {
		uint8_t bssid[6];
		uint8_t status;
	} *bss_data = NULL;

	if (!data)
		return -1;

	bss_data = (struct bss_data *)data;
	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = MAP_TLV_ASSOCIATION_STATUS_NOTIF;

	t->data[offset++] = (uint8_t) num_data;		/* num bss */
	for (i = 0; i < num_data; i++) {
		memcpy(&t->data[offset], bss_data[i].bssid, 6);	/* bssid */
		offset += 6;
		t->data[offset++] = bss_data[i].status;		/* status */
	}

	t->len = offset;
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_client_info(struct agent *a, struct cmdu_buff *frm,
		uint8_t *sta, uint8_t *bssid)
{
	int ret;
	struct tlv *t;
	struct tlv_client_info *data;

	t = cmdu_reserve_tlv(frm, 30);
	if (!t)
		return -1;

	t->type = MAP_TLV_CLIENT_INFO;
	t->len = sizeof(*data);
	data = (struct tlv_client_info *)t->data;
	memcpy(data->bssid, bssid, 6);
	memcpy(data->macaddr, sta, 6);

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_client_cap_report(struct agent *a, struct cmdu_buff *frm,
		uint8_t result, struct sta *s)
{
	int ret;
	struct tlv *t;
	struct tlv_client_cap_report *data;

	if (result != 0x00) {
		t = cmdu_reserve_tlv(frm, 10);
		if (!t)
			return -1;

		t->type = MAP_TLV_CLIENT_CAPABILITY_REPORT;
		t->len = sizeof(*data);
		data = (struct tlv_client_cap_report *)t->data;

		data->result = result;
	} else {
		/* [re]assoc frame received without the header
		 * so no need to skip bytes
		 */
		uint8_t *body;
		int len;

		len = s->assoc_frame->len;
		body = s->assoc_frame->frame;

		/* reserve addition few bytes (say 10 more bytes)
		 * actual required: len + 3; (1: tlv_type, 2: tlv_len)
		 */
		t = cmdu_reserve_tlv(frm, len + 10);
		if (!t)
			return -1;

		t->type = MAP_TLV_CLIENT_CAPABILITY_REPORT;
		t->len = sizeof(*data);
		data = (struct tlv_client_cap_report *)t->data;
		data->result = result;

		/* copy the raw frame */
		memcpy(data->frame, body, len);

		t->len += len;
	}

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_tlv_higher_layer_data(struct agent *a, struct cmdu_buff *frm,
		uint8_t proto, uint8_t *data, int len)
{
	struct tlv *t;

	t = cmdu_reserve_tlv(frm, len + 1);
	if (!t)
		return -1;

	t->type = MAP_TLV_HIGHER_LAYER_DATA;
	t->len = len + 1;
	t->data[0] = proto;
	memcpy(t->data + 1, data, len);

	if (cmdu_put_tlv(frm, t))
		return -1;

	return 0;
}

int agent_gen_status_code(struct agent *a, struct cmdu_buff *frm,
		int status_code)
{
	int ret;
	struct tlv *t;
	struct tlv_status_code *data;

	t = cmdu_reserve_tlv(frm, 20);
	if (!t)
		return -1;

	t->type = MAP_TLV_STATUS_CODE;
	t->len = sizeof(*data);
	data = (struct tlv_status_code *) t->data;

	BUF_PUT_BE16(data->code, status_code & 0xffff);
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

#if (EASYMESH_VERSION > 2)
int agent_gen_bss_config_report_tlv(struct agent *a, struct cmdu_buff *frm)
{
	struct tlv *t;
	struct tlv_bss_configuration_report *data;
	int ret, i = 0;
	uint8_t *ptr;

	t = cmdu_reserve_tlv(frm, 1024);
	if (!t)
		return -1;

	t->type = MAP_TLV_BSS_CONFIGURATION_REPORT;
	t->len = 1;

	ptr = t->data;
	data = (struct tlv_bss_configuration_report *)t->data;

	data->num_radio = (uint8_t) a->num_radios;
	ptr += 1;

	for (i = 0; i < a->num_radios; i++) {
		int j;
		uint8_t *num_bss;

		/* radio mac */
		memcpy(ptr, a->radios[i].macaddr, 6);
		ptr += 6;
		t->len += 6;

		/* num_bss */
		num_bss = ptr;
		*num_bss = 0;
		ptr += 1;
		t->len += 1;
		for (j = 0; j < a->radios[i].num_bss; j++) {
			uint8_t report = 0x00;
			/* only report BSS in PWR_ON or PWR_SAVE mode that are in fronthaul*/
			if (a->radios[i].bsslist[j].enabled) {
				int len;
				struct netif_fh *fh;

				(*num_bss)++;

				len = strlen(a->radios[i].bsslist[j].ssid);

				/* iface bssid */
				memcpy(ptr, a->radios[i].bsslist[j].bssid, 6);
				ptr += 6;
				t->len += 6;

				/*report bits */
				fh = wifi_get_netif_by_bssid(a, a->radios[i].bsslist[j].bssid);
				if (!fh)
					continue;

				/* Here the in use flag is 0 and not in use flag is 1*
				 * So if it is backhaul the fronthaul flag is 1*/
				if (fh->cfg->multi_ap == 0x01 || fh->cfg->multi_ap == 0x03) {
					if (fh->cfg->multi_ap == 0x01)
						report = report | 0x40;
					/*As the R1 or R2 disallow will only happen in backhaul*/
					if (fh->cfg->bsta_disallow == 0x01)
						report = report | 0x20;
					else if (fh->cfg->bsta_disallow == 0x02)
						report = report | 0x10;
					else if (fh->cfg->bsta_disallow == 0x03) {
						report = report | 0x20;
						report = report | 0x10;
					}
				} else if (fh->cfg->multi_ap == 0x02)
					report = report | 0x80;

				/*TODO BSS_CONFIG_MBSSID*/
				/*TOD0 BSS_CONFIG_TX_MBSSID*/

				memcpy(ptr, &report, 1);
				ptr += 1;
				t->len += 1;

				/*reserved octet*/
				ptr += 1;
				t->len += 1;

				/* ssid len */
				memcpy(ptr, &len, 1);
				ptr += 1;
				t->len += 1;

				/* ssid */
				memcpy(ptr, a->radios[i].bsslist[j].ssid, len);
				ptr += len;
				t->len += len;
			}
		}
	}

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		err("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_akm_suite_cap(struct agent *a, struct cmdu_buff *frm)
{
	struct tlv *tlv;
	uint8_t *data_ptr;
	int i;

	// todo: populate with real data
	uint8_t num_bh_bss_akm_suite_selectors = 2;
	uint8_t num_fh_bss_akm_suite_selectors = 2;

	tlv = cmdu_reserve_tlv(frm, 100);
	if (!tlv)
		return -1;
	tlv->type = MAP_TLV_AKM_SUITE_CAPS;
	tlv->len = 100;

	data_ptr = tlv->data;

	*data_ptr = num_bh_bss_akm_suite_selectors;
	data_ptr += sizeof(num_bh_bss_akm_suite_selectors);

	for (i = 0; i < num_bh_bss_akm_suite_selectors; ++i) {
		struct akm_suite *suite_selector = (struct akm_suite *)data_ptr;

		suite_selector->oui[0] = 0;
		suite_selector->oui[1] = 1;
		suite_selector->oui[2] = 2;
		suite_selector->type = 3;

		data_ptr += sizeof(*suite_selector);
	}

	*data_ptr = num_fh_bss_akm_suite_selectors;
	data_ptr += sizeof(num_fh_bss_akm_suite_selectors);

	for (i = 0; i < num_fh_bss_akm_suite_selectors; ++i) {
		struct akm_suite *suite_selector = (struct akm_suite *)data_ptr;

		suite_selector->oui[0] = 0;
		suite_selector->oui[1] = 1;
		suite_selector->oui[2] = 2;
		suite_selector->type = 3;

		data_ptr += sizeof(*suite_selector);
	}

	if (cmdu_put_tlv(frm, tlv))
		return -1;

	return 0;
}

int agent_gen_device_1905_layer_security_cap(struct agent *a,
		struct cmdu_buff *frm)
{
	struct tlv *t;
	struct tlv_1905_security_cap *data;

	t = cmdu_reserve_tlv(frm, 10);
	if (!t)
		return -1;

	t->type = MAP_TLV_1905_SECURITY_CAPS;
	data = (struct tlv_1905_security_cap *)t->data;

	t->len = sizeof(*data);
	/* TODO: need to do the mapping */
	data->protocol = SECURITY_PROTOCOL_DPP;
	data->mic = SECURITY_MIC_HMAC_SHA256;
	data->enc = SECURITY_ENC_AES_SIV;

	if (cmdu_put_tlv(frm, t))
		return -1;

	return 0;
}

int agent_gen_conf_req_object_atrributes(struct agent *a, struct cmdu_buff *frm)
{
	struct tlv *tlv;
	int data_len;

	// todo: populate with real data, a sample JSON DPP conf. req. object:
	const char *data =
		"{\
			\"name\":\"My Device\",\
			\"wi-fi_tech\":\"infra\",\
			\"netRole\":\"ap\"\
		}";

	data_len = strlen(data);

	tlv = cmdu_reserve_tlv(frm, data_len);
	if (!tlv)
		return -1;
	tlv->type = MAP_TLV_BSS_CONFIGURATION_REQUEST;
	tlv->len = data_len;

	memcpy(tlv->data, data, data_len);

	if (cmdu_put_tlv(frm, tlv))
		return -1;

	return 0;
}

int agent_gen_device_inventory(struct agent *a, struct cmdu_buff *frm)
{
	struct tlv *t;
	uint8_t *data;
	int i, offset = 0;
	int lsn, lsv, lee;
	int reserve_len = (65 * 3) + (a->num_radios * 72);

	t = cmdu_reserve_tlv(frm, reserve_len);
	if (!t)
		return -1;

	t->type = MAP_TLV_DEVICE_INVENTORY;
	data = (uint8_t *)t->data;

	lsn = strlen(a->device_inventory.serial_number);
	data[offset] = lsn;
	offset++;	/* serial number len */
	memcpy(&data[offset], a->device_inventory.serial_number, lsn);
	offset += lsn;	/* serial number */

	lsv = strlen(a->device_inventory.sw_version);
	data[offset] = lsv;
	offset++;	/* software version len */
	memcpy(&data[offset], a->device_inventory.sw_version, lsv);
	offset += lsv;	/* software version */

	lee = 0;
	data[offset] = lee;
	offset++;	/* execution env len */
	/* TODO : not available currently */
	// data->exenv.ee ??;
	offset += lee;	/* execution env */

	data[offset] = a->num_radios;
	offset++;	/* num radio */
	for (i = 0; i < a->num_radios; i++) {
		struct wifi_radio_element *r = a->radios + i;
		struct device_inventory_radio *ir =
			(struct device_inventory_radio *)&t->data[offset];

		memcpy(ir->ruid, r->macaddr, 6);
		ir->lcv = strlen(r->vendor);
		memcpy(ir->cv, r->vendor, ir->lcv);
		offset += 6 + 1 + ir->lcv;
	}

	t->len = offset;
	if (cmdu_put_tlv(frm, t))
		return -1;

	return 0;
}

/* TODO: fill the following fields
 * DPP flag,
 * Enrollee MAC & hash
 */
int agent_gen_dpp_chirp(struct agent *a, struct cmdu_buff *frm)
{
	struct tlv *t;
	int offset = 0;
	uint8_t flag = 0x00;
	bool specify_enrollee;

	/* dummy values */
	uint8_t enrollee[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	int hashlen = 1;
	uint8_t hash[1] = { 0xff };

	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = MAP_TLV_DPP_CHIRP_VALUE;
	t->data[offset++] = flag;
	specify_enrollee = BIT(7, flag) ? true : false;
	// specify_enrollee = (flag & DPP_CHIRP_ENROLLEE_MAC_PRESENT) ? true : false;
	if (specify_enrollee) {
		memcpy(&t->data[offset], enrollee, 6);
		offset += 6;
	}

	t->data[offset++] = hashlen;
	memcpy(&t->data[offset], hash, hashlen);
	offset += hashlen;

	t->len = offset;
	if (cmdu_put_tlv(frm, t))
		return -1;

	return 0;
}

int agent_gen_assoc_wifi6_sta_status_report(struct agent *a,
		struct cmdu_buff *frm, struct sta *s)
{
	int ret, offset = 0;
	struct tlv *t = NULL;
	struct tlv_assoc_wifi6_sta_status_report *data;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_ASSOCIATED_WIFI6_STA_STATUS;
	data = (struct tlv_assoc_wifi6_sta_status_report *)t->data;
	memcpy(data->macaddr, s->macaddr, 6);
	offset += sizeof(*data);
	/* TODO:
	 * fill the queue size & tid data
	 * need to add the same in struct sta
	 */
	t->len = offset;
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int agent_gen_dpp_bootstrapping_uri_notif(struct agent *a,
		struct cmdu_buff *frm, uint8_t *radio_id, uint8_t *bssid,
		uint8_t *bksta, char *dpp_uri, int uri_len)
{
	struct tlv *t;
	struct tlv_dpp_uri_bootstrap *data;
	int reserve_len = uri_len + 30;

	t = cmdu_reserve_tlv(frm, reserve_len);
	if (!t)
		return -1;

	t->type = MAP_TLV_DPP_BOOTSTRAP_URI_NOTIFICATION;
	t->len = sizeof(*data) + uri_len;
	data = (struct tlv_dpp_uri_bootstrap *)t->data;

	memcpy(data->ruid, radio_id, 6);
	memcpy(data->bssid, bssid, 6);
	memcpy(data->bsta, bksta, 6);
	memcpy(data->uri, dpp_uri, uri_len);

	if (cmdu_put_tlv(frm, t))
		return -1;

	return 0;
}

#endif
