#ifndef WIFI_H
#define WIFI_H

#include "wifidefs.h"
#include "wifi_opclass.h"
#include "wifi_scanresults.h"

/* Extra - try to remove it ... */
struct supp_channel {
	uint8_t channel;
	uint8_t pref;
	uint8_t dfs;
	char dfs_state[32];
	uint32_t cac_time;
	uint32_t nop_time;
	uint8_t ctrl_channels[32];
};

struct wifi_opclass_supported_element {
	uint8_t id;                     /* class number */
	int8_t max_txpower;
	uint32_t bandwidth;
	uint32_t num_exclude_channels;
	uint8_t *exclude_chanlist;      /* list of non-operable channels */
	uint32_t num_supported_channels;
	struct supp_channel supp_chanlist[64];         /*list of supporting channels for each class*/
};

struct wifi_radio_status {
	struct wifi_radio info;

	uint8_t opclass;
	uint8_t channel;
	uint8_t bandwidth;
};

struct wifi_request_neighbor_param {
	uint8_t opclass;
	uint8_t channel;
	uint8_t *bssid;
	uint8_t reporting_detail;
	uint8_t ssid_len;
	char *ssid;
	uint8_t num_report;
	uint8_t *report;
	uint8_t num_element;
	uint8_t *element;
};

/* TODO try to use wifi_caps and bitmap */
struct wifi_mcs {
	uint16_t vht_mcs_rxmap;
	uint16_t vht_mcs_txmap;
};

struct wifi_wifi6_capabilities {
	bool he160;
	bool he8080;
	uint8_t mcs_nss_len;
	union {
		uint8_t mcs_nss_4[4];
		uint8_t mcs_nss_8[8];
		uint8_t mcs_nss_12[12];
	};
	bool su_beamformer;
	bool su_beamformee;
	bool mu_beamformer;
	bool beamformee_le80;
	bool beamformee_gt80;
	bool ul_mumimo;
	bool ul_ofdma;
	bool dl_ofdma;
	uint8_t max_dl_mumimo;
	uint8_t max_ul_mumimo;
	uint8_t max_dl_ofdma;
	uint8_t max_ul_ofdma;
	bool rts;
	bool mu_rts;
	bool multi_bssid;
	bool mu_edca;
	bool twt_requester;
	bool twt_responder;
	bool spatial_reuse;
	bool anticipated_ch_usage;
};

struct wifi_caps_element {
	uint8_t ht;
	uint8_t vht[6];
	uint8_t he[15];		/* 1 (supp-mcs-len), 12 (Tx Rx mcs), 2 (others) */
	struct wifi_mcs mcs;
	struct wifi_wifi6_capabilities wifi6;
	bool wmm;
};

struct wifi_ap_status {
	struct wifi_ap ap;

	/* TODO check if we can use ap.caps */
	struct wifi_caps_element caps;
};

struct wifi_bsta_status {
	struct wifi_sta sta;

	uint8_t ssid[33];
	enum wifi_band band;
	enum wifi_bw bandwidth;
	uint32_t channel;
	uint32_t frequency;
	bool mode4addr;
};

/* WiFi radio APIs */
int wifi_radio_status(const char *name, struct wifi_radio_status *status);
int wifi_scan(const char *name, struct scan_param_ex *p,
	      int num_opclass, uint8_t *opclass,
	      int num_channel, uint8_t *channel);
int wifi_get_scan_results(const char *name, struct wifi_bss *bsss, int *num);
int wifi_start_cac(const char *name, int channel, enum wifi_bw bw,
		   enum wifi_cac_method method);
int wifi_stop_cac(const char *name);
int wifi_opclass_preferences(const char *radio,
			     struct wifi_radio_opclass *opclass);

/** WiFi interface APIs */
int wifi_subscribe_frame(const char *ifname, uint8_t type, uint8_t stype);
int wifi_unsubscribe_frame(const char *ifname, uint8_t type, uint8_t stype);
int wifi_set_4addr(const char *ifname, bool enable);
int wifi_get_4addr(const char *ifname, bool *enabled);


/* WiFi AP interface specific APIs */
int wifi_ap_status(const char *name, struct wifi_ap_status *ap_status);
int wifi_ap_stats(const char *ifname, struct wifi_ap_stats *stats);
int wifi_get_assoclist(const char *ifname, uint8_t *stas, int *num_stas);
int wifi_get_stations(const char *ifname, struct wifi_sta *sta, int *num);
int wifi_get_station(const char *ifname, uint8_t *sta_addr, struct wifi_sta *sta);
int wifi_disconnect_sta(const char *ifname, uint8_t *sta, uint16_t reason);
int wifi_restrict_sta(const char *ifname, uint8_t *sta, int enable);
int wifi_monitor_sta(const char *ifname, uint8_t *sta, struct wifi_monsta_config *cfg);
int wifi_monitor_sta_add(const char *ifname, uint8_t *sta);
int wifi_monitor_sta_del(const char *ifname, uint8_t *sta);
int wifi_get_monitor_sta(const char *ifname, uint8_t *sta, struct wifi_monsta *mon);

int wifi_add_neighbor(const char *ifname, struct nbr *nbr);
int wifi_del_neighbor(const char *ifname, unsigned char *bssid);
int wifi_get_neighbor_list(const char *ifname, struct nbr *nbrs, int *nr);
int wifi_req_bss_transition(const char *ifname, unsigned char *sta,
			    int bsss_nr, unsigned char *bsss,
			    unsigned int tmo);
int wifi_req_btm(const char *ifname, uint8_t *sta, int bsss_nr, uint8_t *bsss,
		 struct wifi_btmreq *b);
int wifi_chan_switch(const char *ifname, struct chan_switch_param *param);
int wifi_ap_set_state(const char *ifname, bool up);
int wifi_add_vendor_ie(const char *ifname, int mgmt, char *oui, char *data);
int wifi_del_vendor_ie(const char *ifname, int mgmt, char *oui, char *data);
int wifi_req_neighbor(const char *ifname, uint8_t *sta,
		      struct wifi_request_neighbor_param *param);

int wifi_bsta_status(const char *ifname, struct wifi_bsta_status *bsta_status);

/* WiFi STA interface APIs */
int wifi_sta_info(const char *ifname, struct wifi_sta *sta);
int wifi_sta_disconnect_ap(const char *ifname, uint32_t reason);


int c2f(int chan);
uint32_t wifi_bw_to_bw(enum wifi_bw bw);
enum wifi_bw bw_to_wifi_bw(uint32_t bandwidth);

#endif /* WIFI_H */


