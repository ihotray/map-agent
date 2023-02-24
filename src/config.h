/*
 * config.h - Agent configurations header
 *
 * Copyright (C) 2019 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#ifndef CONFIG_H
#define CONFIG_H

// TODO: try to get rid of these
#include <easy/easy.h>
#include "wifidefs.h"

#if 0
enum steer_action {
	STEER_DISABLE,     /** steer disallowed */
	STEER_MANDATE,     /** steer immediately */
	STEER_OPPORTUNITY, /** steer at the next opportunity within a time-window */
};
#endif

#define STEER_LEGACY_FALLBACK_INT	0	/* no legacy = 0, else in secs */
#define STEER_LEGACY_REASSOC_INT	600	/* secs */
#define STEER_LEGACY_RETRY_INT		21600	/* secs */

#define STEER_BTM_RETRY			0	/* no retry */
#define STEER_BTM_RETRY_INT		180	/* secs */

#define ASSOC_CONTROL_INT		10	/* secs */

#define CONTROLLER_SELECT_LOCAL			0	/* external cntlr */
#define CONTROLLER_SELECT_AUTODETECT	1	/* discover cntlr ID */
#define CONTROLLER_SELECT_PROBE_INT		20	/* secs */
#define CONTROLLER_SELECT_RETRY_INT		3	/* attempts */
#define CONTROLLER_SELECT_AUTOSTART		0	/* don't start cntlr */
#define UCI_DEVICE     "wifi-device"

/* defined in main.c */
extern int verbose;

struct wsc_ext;
struct wifi_radio_element;

struct steer_policy {
	char name[16];	/* XXX: maps to struct steer_rule.name in (all)?
			 * cases otherwise there is no way of knowing how
			 * a steer_policy will be applied.
			 */

	bool enabled;
	void *policy;	/** policy specific data */
	struct list_head list; /* link to next policy */
};

struct stax {
	char macstring[32];	/* ':' separated mac address string */
	struct list_head list;
};

void stax_add_entry(struct list_head *h, char *sta_macstr);
void stax_del_entry(struct list_head *h, char *sta_macstr);

enum agent_steer_policy {
	AGENT_STEER_DISALLOW,		/* agent shall not steer based on rcpi */
	AGENT_STEER_RCPI_MANDATE,	/* agent shall steer based on rcpi */
	AGENT_STEER_RCPI_ALLOW,		/* agent may steer based on rcpi */
};

/* per-bss interface config is good for now.
 * per-sta config is overkill, or maybe not ;)
 */
struct netif_fhcfg {
	bool invalid;
	char name[16];
	char device[16];
	char ssid[33];
	char key[65];
	char encryption[32];
	enum wifi_band band;
	bool enabled;
	bool sta_steer_enabled;
	bool assoc_control;

	/* int steer_policy; */

	/** legacy steer if BTM request is rejected/unsupported */
	unsigned int fallback_legacy;       /* secs after which to trigger legacy ap-steering */
	unsigned int steer_btm_retry;       /* num retries for btm requests */
	unsigned int steer_btm_retry_secs;  /* btm retry interval in secs */

	unsigned int assoc_control_time;    /* secs to restrict sta from associating */

	/** Monitor interval for STA (re)assoc'ng after legacy steered */
	unsigned int steer_legacy_reassoc_secs;
	/** Skip interval for legacy steering STA if it (re)assoc'd within reassoc_secs */
	unsigned int steer_legacy_retry_secs;

	/** ordered list of policies effective on per-bss interface */
	struct list_head steer_policylist;

	/** STAs assoc controlled; list of stax structs */
	struct list_head assoc_ctrllist;

	enum agent_steer_policy policy;

	struct list_head list;  /* link to next netif_config */
	uint8_t multi_ap;	/* this option is 1 fh 2 bh 3 both */
	unsigned int vid;	/* traffic separation vlan id */
	uint8_t bsta_disallow;  /*this option 1 p1 2 p2 3 both disallow*/
};

struct netif_bkcfg {
	char name[16];
	enum wifi_band band;
	char device[16];
	char ssid[33];
	char key[65];
	char encryption[32];
	bool enabled;
	bool onboarded;
	uint8_t priority;
	uint8_t bssid[6];
	/* TODO: others as needed */
	struct list_head list;  /* link to next netif_bkcfg */
};

struct policy_cfg {
	uint8_t report_interval;
	uint16_t pvid;
	uint8_t pcp_default;
	bool report_scan;
	bool report_sta_assocfails;
	uint32_t report_sta_assocfails_rate;

	/** STAs excluded from steering; list of stax structs */
	struct list_head steer_excludelist;
	/** STAs excluded from BTM req steering; list of stax structs */
	struct list_head steer_btm_excludelist;
};

struct ctrl_select_cfg {
	bool local;			/* true - own MAP Controller treated as the main or primary. */
	bool auto_detect;	/* Set to true if alid of controller is not explicitly provided by config. */
	uint16_t probe_int;	/* Time interval in seconds between controller discovery by the MAP Agent. */
	uint8_t retry_int;	/* Num of discovery retries before taking next action. */
	bool autostart;		/* true - agent will try to start own controller after not finding one. */
	uint8_t alid[6];	/* 1905 ALID of the device that will have the MAP Controller service */
};

struct dyn_bh_cfg {
	uint16_t bh_miss_tmo; /* Time interval (sec) between bh lost and recovery actions. */
	uint16_t bh_reconf_tmo; /* Time interval (sec) between bh link is lost and fallback recovery actions. */
};

enum runfreq {
	AGENT_RUN_OFF,
	AGENT_RUN_HIGH,
	AGENT_RUN_MOD = 5,
	AGENT_RUN_AUTO = AGENT_RUN_MOD,
	AGENT_RUN_LOW = 10,
};

struct agent_config_radio {
	char name[16];
	uint8_t band;
	bool onboarded;
	bool dedicated_backhaul;
	uint16_t encryption;
	uint8_t steer_policy;
	uint8_t util_threshold;
	uint8_t rcpi_threshold;
	uint8_t report_rcpi_threshold;
	uint8_t rcpi_hysteresis_margin;
	uint8_t report_util_threshold;
	bool include_sta_stats;
	bool include_sta_metric;
#if (EASYMESH_VERSION > 2)
	bool include_wifi6_sta_status;
#endif
	struct list_head list;
};

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
struct agent_config {
	bool enabled;
	int debug_level;
	enum runfreq runfreq;
	struct list_head radiolist;
	struct list_head fhlist;  /* list of netif_fhcfg */
	struct list_head bklist;  /* list of netif_bkcfg */
	uint8_t map_profile;
	bool brcm_setup;
	bool configured;
	bool dyn_cntlr_sync;
	int resend_num;
	uint8_t cntlr_almac[6];
	char al_bridge[16];
	char netdev[IFNAMSIZ];
	bool island_prevention;
	bool eth_onboards_wifi_bhs;
	bool ap_follow_sta_dfs;
	bool guest_isolation;
	bool scan_on_boot_only;

	struct policy_cfg *pcfg;  /* policy section */
	struct ctrl_select_cfg *cscfg;  /* controller select section */
	struct dyn_bh_cfg dbhcfg;  /* dynamic backhaul section */
	atimer_t metric_report_timer;
};

#if 0
union config {
	struct agent_config agent;
	struct controller_config cntlr;
};
#endif

struct agent;
struct netif_bk;

enum m2_process_status {
	M2_PROCESS_OK,
	M2_PROCESS_ERROR,
	M2_PROCESS_TEARDOWN
};

/* TODO: move to a uci_utils.c */
int set_value(struct uci_context *ctx, struct uci_package *pkg,
		struct uci_section *section, const char *key,
		const char *value, enum uci_option_type type);
int set_value_by_string(const char *package, const char *section,
		const char *key, const char *value, enum uci_option_type type);
char *agent_get_controller_enabled(struct agent *a, char *buf);
struct uci_section *config_get_iface_section(struct uci_context *ctx,
		struct uci_package *pkg, const char *type, const char *ifname);
bool uci_reload_services(char *services);
struct uci_package *uci_load_pkg(struct uci_context **ctx, const char *config);
int wifi_get_iface_bssid(char *ifname, uint8_t *bssid);
int wifi_set_iface_bssid(struct netif_bk *bk, uint8_t *bssid);

/* END TODO */
struct agent_config_radio *get_agent_config_radio(struct agent_config *c,
		const char *ifname);
char *agent_config_get_ethwan(char *ifname);

int agent_config_init(struct agent *a, struct agent_config *cfg);
int agent_config_load(struct agent_config *cfg);
int agent_config_clean(struct agent_config *cfg);
int agent_config_defaults(struct agent *a, struct agent_config *cfg);
void agent_config_dump(struct agent_config *cfg);

int config_update(const char *confname, struct agent_config *cfg,
		const char *section, const char *option, int add,
		void *value, int len);


int config_update2(const char *confname, struct agent_config *cfg,
		const char *section_type,
		const char *match_option,
		const char *match_option_value,
		const char *option, int add, void *value, int len);

int wifi_apply_iface_cfg(const char *ifname, const char *encryption,
		const char *ssid, const char *key);
int config_del_iface(const char *config, const char *type, const char *ifname);
struct uci_section *config_add_section(struct uci_context *ctx,
		struct uci_package *pkg, const char *config, const char *type,
		const char *key, const char *value);
int config_add_default_wifi_iface(const char *config, const char *type,
		const char *ifname, const char *device, const char *network,
		const char *mode);

bool uci_check_wifi_iface(char *package_name, char *ifname,
		char *section);
bool uci_set_wireless_interface_option(char *package_name,
		char *section_type, char *search_key, char *search_val,
		char *option, char *value);
bool uci_add_wireless_iface_sec(char *package_name, char *interface_name,
		char *section_type, char *section_name);
int agent_init_wsc_attributes(struct agent *a);
int wifi_get_section_option(const char *package, const char *sec_type,
			    const char *sec_key, const char *sec_value,
			    const char *get_key, char *buf, int len);
void clean_bk(struct netif_bkcfg *p);
int clean_all_bk(struct agent_config *cfg);
void clean_fh(struct netif_fhcfg *p);
int clean_all_fh(struct agent_config *cfg);

int uci_apply_m2(struct agent_config *cfg, char *interface_name, char *device,
		struct wps_credential *out, bool onboarded, struct wsc_ext *exts);
int uci_apply_wps_credentials(struct agent_config *cfg, enum wifi_band band);
int config_calc_ifname(struct agent_config *cfg, uint8_t dev_num,
		uint8_t index, char *ifname);
int uci_set_bridge(char *config, char *bridge, char *proto, char *ipaddress);
int uci_add_dhcp(char *interface);
int uci_add_fw(struct agent_config *cfg, char *interface);
void config_disable_bstas(struct agent_config *cfg);
int config_disable_bsta(struct netif_bkcfg *bk);
int config_enable_bsta(struct netif_bkcfg *bk);
int uci_apply_default_8021q_settings(struct tlv_default_8021q_settings *tlv);
int uci_clear_traffic_sep(struct agent_config *cfg);
void uci_apply_traffic_sep(struct tlv_traffic_sep_policy *tlv);
int wifi_set_opclass_preference(char *radio_name, uint32_t opclass_id,
	uint32_t preference, uint8_t *channel_list, int channel_num);
int agent_config_opclass(struct  wifi_radio_element *radio);

#endif
