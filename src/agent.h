/*
 * agent.h - wifiagent header
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#ifndef AGENT_H
#define AGENT_H

#include <easy/easy.h>
#include "wifi.h"

#include "timer.h"
#include <cmdu_ackq.h>
#include <map_module.h>
#include <linux/if_bridge.h>

// TODO: TODO: fixme: remove this include
//#include <ieee1905/1905_tlvs.h>

#ifndef EASYMESH_VENDOR_EXT_OUI
#define EASYMESH_VENDOR_EXT_OUI         (uint8_t *)"\x00\x11\x22"
#endif

#define MAPAGENT_OBJECT		"map.agent"
#define MAPAGENT_DBG_OBJECT	"map.agent.dbg"
#define MAP_UPLINK_PATH 	"/var/run/multiap/multiap.backhaul"

#define MAX_STA 32

#define AGENT_RECONFIG_REASON_AP_AUTOCONF	0x01
#define AGENT_RECONFIG_REASON_VLAN_SETUP	0x02
#define AGENT_RECONFIG_REASON_VLAN_TEARDOWN	0x04

typedef char timestamp_t[32];

/* defined in agent/main.c */
extern const char *ubus_socket;
extern const char *pidfile;

/* struct node - maps to a 1905 device */
struct node {
	uint8_t alid[6];
	uint8_t map_profile;		   /** profile info of node */

	struct agent *agent;
	struct list_head list;
};

/** TODO - refine - preferred neighbor candiate for a STA */
struct pref_neighbor {
	uint8_t bssid[6];
	int8_t rssi;
	int8_t rsni;
	uint32_t bssid_info;
	uint8_t reg;
	uint8_t channel;
	uint8_t phy;
	struct list_head list;
	/* to calculate preference */
	uint32_t max_bwrate;	/* max possible downlink phy rate */
	uint32_t est_bwrate;	/* estimated downlink phy rate */
	uint32_t ch_util;	/* channel utilization percent */
	int num_stas;           /* number of stas connected */
	uint32_t flags;         /* struct neighbor flags */
};

struct sta_neighbor {
	struct sta_nbr nbr;
	struct timespec tsp;
	struct list_head list;
};

struct sta_channel_report {
	uint8_t opclass;
	uint8_t num_channel;
	uint8_t channel[128];
};

#define MAX_UNASSOC_STAMACS 10
struct unassoc_sta_metric {
	uint8_t channel;
	uint8_t num_sta;
	struct {
		uint8_t macaddr[6];
	} sta[MAX_UNASSOC_STAMACS];
};

struct action_frame_container {
	uint8_t frame_control[2];
	uint8_t duration[2];
	uint8_t dst[6];
	uint8_t src[6];
	uint8_t bssid[6];
	uint8_t seq_num[2];
	uint8_t category_code;
	uint8_t action_code;
	uint8_t dialog_token;
	uint8_t tags[];
} __attribute__((packed));

struct sta_error_response {
	uint8_t sta_mac[6];
	uint8_t response;
};

struct wifi_assoc_frame {
	uint16_t len;
	uint8_t macaddr[6];
	uint8_t *frame;
	struct list_head list;
};

#define STA_PERIODIC_RUN_INTERVAL       1000       /** 1 sec */
#define STA_NBR_REFRESH_CNT             120        /** x5 = 10 mins in auto */
#define STA_NBR_LIST_INTERVAL           2000  /** fetch bcn rpt after 2 secs of requesting*/
#define STA_NBR_AGEOUT_INTERVAL         10000   /** sta bcnreport is dynamic; expires quickly */

typedef struct cntlr_preflist {
	int num;
	unsigned char bsss[];
} cntlr_preflist_t;

enum sta_steer_policy {
	STA_STEER_ALLOWED  = 1 << 0,    /** steer allowed by agent (default set) */
	STA_STEER_MANDATE  = 1 << 1,    /** steer immediately as instructed by cntlr */
	STA_STEER_OPPORTUNITY = 1 << 2, /** steer at the next opportunity within a time-window */
};

enum sta_disallowed {
	STA_DISALLOWED_NONE = 0,
	STA_DISALLOWED_BTM = 1 << 0,
	STA_DISALLOWED_LOCAL = 1 << 1,
};

#define sta_steer_allowed(p)	(!!((p) & STA_STEER_ALLOWED))

struct sta_bcn_req {
	struct netif_fh *fh;
	uint8_t sta_addr[6];
	uint8_t opclass;
	uint8_t channel;
	uint8_t bssid[6];
	uint8_t reporting_detail;
	uint8_t ssid_len;
	char ssid[33];
	uint8_t num_element;
	uint8_t element[128];
};

struct sta {
	unsigned char macaddr[6];
	uint32_t caps;                  /** capability bitmap */
	int rssi[4];                    /** rssi of last received pkt */
	uint64_t connected_ms;          /** number of msecs connected */
	struct timespec last_update;
	uint32_t tx_rate;
	uint32_t rx_rate;
	uint64_t tx_bytes;
	uint64_t rx_bytes;
	uint64_t tx_pkts;
	uint64_t rx_pkts;
	uint32_t tx_fail_pkts;
	uint32_t rx_fail_pkts;
	int tx_thput;              /** estimate based on tx-bytes per sec */
	int rx_thput;              /** rx-bytes per sec */
	int tx_airtime;
	int rx_airtime;
	struct sta_config *cfg;
#define STEER_BTM	0x10
#define STEER_LEGACY	0x20
	int steer_ready;                    /** steer when reached this state */
	uint32_t steer_policy;              /** steer policies, STA_STEER_* */
	int steer_btm_cnt;                  /** num times tried to BTM-steer STA */
	int steer_secs;                     /** num secs STA adjudged as steering candidate */
	struct list_head rulelist;          /** steering rule list */
	uint32_t steer_opportunity_tmo;     /** steer op timeout in msec */
	struct timespec steer_opportunity;  /** steer opportunity time window */
	atimer_t sta_steer_timer;           /** steer opportunity timer */
	atimer_t sta_finalize_timer;        /** for sta cleanup */
	int ref;                            /** ref counting purpose */
	bool legacy_steered;                /** legacy steered */
	int inform_leaving;                 /** flag indicating leaving BSS */
	bool wait_for_cntlr_nbr;            /** awaiting pref nbr from cntlr */
	bool supports_bcnreport;            /** supports 11K beacon reporting */
	atimer_t sta_timer;                 /** periodic run */
	atimer_t sta_bcn_req_timer;         /** enqueue bcn requests */
	struct list_head sta_nbrlist;       /** neighbor BSSs as seen by this STA */
	struct list_head pref_nbrlist;      /** neighbors arranged by preference */
	cntlr_preflist_t *cntlr_preflist;   /** neighbors preferred by controller */
	int sta_nbr_nr;                     /** number of neighbor BSSs */
	int sta_bcn_req_nr;                 /** num of bcn requests in queue */
	struct sta_bcn_req bcn_req_queue[16]; /** beacon request queue */
	struct list_head list;              /** next STA in the list */
	struct netif_fh *vif;
	struct wifi_assoc_frame *assoc_frame;
};

/* enum netif_type { IFTYPE_WIRED, IFTYPE_WIFI, IFTYPE_UNKNOWN }; */

#define BSS_REFRESH_INTERVAL		60000       /** 1 min */

#define NBR_REFRESH_INTERVAL		600000      /** 10 mins */
#define NBR_AGEOUT_INTERVAL		1800000U    /** not dynamic; so 30mins is good */
#define NBR_SCAN_CNT			60          /** 1 hr */

struct neighbor {
	struct nbr nbr;
	struct timespec tsp;	/* last seen tsp */
	uint8_t radio_mac[6];	/* Radio Unique Identifier */
	struct list_head list;
#define NBR_FLAG_DRV_UPDATED     0x1
	uint32_t flags;
};

struct restrict_sta_entry {
	uint8_t sta[6];
	char fh_ifname[16]; /*TODO remove as param not needed*/
	struct netif_fh *vif;
	atimer_t restrict_timer;
	struct list_head list;
};

typedef uint32_t wifi_object_t;

#define WIFI_OBJECT_INVALID	((uint32_t)-1)

#define TS_VID_INVALID 0x0FFF

/* fronthaul wifi (ap) interface */
struct netif_fh {
	char name[16];
	int channel;
	int bandwidth;
	unsigned char bssid[6];
	char ssid[33];
	char standard[32];
	char radio_name[16];
	bool enabled;
	bool torndown;
	int bssload;
	struct netif_fhcfg *cfg;
	int nbr_scan;
	atimer_t rdr_timer; /** radar nop timer */
	atimer_t nbr_timer; /** refresh neighbor list timer */
	atimer_t bss_timer; /** refresh own bss timer */

	/* Channel utilization threshold timer */
	atimer_t util_threshold_timer;
	/* Unassociated station measurement timer */
	atimer_t una_sta_meas_timer;

	struct list_head restrict_stalist;  /* list of restrict_sta_entry */
	struct list_head nbrlist;
	int nbr_nr;
	struct list_head list;
	uint16_t nbr_sta;
	struct list_head stalist;
	wifi_object_t wifi;
	wifi_object_t radio;
	struct agent *agent;

	/* AP TLV information, move out of netif_fh? */
	uint8_t rx_spatial_streams;
	uint8_t tx_spatial_streams;

	struct wifi_caps_element caps;

	/* previous rcpi threshold value */
	uint8_t prev_rcpi;

	/* previous channel utilization threshold value */
	uint8_t prev_util;
};

/* backhaul wifi (sta) interface */
struct netif_bk {
	char name[16];
	bool enabled;
	int channel;
	uint8_t bssid[6];
	uint8_t wan_bssid[6];
	char ssid[33];
	bool connected;
	bool wps_active;
	struct netif_bkcfg *cfg;
	/* enum netif_type iftype; */
	struct list_head list;
	wifi_object_t wifi;
	wifi_object_t radio;
	struct agent *agent;
	struct {
		uint8_t new_bssid[6];
		uint8_t prev_bssid[6];
		struct cmdu_buff *cmdu;
	} bsta_steer;
	atimer_t connect_timer;
	struct timespec cac_start;
	int cac_time;

#define BSTA_BLACKLIST_MAX_NUM 16
	int num_blacklist_bssids;
	uint8_t blacklist_bssid[16][6];
};

#if 0
struct agent_msg {
	void *ctx;
	struct CMD_struct msg;
	struct list_head list;
};
#endif

#define WIFI_DEVICE_MAX_NUM	4
#define WIFI_IFACE_MAX_NUM	16

enum {
	WIFI_IFACE_FH,
	WIFI_IFACE_BK,
};

struct wifi_opclass_current_element {
	timestamp_t tsp;
	uint8_t id;
	uint8_t channel;
	int8_t txpower;
};

struct wifi_sta_element {
	timestamp_t tsp;
	uint8_t macaddr[6];
	struct wifi_caps_element caps;
	uint32_t dl_rate;             /* latest data rate in Kbps: ap -> sta */
	uint32_t ul_rate;             /* latest data rate in Kbps: sta -> ap */
	unsigned long ul_utilization; /* time in msecs for receive from sta */
	unsigned long dl_utilization; /* time in msecs for transmit to sta */
	uint32_t dl_est_thput;        /* in Mbps */
	uint32_t ul_est_thput;        /* in Mbps */
	int8_t rssi;                 /* in dBm */
	uint32_t conn_time;           /* in secs since last associated */
	uint64_t tx_bytes;            /* transmit bytes count: ap -> sta */
	uint64_t rx_bytes;            /* receive bytes count: sta -> ap */
	uint32_t tx_pkts;
	uint32_t rx_pkts;
	uint32_t tx_errors;
	uint32_t rx_errors;
	uint32_t rtx_pkts;            /* total retransmitted packets */
	struct ip_address ipaddr;
	char hostname[128];
	uint8_t num_bcn_reports;
	uint8_t *bcn_reportlist;      /* list of beacon reports */
};

struct wifi_bss_element {
	timestamp_t tsp;
	uint8_t bssid[6];
	char ssid[33];
	bool enabled;
	uint32_t uptime;
	uint64_t tx_ucast_bytes;
	uint64_t rx_ucast_bytes;
	uint64_t tx_mcast_bytes;
	uint64_t rx_mcast_bytes;
	uint64_t tx_bcast_bytes;
	uint64_t rx_bcast_bytes;
	uint8_t is_ac_be;
	uint8_t is_ac_bk;
	uint8_t is_ac_vo;
	uint8_t is_ac_vi;
	uint8_t est_wmm_be[3];
	uint8_t est_wmm_bk[3];
	uint8_t est_wmm_vi[3];
	uint8_t est_wmm_vo[3];
	uint32_t num_stations;
	struct wifi_sta_element *stalist;
};

#define MIN_SCAN_ITV_SEC 3 /* 3 sec */

struct wifi_scanres_neighbor_element {
	uint8_t bssid[6];
	char ssid[33];
	int rssi;
	uint32_t bw;
	uint8_t utilization;
	uint32_t num_stations;
};

struct wifi_scanres_channel_element {
	timestamp_t tsp;
	uint8_t channel;
	uint8_t utilization;
	uint8_t anpi;
	uint32_t num_neighbors;
	struct wifi_scanres_neighbor_element *nbrlist;  /* scanned AP list */
};

struct wifi_scanres_opclass_element {
	uint8_t opclass;
	uint32_t bandwidth;
	uint32_t num_channels_scanned;
	struct wifi_scanres_channel_element *channel_scanlist;
};

struct wifi_scanres_element {
	timestamp_t tsp;
	uint32_t num_opclass_scanned;
	struct wifi_scanres_opclass_element *opclass_scanlist;
};

struct wifi_backhaul_element {
	uint8_t macaddr[6];
};

struct wifi_sta_measurement {
		uint8_t opclass;
		uint8_t channel;
		int8_t rssi;
		uint8_t rcpi;
		/* of most recent measurement */
		struct timespec timestamp;
		/* num of failed measurements */
		int num_tries;
};

struct wifi_unassoc_sta_element {
	uint8_t macaddr[6];
	bool monitor;
	struct wifi_sta_measurement meas;
};

struct wsc_ext {
	bool enabled;
#define VEN_IES_MAX 16
	uint8_t num_ven_ies;
	struct wsc_vendor_ie ven_ies[VEN_IES_MAX];
};

struct wsc_data {
	uint8_t *m1_frame;
	uint16_t m1_size;
	struct wsc_key *key;
};

#define HEARTBEAT_AUTOCFG_INTERVAL 70
enum autocfg_state {
	AUTOCFG_HEARTBEAT,
	AUTOCFG_ACTIVE
};

#define SCAN_MAX_CHANNEL 16
struct wifi_scan_request_opclass {
	uint8_t classid;
	uint8_t num_channel;
	uint8_t channel[SCAN_MAX_CHANNEL];
};

#define SCAN_MAX_OPCLASS 8
struct wifi_scan_request_radio {
	uint16_t mid;	/* message id of the request */
	uint8_t status; /* current status for the request */
	uint8_t radio[6];
	uint8_t num_opclass;
	struct wifi_scan_request_opclass opclass[SCAN_MAX_OPCLASS];
};

#define SCAN_MAX_RADIO 4
struct wifi_scan_request {
	uint8_t mode;
	uint8_t num_radio;
	struct wifi_scan_request_radio radio[SCAN_MAX_RADIO];
};

struct wifi_radio_element {
	char name[16];
	uint8_t macaddr[6];
	uint8_t country_code[2];
	enum wifi_band band;
	bool enabled;
	int anpi;
	uint8_t total_utilization;   /** in %age, linearly scaled 0..255 */
	uint8_t tx_utilization;
	uint8_t rx_utilization;
	uint8_t other_utilization;
	uint8_t rx_streams;
	uint8_t tx_streams;

	uint8_t current_opclass;
	uint8_t current_channel;
	uint8_t current_txpower_percent;
	uint32_t current_bandwidth;
	bool cac_required;

	uint8_t transmit_power_limit; /* set in the channel selection message */
	uint8_t max_bss;

	uint32_t num_curr_opclass;
	uint32_t num_unassoc_sta;
	uint32_t num_bss;
	uint32_t num_scanresult;

	uint64_t tx_bytes;
	uint64_t tx_packets;
	uint64_t tx_error_packets;
	uint64_t tx_dropped_packets;
	uint64_t rx_bytes;
	uint64_t rx_packets;
	uint64_t rx_error_packets;
	uint64_t rx_dropped_packets;
	uint64_t rx_plcp_error_packets;
	uint64_t rx_fcs_error_packets;
	uint64_t rx_mac_error_packets;
	uint64_t rx_unknown_packets;

	struct wifi_backhaul_element bksta;

	/* Device reported opclass */
	struct wifi_radio_opclass opclass;

	/* Controller requested opclass */
	struct wifi_radio_opclass req_opclass;

	struct wifi_bss_element *bsslist;

	/* Scan results to be reported to the controller */
	struct wifi_scanres_element *scanlist;

	/* Device reported scanresults */
	struct wifi_scanresults scanresults;

	/* List used to keep track of unassociated STAs with
	 * their monitor status and current RCPI measurements.
	 */
	struct wifi_unassoc_sta_element *unassoc_stalist;

	/** AP-Autoconfig */
	enum autocfg_state state;
	bool onboarded;
	bool dedicated_backhaul;
	struct wsc_data autconfig;
	uint16_t mid;
	uint16_t wsc_mid;
	uint16_t renew_mid; /* debug purposes */

	/* radio scan state */
	enum wifi_scan_state scan_state;

	struct {
		bool opclass_preferences;
	} post_scan_action;

	/* wps metadata */
	uint8_t uuid[16];
	char manufacturer[65];          /* with terminating '\0' */
	char model_name[33];
	char device_name[33];
	char model_number[33];
	char serial_number[33];
	uint8_t device_type[8];         /* <category>0050F204<subcategory> */
	uint32_t os_version;
	char vendor[65];

	bool report_oper_channel;
	bool local_acs_enabled;

	uint8_t reported_channel;
	uint32_t reported_bandwidth;
};

struct wifi_netdev {
	char radio[16];
	struct {
		char name[16];
		int mode;
	} iface[WIFI_IFACE_MAX_NUM];

	/* Scan request data recorded for this device */
	struct wifi_scan_request_radio scan_req;
	/* 5 minutes available for scan */
	atimer_t available_scan_timer;
	/* Last scan request timestamp */
	struct timespec last_scan_tsp;

	struct wifi_radio_element *re;

	struct agent *agent;
};

struct wifi_sta_steer_list {
	uint8_t sta_mac[6];
	uint8_t complete;
};

/** struct agent - wifi agent */
struct agent {
	int debug;
	uint8_t almac[6];
	uint8_t cntlr_almac[6];
	atimer_t autocfg_dispatcher;
	atimer_t loop_detection_dispatcher;
	atimer_t reload_scheduler;
	uint8_t reconfig_reason; /* bitmap: 1<<0 apconf, 1<<1 vlan teardown */
	atimer_t cntlr_scheduler;
	atimer_t onboarding_scheduler;
	atimer_t disable_unconnected_bstas_scheduler;
	atimer_t init_ifaces_scheduler;
	atimer_t enable_fhs_scheduler;
	atimer_t boot_scan_scheduler;
	/* refresh radio stats data */
	atimer_t radio_stats_scheduler;
	struct list_head fhlist;
	struct list_head bklist;
	struct list_head framelist;
	struct list_head ethlist;

	uint16_t pvid;

	int num_nodes;
	struct list_head nodelist;

	wifi_object_t wifi;
	int num_radios;
	struct wifi_radio_element radios[WIFI_DEVICE_MAX_NUM];
	struct wifi_netdev ifs[WIFI_DEVICE_MAX_NUM];
	struct agent_config cfg;
	struct cmdu_ackq cmdu_ack_q;

	/* backhaul link info */
	struct {
		char ifname[16];
		uint8_t ul_almac[6];
		uint8_t ul_hwaddr[6];
	} ul_dev;

	/* controller selection configuration */
	struct {
		bool local;
		bool auto_detect;
		uint16_t probe_int;
		uint8_t retry_int;
		bool autostart;
		uint8_t alid[6];
	} cntlr_select;

	/* dynamic controller config sync */
	uint16_t sync_config_reqsize;
	uint8_t *sync_config_req;
	void *privkey;

	/* plugins */
	struct list_head pluginlist;

	/* steering opportunity */
	bool is_sta_steer_start; /* To know whether STA steering is on going */
	atimer_t sta_steer_req_timer; /** steer opportunity timer */
	uint32_t sta_steerlist_count;
	struct wifi_sta_steer_list sta_steer_list[MAX_STA];

	/* immediate loop detection - TODO: remove */
	struct {
		time_t rx_time;
		uint16_t rx_mid;
		uint16_t tx_mid;
	} loop_detection;

	/* timestamp of most recent occurence of controller in the network */
	struct timespec observed_time;
	/* number of autoconfig searches w/o reply from controller */
	int cntlr_miss_count;
	/* running controller available in network */
	bool active_cntlr;
	/* multiple controllers found in network */
	bool multiple_cntlr;
	/* current autoconfig search interval - depends on state */
	uint16_t autocfg_interval;

	/* channel scan */
	uint8_t scan_status_code;
	int boot_scan_tries;

	/* i1905 stack subscription */
	uint32_t map_oid;
	mapmodule_cmdu_mask_t cmdu_mask;
	void *subscriber;
	bool subscribed;

	/* ubus object and events */
	struct ubus_context *ubus_ctx;
	struct ubus_event_handler evh;
	struct ubus_event_handler ieee1905_evh;
	struct ubus_object obj;

	/* ubus debug object */
	struct ubus_object obj_dbg;

	/* STA Metrics Reporting RCPI Threshold timer */
	atimer_t rcpi_threshold_timer;

	atimer_t bh_lost_timer;
	atimer_t bh_reconf_timer;
#ifdef AGENT_ISLAND_PREVENTION
	atimer_t sta_disconnect_timer;
	atimer_t fh_disable_timer;
#endif /* AGENT_ISLAND_PREVENTION */

	/* dynamic backhaul */
	atimer_t upgrade_backhaul_scheduler;
	bool progressing;
	int progress_attempts;
	bool connected;
	struct timespec dynbh_last_start;
	struct timespec dynbh_last_end;
	struct timespec connect_t;
	struct timespec disconnect_t;
	uint8_t backhaul_macaddr[2][6];
	struct timespec backhaul_change_t;
	struct timespec eth_connect_t;

	struct ts_context ts;

	/* Device Inventory */
	struct {
		char serial_number[65];
		char sw_version[65];
		char ex_env[65];
	} device_inventory;

	/* unsuccessful association */
	struct timespec last_unassoc;
	uint32_t unassoc_cnt;
};

struct netif_bk *find_bkhaul_by_bssid(struct agent *a, uint8_t *bssid);
struct wsc_data *agent_free_wsc_data(struct wsc_data *wsc);
void agent_link_ap_to_cfg(struct agent *a);
void agent_config_load_post_action(struct agent *a);
int agent_config_reload(struct agent *a);

extern void run_agent(void);

int agent_exec_platform_scripts(char *arg);
struct node *agent_find_node(struct agent *c, uint8_t *almac);
struct node *agent_alloc_node(struct agent *a, uint8_t *almac);
struct node *agent_add_node(struct agent *a, uint8_t *almac);

extern int wifiagent_steer_sta(struct ubus_context *ctx, char *ifname,
		unsigned char *sta, int bsscnt, unsigned char *bsss,
		int optime);

extern int wifiagent_assoc_control_sta(char *fh_ifname, unsigned char *sta,
		int enable, int tmo);

extern int wifiagent_toggle_fh(struct ubus_object *obj, bool isl_prev,
		char *fh_ifname, int enable);

extern int wifiagent_process_cmd(struct ubus_context *ctx,
		struct ubus_request_data *req,
		int cmd_id, char *cmd_data, int cmd_len);

extern int wifiagent_process_cmd_async(struct ubus_context *ctx,
		struct ubus_request_data *req,
		int cmd_id, char *cmd_data,
		int cmd_len);

extern int wifiagent_get_status(struct ubus_context *ctx,
					struct ubus_request_data *req);
int wifiagent_get_nodes(struct ubus_context *ctx,
		       struct ubus_request_data *req);
extern int wifiagent_get_info(struct ubus_context *ctx,
					struct ubus_request_data *req);
int wifiagent_get_bk_info(struct ubus_context *ctx,
					struct ubus_request_data *req);
#ifdef NOTIFY_EVENTS
extern void wifiagent_notify_event(struct agent *a, void *ev_type,
		void *ev_data);
#else
#define wifiagent_notify_event(a, e, d)
#endif

extern int plugins_load(int argc, char *argv[], struct list_head *plugins);
extern int plugins_unload(struct list_head *plugins);
struct netif_fh *get_netif_by_name(struct agent *a, const char *name);
struct netif_fh *wifi_get_netif_by_bssid(struct agent *a, uint8_t *bssid);
struct netif_bk *agent_get_netif_bk_by_name(struct agent *a, const char *name);
struct netif_fh *wifi_radio_to_ap(struct agent *a, const char *radio);
struct wifi_radio_element *wifi_ifname_to_radio_element(struct agent *a,
		char *ifname);
const char *wifi_ifname_to_radio(struct agent *a, char *ifname);
struct wifi_radio_element *wifi_get_radio_by_mac(struct agent *a,
		uint8_t *hwaddr);
int prepare_tunneled_message(void *agent, const char *ifname,
		uint8_t protocol, const char *framestr);
int wifi_mod_bridge(struct agent *a, char *ifname, char *action);
char *agent_get_backhaul_ifname(struct agent *a, char *ifname);
uint32_t ubus_get_object(struct ubus_context *ctx, const char *name);
int ubus_call_object(struct agent *a, wifi_object_t wobj, const char *method,
		void (*response_cb)(struct ubus_request *, int, struct blob_attr *), void *priv);
void free_scanresults_neighbors(struct wifi_radio_element *re);
void list_stas(struct ubus_request *req, int type, struct blob_attr *msg);
struct wifi_scanres_channel_element *wifi_get_scanres_ch_element(struct wifi_radio_element *re,
		uint8_t ch);
void reschedule_nbrlist_update(struct netif_fh *fh);
void agent_disable_local_cntlr(struct agent *a);
void wifiagent_log_cntlrinfo(struct agent *a);
void agent_free_radios(struct agent *a);
void agent_free_cntlr_sync(struct agent *a);
void clear_fhlist(struct agent *a);
void clear_bklist(struct agent *a);
int agent_radio_scanresults(struct agent *a, struct wifi_radio_element *re);
int agent_init_interfaces(struct agent *a);
struct sta *find_sta_by_mac(struct agent *a, uint8_t *mac);
int agent_switch_according_to_pref(struct agent *a);
struct wifi_radio_element *wifi_radio_to_radio_element(struct agent *a,
		const char *radio);
struct wifi_netdev *wifi_radio_to_netdev(struct agent *a,
		const char *radio);
void agent_set_post_scan_action_pref(struct agent *agent, const char *radio,
				     bool opclass_preferences);
struct wifi_netdev *wifi_radio_id_to_netdev(struct agent *a,
							  uint8_t *radio_id);
struct wifi_radio_element *wifi_radio_id_to_radio_element(struct agent *a,
							  uint8_t *radio_id);
bool is_channel_supported_by_radio(struct wifi_radio_element *r,
				   uint8_t opclass,
				   uint8_t channel);
int agent_send_ch_scan_response(struct agent *a, struct wifi_netdev *ndev,
		struct wifi_scan_request_radio *req);
bool agent_ch_scan_succesful(struct agent *a);
struct netif_fh *netif_alloc_fh(const char *ifname);
#endif /* AGENT_H */
