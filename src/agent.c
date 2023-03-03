/*
 * agent.c
 * wifiagent core
 *
 * Copyright (C) 2019 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/stat.h>
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>

#include <linux/if_bridge.h>
#include <netlink/socket.h>

#include <netinet/in.h>
#include <net/if.h>

#include <cmdu.h>
#include <1905_tlvs.h>
#include <easy/easy.h>
#include <easy/utils.h>
#include "wifi.h"

#include <i1905_wsc.h>

#include <uci.h>
#include <map_module.h>
#include <easymesh.h>
#include <dirent.h>

#include "timer.h"
#include "utils/1905_ubus.h"
#include "utils/utils.h"
#include "utils/debug.h"
#include "utils/liblist.h"
#include "steer_rules.h"
#include "config.h"
#include "nl.h"
#include "agent.h"
#include "agent_ubus.h"
#include "agent_ubus_dbg.h"
#include "agent_map.h"
#include "plugin.h"
#include "agent_cmdu.h"
#include "agent_tlv.h"
#include "backhaul.h"

#define map_plugin	"ieee1905.map"

#define IFACE_TIMEOUT 1
#define BOOT_UP_SCAN_TIME	(0 * 1000)
#define BOOT_UP_SCAN_ITV	(2 * 1000)
#define BOOT_UP_SCAN_MAX_TRY 5

static struct agent *this_agent;

static int agent_subscribe_for_cmdus(struct agent *a);
static void agent_check_bsta_connections(struct agent *a);
static void wifi_bsta_check_cac_done(struct agent *a);

static void bsta_steer_cb(atimer_t *t)
{
	struct tlv_backhaul_steer_resp *p;
	struct cmdu_buff *cmdu;
	struct tlv *tv[1][16] = {0};
	struct netif_bk *bk = container_of(t, struct netif_bk, connect_timer);
	struct agent *a = bk->agent;
	char fmt[64] = {0};
	int ret;
	struct node *n;

	dbg("|%s:%d| steer timer expired, restoring old bssid (" MACFMT ") for"\
			"bsta %s\n",
			__func__, __LINE__, MAC2STR(bk->bsta_steer.prev_bssid),
			bk->name);

	cmdu = bk->bsta_steer.cmdu;

	wifi_set_iface_bssid(bk, bk->bsta_steer.prev_bssid);

	//snprintf(fmt, sizeof(fmt), "set_network %.15s %d "MACFMT, bk->name, 0,
	//		MAC2STR(bk->bsta_steer.prev_bssid));

	char bssidstr[18] = {0};

	hwaddr_ntoa(bk->bsta_steer.prev_bssid, bssidstr);

	strncat(fmt, "set_network ", sizeof(fmt) - strlen(fmt) - 1);
	strncat(fmt, bk->name, sizeof(fmt) - strlen(fmt) - 1);
	strncat(fmt, " 0 ", sizeof(fmt) - strlen(fmt) - 1);
	strncpy(fmt, bssidstr, sizeof(fmt) - strlen(fmt));
	fmt[63] = '\0';

	dbg("%s %d fmt = %s\n", __func__, __LINE__, fmt);
	agent_exec_platform_scripts(fmt);

	n = agent_find_node(a, cmdu->origin);
	if (!n)
		goto out;

	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		goto out;
	}

	if (!tv[0][0])
		goto out;

	p = (struct tlv_backhaul_steer_resp *) tv[0][0]->data;
	if (!p)
		goto out;

	p->result = 0x01;
	if (!agent_gen_tlv_error_code(a, cmdu, NULL, 0x05))
		goto out;

	agent_send_cmdu(a, cmdu);
out:
	cmdu_free(cmdu);
	bk->bsta_steer.cmdu = NULL;
}

static void agent_sighandler(int sig)
{
	uloop_end();
}

int agent_exec_platform_scripts(char *arg)
{
	char buf[16] = {0};

	warn("/lib/wifi/multiap %s\n", arg);
	chrCmd(buf, sizeof(buf), "/lib/wifi/multiap %s", arg);
	return atoi(buf);
}

/* find node by macaddress */
struct node *agent_find_node(struct agent *a, uint8_t *almac)
{
	struct node *n = NULL;

	list_for_each_entry(n, &a->nodelist, list) {
		if (!memcmp(n->alid, almac, 6))
			return n;
	}

	return NULL;
}

struct node *agent_alloc_node(struct agent *a, uint8_t *almac)
{
	struct node *n;

	n = calloc(1, sizeof(struct node));
	if (!n) {
		warn("OOM: node malloc failed!\n");
		return NULL;
	}

	n->agent = a;
	memcpy(n->alid, almac, 6);
	n->map_profile = MULTIAP_PROFILE_1;

	list_add(&n->list, &a->nodelist);
	a->num_nodes++;

	dbg("|%s:%d| ------- " MACFMT "\n", __func__, __LINE__, MAC2STR(almac));
	return n;
}

struct node *agent_add_node(struct agent *a, uint8_t *almac)
{
	struct node *n;

	n = agent_find_node(a, almac);
	if (!n) {
		n = agent_alloc_node(a, almac);
		if (!n) {
			err("|%s:%d| failed to allocate node "MACFMT"\n",
			    __func__, __LINE__, MAC2STR(almac));
			return NULL;
		}
	} else {
		return n;
	}

	/* Add actions
	 * 1. Write to UCI?
	 */

	return n;
}

const char *wifi_ifname_to_radio(struct agent *a, char *ifname)
{
	int i, j;
	const char *ret;

	for (i = 0; i < WIFI_DEVICE_MAX_NUM; i++) {
		for (j = 0; j < WIFI_IFACE_MAX_NUM; j++) {
			if (a->ifs[i].iface[j].name[0] != '\0' &&
				!strncmp(a->ifs[i].iface[j].name, ifname, 15)) {

				ret = a->ifs[i].radio;
				return ret;
			}
		}
	}

	trace("|%s %d| couldn't find radio for ifname %s\n",
		   __func__, __LINE__, ifname);

	return NULL;
}

struct wifi_netdev *wifi_radio_to_netdev(struct agent *a,
		const char *radio)
{
	int i;

	if (!radio)
		return NULL;

	for (i = 0; i < WIFI_DEVICE_MAX_NUM; i++) {
		if (a->ifs[i].radio[0] != '\0' &&
			!strncmp(a->ifs[i].radio, radio, 15)) {

			return &a->ifs[i];
		}
	}

	return NULL;
}

struct wifi_radio_element *wifi_radio_to_radio_element(struct agent *a,
		const char *radio)
{
	int i;

	if (!radio)
		return NULL;

	for (i = 0; i < WIFI_DEVICE_MAX_NUM; i++) {
		if (a->radios[i].name[0] != '\0' &&
			!strncmp(a->radios[i].name, radio, 15)) {

			return &a->radios[i];
		}
	}

	return NULL;
}

struct wifi_netdev *wifi_radio_id_to_netdev(struct agent *a,
							  uint8_t *radio_id)
{
	int i;

	if (!radio_id)
		return NULL;

	for (i = 0; i < WIFI_DEVICE_MAX_NUM; i++) {
		if (!memcmp(a->ifs[i].re->macaddr, radio_id, 6))
			return &a->ifs[i];
	}

	return NULL;
}

struct wifi_radio_element *wifi_radio_id_to_radio_element(struct agent *a,
							  uint8_t *radio_id)
{
	int i;

	if (!radio_id)
		return NULL;

	for (i = 0; i < WIFI_DEVICE_MAX_NUM; i++) {
		if (!memcmp(a->radios[i].macaddr, radio_id, 6))
			return &a->radios[i];
	}

	return NULL;
}

struct wifi_radio_element *wifi_ifname_to_radio_element(struct agent *a,
		char *ifname)
{
	const char *radio;

	radio = wifi_ifname_to_radio(a, ifname);
	if (!radio)
		return NULL;

	return wifi_radio_to_radio_element(a, radio);
}

struct wifi_radio_element *wifi_get_radio_by_mac(struct agent *a,
		uint8_t *hwaddr)
{
	struct wifi_radio_element *radio;
	int i;

	for (i = 0; i < a->num_radios; i++) {
		radio = a->radios + i;

		if (memcmp(radio->macaddr, hwaddr, 6))
			continue;

		return radio;
	}

	return NULL;
}

static void wifiagent_log_steer(struct agent *a,
				unsigned char *stamac,
				char *vifname,
				char *steer_type,
				unsigned char *to_bss)
{
	char ev[512] = {0};
	unsigned char macaddr[6] = {0};
	char ifname[16] = {0};
	char type[32] = {0};

	if (!stamac || !vifname || !steer_type)
		return;

	memcpy(macaddr, stamac, 6);
	strncpy(ifname, vifname, 16);
	ifname[15] = '\0';
	strncpy(type, steer_type, 31);

	snprintf(ev, sizeof(ev), "{\"macaddr\":\""MACFMT"\""
		 ",\"vif\":\"%.16s\",\"action\":\"%.32s\"",
		 MAC2STR(macaddr), ifname, type);
	if (to_bss) {
		snprintf(ev + strlen(ev), sizeof(ev), ",\"to\":\""MACFMT"\"}",
							MAC2STR(to_bss));
	} else {
		snprintf(ev + strlen(ev), sizeof(ev), "%s", "}");
	}

	info("steer: %s\n", ev);
	agent_notify_event(a, "map.agent", ev);
}

static void wifiagent_log_stainfo(struct agent *a, struct sta *s)
{
	int i;
	char ev[512] = {0};
	char rssis[64] = {0};

	if (!a || !s)
		return;

	for (i = 0; i < 4; i++) {
		if (s->rssi[i] > -100 && s->rssi[i] <= -10)
			snprintf(rssis + strlen(rssis), sizeof(rssis), "%d%s",
					s->rssi[i], i == 3 ? "" : ",");
	}

	snprintf(ev, sizeof(ev),
			"{\"macaddr\":\""MACFMT"\""
			",\"rssi\":\"%s\""
			",\"tx_rate\":%u"
			",\"rx_rate\":%u"
			",\"tx_Bps\":%d"
			",\"rx_Bps\":%d"
			",\"tx_pkts\":%" PRIu64
			",\"rx_pkts\":%" PRIu64
			",\"tx_fpkts\":%u"
			",\"rx_fpkts\":%u}",
			MAC2STR(s->macaddr), rssis, s->tx_rate, s->rx_rate,
			s->tx_thput, s->rx_thput,
			s->tx_pkts,
			s->rx_pkts,
			s->tx_fail_pkts, s->rx_fail_pkts);

	//trace("stainfo: %s\n", ev);
	agent_notify_event(a, "map.agent", ev);
}

void wifiagent_log_cntlrinfo(struct agent *a)
{
	char ev[512] = {0};

	dbg("%s: called.\n", __func__);

	if (!a)
		return;

	sprintf(ev,
		"{\"active_cntlr\":%u"
		",\"cntlr_almac\":\""MACFMT"\""
		",\"local_cntlr\":%u"
		",\"multiple_cntlr_found\":%u}",
		a->active_cntlr ? true : false,
		MAC2STR(a->cntlr_almac),
		is_local_cntlr_running() ? 1 : 0,
		a->multiple_cntlr ? 1 : 0);

	trace("cntlrinfo: %s\n", ev);
	agent_notify_event(a, "map.agent", ev);
}

// static
int ubus_call_object(struct agent *a, wifi_object_t wobj,
		const char *method,
		void (*response_cb)(struct ubus_request *, int, struct blob_attr *),
		void *priv)
{
	struct blob_buf bb = {};
	int ret;

	blob_buf_init(&bb, 0);
	ret = ubus_invoke(a->ubus_ctx, wobj, method, bb.head,
				response_cb, priv, 20 * 1000);
	if (ret) {
		err("Failed to get '%s' (ret = %d)\n", method, ret);
		blob_buf_free(&bb);
		return -1;
	}

	blob_buf_free(&bb);
	return 0;
}

// static
uint32_t ubus_get_object(struct ubus_context *ctx, const char *name)
{
	uint32_t id;
	int status;

	status = ubus_lookup_id(ctx, name, &id);
	if (status != UBUS_STATUS_OK) {
		err("object '%s' not present!\n", name);
		return WIFI_OBJECT_INVALID;
	}

	return id;
}

struct wifi_assoc_frame *wifi_get_frame(struct agent *a, uint8_t *macaddr)
{
	struct wifi_assoc_frame *f;

	list_for_each_entry(f, &a->framelist, list) {
		trace("frame mac: " MACFMT " input: " MACFMT "\n",
				MAC2STR(f->macaddr),
				MAC2STR(macaddr));
		if (!memcmp(f->macaddr, macaddr, 6))
			return f;
	}

	return NULL;
}

/* lookup netif struct by name */
struct netif_bk *agent_get_netif_bk_by_name(struct agent *a, const char *name)
{
	struct netif_bk *p;

	list_for_each_entry(p, &a->bklist, list) {
		if (!strncmp(name, p->name, 16))
			return p;
	}

	return NULL;
}

/* lookup netif_bk struct by device */
struct netif_bk *agent_get_netif_bk_by_device(struct agent *a,
		const char *device)
{
	struct netif_bk *p;

	list_for_each_entry(p, &a->bklist, list) {
		if (!strncmp(device, p->cfg->device, 16))
			return p;
	}

	return NULL;
}


/* lookup netif struct by name */
struct netif_fh *get_netif_by_name(struct agent *a, const char *name)
{
	struct netif_fh *p;

	list_for_each_entry(p, &a->fhlist, list) {
		if (!strncmp(name, p->name, 16))
			return p;
	}

	return NULL;
}

/* get netif_fh based on bssid */
struct netif_fh *wifi_get_netif_by_bssid(struct agent *a, uint8_t *bssid)
{
	struct netif_fh *fh;

	list_for_each_entry(fh, &a->fhlist, list) {
		if (hwaddr_equal(fh->bssid, bssid))
			return fh;
	}

	return NULL;
}

/* find sta by macaddress */
struct sta *find_sta_by_mac(struct agent *a, uint8_t *mac)
{
	struct netif_fh *p;

	list_for_each_entry(p, &a->fhlist, list) {
		struct sta *s;

		list_for_each_entry(s, &p->stalist, list) {
			if (!memcmp(s->macaddr, mac, 6))
				return s;
		}
	}

	return NULL;
}

/* find bkhaul by hwaddr */
struct netif_bk *find_bkhaul_by_ifname(struct agent *a, char *ifname)
{
	struct netif_bk *p;

	list_for_each_entry(p, &a->bklist, list) {
		if (!strncmp(p->name, ifname, sizeof(p->name)))
			return p;
	}

	return NULL;
}

/* find bkhaul by hwaddr */
struct netif_bk *find_bkhaul_by_bssid(struct agent *a, uint8_t *bssid)
{
	struct netif_bk *p;

	list_for_each_entry(p, &a->bklist, list) {
		if (!memcmp(p->bssid, bssid, 6))
			return p;
	}

	return NULL;
}

void agent_link_ap_to_cfg(struct agent *a)
{
	struct netif_fhcfg *fcfg;

	list_for_each_entry(fcfg, &a->cfg.fhlist, list) {
		struct netif_fh *f;

		f = get_netif_by_name(a, fcfg->name);
		if (!f)
			continue;

		f->cfg = fcfg;
	}
}

void agent_config_load_post_action(struct agent *a)
{
	agent_link_ap_to_cfg(a);

	if (a->cfg.pcfg)
		a->pvid = a->cfg.pcfg->pvid;
}

int agent_config_reload(struct agent *a)
{
	int ret;

	ret = agent_config_load(&a->cfg);
	agent_config_load_post_action(a);

	return ret;
}

typedef void (*destructor)(void *);

#define delete_expired_entries(vif, type, h, l, ts_member, tmo, func, _nr) \
do {									   \
	type *e, *etmp;							   \
	typeof((destructor) func) fptr = (func);			   \
									   \
	list_for_each_entry_safe(e, etmp, h, l) {			   \
		if (timestamp_expired(&e->ts_member, tmo)) {		   \
			dbg("%s: Entry aged out.. delete.\n", __func__);   \
			if (fptr)					   \
				fptr(e);				   \
			list_del(&e->l);				   \
			(_nr)--;                                           \
			free(e);					   \
		}							   \
	}								   \
} while (0)

static int agent_load_plugins(struct agent *a)
{
	char *argv[] = {"wfa_delm"};
	int argc = 1;
	int ret;

	INIT_LIST_HEAD(&a->pluginlist);

	info("map-agent: load plugins\n");
	ret = plugins_load(argc, argv, &a->pluginlist);

	return ret;
}

int (*compare)(const void *a, const void *b);

/* Private 'cmp()' function to sort neighbors by RSSI decreasing */
static int cmp_nbr_rssi(void *priv, struct list_head *a, struct list_head *b)
{
	struct pref_neighbor *ea, *eb;

	UNUSED(priv);
	ea = container_of(a, struct pref_neighbor, list);
	eb = container_of(b, struct pref_neighbor, list);

	return eb->rssi - ea->rssi;
}

#define alloc_entry(type)		\
({					\
	type *__n;			\
	__n = calloc(1, sizeof(type));	\
	__n ? &__n->list : NULL;	\
})

#define free_entry(ptr, type)					\
({								\
	if (ptr)						\
		free(container_of(ptr, type, list));		\
})

#define copy_entry(from, to, type)			\
({							\
	type *__s, *__d;				\
	if (from && to)	{				\
		__s = container_of(from, type, list);	\
		__d = container_of(to, type, list);	\
		memcpy(__d, __s, sizeof(type));		\
	}						\
})

static void *alloc_neighbor_entry(void)
{
	struct neighbor *n;

	n = calloc(1, sizeof(struct neighbor));
	if (n)
		return &n->list;

	return NULL;
}

static void free_neighbor_entry(struct list_head *n)
{
	free_entry(n, struct neighbor);
}

static void copy_neighbor_entry(struct list_head *from, struct list_head *to)
{
	copy_entry(from, to, struct neighbor);
}

static void *alloc_sta_neighbor_entry(void)
{
	struct sta_neighbor *n;

	n = calloc(1, sizeof(struct sta_neighbor));
	if (n)
		return &n->list;

	return NULL;
}

static void free_sta_neighbor_entry(struct list_head *n)
{
	free_entry(n, struct sta_neighbor);
}

static void copy_sta_neighbor_entry(struct list_head *from,
		struct list_head *to)
{
	copy_entry(from, to, struct sta_neighbor);
}

/* Function used to match duplicate entries in neighbor list */
static int match_bssid(void *priv, struct list_head *a, struct list_head *b)
{
	struct neighbor *ea;
	struct sta_neighbor *eb;

	UNUSED(priv);
	ea = container_of(a, struct neighbor, list);
	eb = container_of(b, struct sta_neighbor, list);

	return hwaddr_equal(ea->nbr.bssid, eb->nbr.bssid);
}

static struct list_head *create_joined_node(void *priv, struct list_head *a,
		struct list_head *b)
{
	struct pref_neighbor *new;
	struct neighbor *ea = NULL;
	struct sta_neighbor *eb = NULL;
	struct wifi_bss bss;
	struct sta *sta = (struct sta *)priv;
	struct netif_fh *nif = NULL;

	if (a)
		ea = container_of(a, struct neighbor, list);

	if (b)
		eb = container_of(b, struct sta_neighbor, list);

	if (!ea && !eb)
		return NULL;

	new = malloc(sizeof(*new));
	if (!new) {
		warn("OOM: failed to alloc preferred neighbor!\n");
		return NULL;
	}

	memset(new, 0, sizeof(*new));

	if (ea)
		memcpy(new->bssid, ea->nbr.bssid, 6);
	else
		memcpy(new->bssid, eb->nbr.bssid, 6);

	if (sta)
		nif = sta->vif;

	memset(&bss, 0, sizeof(struct wifi_bss));
	if (nif && wifi_scanresults_get_bss(nif->name, new->bssid, &bss)) {
		/* new->rssi = bss.rssi; */ /* it is AP's view; meaningless */
		new->ch_util = bss.load.utilization;
		new->num_stas = bss.load.sta_count;
	}

	if (ea) {
		new->bssid_info = ea->nbr.bssid_info;
		new->reg = ea->nbr.reg;
		new->channel = ea->nbr.channel;
		new->phy = ea->nbr.phy;
		new->flags = ea->flags;
		/* TODO: est_bwrate from snr */
	}

	if (eb) {
		new->rssi = eb->nbr.rssi; /* override rssi by sta's view */
		new->rsni = eb->nbr.rsni;
	}

	return &new->list;
}

static void free_joined_node(void *priv, struct list_head *a)
{
	struct pref_neighbor *ea = NULL;

	UNUSED(priv);
	if (a)
		ea = container_of(a, struct pref_neighbor, list);

	free(ea);
}

static void recalc_desired_neighbors(struct sta *s)
{
	struct netif_fh *vif = s->vif;
	struct list_head nbrlist_copy, sta_nbrlist_copy;

	/**
	 * First, does a splice of the two lists -
	 *	11k neighbor list and
	 *	11k STA beacon list.
	 *
	 * It then rearranges the combined list on the basis of decreasing
	 * 'rssi'.
	 * In rule matching modules, walk the pref_nbrlist to select the
	 * next best neighbor Bss based on rssi, bssload, est_dl_throughput etc.
	 */

	INIT_LIST_HEAD(&nbrlist_copy);
	list_dup(&vif->nbrlist, &nbrlist_copy,
			alloc_neighbor_entry,
			free_neighbor_entry,
			copy_neighbor_entry);

	INIT_LIST_HEAD(&sta_nbrlist_copy);
	list_dup(&s->sta_nbrlist, &sta_nbrlist_copy,
			alloc_sta_neighbor_entry,
			free_sta_neighbor_entry,
			copy_sta_neighbor_entry);

	list_flush(&s->pref_nbrlist, struct pref_neighbor, list);

	dbg_list_print("Neighbor nodes", &nbrlist_copy,
			struct neighbor, list, nbr.bssid);

	list_join_uniq(s, &nbrlist_copy, &sta_nbrlist_copy, &s->pref_nbrlist,
			match_bssid, create_joined_node, free_joined_node,
			free_neighbor_entry, free_sta_neighbor_entry);

	dbg_list_print("STA Neighbors", &s->pref_nbrlist,
			struct pref_neighbor, list, bssid);

	list_flush(&nbrlist_copy, struct neighbor, list);
	list_flush(&sta_nbrlist_copy, struct sta_neighbor, list);

	list_sort(NULL, &s->pref_nbrlist, cmp_nbr_rssi);
}

static int update_sta_entry(struct netif_fh *vif, struct wifi_sta *e)
{
	struct sta *s;

	list_for_each_entry(s, &vif->stalist, list) {
		if (!memcmp(s->macaddr, e->macaddr, 6)) {
			uint64_t tx_bytes_lastsec;
			uint64_t rx_bytes_lastsec;

			/* dbg("%s: update STA " MACFMT " entry\n", __func__,
			 *	MAC2STR(s->macaddr));
			 */
			timestamp_update(&s->last_update);
			s->rssi[0] = e->rssi[0];
			s->rssi[1] = e->rssi[1];
			s->rssi[2] = e->rssi[2];
			s->rssi[3] = e->rssi[3];
			s->connected_ms = e->conn_time * 1000;
			s->tx_rate = e->stats.tx_rate.rate;
			s->rx_rate = e->stats.rx_rate.rate;

			tx_bytes_lastsec = s->tx_bytes;
			rx_bytes_lastsec = s->rx_bytes;
			s->tx_bytes = e->stats.tx_bytes;
			s->rx_bytes = e->stats.rx_bytes;
			s->tx_thput = s->tx_bytes - tx_bytes_lastsec;
			s->rx_thput = s->rx_bytes - rx_bytes_lastsec;

			s->tx_pkts = e->stats.tx_pkts;
			s->rx_pkts = e->stats.rx_pkts;
			s->tx_fail_pkts = e->stats.tx_fail_pkts;
			s->rx_fail_pkts = e->stats.rx_fail_pkts;

		/*loud("STA: " MACFMT " (rssi = %d)   " \
				"Tx-bytes/sec = %u    Rx-bytes/sec = %u\n",
				MAC2STR(s->macaddr), s->rssi[0],
				s->tx_thput, s->rx_thput);*/
			wifiagent_log_stainfo(vif->agent, s);
			return 0;
		}
	}

	return -1;
}

static int agent_req_beacon_metrics(struct agent *a,
	struct netif_fh *fh, uint8_t *sta_addr, uint8_t opclass,
	uint8_t channel, uint8_t *bssid, uint8_t reporting_detail,
	uint8_t ssid_len, char *ssid, uint8_t num_report,
	uint8_t *report, uint8_t num_element, uint8_t *element)
{
	struct wifi_request_neighbor_param param = {};

	trace("agent: %s: --->\n", __func__);

	if (!sta_addr)
		return -1;

	param.opclass = opclass;
	param.channel = channel;
	param.bssid = bssid;
	param.reporting_detail = reporting_detail;
	param.ssid_len = ssid_len;
	param.ssid = ssid;
	param.num_report = num_report;
	param.report = report;
	param.num_element = num_element;
	param.element = element;

	return wifi_req_neighbor(fh->name, sta_addr, &param);
}

static void wifi_sta_bcn_req(atimer_t *t)
{
	struct sta *s = container_of(t, struct sta, sta_bcn_req_timer);
	struct netif_fh *vif = s->vif;
	struct agent *a = vif->agent;
	struct sta_bcn_req *breq;

	if (s->sta_bcn_req_nr < 1)
		/* No request enqueued */
		return;

	/* LIFO */
	breq = &s->bcn_req_queue[s->sta_bcn_req_nr - 1];

	agent_req_beacon_metrics(a, breq->fh, s->macaddr,
			breq->opclass, breq->channel, breq->bssid,
			breq->reporting_detail,
			breq->ssid_len, breq->ssid, 0, NULL,
			breq->num_element, breq->element);

	/* Dequeue */
	memset(breq, 0, sizeof(struct sta_bcn_req));
	s->sta_bcn_req_nr--;

	if (s->sta_bcn_req_nr >= 1)
		/* requests remainig, send next in 3 sec */
		timer_set(&s->sta_bcn_req_timer, 3 * 1000);
}

static void wifi_sta_finalize(atimer_t *t)
{
	struct sta *s = container_of(t, struct sta, sta_finalize_timer);
	struct sta *p, *tmp;
	struct netif_fh *vif = s->vif;

	list_for_each_entry_safe(p, tmp, &vif->stalist, list) {
		if (!memcmp(p->macaddr, s->macaddr, 6)) {
			s->ref--;
			if (s->legacy_steered)
				s->legacy_steered = false;

			if (!s->ref) {
				dbg("Finalize STA " MACFMT "\n",
						MAC2STR(s->macaddr));
				timer_del(&s->sta_timer);
				timer_del(&s->sta_bcn_req_timer);
				timer_del(&s->sta_steer_timer);
				list_del(&s->list);
				list_flush(&s->pref_nbrlist, struct pref_neighbor, list);
				list_flush(&s->sta_nbrlist, struct sta_neighbor, list);
				if (s->assoc_frame) {
					free(s->assoc_frame->frame);
					free(s->assoc_frame);
				}
				free(s);
			}
		}
	}
}

static int steer_sta_legacy(struct sta *s)
{
	struct netif_fh *vif = s->vif;
	uint16_t reason = 0;

	if (s->legacy_steered) {
		dbg("Skip Legacy Steering " MACFMT " again\n",
				MAC2STR(s->macaddr));
		return 0;
	}

	s->legacy_steered = true;
	s->ref++;
	dbg("Try to Legacy Steer " MACFMT " ------>\n", MAC2STR(s->macaddr));
	wifi_disconnect_sta(vif->name, s->macaddr, reason);
	wifiagent_log_steer(vif->agent, s->macaddr, vif->name,
					"steer_legacy", NULL);

	timer_set(&s->sta_finalize_timer,
			vif->cfg->steer_legacy_reassoc_secs * 1000);

	return 0;
}

static int steer_sta(struct sta *s, struct pref_neighbor *pref_nbr)
{
	struct netif_fh *vif = s->vif;
	struct agent *a = vif->agent;
	struct pref_neighbor *pref_bss;
	int ret = 0;

	s->steer_secs++;
	trace("Steer STA " MACFMT " (steer_secs = %u)\n",
				MAC2STR(s->macaddr), s->steer_secs);

	if (pref_nbr) {
		pref_bss = pref_nbr;
	} else {
		if (list_empty(&s->pref_nbrlist)) {
			trace("No better BSS for STA " MACFMT " found\n",
							MAC2STR(s->macaddr));
			return 0;
		}

		pref_bss = list_first_entry(&s->pref_nbrlist,
						struct pref_neighbor, list);
	}

	if (!pref_bss) {
		warn("Unexpected! pref_bss is NULL or empty!\n");
		return -1;
	}

	/* btm steer ? */
	if (!s->steer_btm_cnt) {
		s->steer_btm_cnt++;
		info("Try {%d} to BTM Steer " MACFMT " =======>\n",
				s->steer_btm_cnt, MAC2STR(s->macaddr));

		ret = wifi_req_bss_transition(vif->name, s->macaddr, 1, pref_bss->bssid, 0);
		if (!ret) {
			wifiagent_log_steer(a, s->macaddr, vif->name,
					"steer_btmreq", pref_bss->bssid);
		} else  {
			warn("Failed to send BTM request to " MACFMT "\n",
					MAC2STR(s->macaddr));
		}

		return ret;
	}

	/* retry btm steer ? */
	if (vif->cfg->steer_btm_retry) {
		if (!((s->steer_secs - 1) % vif->cfg->steer_btm_retry_secs) &&
			(s->steer_btm_cnt < vif->cfg->steer_btm_retry + 1)) {

			s->steer_btm_cnt++;
			info("Try {%d} to BTM Steer " MACFMT " =======>\n",
					s->steer_btm_cnt, MAC2STR(s->macaddr));

			ret = wifi_req_bss_transition(vif->name, s->macaddr, 1, pref_bss->bssid, 0);
			if (!ret)
				wifiagent_log_steer(a, s->macaddr, vif->name,
						"steer_btmreq", pref_bss->bssid);
			else
				warn("Failed to send BTM request to " MACFMT "\n",
						MAC2STR(s->macaddr));

			return ret;
		}
	}

	/* fallback to legacy steer ? */
	if (vif->cfg->fallback_legacy
			&& !s->legacy_steered
			&& (s->steer_secs >= vif->cfg->fallback_legacy))
		return steer_sta_legacy(s);

	return ret;
}

static void rebuild_cntlr_preflist(struct agent *a, struct sta *s,
					int cnt, unsigned char *bsss)
{
	int sz = sizeof(int) + cnt * 6;	/* #define macaddr_sz 6 */

	if (s->cntlr_preflist)
		free(s->cntlr_preflist);

	s->cntlr_preflist = malloc(sz);
	if (s->cntlr_preflist) {
		memset(s->cntlr_preflist, 0, sz);
		s->cntlr_preflist->num = cnt;
		memcpy(s->cntlr_preflist->bsss, bsss, cnt * 6);
	} else
		warn("OOM: cntlr_preflist\n");
}

int calculate_steer_verdict(struct sta *s, struct pref_neighbor **nbr)
{
	struct steer_rule *r;
	steer_verdict_t v = STEER_SKIP;

	list_for_each_entry(r, &regd_steer_rules, list) {
		if (!r->enabled)
			continue;

		if (r->check) {
			loud("STA " MACFMT " Check rule '%s'\n",
					MAC2STR(s->macaddr), r->name);
			v = r->check(r, s, nbr);
		}
		if (v != STEER_SKIP)
			return v;
	}

	return v;
}

/* returns 0 = don't steer, = 1 for steer */
static int should_steer_sta(struct sta *s, unsigned int *res)
{
	*res = 0;

	/* TODO:
	 * Check sta stats viz. active data sessions, retransmits etc. to
	 * decide if should steer sta.
	 * If verdict is OK, steer to cntlr_preflist.
	 */

	return 0;
}

/* returns 0 = don't steer, >= 1 for steer */
static int maybe_steer_sta(struct sta *s, unsigned int *res,
					struct pref_neighbor **nbr)
{
	struct netif_fh *vif = s->vif;
	struct agent *a = vif->agent;
	struct stax *x;

	/* dbg("%s: vif = %p  cfg = %p ifname = %s\n",
	 *	__func__, vif, cfg, vif->name);
	 */

	/* TODO: don't check here ..
	 * flag exclude whenever cfg is updated to exclude a STA.
	 */
	list_for_each_entry(x, &a->cfg.pcfg->steer_excludelist, list) {
		unsigned char xmac[6] = {0};
		int m_len;

		hwaddr_aton(x->macstring, xmac);
		m_len = strlen(x->macstring) == 17 ? 6 : strlen(x->macstring)/3;
		if (!memcmp(s->macaddr, xmac, m_len)) {
			loud("STA " MACFMT " in exclude list. Do nothing\n",
					MAC2STR(s->macaddr));
			return 0;
		}
	}

	/* Following if local steering is NOT disallowed */
	if (calculate_steer_verdict(s, nbr) == STEER_OK)
		return 1;

	return 0;
}

static void wifi_sta_steer_timeout(atimer_t *t)
{
	struct sta *s = container_of(t, struct sta, sta_steer_timer);
	unsigned int reason;

	if (timestamp_expired(&s->steer_opportunity, s->steer_opportunity_tmo)) {
		/* close steer opportunity window */
		s->steer_policy &= ~STA_STEER_OPPORTUNITY;
		return;
	}

	if (should_steer_sta(s, &reason)) {
		steer_sta(s, NULL);
		/* log_steer_action("Cntlr", s->macaddr, reason, ret); */
	}

	/* check for steer opportunity again in 1 sec */
	timer_set(&s->sta_steer_timer, 1000);
}

static int cond_refresh_sta_neighbor_list(struct agent *a, struct sta *s)
{
	struct netif_fh *vif = s->vif;
#define STA_NBR_REFRESH_BAD_RSSI	-78
	char ev[256] = {0};


	if (s->rssi[0] > STA_NBR_REFRESH_BAD_RSSI) {
		s->inform_leaving = 0;
		return 0;
	}

#if 0
	s->sta_nbr_invalid %= STA_NBR_REFRESH_CNT * a->cfg.runfreq;
	if (!s->sta_nbr_invalid)
		refresh_sta_neighbor_list(vif, s);

	s->sta_nbr_invalid++;
#endif
#if 0
	if (s->supports_bcnreport && s->sta_nbr_nr == 0)
		refresh_sta_neighbor_list(vif, s);
#endif

	if (!(s->inform_leaving++ % 5)) {
		/* tell cntlr about this bad rssi */
		snprintf(ev, sizeof(ev),
			"{\"macaddr\":\""MACFMT"\""
			",\"vif\":\"%s\""
			",\"action\":\"monitor\""
			",\"lowrssi\":%d}",
			MAC2STR(s->macaddr), vif->name, s->rssi[0]);

		agent_notify_event(a, "map.agent", ev);
		/* s->inform_leaving = (s->inform_leaving + 1) % 3; */
		s->wait_for_cntlr_nbr = true;

		/* If no pref_nbr reply from cntlr, and
		 * sta->supports_bcnreport = false, then do not steer.
		 * Either of these is true, then steer based on other
		 * criteria.
		 */
	}

	return 0;
}

static void wifi_sta_periodic_run(atimer_t *t)
{
	struct sta *s = container_of(t, struct sta, sta_timer);
	struct pref_neighbor *pref_nbr = NULL;
	struct netif_fh *vif = s->vif;
	struct wifi_sta sta = {};
	unsigned int reason;
	struct agent *a;
	int ret;


	if (!vif)
		return;

	a = vif->agent;

	/* if (strcmp(vif->name, s->vif_name))
	 *	err(stderr, "%s: vif changed under the hood!\n", __func__);
	 */
	if (!vif->cfg || !vif->cfg->enabled)
		return;

	//trace("%s: STA = " MACFMT " ref = %d\n", __func__,
	//					MAC2STR(s->macaddr), s->ref);

	if (s->legacy_steered && s->ref == 2)
		goto rearm_periodic;

	ret = wifi_get_station(vif->name, s->macaddr, &sta);
	if (ret)
		goto rearm_periodic;

	update_sta_entry(vif, &sta);
	cond_refresh_sta_neighbor_list(a, s);

	if (sta_steer_allowed(s->steer_policy)
			&& !list_empty(&s->pref_nbrlist)
			&& maybe_steer_sta(s, &reason, &pref_nbr)) {

		steer_sta(s, pref_nbr);
	}

	if (!list_empty(&vif->nbrlist) && list_empty(&s->pref_nbrlist))
		recalc_desired_neighbors(s);

rearm_periodic:
	timer_set(&s->sta_timer, STA_PERIODIC_RUN_INTERVAL);
}

static int wifi_send_sta_report(struct agent *a, const char *vif,
		uint8_t *macaddr, uint32_t status, uint8_t *bssid)
{
	uint8_t src_bssid[6] = { 0 };
	char ifname[16] = {0};
	uint8_t origin[6] = { 0 };
	uint8_t ret = 0;
	struct netif_fh *ifptr;
	bool ifready = false;

	list_for_each_entry(ifptr, &a->fhlist, list) {
		if (!strcmp(ifptr->name, vif)) {
			ifready = true;
			memcpy(src_bssid, ifptr->bssid, 6);
			break;
		}
	}

	if (!ifready)
		return -1;

	//TODO use the cntl ifname and origin address
	strncpy(ifname, a->cfg.al_bridge, sizeof(ifname));
	memcpy(origin, a->cntlr_almac, 6);

	/* Here we get need to send the steering report */
	ret = send_steer_btm_report(a, origin, ifname,
		bssid, src_bssid, macaddr, status);

	return ret;
}

static int wifi_add_sta(struct agent *a, const char *vif,
		unsigned char *macaddr)
{
	struct netif_fh *ifptr;
	//struct netif_fhcfg *cfg;
	struct sta *sptr, *new;
	struct wifi_assoc_frame *af;
	bool ifready = false;

	list_for_each_entry(ifptr, &a->fhlist, list) {
		if (!strcmp(ifptr->name, vif)) {
			ifready = true;
			break;
		}
	}
	if (!ifready)
		return -1;

#if 0
{
	/* [NOTE] Ext/Rept are now configured in the Disallow Steer List.
	 * There should be no restriction in steering a WiFi Rept (because it
	 * is a normal STA afterall to the upstream AP), but steering it needs
	 * special care. It has cascading effect on the downstream clients.
	 * If a Rept becomes steering candidate, it means it is not hearing
	 * well and/or performing poorly. Such events should be recorded.
	 */
	struct stax *x;

	cfg = ifptr->cfg;
	if (!cfg) {
		warn("%s: NULL config!\n", vif);
		return -1;
	}

//	TODO: test more thorouhgly and comment back in
//	list_for_each_entry(x, &a->cfg.steer_excludelist, list) {
//		unsigned char xmac[6] = {0};
//		int m_len;
//
//		hwaddr_aton(x->macstring, xmac);
//		m_len = strlen(x->macstring) == 17 ? 6 : strlen(x->macstring)/3;
//		if (!memcmp(macaddr, xmac, m_len)) {
//			dbg("Ignore STA " MACFMT " in steer exclude list\n",
//					MAC2STR(macaddr));
//			return 0;
//		}
//	}
}
#endif
	list_for_each_entry(sptr, &ifptr->stalist, list) {
		if (!memcmp(sptr->macaddr, macaddr, 6)) {
			dbg("STA " MACFMT "already in list.\n",
					MAC2STR(macaddr));
			sptr->ref++;
			if (sptr->legacy_steered) {
				timer_set(&sptr->sta_finalize_timer,
						ifptr->cfg->steer_legacy_retry_secs * 1000);
			}
			return 0;
		}
	}

	/* add new sta */
	new = malloc(sizeof(struct sta));
	if (!new) {
		warn("OOM: new sta malloc failed!\n");
		return -1;
	}
	memset(new, 0, sizeof(struct sta));
	memcpy(new->macaddr, macaddr, 6);
	new->vif = ifptr;
	new->ref++;
	timer_init(&new->sta_timer, wifi_sta_periodic_run);
	timer_init(&new->sta_bcn_req_timer, wifi_sta_bcn_req);
	timer_init(&new->sta_steer_timer, wifi_sta_steer_timeout);
	timer_init(&new->sta_finalize_timer, wifi_sta_finalize);
	timestamp_update(&new->last_update);
	INIT_LIST_HEAD(&new->sta_nbrlist);
	INIT_LIST_HEAD(&new->pref_nbrlist);
	recalc_desired_neighbors(new);
#if 0
	refresh_sta_neighbor_list(ifptr, new);
#endif
	new->steer_policy |= STA_STEER_ALLOWED;
	dbg("STA steer policy = 0x%x\n", new->steer_policy);
	af = wifi_get_frame(a, new->macaddr);
	if (af) {
		new->assoc_frame = af;
		list_del(&af->list);
	}

	ifptr->nbr_sta++;

	/* INIT_LIST_HEAD(&new->cntlr_preflist); */
	list_add(&new->list, &ifptr->stalist);

	timer_set(&new->sta_timer, 1 * 1000);
	return 0;
}

static int wifi_del_sta(struct agent *a, const char *vif,
		unsigned char *macaddr)
{
	struct netif_fh *ifptr;
	struct sta *s, *tmp;
	bool ifready = false;

	list_for_each_entry(ifptr, &a->fhlist, list) {
		if (!strcmp(ifptr->name, vif)) {
			ifready = true;
			break;
		}
	}
	if (!ifready)
		return -1;

	list_for_each_entry_safe(s, tmp, &ifptr->stalist, list) {
		if (!memcmp(s->macaddr, macaddr, 6)) {
			/* TODO: defer delete if in periodic_run..lock? */
			s->ref--;
			if (!s->ref) {
				dbg("Delete STA " MACFMT "record\n",
							MAC2STR(macaddr));
				timer_del(&s->sta_finalize_timer);
				timer_del(&s->sta_steer_timer);
				timer_del(&s->sta_bcn_req_timer);
				timer_del(&s->sta_timer);
				list_del(&s->list);
				list_flush(&s->pref_nbrlist, struct pref_neighbor, list);
				list_flush(&s->sta_nbrlist, struct sta_neighbor, list);
				if (s->assoc_frame) {
					free(s->assoc_frame->frame);
					free(s->assoc_frame);
				}
				free(s);
				return 0;
			}
			return 0;
		}
	}
	ifptr->nbr_sta--;

	return -2;
}

int wifi_topology_notification(struct agent *agent, uint8_t *mac, char *ifname, uint8_t assoc_event, uint16_t reason)
{
	trace("%s: --->\n", __func__);
	struct agent *a = (struct agent *) agent;
	struct cmdu_buff *cmdu;
	struct netif_fh *fh;

	fh = get_netif_by_name(a, ifname);
	if (!fh)
		return -1;

	if (!assoc_event) {
		cmdu = agent_gen_client_disassoc(a, mac, fh->bssid, reason);
		if (cmdu) {
			agent_send_cmdu(a, cmdu);
			cmdu_free(cmdu);
		}
	}

	cmdu = agent_gen_topology_notification(a, mac, fh->bssid, assoc_event);
	if (!cmdu)
		return -1;

	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	return 0;
}

#if 0	// unused
static char *arp_get_ip_by_mac(const char *mac, char *ip)
{
	FILE *arpt;
	char line[256] = {0};
	char macaddr[24] = {0};
	char ipaddr[24] = {0};
	char device[32] = {0};
	char mask[256] = {0};
	int flag, hw;
	unsigned char sta[6];

	if (!hwaddr_aton(mac, sta))
		return NULL;

	arpt = fopen("/proc/net/arp", "r");
	if (!arpt)
		return NULL;

	while (fgets(line, sizeof(line), arpt) != NULL) {
		int rc;
		unsigned char hwaddr[6];

		rc = sscanf(line, "%23s 0x%x 0x%x %23s %255s %31s",
				ipaddr, &hw, &flag, macaddr, mask, device);
		if (rc != 6)
			continue;

		if (!hwaddr_aton(macaddr, hwaddr))
			continue;

		if (memcmp(sta, hwaddr, 6)) {
			if (!memcmp(sta + 3, hwaddr + 3, 3)) {
				dbg("Arp flush: found (%s) was NOT a match," \
					"however mac was a masked match (%s)," \
					"nothing to flush?\n",
					mac, macaddr);
			}
			continue;
		}
		strncpy(ip, ipaddr, 16);
		break;
	}

	fclose(arpt);

	return ip;
}

static int arp_flush_entry(const char *macaddr)
{
	struct arpreq ar = {0};
	int sd;
	int ret = 0;
	char ipstr[16] = {0};
	struct sockaddr_in *in = (struct sockaddr_in *)&ar.arp_pa;

	dbg("Arp flush: ---- Setting up for arp entry flush mac = %s ----\n",
								macaddr);

	if (!arp_get_ip_by_mac(macaddr, ipstr)) {
		dbg("Arp flush: Flush attempt FAILED, " \
			"no match was found for mac = %s\n", macaddr);
		goto out;
	}

	inet_pton(AF_INET, ipstr, &in->sin_addr.s_addr);
	in->sin_family = AF_INET;
	sd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	ret = ioctl(sd, SIOCDARP, &ar);
	if (ret) {
		dbg("Arp flush: Failed to flush STA %s (%s) from arp table, " \
				"return value = %d\n", macaddr, ipstr, ret);
	} else {
		dbg("Arp flush: Flushed STA: %s (%s), from ARP table\n",
				macaddr, ipstr);
	}
	close(sd);
out:
	dbg("Arp flush: ---- Flush attempt done ----\n");
	return ret;
}
#endif

static void wifi_chan_change_event_handler(void *c, struct blob_attr *msg)
{
	struct agent *a = c;
	struct cmdu_buff *cmdu;
	static const struct blobmsg_policy ev_attr[] = {
		[0] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "event", .type = BLOBMSG_TYPE_STRING },
		[2] = { .name = "data", .type = BLOBMSG_TYPE_TABLE },
	};
	struct blob_attr *tb[ARRAY_SIZE(ev_attr)];
	struct wifi_radio_element *radio;
	char *ifname, *event;
	char *chan = NULL;
	char *bw = NULL;

	blobmsg_parse(ev_attr, ARRAY_SIZE(ev_attr), tb, blob_data(msg), blob_len(msg));
	if (!tb[0] || !tb[1] || !tb[2])
		return;

	ifname = blobmsg_data(tb[0]);
	event = blobmsg_data(tb[1]);

	radio = wifi_ifname_to_radio_element(a, ifname);
	if (!radio)
		return;

	if (!strcmp(event, "ap-chan-change")) {
		static const struct blobmsg_policy data_attr[] = {
			[0] = { .name = "target-channel", .type = BLOBMSG_TYPE_STRING },
			[1] = { .name = "target-width", .type = BLOBMSG_TYPE_STRING },
			[2] = { .name = "reason", .type = BLOBMSG_TYPE_STRING },
		};
		struct blob_attr *data[ARRAY_SIZE(data_attr)];

		blobmsg_parse(data_attr, ARRAY_SIZE(data_attr), data, blobmsg_data(tb[2]),
			      blobmsg_data_len(tb[2]));

		if (!data[0] || !data[1] || !data[2]) {
			WARN_ON(1);
			return;
		}

		chan = blobmsg_data(data[0]);
		bw = blobmsg_data(data[1]);

	} else if (!strcmp(event, "csa-finished")) {
		static const struct blobmsg_policy data_attr[] = {
			[0] = { .name = "channel", .type = BLOBMSG_TYPE_STRING },
			[1] = { .name = "bandwidth", .type = BLOBMSG_TYPE_STRING },
			[2] = { .name = "status", .type = BLOBMSG_TYPE_STRING },
		};
		struct blob_attr *data[ARRAY_SIZE(data_attr)];

		blobmsg_parse(data_attr, ARRAY_SIZE(data_attr), data, blobmsg_data(tb[2]),
			      blobmsg_data_len(tb[2]));

		if (!data[0] || !data[1] || !data[2]) {
			WARN_ON(1);
			return;
		}

		chan = blobmsg_data(data[0]);
		bw = blobmsg_data(data[1]);
	}

	if (!chan || !bw)
		return;

	if (!atoi(chan) || !atoi(bw))
		return;

	if (radio->reported_channel == atoi(chan) &&
	    radio->reported_bandwidth == atoi(bw))
		return;

	radio->current_channel = atoi(chan);
	radio->current_bandwidth = atoi(bw);
	radio->current_opclass = wifi_opclass_find_id_from_channel(&radio->opclass,
			radio->current_channel, radio->current_bandwidth);

	/* Finally send this to controller */
	dbg("[%s] oper_channel_response chan %d bw %d opclass %d\n",
	    ifname, radio->current_channel, radio->current_bandwidth,
	    radio->current_opclass);

	cmdu = agent_gen_oper_channel_response(a, radio, radio->current_channel,
					       radio->current_bandwidth, 0);
	if (WARN_ON(!cmdu))
		return;

	agent_send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	radio->reported_channel = radio->current_channel;
	radio->reported_bandwidth = radio->current_bandwidth;
}

static void wifi_cac_event_handler(void *c, struct blob_attr *msg)
{
	struct agent *a = c;
	static const struct blobmsg_policy ev_attr[] = {
		[0] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "event", .type = BLOBMSG_TYPE_STRING },
		[2] = { .name = "data", .type = BLOBMSG_TYPE_TABLE },
	};
	struct blob_attr *tb[ARRAY_SIZE(ev_attr)];
	struct wifi_radio_element *radio;
	char *ifname, *event;

	if (!a->cfg.ap_follow_sta_dfs)
		return;

	blobmsg_parse(ev_attr, ARRAY_SIZE(ev_attr), tb, blob_data(msg), blob_len(msg));
	if (!tb[0] || !tb[1] || !tb[2])
		return;

	ifname = blobmsg_data(tb[0]);
	event = blobmsg_data(tb[1]);

	radio = wifi_ifname_to_radio_element(a, ifname);
	if (!radio)
		return;

	if (!strcmp(event, "cac-end")) {
		static const struct blobmsg_policy data_attr[] = {
			[0] = { .name = "success", .type = BLOBMSG_TYPE_STRING },
		};
		struct blob_attr *data[ARRAY_SIZE(data_attr)];

		blobmsg_parse(data_attr, ARRAY_SIZE(data_attr), data, blobmsg_data(tb[2]),
			      blobmsg_data_len(tb[2]));

		if (!data[0])
			return;

		if (strcmp(blobmsg_data(data[0]), "1"))
			return;

		timer_set(&a->upgrade_backhaul_scheduler, 1 * 1000);
	}
}

bool is_channel_supported_by_radio(struct wifi_radio_element *re,
				   uint8_t opclass,
				   uint8_t channel)
{
	return wifi_opclass_id_channel_supported(&re->opclass, opclass, channel);
}

struct netif_bk *agent_get_netif_bk_with_channel(struct agent *a,
						 uint8_t opclass,
						 uint8_t channel)
{
	int i;
	uint8_t priority = -1;
	struct netif_bk *best = NULL;

	for (i = 0; i < a->num_radios; i++) {
		struct wifi_radio_element *r = &a->radios[i];
		struct netif_bk *bk;

		if (!is_channel_supported_by_radio(r, opclass, channel))
			continue;

		bk = agent_get_netif_bk_by_device(a, r->name);
		if (!bk)
			continue;

		if (best && bk->cfg->priority < priority)
			continue;

		best = bk;
		priority = bk->cfg->priority;
	}

	return best;
}

static int wifi_parse_frame(struct agent *a, struct json_object *frameobj)
{
	struct wifi_assoc_frame *new, *old;
	struct sta *s;
	const char *framestr, *macaddr;
	int len;
	uint8_t *frame;

	trace("|%s:%d| parsing wifi frame\n", __func__, __LINE__);

	macaddr = json_get_string(frameobj, "macaddr");
	if (!macaddr)
		return -1;

	framestr = json_get_string(frameobj, "raw");
	if (!framestr)
		return -1;

	len = strlen(framestr);
	len = (len - 1) / 2;
	frame = calloc(len, sizeof(uint8_t));
	if (!frame)
		return -1;

	if (!strtob((char *)framestr, len, frame))
		goto out_frame;

	new = calloc(1, sizeof(*new));
	if (!new)
		goto out_frame;

	new->frame = frame;
	hwaddr_aton(macaddr, new->macaddr);
	new->len = len;

	/* if frame for client exists in list, replace it */
	old = wifi_get_frame(a, new->macaddr);
	if (old) {
		list_del(&old->list);
		free(old->frame);
		free(old);
	}

	/* if sta exists attach to sta directly and exit*/
	s = find_sta_by_mac(a, new->macaddr);
	if (s) {
		if (s->assoc_frame) {
			free(s->assoc_frame->frame);
			free(s->assoc_frame);
		}
		s->assoc_frame = new;
		return 0;
	}

	list_add(&new->list, &a->framelist);

	return 0;
out_frame:
	free(frame);
	return -1;
}

static int get_frame_type(struct agent *a, struct json_object *frameobj)
{
	const char *framestr;
	int frame_type = -1;

	framestr = json_object_to_json_string(frameobj);
	if (!framestr)
		return -1;

	if (strstr(framestr, "reassoc"))
		frame_type = WIFI_FRAME_REASSOC_REQ;
	else if (strstr(framestr, "assoc"))
		frame_type = WIFI_FRAME_ASSOC_REQ;
	else if (strstr(framestr, "action"))
		frame_type = WIFI_FRAME_ACTION;

	return frame_type;
}

static void check_protocol(const char *framestr, uint8_t *protocol)
{
	uint8_t *frame;
	uint8_t category;
	uint8_t action;
	int offset = 0;
	int len;

	len = strlen(framestr);
	len = (len - 1)/2;
	frame = calloc(len, sizeof(uint8_t));
	if (!frame)
		return;

	if (!strtob((char *)framestr, len, frame))
		goto out;

	if (len < 26)
		goto out;

	/* 2: frame control,
	 * 2: duration,
	 * 6: destination addr,
	 * 6: source addr,
	 * 6: bssid,
	 * 2: seq control
	 */
	offset = 2 + 2 + 6 + 6 + 6 + 2;
	memcpy(&category, frame + offset, 1);
	memcpy(&action, frame + offset + 1, 1);

	if (category == 0x0a) {
		if (action == 0x06)
			*protocol = 0x02;
		else if (action == 0x1a)
			*protocol = 0x03;
	}

	/* TODO:check the action frame category &
	 * type for ANQP.
	 */

out:
	free(frame);
}

static int wifi_parse_all_frame(struct agent *a, const char *ifname,
		struct json_object *frameobj)
{
	trace("%s\n", __func__);
	const char *framestr;
	int stype;
	uint8_t protocol = 0xff;

	stype = get_frame_type(a, frameobj);
	if (stype == -1)
		return -1;

	switch (stype) {
	case WIFI_FRAME_REASSOC_REQ:
		protocol = 0x01;
		framestr = json_get_string(frameobj, "reassoc");
		break;
	case WIFI_FRAME_ASSOC_REQ:
		protocol = 0x00;
		framestr = json_get_string(frameobj, "assoc");
		break;
	case WIFI_FRAME_ACTION:
		framestr = json_get_string(frameobj, "action");
		check_protocol(framestr, &protocol);
		break;
	default:
		framestr = NULL;
		break;
	}

	if (!framestr)
		return -1;

	prepare_tunneled_message((void *)a, ifname, protocol, framestr);

	return 0;
}

static int wifi_process_action_frame(struct agent *a, const char *framestr)
{
	trace("%s\n", __func__);

	int len;
	uint8_t *frame;

	if (!framestr)
		return -1;

	len = strlen(framestr);
	len = len / 2; /* octets */
	frame = calloc(len, sizeof(uint8_t));
	if (!frame)
		return -1;

	if (!strtob((char *)framestr, len, frame))
		goto out_frame;

	if (frame) {
		struct action_frame_container *frame_ptr;
		uint16_t head_len = sizeof(struct action_frame_container);
		uint16_t tags_len = len - head_len;
		uint16_t pos = 0;
		int count = 0;
		struct sta *s;

		frame_ptr = (struct action_frame_container *) frame;

		/* Count action frame elements (Measurement Reports) */
		while (pos < tags_len) {
			if (frame_ptr->tags[pos] != 0x27) /* EID 39 - Meas Report */
				warn("|%s:%d| action frame contains unsupported" \
					 "Element ID\n", __func__, __LINE__);
			/* +2 for tag_no & tag_len */
			pos += (frame_ptr->tags[pos+1] + 2);
			count++;
		}

		s = find_sta_by_mac(a, frame_ptr->src);
		if (!s)
			goto out_frame;

		if (!s->supports_bcnreport)
			s->supports_bcnreport = true;

		trace("|%s:%d| sending beacon metrics response to the cntlr\n",
				__func__, __LINE__);

		/* TODO: consider adding some time constrains on the metrics
		 * received, so that we don't use outdated data. Current
		 * implementation seems to  work with accordance to
		 * specification (10.3.3 & 17.2.28) though. This is the
		 * good place to add constraints in case of future issues.
		 * Please check issue 5455 for more details.
		 */

		send_beacon_metrics_response(a, frame_ptr->src,
				count, frame_ptr->tags, tags_len);

		free(frame);
	}

	return 0;
out_frame:
	free(frame);
	return -1;
}

static int wifi_process_rx_frame(struct agent *a, struct json_object *frameobj)
{
	trace("%s\n", __func__);
	const char *framestr = NULL;
	int stype;

	stype = get_frame_type(a, frameobj);
	if (stype == -1)
		return -1;

	if (stype == WIFI_FRAME_ACTION) {
		framestr = json_get_string(frameobj, "action");
		if (framestr) {
			dbg("|%s:%d| processing action frame %s\n",
					__func__, __LINE__, framestr);
			return wifi_process_action_frame(a, framestr);
		}
	}

	return -1;
}

static uint16_t wifi_process_pvid_assoc_frame(struct agent *a, uint8_t *frame,
					    int len)
{
	int i;
	uint16_t pvid = 0;

	for (i = 0; i < len; i++) {
		uint8_t *p = frame + i;
		uint8_t elem_len = 0;
		uint8_t wfa_oui[4] = {0x50, 0x6f, 0x9a, 0x1b};

		if (*p++ != 0xdd) /* IEEE 802.1 vendor specific element */
			continue;

		elem_len = *p;

		if (elem_len < 14) { /* At least 14 bytes long */
			i += elem_len;
			continue;
		}

		if (elem_len > len - (i + 2)) {
			dbg("|%s:%d| WFA Element len exceeds raw frame len!\n", __func__, __LINE__);
			break;
		}


		p++; /* len */
		if (memcmp(p, wfa_oui, 4)) {
			i += elem_len;
			continue;
		}

		p += 4; /* wfa oui */

		if (*p++ != 0x06)  { /* multi-ap ext */
			i += elem_len;
			continue;
		}

		p += *p; /* subelem len */
		p++; /* len */


		if (*p++ != 0x07) { /* multi-ap profile */
			i += elem_len;
			continue;
		}

		p += *p; /* subelem len */
		p++; /* len */

		if (*p++ != 0x08) { /* multi-ap def 8021q */
			i += elem_len;
			continue;
		}

		p++; /* len */
		memcpy(&pvid, p, 2);
		dbg("|%s:%d| Found 8021q PVID %d\n", __func__, __LINE__, pvid);
		break;
	}

	return pvid;
}

#define REASON_BSS_TRANSITION_DISASSOC 12
#define ASSOC_TIMEOUT	60

static void wifi_sta_event_handler(void *c, struct blob_attr *msg)
{
	struct agent *a = (struct agent *)c;
	char ifname[16] = {0}, event[16] = {0};
	struct blob_attr *tb[3];
	static const struct blobmsg_policy ev_attr[3] = {
		[0] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "event", .type = BLOBMSG_TYPE_STRING },
		[2] = { .name = "data", .type = BLOBMSG_TYPE_TABLE },
	};
	bool add = false, del = false;

	blobmsg_parse(ev_attr, 3, tb, blob_data(msg), blob_len(msg));

	if (!tb[0] || !tb[1] || !tb[2])
		return;

	strncpy(ifname,	blobmsg_data(tb[0]), sizeof(ifname) - 1);
	strncpy(event, blobmsg_data(tb[1]), sizeof(event) - 1);

	add = !strcmp(event, "connected");
	del = !strcmp(event, "disconnected");

	if (add || del) {
		struct blob_attr *data[1];
		static const struct blobmsg_policy data_attr[1] = {
			[0] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
		};
		char mac_str[18] = {0};
		uint8_t mac[6] = {0};

		blobmsg_parse(data_attr, 1, data, blobmsg_data(tb[2]),
				blobmsg_data_len(tb[2]));

		if (!data[0])
			return;

		strncpy(mac_str, blobmsg_data(data[0]), sizeof(mac_str) - 1);

		if (!hwaddr_aton(mac_str, mac))
			return;

#ifndef UNAUTHORIZED_STA_IN_ASSOCLIST
		if (add) {
			wifi_topology_notification(a, mac, ifname, 0x01 /* joined */,
						   0x00 /* success */);
			wifi_add_sta(a, ifname, mac);
		} else if (del) {
			wifi_topology_notification(a, mac, ifname, 0x00 /* left */,
						   0x01 /* unspecified reason */);
			wifi_del_sta(a, ifname, mac);
		}
#endif
	} else if (!strcmp(event, "deauth")) {
		static const struct blobmsg_policy data_attr[] = {
			[0] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
			[1] = { .name = "reason", .type = BLOBMSG_TYPE_INT32 },
		};
		struct blob_attr *data[ARRAY_SIZE(data_attr)];
		uint8_t mac[6] = {};
		uint16_t reason = 1;
		struct agent_config *cfg = &a->cfg;
		struct policy_cfg *pcfg;

		blobmsg_parse(data_attr, ARRAY_SIZE(data_attr), data, blobmsg_data(tb[2]),
				blobmsg_data_len(tb[2]));

		if (!data[0] || !data[1] || !cfg)
			return;

		pcfg = cfg->pcfg;
		if (!pcfg)
			return;

		if (!hwaddr_aton(blobmsg_data(data[0]), mac))
			return;

		reason = blobmsg_get_u32(data[1]);

		/* Send failed connection message if the map-agent
		 * has sent fewer than the maximum number of Send Failed
		 * Connection messages (as specified in the
		 * Maximum Reporting Rate element of the Unsuccessful
		 * Association Policy TLV) in the preceding minute
		 */
		if (pcfg->report_sta_assocfails) {
			if (timestamp_expired(&a->last_unassoc,
						ASSOC_TIMEOUT * 1000)) {

				timestamp_update(&a->last_unassoc);
				a->unassoc_cnt = 1;
				send_failed_connection_msg(a, mac, 0, reason);
			} else {
				if (a->unassoc_cnt < pcfg->report_sta_assocfails_rate) {
					a->unassoc_cnt++;
					send_failed_connection_msg(a, mac, 0, reason);
				}
			}
		}
#ifdef UNAUTHORIZED_STA_IN_ASSOCLIST
		wifi_topology_notification(a, mac, ifname, 0, reason);
		wifi_del_sta(a, ifname, mac);
#endif
	} else if (!strcmp(event, "btm-resp")) {
		struct blob_attr *data[3];
		static const struct blobmsg_policy data_attr[3] = {
			[0] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
			[1] = { .name = "target_bssid", .type = BLOBMSG_TYPE_STRING },
			[2] = { .name = "status", .type = BLOBMSG_TYPE_STRING },
		};
		char mac_str[18] = {0}, bssid_str[18] = {0};
		uint8_t mac[6] = {0}, bssid[6] = {0};
		int status;


		blobmsg_parse(data_attr, 3, data, blobmsg_data(tb[2]),
				blobmsg_data_len(tb[2]));

		if (!data[0] || !data[2])
			return;

		/* macaddr */
		strncpy(mac_str, blobmsg_data(data[0]), sizeof(mac_str) - 1);
		if (!hwaddr_aton(mac_str, mac))
			return;

		/* target bssid - may be empty in case of failure */
		if (data[1]) {
			strncpy(bssid_str, blobmsg_data(data[1]),
					sizeof(bssid_str) - 1);
			if (!hwaddr_aton(bssid_str, bssid))
				return;
		}

		/* status */
		status = atoi(blobmsg_data(data[2]));

		wifi_send_sta_report(a, ifname, mac, status, bssid);

		if (!status) {
			/* simulate sta disconnect */
			wifi_disconnect_sta(ifname, mac, REASON_BSS_TRANSITION_DISASSOC);
		} else {
			/* TODO:
			 * update reject counter and retry steer later
			 */
		}
	} else if (!strcmp(event, "bcn-report")) {
		struct blob_attr *data[4];
		static const struct blobmsg_policy data_attr[4] = {
			[0] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
			[1] = { .name = "token", .type = BLOBMSG_TYPE_STRING },
			[2] = { .name = "mode", .type = BLOBMSG_TYPE_STRING },
			[3] = { .name = "nbr", .type = BLOBMSG_TYPE_STRING },
		};
		char mac_str[18] = {0};
		uint8_t sta_addr[6] = {0};
		struct sta *s;
		uint8_t mode = 0;

		blobmsg_parse(data_attr, 4, data, blobmsg_data(tb[2]),
				blobmsg_data_len(tb[2]));

		if (!data[0] || !data[1] || !data[2] || !data[3])
			return;

		mode = atoi(blobmsg_data(data[2]));

		if (mode) /* Measurement Report Mode should be 0x00 */
			return;

		strncpy(mac_str, blobmsg_data(data[0]), sizeof(mac_str) - 1);

		if (!hwaddr_aton(mac_str, sta_addr))
			return;

		s = find_sta_by_mac(a, sta_addr);
		if (!s)
			return;

		if (!s->supports_bcnreport)
			s->supports_bcnreport = true;
	} else if (!strcmp(event, "wds-station-add")) {
		/* TODO: wds handling */
	} else if (!strcmp(event, "action")) { /* TODO: this event belongs under wifi.iface handler */
		struct blob_attr *data[2];
		static const struct blobmsg_policy data_attr[2] = {
			[0] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
			[1] = { .name = "raw", .type = BLOBMSG_TYPE_STRING },
		};
		char mac_str[18] = {0};
		uint8_t bbss_addr[6] = {0};
		struct netif_bk *bk;
		char *framestr;
		uint8_t *frame;
		int len = 0;

		blobmsg_parse(data_attr, 2, data, blobmsg_data(tb[2]),
				blobmsg_data_len(tb[2]));

		if (!data[0] || !data[1])
			return;

		strncpy(mac_str, blobmsg_data(data[0]), sizeof(mac_str) - 1);

		if (!hwaddr_aton(mac_str, bbss_addr))
			return;

		bk = agent_get_netif_bk_by_name(a, ifname);
		if (!bk)
			return;

		framestr = (char *)blobmsg_data(data[1]);

		len = strlen(framestr);
		len = (len - 1) / 2;
		frame = calloc(len, sizeof(uint8_t));
		if (!frame)
			return;

		if (!strtob(framestr, len, frame)) {
			free(frame);
			return;
		}

		if (*frame == 0x09 || *frame == 0x04) {
			struct wifi_radio_element *r;
			uint8_t channel = 0;
			uint8_t opclass = 0;
			uint8_t *ptr = frame;

			ptr++;

			if (*ptr == 0x04) {
				ptr += 2;
				opclass = *ptr;

				ptr++;
				channel = *ptr;

				r = wifi_ifname_to_radio_element(a, ifname);
				if (!r) {
					free(frame);
					return;
				}

				if (is_channel_supported_by_radio(r, opclass, channel)) {
					dbg("|%s:%d| bsta %s supports new "\
					     "channel, no action required\n",
					     __func__, __LINE__, bk->name);
					free(frame);
					return;
				}

				bk = agent_get_netif_bk_with_channel(a, opclass, channel);
				if (bk) {
					char fmt[64] = {0};

					dbg("|%s:%d| swapping link to bsta %s\n",
					    __func__, __LINE__, bk->name);

					snprintf(fmt, sizeof(fmt),
						"bsta_swap_to_link %s",
						bk->name);
					agent_exec_platform_scripts(fmt);
					agent_config_reload(a);
				} else
					agent_exec_platform_scripts("bsta_enable_all");
			}
		}

		free(frame);
	} else if (!strcmp(event, "assoc") || !strcmp(event, "reassoc")) {
		struct json_object *jmsg, *data;
		char *str;
		struct blob_attr *bdata[2];
		static const struct blobmsg_policy data_attr[2] = {
			[0] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
			[1] = { .name = "raw", .type = BLOBMSG_TYPE_STRING },
		};
		char *framestr;
		uint8_t *frame;
		int len;
		uint16_t pvid;
#ifdef UNAUTHORIZED_STA_IN_ASSOCLIST
		char mac_str[18] = {0};
		uint8_t mac[6] = {0};
#endif

		blobmsg_parse(data_attr, 2, bdata, blobmsg_data(tb[2]),
				blobmsg_data_len(tb[2]));

		if (!bdata[0] || !bdata[1])
			return;

		framestr = (char *)blobmsg_data(bdata[1]);

		len = strlen(framestr);
		len = (len - 1) / 2;
		frame = calloc(len, sizeof(uint8_t));
		if (!frame)
			return;

		if (!strtob(framestr, len, frame)) {
			free(frame);
			return;
		}

		pvid = wifi_process_pvid_assoc_frame(a, frame, len);
		if (pvid) {
			agent_fill_8021q_setting(a, pvid, 0);
			agent_apply_traffic_separation(a);
		}

		free(frame);

#ifdef UNAUTHORIZED_STA_IN_ASSOCLIST
		strncpy(mac_str, blobmsg_data(bdata[0]), sizeof(mac_str) - 1);
		hwaddr_aton(mac_str, mac);
		wifi_add_sta(a, ifname, mac);
		wifi_topology_notification(a, mac, ifname,
					   0x01 /* client joined */,
					   0x00 /* success */);
#endif
		trace("%s: ------------>\n", __func__);

		str = blobmsg_format_json(msg, true);
		if (!str)
			return;

		jmsg = json_tokener_parse(str);
		if (!jmsg)
			goto out_str;

		if (!json_object_is_type(jmsg, json_type_object))
			goto out_json;

		json_object_object_get_ex(jmsg, "data", &data);
		if (!data)
			goto out_json;

		wifi_parse_frame(a, data);

		/* parse (re-)assoc message
		*/
		wifi_parse_all_frame(a, ifname, data);

out_json:
		json_object_put(jmsg);
out_str:
		free(str);
	}
}

static void wifi_iface_event_handler(void *c, struct blob_attr *msg)
{
	struct agent *a = (struct agent *)c;
	const char *ifname, *event;
	struct json_object *jmsg, *data;
	char *str;

	trace("%s: ------------>\n", __func__);

	str = blobmsg_format_json(msg, true);
	if (!str)
		return;

	jmsg = json_tokener_parse(str);
	if (!jmsg)
		goto out_str;

	if (!json_object_is_type(jmsg, json_type_object))
		goto out_json;

	json_object_object_get_ex(jmsg, "data", &data);
	if (!data)
		goto out_json;

	ifname = json_get_string(jmsg, "ifname");
	if (!ifname)
		goto out_json;

	event = json_get_string(jmsg, "event");
	if (!event)
		goto out_json;

	if (!strcmp(event, "assoc") || !strcmp(event, "reassoc")) {
		wifi_parse_frame(a, data);

		/* parse (re-)assoc message
		 */
		wifi_parse_all_frame(a, ifname, data);
	} else if (!strcmp(event, "frame-rx")) {
		wifi_process_rx_frame(a, data);
	} else if (!strcmp(event, "action")) {
		/* parse action frame
		 * BTM, WNM, ANQP
		 */
		wifi_parse_all_frame(a, ifname, data);
	}

out_json:
	json_object_put(jmsg);
out_str:
	free(str);
}

static void wifi_channel_event_handler(void *c, struct blob_attr *msg)
{
	/* struct agent *a = (struct agent *)c; */
	const char *ifdev, *res;
	int ch = 0;
	struct json_object *jmsg;
	char *str;

	trace("%s: ------------>\n", __func__);
	str = blobmsg_format_json(msg, true);
	if (!str)
		return;

	jmsg = json_tokener_parse(str);
	if (!jmsg)
		goto out_str;

	if (!json_object_is_type(jmsg, json_type_object))
		goto out_json;

	ifdev = json_get_string(jmsg, "radio");
	if (!ifdev)
		goto out_json;

	ch = json_get_int(jmsg, "channel");
	UNUSED(ch);

	res = json_get_string(jmsg, "reason");
	if (!res)
		goto out_json;

	if (!strcmp(res, "radar")) {
		fprintf(stderr, "TODO handle ch change due to radar!\n");
		/* wifi_handle_channel_event(a, ifdev, ch, res); */
	}

out_json:
	json_object_put(jmsg);
out_str:
	free(str);
}

static void wifi_handle_radar_event_done(atimer_t *t)
{
	struct netif_fh *ifptr = container_of(t, struct netif_fh, rdr_timer);
	char oui[7] = {0};

	if (!btostr((uint8_t *)EASYMESH_VENDOR_EXT_OUI, 3, oui))
		return;

	wifi_del_vendor_ie(ifptr->name, 1, oui, NULL);
}

static int wifi_handle_radar_event(struct agent *a, char *ifname)
{
	struct netif_fh *ifptr;
	bool ifready = false;
	int ret;
	struct timeval now;
	char oui[7] = {0};
	char data[20]= "dd06aa04";
	unsigned char buf[] = {
			0xdd, 0x06,
			0xaa, 0x04, 0x00, 0x00, 0x00, 0x00,
	};

	if (!btostr((uint8_t *)EASYMESH_VENDOR_EXT_OUI, 3, oui))
		return -1;

	list_for_each_entry(ifptr, &a->fhlist, list) {
		if (!strcmp(ifptr->name, ifname)) {
			ifready = true;
			break;
		}
	}
	if (!ifready)
		return -1;

	if (!gettimeofday(&now, NULL))
		memcpy(&buf[4], (uint32_t *)&now.tv_sec, 4);

	btostr(buf, 8, data);

	ret = wifi_add_vendor_ie(ifname, 1, oui, data);

	timer_init(&ifptr->rdr_timer, wifi_handle_radar_event_done);
	timer_set(&ifptr->rdr_timer, 1800 * 1000);  /* 30 mins */

	return ret;
}

static void wifi_dfs_event_handler(void *c, struct blob_attr *msg)
{
	struct agent *a = (struct agent *)c;
	const char *ifdev, *action;
	struct json_object *jmsg;
	char *str;

	dbg("%s: ------------>\n", __func__);

	str = blobmsg_format_json(msg, true);
	if (!str)
		return;

	jmsg = json_tokener_parse(str);
	if (!jmsg)
		goto out_str;

	if (!json_object_is_type(jmsg, json_type_object))
		goto out_json;

	ifdev = json_get_string(jmsg, "radio");
	if (!ifdev)
		goto out_json;

	action = json_get_string(jmsg, "action");
	if (!action)
		goto out_json;

	if (!strcmp(action, "radar_detected"))
		wifi_handle_radar_event(a, (char *)ifdev);

out_json:
	json_object_put(jmsg);
out_str:
	free(str);
}

uint8_t wifi_noise_to_anpi(int n)
{
	if (!n)
		return 255;
	if (n < -110)
		return 0;
	if (n > 0)
		return 220;
	return (n + 110) * 2;
}

static bool agent_is_bsta_connected(struct agent *a)
{
	struct netif_bk *bk;

	list_for_each_entry(bk, &a->bklist, list) {
		if (bk->connected)
			return true;
	}

	return false;
}

static bool is_backhaul_type_eth(void)
{
	struct blob_buf bk = { 0 };
	char *type;
	struct blob_attr *tb[1];
	static const struct blobmsg_policy bk_attr[1] = {
		[0] = { .name = "type", .type = BLOBMSG_TYPE_STRING }
	};

	blob_buf_init(&bk, 0);

	if (!blobmsg_add_json_from_file(&bk, MAP_UPLINK_PATH)) {
		dbg("Failed to parse %s\n", MAP_UPLINK_PATH);
		goto out;
	}

	blobmsg_parse(bk_attr, 1, tb, blob_data(bk.head), blob_len(bk.head));

	if (!tb[0])
		goto out;

	type = blobmsg_data(tb[0]);

	blob_buf_free(&bk);
	return !strncmp(type, "eth", 4);
out:
	blob_buf_free(&bk);
	return false;
}

static bool agent_has_active_backhaul(struct agent *a)
{
	return (agent_is_bsta_connected(a) || is_backhaul_type_eth());
}

static bool may_enable_fhs(struct agent *a)
{
#ifdef AGENT_ISLAND_PREVENTION
	if (a->cfg.island_prevention)
		return agent_has_active_backhaul(a) ? true : false;
#endif
	return agent_has_active_backhaul(a) ? true : false;
}

static void wifi_radio_event_handler(void *c, struct blob_attr *msg)
{
	dbg("%s --->\n", __func__);
	struct agent *a = (struct agent *) c;
	struct blob_attr *tb[6];
	static const struct blobmsg_policy ev_attr[6] = {
		[0] = { .name = "radio", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "action", .type = BLOBMSG_TYPE_STRING },
		[2] = { .name = "event", .type = BLOBMSG_TYPE_STRING },
		[3] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
		[4] = { .name = "event", .type = BLOBMSG_TYPE_STRING },
		[5] = { .name = "data", .type = BLOBMSG_TYPE_TABLE },
	}; /* TODO: poor solution*/

	int dBm;
	int radio_index, op_index, ch_index;
	uint32_t cur_ch;

	struct wifi_radio_element *r;
	struct wifi_scanres_opclass_element *op;
	struct wifi_scanres_channel_element *ch;

	blobmsg_parse(ev_attr, 6, tb, blob_data(msg), blob_len(msg));

	/* FIXME: these should be parsed based on event name */
	if (tb[0] && tb[1]) {
		char radio[18] = {0}, action[14] = {0};
		bool scan_finished;

		strncpy(radio, blobmsg_data(tb[0]), sizeof(radio) - 1);
		strncpy(action, blobmsg_data(tb[1]), sizeof(action) - 1);
		dbg("%s for %s\n", action, radio);

		scan_finished = !strcmp(action, "scan_finished");
		if (scan_finished) {
			struct wifi_netdev *ndev =
				wifi_radio_to_netdev(a, radio);

			if (WARN_ON(!ndev || !ndev->re)) {
				dbg("Current radio_element not found.\n");
				return;
			}
			ndev->re->scan_state = SCAN_DONE;

			handle_wifi_radio_scan_finished(a, ndev);
		}
	}

	if (tb[2] && tb[3]) {
		char radio[18] = {0}, event[14] = {0};

		strncpy(radio, blobmsg_data(tb[3]), sizeof(radio) - 1);
		strncpy(event, blobmsg_data(tb[2]), sizeof(event) - 1);
		dbg("%s for %s\n", event, radio);

		if (!strcmp(event, "ap-enabled")) {
			/* TODO: do this on event-basis, meaning don't teardown
			* everything and rebuild everything
			*/
			/* completely re-init data */
			timer_set(&a->init_ifaces_scheduler,
					IFACE_TIMEOUT * 1000);

			if (may_enable_fhs(a))
				/* Enable fronthauls */
				timer_set(&a->enable_fhs_scheduler,
						(IFACE_TIMEOUT + 1) * 1000);

		} else if (!strcmp(event, "ap-disabled")) {
			timer_set(&a->init_ifaces_scheduler,
					IFACE_TIMEOUT * 1000);
			/* TODO address above TODO and handle cases for
			 * traffic separation properly
			 */
		} else if (!strcmp(event, "ap-updated")) {
			timer_set(&a->init_ifaces_scheduler,
					IFACE_TIMEOUT * 1000);
		} else if (!strcmp(event, "radar")) {
			struct cmdu_buff *cmdu;

			cmdu = agent_gen_channel_preference_report(a, NULL);
			if (cmdu) {
				agent_send_cmdu(a, cmdu);
				cmdu_free(cmdu);
			}
		}
	}

	if (tb[3] && tb[4] && tb[5]) {
		struct blob_attr *data[3];
		static const struct blobmsg_policy supp_attrs[3] = {
			[0] = { .name = "channel", .type = BLOBMSG_TYPE_INT32 },
			[1] = { .name = "noise", .type = BLOBMSG_TYPE_INT32 },
			[2] = { .name = "utilization", .type = BLOBMSG_TYPE_INT32 },
		};

		blobmsg_parse(supp_attrs, 3, data,
				blobmsg_data(tb[5]), blobmsg_data_len(tb[5]));
		if (!data[0] || !data[1] || !data[2]) {
			dbg("Wifi event parse error.\n");
			return;
		}

		cur_ch = (uint8_t)blobmsg_get_u32(data[0]);
		for (radio_index = 0; radio_index < a->num_radios; radio_index++) {
			if (strcmp(a->radios[radio_index].name, blobmsg_data(tb[3])))
				continue;
			r = a->radios + radio_index;

			if (r->num_scanresult == 0 || !r->scanlist)
				continue;

			for (op_index = 0; op_index < r->scanlist->num_opclass_scanned; op_index++) {
					op = r->scanlist->opclass_scanlist + op_index;
				for (ch_index = 0; ch_index < op->num_channels_scanned; ch_index++) {
					if (op->channel_scanlist[ch_index].channel == cur_ch) {
						ch = op->channel_scanlist + ch_index;
						dBm = (int8_t)blobmsg_get_u32(data[1]);
						ch->anpi = wifi_noise_to_anpi(dBm);
						ch->utilization = (uint8_t)blobmsg_get_u32(data[2]);
						return;
					}
				}
			}
		}
	}
}

int wifi_mod_bridge(struct agent *a, char *ifname, char *action)
{
	char cmd[256] = {0};
	int offset = 0;
	struct blob_buf bb = {0};
	int ret;
	uint32_t id;
	bool add;

	add = !strcmp(action, "add");

	if (!strncmp(a->cfg.al_bridge, "br-", 3))
		offset = 3;

	/* add wds iface to bridge */

	snprintf(cmd, sizeof(cmd), "network.interface.%s", (a->cfg.al_bridge + offset));

	dbg("|%s:%d| %s interface %s to bridge %s using netifd API\n", __func__,
			__LINE__, (add ? "Adding" : "Deleting"),
			ifname, a->cfg.al_bridge + offset);

	blob_buf_init(&bb, 0);

	blobmsg_add_string(&bb, "name", ifname);

	id = ubus_get_object(a->ubus_ctx, cmd);
	snprintf(cmd, sizeof(cmd), "%s_device", action);
	ret = ubus_invoke(a->ubus_ctx, id, cmd, bb.head,
			NULL, NULL, 30 * 1000);

	/* explicitly disable if removing from bridge */
	if (!ret && !add) {
		int rc;

		rc = wifi_set_4addr(ifname, false);
		dbg("|%s:%d| Disabled 4addr mode for %s (rc:%d)\n", __func__,
				__LINE__, ifname, rc);
	}

	blob_buf_free(&bb);
	return ret;
}

#if 0
static void agent_detect_loop(struct agent *a, int secs)
{
	timer_set(&a->loop_detection_dispatcher, secs * 1000);
}
#endif

/* Check if Primary VLAN is set on bSTA in assoc IE */
static void agent_check_ts(struct agent *a, struct netif_bk *bk, char *ifname)
{
#if 0 /* Not used at present */
	char buf[64] = {0};
	if (Cmd(buf, sizeof(buf), "/lib/wifi/multiap ts primary get %s", ifname)) {
		err("|%s:%d| Unable to fetch Primary VID info from system",
		    __func__, __LINE__);
	}

	if (atoi(buf) && a) {
		if (!(a->cfg.pcfg)) {
			a->cfg.pcfg = (struct policy_cfg *)calloc(1, sizeof(struct policy_cfg));
			if (!(a->cfg.pcfg)) {
				err("%s:%d - memory allocation failed\n",
				    __func__, __LINE__);
				return;
			}
		}

		a->cfg.pcfg->pvid = atoi(buf);

		/* TODO save pvid in the config file */
	}
#endif
}

char *agent_get_backhaul_ifname(struct agent *a, char *ifname)
{
	struct blob_buf bk = { 0 };
	struct blob_attr *tb[2];
	static const struct blobmsg_policy bk_attr[2] = {
		[0] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
	};

	blob_buf_init(&bk, 0);

	if (!blobmsg_add_json_from_file(&bk, MAP_UPLINK_PATH)) {
		dbg("Failed to parse %s\n", MAP_UPLINK_PATH);
		goto out;
	}

	blobmsg_parse(bk_attr, 2, tb, blob_data(bk.head), blob_len(bk.head));

	if (!tb[0])
		goto out;

	strncpy(ifname, blobmsg_data(tb[0]), IFNAMSIZ);

	if (tb[1]) {
		uint8_t macaddr[6] = {0};

		if (!hwaddr_aton(blobmsg_data(tb[1]), macaddr))
			goto out;

		/* if backhaul differs from last seen backhaul, move last seen to idx 1 */
		if (memcmp(macaddr, a->backhaul_macaddr[0], 6)) {
			memcpy(a->backhaul_macaddr[1], a->backhaul_macaddr[0], 6);
			timestamp_update(&a->backhaul_change_t);
		}

		memcpy(a->backhaul_macaddr[0], macaddr, 6);
	}

	blob_buf_free(&bk);
	return ifname;
out:
	blob_buf_free(&bk);
	return NULL;
}

static void wifi_bsta_disconnect(struct agent *a, const char *ifname)
{
	wifi_sta_disconnect_ap(ifname, 0);
}

static int agent_handle_bh_lost(struct agent *a)
{
	trace("|%s:%d| detected backhaul link loss!\n",
		  __func__, __LINE__);

	struct agent_config *cfg;
	struct dyn_bh_cfg *c;

	if (!a)
		return -1;

	cfg = &a->cfg;
	if (!cfg) {
		err("%s:%d - missing configuration!\n", __func__, __LINE__);
		return -1;
	}

	c = &cfg->dbhcfg;
	if (!c) {
		err("%s:%d - missing dynamic backhaul configuration!\n",
		    __func__, __LINE__);
		return -1;
	}

	dbg("|%s:%d| backhaul link loss timeout: %d sec\n",
		  __func__, __LINE__, c->bh_miss_tmo);

	if (c->bh_miss_tmo)
		/* Trigger bh link loss timer */
		timer_set(&a->bh_lost_timer, c->bh_miss_tmo * 1000);

	timestamp_update(&a->disconnect_t);
	return 0;
}

static void agent_manage_bsta(struct agent *a, struct netif_bk *bk)
{
	bool enabled = false;
	char *ifname = bk->name;

	if (is_backhaul_type_eth()) {
		wifi_bsta_disconnect(a, ifname);
		return;
	}

	wifi_get_4addr(ifname, &enabled);
	trace("|%s:%d| %s has got 4addr mode %s\n", __func__, __LINE__,
			ifname, (enabled ? "enabled" : "disabled"));

	if (enabled && bk->connected) {
		if (!if_isbridge_interface(ifname)) {
			trace("|%s:%d| Attempting to add interface (%s) "\
					" to the bridge\n", __func__, __LINE__,
					ifname);
			wifi_mod_bridge(a, ifname, "add");
		}
	} else {
		if (if_isbridge_interface(ifname)) {
			wifi_mod_bridge(a, ifname, "remove");

			/* Handle bk link loss if this is an active bsta */
			if (bk->cfg->enabled) {
				char ul_ifname[16] = {0};

				agent_handle_bh_lost(a);

				if (agent_get_backhaul_ifname(a, ul_ifname)) {
					if (!strncmp(ul_ifname, bk->name, IFNAMSIZ))
						agent_exec_platform_scripts("unset_uplink wifi");
				}
			}
		}
	}
}

static void agent_reload_local_cntlr(struct agent *a, bool on)
{
	set_value_by_string("mapcontroller", "controller",
			"enabled", on ? "1" : "0", UCI_TYPE_STRING);
	trace("Reloading mapcontroller\n");

	/* procd is too slow to send signal - manual kill prior to reload
	 * TODO: leverage pidfile
	 */
	runCmd("kill `pidof mapcontroller`");
	uci_reload_services("mapcontroller");

	/* Enable is now set to '1' in config; ensure service is started */
	if (on) {
		runCmd("/etc/init.d/mapcontroller reload");
	}
}

static void agent_enable_local_cntlr(atimer_t *t)
{
	struct agent *a = container_of(t, struct agent, cntlr_scheduler);

	dbg("|%s:%d| Attempting to start local controller\n", __func__, __LINE__);

	if (is_local_cntlr_running()) {
		warn("Skip starting local mapcontroller: already running\n");
	} else {
		agent_reload_local_cntlr(a, true);
	}
}

void agent_disable_local_cntlr(struct agent *a)
{
	dbg("|%s:%d| Disable local controller in UCI\n", __func__, __LINE__);
	agent_reload_local_cntlr(a, false);
}

static void agent_schedule_cntlr_start(struct agent *a, int secs)
{
	dbg("|%s:%d| Scheduled controller start in %d sec\n",
			__func__, __LINE__, secs);
	timer_set(&a->cntlr_scheduler, secs * 1000);
}

static void agent_rcpi_thresold_timer_cb(atimer_t *t)
{
	struct agent *a = container_of(t, struct agent,
			rcpi_threshold_timer);
	struct netif_fh *fh;

	list_for_each_entry(fh, &a->fhlist, list) {
		struct sta *s;
		struct agent_config_radio *rcfg;


		dbg("%s %d checking clients on %s\n", __func__, __LINE__, fh->name);

		rcfg = get_agent_config_radio(&a->cfg, fh->cfg->device);
		if (!rcfg)
			continue;

		list_for_each_entry(s, &fh->stalist, list) {
			uint8_t rcpi;

			dbg("%s %d found client "MACFMT"\n", __func__, __LINE__, MAC2STR(s->macaddr));

			rcpi = rssi_to_rcpi(s->rssi[0]);
			if (rcpi < rcfg->rcpi_threshold) {
				struct cmdu_buff *cmdu;

				cmdu = agent_gen_assoc_sta_metric_responsex(a,
					a->cntlr_almac, s, fh);
				if (cmdu) {
					agent_send_cmdu(a, cmdu);
					cmdu_free(cmdu);
				}
			}

		}

	}

/*	curr_rcpi = calculate_radio_rcpi(a, p->name);
	prev_rcpi = p->prev_rcpi;
	if (((prev_rcpi > p->cfg->rcpi_threshold) &&
				(curr_rcpi > p->cfg->rcpi_threshold)) ||
			((prev_rcpi < p->cfg->rcpi_threshold) &&
			 (curr_rcpi < p->cfg->rcpi_threshold)))
		goto refresh_interval;
*/
	//prepare_assoc_sta_metric_response(a, p->name);

//refresh_interval:
//	p->prev_rcpi = curr_rcpi;
	timer_set(&a->rcpi_threshold_timer, RCPI_THRESHOLD_TIMER);
}

#if 0
static void agent_trigger_vendor_specific(atimer_t *t)
{
	struct agent *a = container_of(t, struct agent, loop_detection_dispatcher);
	struct cmdu_buff *cmdu;
	uint8_t origin[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x13};

	cmdu = agent_gen_vendor_specific_cmdu(a, origin, a->depth);
	if (cmdu) {
		a->loop_detection.tx_mid = agent_send_cmdu(a, cmdu);
		cmdu_free(cmdu);
	}
}
#endif

static bool agent_ap_get_state(struct agent *a, struct netif_fh *fh)
{

	/* TODO: refresh cashed data */
	if (!fh)
		return -1;

	return fh->enabled ? true : false;
}

static int agent_ap_set_state(struct agent *a, struct netif_fh *fh, bool up)
{
	bool is_enabled;

	if (!fh)
		return -1;

	is_enabled = agent_ap_get_state(a, fh);

	dbg("|%s:%d| setting AP %s %s (current: %s)\n",
	    __func__, __LINE__,
	    fh->name, up ? "up" : "down",
	    is_enabled ? "up" : "down");

	if (is_enabled == up)
		return 0;

	if (up && fh->cfg && !fh->cfg->enabled) {
		/* start_disabled set for given fh in cfg */
		dbg("|%s:%d| will not enable fh %s - start_disabled set\n",
		    __func__, __LINE__, fh->name);
		return 0;
	}

	if (wifi_ap_set_state(fh->name, up)) {
		dbg("|%s:%d| failed to set AP %s %s\n",
		    __func__, __LINE__, fh->name, up ? "up" : "down");
		return -1;
	} /* check if the state has changed */ if (agent_ap_get_state(a, fh) != up) {
		dbg("|%s:%d| sheduling iface init\n", __func__, __LINE__);
		timer_set(&a->init_ifaces_scheduler,
				IFACE_TIMEOUT * 1000);
	}

	return 0;
}

static void agent_enable_fronthauls(struct agent *a)
{
	struct netif_fh *fh;

	dbg("|%s:%d| enabling all fronthauls\n", __func__, __LINE__);

	list_for_each_entry(fh, &a->fhlist, list)
		agent_ap_set_state(a, fh, true);
}

#ifdef AGENT_ISLAND_PREVENTION
static int agent_sent_req_btm(struct agent *a, struct netif_fh *fh,
		struct sta *s, uint32_t tmo)
{
	struct wifi_btmreq req = {};
	uint32_t tbtts = 0;

	dbg("Calling wifi.ap.%s wifi_req_btm for sta " MACFMT "\n",
			fh->name, MAC2STR(s->macaddr));

	/* Inform remaining clients of imminent disassociation */
	req.mode |= WIFI_BTMREQ_DISASSOC_IMM;
	/* Inform clients about BSS termination */
	req.mode |= WIFI_BTMREQ_BSSTERM_INC;

	/* Number of beacon transmission times (TBTTs) until the AP sends
	 * a Disassociation frame to STA. 0 indicates that the AP has not
	 * determined when it will send a Disassociation.
	 */
	tbtts = tmo * 1000 / 100; /* beacon_int: ~100ms */

	/* Duration - number of minutes for which the BSS is not present.
	 * Value of 0 is reserved. Value 65 535 when the BSS is terminated
	 * for a period longer than or equal to 65 535 minutes.
	 */
	req.bssterm_dur = 1; /* away (min) */
	req.disassoc_tmo = tbtts;

	if (wifi_req_btm(fh->name, s->macaddr, 0, NULL, &req)) {
		dbg("|%s:%d| failed to send wifi_req_btm\n", __func__, __LINE__);
		return -1;
	}

	return 0;
}

#define STA_DISCONNECT_TM 30
static void agent_schedule_fh_disable(struct agent *a)
{
	trace("%s: --->\n", __func__);

	struct netif_fh *fh;
	struct sta *s;

	if (agent_has_active_backhaul(a))
		/* backhaul regained, don't send BTM */
		return;

	dbg("|%s:%d| will disable FHs in %d seconds\n",
	    __func__, __LINE__, STA_DISCONNECT_TM + 2);

	list_for_each_entry(fh, &a->fhlist, list) {
		/* Try to steer all remaining (b)STAs away */
		list_for_each_entry(s, &fh->stalist, list) {
			agent_sent_req_btm(a, fh, s, STA_DISCONNECT_TM);
		}
	}

	/* Disconnect all STAs in in STA_DISCONNECT_TM seconds */
	timer_set(&a->sta_disconnect_timer, STA_DISCONNECT_TM * 1000);
}

static int agent_sta_disconnect(struct agent *a, struct netif_fh *fh, struct sta *s)
{
	dbg("Calling wifi.ap.%s disconnect for sta " MACFMT "\n",
	    fh->name, MAC2STR(s->macaddr));

	return wifi_disconnect_sta(fh->name, s->macaddr, 12);
}

static void agent_fh_disable_cb(atimer_t *t)
{
	trace("%s: --->\n", __func__);

	struct agent *a = container_of(t, struct agent, fh_disable_timer);
	struct netif_fh *fh;

	if (agent_has_active_backhaul(a))
		/* backhaul regained, don't disable FHs */
		return;

	list_for_each_entry(fh, &a->fhlist, list) {
		agent_ap_set_state(a, fh, false);
	}
}

static void agent_sta_disconnnect_cb(atimer_t *t)
{
	trace("%s: --->\n", __func__);

	struct agent *a = container_of(t, struct agent, sta_disconnect_timer);
	struct netif_fh *fh;
	struct sta *s;

	if (agent_has_active_backhaul(a))
		/* backhaul regained, don't disconnect STAs */
		return;

	list_for_each_entry(fh, &a->fhlist, list) {
		list_for_each_entry(s, &fh->stalist, list) {
			agent_sta_disconnect(a, fh, s);
		}
	}

	/* Disable all fronthauls in 2 seconds */
	timer_set(&a->fh_disable_timer, 2 * 1000);
}
#endif /* AGENT_ISLAND_PREVENTION */

int wifiagent_toggle_fh(struct ubus_object *obj, bool isl_prev,
		char *fh_ifname, int enable)
{
	struct agent *a = container_of(obj, struct agent, obj);

#ifdef AGENT_ISLAND_PREVENTION
	if (isl_prev && a->cfg.island_prevention && !enable) {
		/* schedule bringing down all STAs & FHs */
		dbg("|%s:%d| island prevention: schedule FHs down\n",
		    __func__, __LINE__);
		agent_schedule_fh_disable(a);
		return 0;
	}
#else
	UNUSED(isl_prev);
#endif

	if (fh_ifname && fh_ifname[0]) {
		struct netif_fh *fh = NULL;

		/* enable/disable fronthaul(s)  */
		if (strncmp(fh_ifname, "all", 16)) {
			fh = get_netif_by_name(a, fh_ifname);
			if (!fh) {
				dbg("interface \'%s\' not found\n", fh_ifname);
				return -1;
			}
			agent_ap_set_state(a, fh, enable ? true : false);
		} else { /* all interfaces */
			list_for_each_entry(fh, &a->fhlist, list) {
				agent_ap_set_state(a, fh, enable ? true : false);
			}
		}
	}

	return 0;
}

static void agent_bh_reconf_cb(atimer_t *t)
{
	trace("%s: --->\n", __func__);

	struct agent *a = container_of(t, struct agent, bh_reconf_timer);
	struct agent_config *cfg;
	struct dyn_bh_cfg *c;

	if (!a)
		return;

	cfg = &a->cfg;
	if (!cfg) {
		err("%s:%d - missing configuration!\n", __func__, __LINE__);
		return;
	}

	c = &cfg->dbhcfg;
	if (!c) {
		err("%s:%d - missing dynamic backhaul configuration!\n",
		    __func__, __LINE__);
		return;
	}

	dbg("|%s:%d| backhaul fallback link loss timeout: %d sec\n",
		  __func__, __LINE__, c->bh_reconf_tmo);

	if (is_backhaul_type_eth() && c->bh_reconf_tmo) {
		/* additional time */
		timer_set(&a->bh_reconf_timer, c->bh_reconf_tmo * 1000);
		return;
	}

	agent_exec_platform_scripts("bsta_clear_bssid");
	agent_config_reload(a);
}

static void agent_bh_lost_cb(atimer_t *t)
{
	trace("%s: --->\n", __func__);

	struct agent *a = container_of(t, struct agent, bh_lost_timer);
	struct agent_config *cfg;
	struct dyn_bh_cfg *c;

	if (!a)
		return;

	cfg = &a->cfg;
	if (!cfg) {
		err("%s:%d - missing configuration!\n", __func__, __LINE__);
		return;
	}

	c = &cfg->dbhcfg;
	if (!c) {
		err("%s:%d - missing dynamic backhaul configuration!\n",
		    __func__, __LINE__);
		return;
	}

	dbg("|%s:%d| backhaul link loss timeout: %d sec\n",
		  __func__, __LINE__, c->bh_miss_tmo);

	if (is_backhaul_type_eth() && c->bh_miss_tmo) {
		/* additional time */
		timer_set(&a->bh_lost_timer, c->bh_miss_tmo * 1000);
		return;
	}

#ifdef AGENT_ISLAND_PREVENTION
	if (a->cfg.island_prevention)
		/* Stop beaconing, ignore connect attempts, disassociate STAs */
		agent_schedule_fh_disable(a);
#endif /* AGENT_ISLAND_PREVENTION */

	agent_exec_platform_scripts("bsta_enable_all");

	a->progress_attempts = 0;
	if (!a->progressing)
		timer_set(&a->upgrade_backhaul_scheduler, 60 * 1000);

	agent_config_reload(a);
	if (timer_remaining_ms(&a->bh_reconf_timer) == -1)
		timer_set(&a->bh_reconf_timer,
				  (c->bh_reconf_tmo - c->bh_miss_tmo) * 1000);
}

static void agent_trigger_bsta_sync(atimer_t *t)
{
	struct agent *a = container_of(t, struct agent, onboarding_scheduler);

	UNUSED(a);

	agent_exec_platform_scripts("bsta_to_wireless");
}

static void agent_disable_unconnected_bsta_cb(atimer_t *t)
{
	struct agent *a = container_of(t, struct agent, disable_unconnected_bstas_scheduler);
	struct netif_bk *bk, *best = NULL;

	list_for_each_entry(bk, &a->bklist, list) {
		if (!bk->cfg->enabled || !bk->connected)
			continue;

		if (!best || bk->cfg->priority > best->cfg->priority)
			best = bk;
	}

	if (best) {
		char fmt[64] = {0};

		snprintf(fmt, sizeof(fmt), "bsta_use_link %s", best->name);
		agent_exec_platform_scripts(fmt);
		if (!a->progressing)
			timer_set(&a->upgrade_backhaul_scheduler, 30 * 1000);
	}

	a->progress_attempts = 0;
}

bool agent_has_downstream(struct agent *a)
{
	struct netif_fh *fh;

	list_for_each_entry(fh, &a->fhlist, list) {
		struct sta *s;

		/* only bbss and combined type interfaces may have downstream APs */
		if (fh->cfg->multi_ap != 1 && fh->cfg->multi_ap != 3)
			continue;

		list_for_each_entry(s, &fh->stalist, list)
			return true;
	}

	return false;
}

static void agent_upgrade_backhaul_cb(atimer_t *t)
{
	struct agent *a = container_of(t, struct agent, upgrade_backhaul_scheduler);
	int timeout = 30; /* 30s default */

	/* Check CAC */
	wifi_bsta_check_cac_done(a);

	if (a->progress_attempts == 1)
		timeout = 60 * 5; /* 5 minutes */
	else if (a->progress_attempts >= 2)
		timeout = 60 * 30; /* 30 minutes */

	if (agent_has_downstream(a) && !a->progressing) {
		timer_set(&a->upgrade_backhaul_scheduler,
				  timeout * 1000);
		return;
	}

	if (!a->progressing) {
		agent_exec_platform_scripts("bsta_scan_on_enabled");
		a->progressing = true;
		a->progress_attempts++;
		timer_set(&a->upgrade_backhaul_scheduler, 15 * 1000);
		timestamp_update(&a->dynbh_last_start);
	} else {
		/* TODO: add to function */
		struct netif_bk *bk, *best = NULL;

		/* ensure latest configs and states are loaded prior to finding
		 * best bsta
		 */
		agent_check_bsta_connections(a);

		list_for_each_entry(bk, &a->bklist, list) {
			dbg("|%s:%d| bsta %s enabled %d connected %d priority %u\n",
					__func__, __LINE__, bk->name,
					bk->cfg->enabled, bk->connected, bk->cfg->priority);
			if (!bk->cfg->enabled || !bk->connected)
				continue;

			if (!best || bk->cfg->priority > best->cfg->priority)
				best = bk;
		}

		if (best) {
			char fmt[64] = {0};

			snprintf(fmt, sizeof(fmt), "bsta_use_link %s", best->name);
			agent_exec_platform_scripts(fmt);
		}

		a->progressing = false;

		timer_set(&a->upgrade_backhaul_scheduler, timeout * 1000);
		timestamp_update(&a->dynbh_last_end);
	}
}

static void ethport_event_handler(void *agent, struct blob_attr *msg)
{
	char ifname[16] = {0}, link[8] = {0};
	struct agent *a = (struct agent *) agent;
	struct blob_attr *tb[4];
	static const struct blobmsg_policy ev_attr[4] = {
		[0] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "link", .type = BLOBMSG_TYPE_STRING },
		[2] = { .name = "speed", .type = BLOBMSG_TYPE_TABLE },
		[3] = { .name = "duplex", .type = BLOBMSG_TYPE_TABLE },
	};
	bool up, down;

	blobmsg_parse(ev_attr, 4, tb, blob_data(msg), blob_len(msg));

	if (!tb[0] || !tb[1]) /* only need ifname and link status */
		return;

	strncpy(ifname,	blobmsg_data(tb[0]), sizeof(ifname) - 1);
	strncpy(link, blobmsg_data(tb[1]), sizeof(link) - 1);

	up = !strcmp(link, "up");
	down = !strcmp(link, "down");

	UNUSED(down);

	if (up) {
		dbg("|%s:%d| Scheduling next ACS in 1 second\n", __func__,
				__LINE__);
		timer_set(&a->autocfg_dispatcher, 1 * 1000);
		timestamp_update(&a->eth_connect_t);
	}

	return;
}


static void parse_i1905_info(struct ubus_request *req, int type,
		struct blob_attr *msg)
{
	struct agent *a = (struct agent *)req->priv;
	struct blob_attr *tb[2];
	static const struct blobmsg_policy ieee_attrs[2] = {
		[0] = { .name = "ieee1905id", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "interface", .type = BLOBMSG_TYPE_ARRAY }
	};

	blobmsg_parse(ieee_attrs, 2, tb, blob_data(msg), blob_len(msg));

	if (tb[0]) {
		char *mac;

		mac = blobmsg_get_string(tb[0]);
		hwaddr_aton(mac, a->almac);
		dbg("almac = " MACFMT "\n", MAC2STR(a->almac));
	}
}

static void router_system_info_cb(struct ubus_request *req, int type,
		struct blob_attr *msg)
{
	struct agent *a = (struct agent *)req->priv;
	static const struct blobmsg_policy rsys_attr[] = {
		[0] = { .name = "serial_number", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "software_version", .type = BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[ARRAY_SIZE(rsys_attr)];

	blobmsg_parse(rsys_attr, ARRAY_SIZE(rsys_attr), tb,
			blob_data(msg), blob_len(msg));

	if (tb[0])
		strncpy(a->device_inventory.serial_number, blobmsg_data(tb[0]),
				sizeof(a->device_inventory.serial_number) - 1);

	if (tb[1])
		strncpy(a->device_inventory.sw_version, blobmsg_data(tb[1]),
				sizeof(a->device_inventory.sw_version) - 1);
}

static void uobj_add_event_handler(void *agent, struct blob_attr *msg)
{
	char path[32] = {0};
	uint32_t id = 0;
	struct agent *a = (struct agent *) agent;
	struct blob_attr *tb[2];
	static const struct blobmsg_policy ev_attr[2] = {
		[0] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
		[1] = { .name = "path", .type = BLOBMSG_TYPE_STRING }
	};

	blobmsg_parse(ev_attr, 2, tb, blob_data(msg), blob_len(msg));

	if (!tb[0] || !tb[1])
		return;

	strncpy(path, blobmsg_data(tb[1]), sizeof(path) - 1);
	id = (uint32_t) blobmsg_get_u32(tb[0]);
	dbg("|%s:%d| path = [%s] id = [%d] [%u]\n", __func__, __LINE__, path, id, id);
	if (!strncmp(path, map_plugin, strlen(map_plugin))) {
		/* TODO: how to handle failure? */
		agent_subscribe_for_cmdus(a);
	} else if (!strncmp(path, "wifi.ap.", 8)) {
		char *ifname = path + 8;
		struct netif_fh *fh;

		dbg("|%s:%d| iface = [%s]\n", __func__, __LINE__, ifname);
		fh = get_netif_by_name(a, ifname);
		if (!fh)
			return;
		fh->wifi = id;
		dbg("|%s:%d|wifi.ap.%s object added is [%d] [%u]\n", __func__, __LINE__, fh->name, fh->wifi, fh->wifi);
	} else if (!strncmp(path, "wifi.backhaul.", 14)) {
		char *ifname = path + 14;
		struct netif_bk *bk;

		warn("|%s:%d| iface = [%s]\n", __func__, __LINE__, ifname);
		bk = agent_get_netif_bk_by_name(a, ifname);
		if (!bk)
			return;
		bk->wifi = id;
		warn("|%s:%d|wifi.backhaul.%s object added is [%d] [%u]\n", __func__, __LINE__, bk->name, bk->wifi, bk->wifi);
	} else if (!strncmp(path, "ieee1905.al.", 12)) {
		uint32_t ieee1905_obj = 0;
		int ret;

		ret = ubus_lookup_id(a->ubus_ctx, "ieee1905", &ieee1905_obj);
		if (ret)
			return;

		ubus_call_object(a, ieee1905_obj, "info", parse_i1905_info, a);
	} else if (!strncmp(path, "wpa_supplicant.", 15)) {
		char *ifname = path + 15;

		/* re-init blacklist upon supplicant coming back up*/
		backhaul_blacklist_update_ifname(agent, ifname);
	}
}

int send_bsta_steer_resp(struct agent *a, struct cmdu_buff *cmdu,
		struct netif_bk *bk, uint8_t *bssid)
{
	struct tlv_backhaul_steer_resp *p;
	struct tlv *tv[1][16] = {0};
	int ret = -1;
	struct node *n;

	n = agent_find_node(a, cmdu->origin);
	if (!n)
		goto out;

	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		goto out;
	}

	if (!tv[0][0])
		goto out;

	p = (struct tlv_backhaul_steer_resp *) tv[0][0]->data;
	if (!p)
		goto out;

	if (memcmp(bssid, p->target_bssid, 6)) {
		p->result = 0x01;
		if (!agent_gen_tlv_error_code(a, cmdu, NULL, 0x05))
			goto out;
	}

	timer_del(&bk->connect_timer);
	ret = !agent_send_cmdu(a, cmdu);

	trace("\n\n%s %d bssid = " MACFMT ", target = " MACFMT "\n", __func__, __LINE__, MAC2STR(bssid), MAC2STR(p->target_bssid));

	/* if steer was successful - write to config */
//	if (p->result == 0x00) {
//		char fmt[64] = {0};
//
//		wifi_set_iface_bssid(bk, bssid);
//		snprintf(fmt, sizeof(fmt), "write_bsta_config %s", bk->name);
//		agent_exec_platform_scripts(fmt);
//	}
out:
	cmdu_free(cmdu);
	bk->bsta_steer.cmdu = NULL;
	return ret;
}

static void agent_update_active_uplink(struct agent *a, char *ifname)
{
	char ev[512] = {0};

	dbg("%s: called.\n", __func__);

	if (!a)
		return;

	sprintf(ev,
		"{\"action\":\"set_uplink\""
		",\"type\":\"wifi\""
		",\"ifname\":\"%s\"}",
		ifname);

	trace("cntlrinfo: %s\n", ev);
	agent_notify_event(a, "map.agent", ev);
	runCmd("/lib/wifi/multiap set_uplink wifi %s", ifname);
}

static bool wifi_is_band_onboarded(struct agent *a, enum wifi_band band)
{
	struct agent_config_radio *rcfg = NULL;

	list_for_each_entry(rcfg, &a->cfg.radiolist, list) {
		if (rcfg->onboarded && rcfg->band == band)
			return true;
	}

	return false;
}

static bool wifi_radio_cac_required(struct agent *a, struct wifi_radio_element *re,
				    int channel, int bandwidth, uint32_t *cac_time)
{
	struct wifi_radio_opclass opclass = {};
	struct netif_fh *ap;
	bool ap_found = false;

	/* Check any AP configured */
	list_for_each_entry(ap, &a->fhlist, list) {
		if (strcmp(ap->radio_name, re->name))
			continue;

		ap_found = true;
		break;
	}

	if (!ap_found)
		return false;

	/* Get fresh opclass preferences */
	if (WARN_ON(wifi_opclass_preferences(re->name, &opclass))) {
		return false;
	}

	return wifi_opclass_cac_required(&opclass, channel, bandwidth, cac_time);
}

static int wifi_bsta_handle_cac_required(struct agent *a,
					 struct wifi_radio_element *re,
					 struct netif_bk *bk)
{
	struct netif_bk *new_bk = NULL;
	struct netif_bk *sta;
	uint32_t cac_time = 0;
	char fmt[64] = {0};

	if (!a->cfg.ap_follow_sta_dfs)
		return 0;

	re->cac_required = wifi_radio_cac_required(a, re, re->current_channel,
						   re->current_bandwidth, &cac_time);

	dbg("bsta %s connected on %d/%d cac required %d time %us\n", bk->name,
	    re->current_channel, re->current_bandwidth, re->cac_required,
	    cac_time);

	if (!re->cac_required)
		return 0;

	/* Find new bsta */
	list_for_each_entry(sta, &a->bklist, list) {
		if (!strcmp(sta->name, bk->name))
			continue;

		new_bk = sta;
		break;
	}

	/* Disable current connection */
	config_disable_bsta(bk->cfg);
	bk->connected = false;


	if (new_bk) {
		dbg("[%s] connect cac required use new link %s\n", bk->name, new_bk->name);
		snprintf(fmt, sizeof(fmt), "bsta_use_link %s", new_bk->name);
		config_enable_bsta(new_bk->cfg);
		agent_exec_platform_scripts(fmt);
	} else {
		dbg("connect cac required disconnect current link %s\n", bk->name);
		agent_exec_platform_scripts("bsta_use_link none");
	}

	wifi_bsta_disconnect(a, bk->name);
	cac_time += 20;
	if (!a->progressing)
		timer_set(&a->upgrade_backhaul_scheduler, cac_time * 1000);

	timestamp_update(&bk->cac_start);
	bk->cac_time = cac_time - 5;

	/* Use 80MHz */
	if (re->current_bandwidth < 80)
		re->current_opclass =
			wifi_opclass_find_id_from_channel(&re->opclass,
					re->current_channel, 80);

	/* Start CAC */
	if (WARN_ON(agent_channel_switch(a, re->macaddr, re->current_channel, re->current_opclass))) {
		bk->cac_time = 0;
		if (!a->progressing)
			timer_set(&a->upgrade_backhaul_scheduler, 5 * 1000);
	}

	/* Don't wait - switch bsta */
	agent_exec_platform_scripts("bsta_scan_on_enabled");

	return 1;
}

static void wifi_bsta_check_cac_done(struct agent *a)
{
	struct wifi_radio_element *re = NULL;
	struct netif_bk *bk;
	uint8_t enable_prio = 255;
	bool cac_required;
	uint32_t cac_time;

	if (!a->cfg.ap_follow_sta_dfs)
		return;

	/* lower prio is better */
	list_for_each_entry(bk, &a->bklist, list) {
		if (!bk->cfg->enabled)
			continue;
		if (bk->cfg->priority < enable_prio)
			enable_prio = bk->cfg->priority;
	}

	list_for_each_entry(bk, &a->bklist, list) {
		if (bk->cac_time) {
			re = wifi_ifname_to_radio_element(a, bk->name);
			if (re) {
				cac_required = wifi_radio_cac_required(a, re,
							re->current_channel,
							re->current_bandwidth,
							&cac_time);
				dbg("[%s] %d/%d cac_required %d\n", bk->name, re->current_channel,
				    re->current_bandwidth, cac_required);
			} else {
				cac_required = true;
			}

			if (timestamp_expired(&bk->cac_start, bk->cac_time * 1000) || !cac_required) {
				dbg("[%s] connect enable bsta again, cac end (required %d)\n", bk->name, cac_required);
				config_enable_bsta(bk->cfg);
				bk->cac_time = 0;
				if (a->progressing) {
					a->progressing = false;
					timer_set(&a->upgrade_backhaul_scheduler, 5 * 1000);
				}
			}
		} else {
			/* In case we loose bk->cac_time during agent stop/start */
			if (!bk->cfg->enabled && bk->cfg->priority < enable_prio) {
				dbg("[%s] connect !cac_time enable higher prio (%d) bsta\n", bk->name, enable_prio);
				config_enable_bsta(bk->cfg);
			}
		}
	}
}

static void wifi_bsta_connect(struct agent *a, struct netif_bk *bk,
		uint8_t *bssid)
{
	int i;
	char fmt[64] = {0};
	int bssid_expired = 0;
	struct wifi_radio_element *re = NULL;

	/* no operation if no bsta on same band is onboarded! */
	if (!wifi_is_band_onboarded(a, bk->cfg->band)) {
		dbg("|%s:%d| band %d is not onboard\n", __func__, __LINE__,
		    bk->cfg->band);
		return;
	}

	if (!a->cntlr_select.local)
		agent_disable_local_cntlr(a);

	dbg("|%s:%d| connect event received\n", __func__, __LINE__);

	bssid_expired = timestamp_expired(&a->disconnect_t,
			(a->cfg.dbhcfg.bh_miss_tmo + 15) * 1000);
	dbg("|%s:%d| new bssid " MACFMT " old bssid " MACFMT ","\
			" difftime exceeds 60s = %d\n", __func__, __LINE__,
			MAC2STR(bssid),	MAC2STR(bk->wan_bssid), bssid_expired);


	if (((!hwaddr_is_zero(bk->wan_bssid) && memcmp(bssid, bk->wan_bssid, 6)) ||
	      bssid_expired) && !a->connected) {
		dbg("|%s:%d| new bssid or difftime exceeded 60s,"\
		    "setting radio states to ACTIVE\n",
		    __func__, __LINE__);
		/** upon connecting to new network - allow radios to be
		 * reconfigured
		 */
		for (i = 0; i < a->num_radios; i++)
			a->radios[i].state = AUTOCFG_ACTIVE;
	}

	agent_enable_fronthauls(a);

	memcpy(bk->wan_bssid, bssid, 6);

	/* assign bssid to configs */
	wifi_set_iface_bssid(bk, bssid);
	snprintf(fmt, sizeof(fmt), "write_bsta_config %s", bk->name);
	agent_exec_platform_scripts(fmt);

	//backhaul_blacklist_clear(a);

	timestamp_update(&a->connect_t);
	/* TODO: eth always takes priority */
	if (!is_backhaul_type_eth())
		agent_update_active_uplink(a, bk->name);
	a->autocfg_interval = 5;
	dbg("|%s:%d| Scheduling next ACS in %u seconds\n", __func__, __LINE__,
			a->autocfg_interval);
	timer_set(&a->autocfg_dispatcher, a->autocfg_interval * 1000);

	/* Update radio channel/bw/opclass */
	re = wifi_ifname_to_radio_element(a, bk->name);
	if (re) {
		struct wifi_bsta_status status = {};

		/* Get channel/bandwidth from bsta */
		if (!wifi_bsta_status(bk->name, &status)) {
			re->current_channel = status.channel;
			re->current_bandwidth = wifi_bw_to_bw(status.bandwidth);
			re->current_opclass = wifi_opclass_find_id_from_channel(&re->opclass,
					re->current_channel, re->current_bandwidth);
		}

		/* Check CAC AP/BSTA action required */
		if (wifi_bsta_handle_cac_required(a, re, bk))
			return;
	}

	bk->connected = true;
	a->connected = true;
}

static void wifi_bsta_event_handler(void *agent, struct blob_attr *msg)
{
	char ifname[16] = {0}, event[16] = {0};
	struct agent *a = (struct agent *) agent;
	struct blob_attr *tb[3];
	static const struct blobmsg_policy ev_attr[3] = {
		[0] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "event", .type = BLOBMSG_TYPE_STRING },
		[2] = { .name = "data", .type = BLOBMSG_TYPE_TABLE },
	};
	struct netif_bk *bk;
	bool add, del;

	blobmsg_parse(ev_attr, 3, tb, blob_data(msg), blob_len(msg));

	if (!tb[0] || !tb[1])
		return;

	strncpy(ifname,	blobmsg_data(tb[0]), sizeof(ifname) - 1);
	strncpy(event, blobmsg_data(tb[1]), sizeof(event) - 1);

	bk = find_bkhaul_by_ifname(a, ifname);
	if (!bk)
		return;

	add = !strcmp(event, "connected");
	del = !strcmp(event, "disconnected");

	/* if scan event and eth backhaul is used - disconnect to prevent loop */
	if ((!strcmp(event, "scan-started") || !strcmp(event, "scan-failed"))
			&& is_backhaul_type_eth())
		wifi_bsta_disconnect(a, ifname);

	/** if receive scan event from non-active link, while we are not trying
	 *  to progress */
	if ((!strcmp(event, "scan-started") || !strcmp(event, "scan-failed"))
			&& ((!bk->connected && !a->progressing && a->connected)))
		wifi_bsta_disconnect(a, ifname);

	if (add) {
		uint8_t bssid[6] = {0};
		char bssid_str[18] = {0};
		struct cmdu_buff *cmdu;
		struct blob_attr *data[1];
		static const struct blobmsg_policy data_attr[1] = {
			[0] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
		};
		int remaining;

		/* don't handle event if bk is not enabled */
		if (!tb[2])
			return;

		if (!bk->cfg->enabled) {
			dbg("|%s:%d| bsta is not enabled - higher prio is "\
					"active, disconnect\n",
					__func__, __LINE__);
			wifi_bsta_disconnect(a, ifname);
			return;
		}

		blobmsg_parse(data_attr, 1, data, blobmsg_data(tb[2]),
				blobmsg_data_len(tb[2]));

		strncpy(bssid_str, blobmsg_data(data[0]),
				sizeof(bssid_str) - 1);

		agent_check_ts(a, bk, bk->name);

		hwaddr_aton(bssid_str, bssid);

		wifi_bsta_connect(a, bk, bssid);
		agent_manage_bsta(a, bk);
		cmdu = bk->bsta_steer.cmdu;
		if (cmdu)
			send_bsta_steer_resp(a, cmdu, bk, bssid);

		timer_del(&a->bh_lost_timer);
		timer_del(&a->bh_reconf_timer);
#ifdef AGENT_ISLAND_PREVENTION
		if (a->cfg.island_prevention) {
			timer_del(&a->sta_disconnect_timer);
			timer_del(&a->fh_disable_timer);
		}
#endif /* AGENT_ISLAND_PREVENTION */
		remaining = timer_remaining_ms(&a->onboarding_scheduler);
		if (remaining == -1 && bk->connected) {
			char fmt[64] = {0};

			snprintf(fmt, sizeof(fmt),
				 "bsta_disable_lower_priority %s", ifname);
			agent_exec_platform_scripts(fmt);
			agent_config_reload(a);
			timer_set(&a->disable_unconnected_bstas_scheduler,
					  15 * 1000);
		}
	} else if (del) {
		bk->connected = false;
		/* Handle link loss if this was supposed to be an active bsta */
		if (bk->cfg->enabled) {
			char ul_ifname[16] = {0};

			agent_handle_bh_lost(a);

			if (agent_get_backhaul_ifname(a, ul_ifname)) {
				if (!strncmp(ul_ifname, bk->name, IFNAMSIZ)) {
					char ev[512] = {0};

					dbg("%s: called.\n", __func__);

					if (!a)
						return;

					sprintf(ev,
						"{\"action\":\"unset_uplink\""
						",\"type\":\"wifi\"}");

					trace("cntlrinfo: %s\n", ev);
					agent_notify_event(a, "map.agent", ev);
					agent_exec_platform_scripts("unset_uplink wifi");
				}
			}
		}
		wifi_mod_bridge(a, ifname, "remove");
		a->connected = agent_is_bsta_connected(a);
	} else if (!strcmp(event, "wps-pbc-active")) {
		bk->wps_active = true;
	} else if (!strcmp(event, "wps-timeout")) {
		bk->wps_active = false;
	} else if (!strcmp(event, "csa")) {
		struct wifi_radio_element *re = NULL;
		struct wifi_bsta_status status = {};
		uint32_t cac_time;

		dbg("[%s] connect csa\n", ifname);

		if (a->cfg.ap_follow_sta_dfs) {
			re = wifi_ifname_to_radio_element(a, ifname);

			if (re) {
				/* Get channel/bandwidth from bsta */
				if (!wifi_bsta_status(ifname, &status)) {
					re->current_channel = status.channel;
					re->current_bandwidth = wifi_bw_to_bw(status.bandwidth);
					re->current_opclass =
						wifi_opclass_find_id_from_channel(
								&re->opclass,
								re->current_channel,
								re->current_bandwidth);
				}

				if (wifi_radio_cac_required(a, re, re->current_channel,
							    re->current_bandwidth, &cac_time)) {
					/* Simple disconnect, new connect will do required actions */
					wifi_bsta_disconnect(a, bk->name);
					agent_exec_platform_scripts("bsta_scan_on_enabled");
				}
			}
		}
	}
}


#define ONBOARDING_TIMER 15
static void wifi_wps_creds_event_handler(void *c, struct blob_attr *msg)
{
	char encryption[32] = {0}, ifname[16] = {0}, ssid[33] = {0},
			key[65] = {0};
	//uint16_t vlan = 0;
	struct blob_attr *tb[5];
	struct wifi_radio_element *radio;
	struct agent *a = (struct agent *) c;
	static const struct blobmsg_policy ap_attr[5] = {
		[0] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "encryption", .type = BLOBMSG_TYPE_STRING },
		[2] = { .name = "ssid", .type = BLOBMSG_TYPE_STRING },
		[3] = { .name = "key", .type = BLOBMSG_TYPE_STRING },
		[4] = { .name = "vlan_id", .type = BLOBMSG_TYPE_INT32 },
	};
	struct netif_bk *bk, *p;
	int timeout = 0;

	blobmsg_parse(ap_attr, 5, tb, blob_data(msg), blob_len(msg));

	if (!tb[0] || !tb[1] || !tb[2] || !tb[3])
		return;

	strncpy(ifname,	blobmsg_data(tb[0]), sizeof(ifname) - 1);
	strncpy(encryption, blobmsg_data(tb[1]), sizeof(encryption) - 1);
	strncpy(ssid, blobmsg_data(tb[2]), sizeof(ssid) - 1);
	strncpy(key, blobmsg_data(tb[3]), sizeof(key) - 1);
	bk = find_bkhaul_by_ifname(a, ifname);
	if (!bk)
		return;

	/* don't wait for other bands if creds are synced via AP-Autoconfig */
	if (!a->cfg.eth_onboards_wifi_bhs) {
		list_for_each_entry(p, &a->bklist, list) {
			if (p->wps_active) {
				int remaining = timer_remaining_ms(&a->onboarding_scheduler);

				/* allow up to extra time for the other
				* band(s) to complete
				*/
				timeout = ONBOARDING_TIMER - (remaining == -1 ? 0 : remaining);
			}
		}
	}

	wifi_apply_iface_cfg(bk->name, encryption, ssid, key);
	bk->wps_active = false;
	bk->cfg->onboarded = true;

	//uci_reload_services("wireless"); /* move to platform script? */

	radio = wifi_ifname_to_radio_element(a, ifname);
	if (!radio)
		return;

	radio->onboarded = 1;
	uci_set_wireless_interface_option("mapagent", "radio", "device",
			radio->name, "onboarded", "1");

	timer_set(&a->onboarding_scheduler, timeout * 1000);

#if 0 /* Not used at present */
	vlan = 0;
	if (tb[4])
		vlan = (uint16_t) blobmsg_get_u16(tb[4]);

	if (vlan && bk->agent) {
		if (!(a->cfg.pcfg)) {
			a->cfg.pcfg = (struct policy_cfg *)calloc(1, sizeof(struct policy_cfg));
			if (!(a->cfg.pcfg)) {
				err("%s:%d - memory allocation failed\n",
				    __func__, __LINE__);
				return;
			}
		}
		bk->agent->cfg.pcfg->pvid = vlan;

		agent_apply_traffic_separation(bk->agent);
	}
#endif
}

static void agent_event_handler(struct ubus_context *ctx,
		struct ubus_event_handler *ev,
		const char *type, struct blob_attr *msg)
{
	int i;
	char *str;
	struct agent *a = container_of(ev, struct agent, evh);
	struct wifi_ev_handler {
		const char *ev_type;
		void (*handler)(void *ctx, struct blob_attr *ev_data);
	} evs[] = {
		{ "wifi.sta", wifi_sta_event_handler },
		{ "wifi.channel", wifi_channel_event_handler },
		{ "wifi.dfs", wifi_dfs_event_handler },
		{ "wifi.radio", wifi_radio_event_handler },
		{ "wifi.iface", wifi_iface_event_handler },
		{ "wps_credentials", wifi_wps_creds_event_handler },
		{ "wifi.bsta", wifi_bsta_event_handler },
		{ "ethport", ethport_event_handler },
		{ "ubus.object.add", uobj_add_event_handler },
		{ "wifi.radio", wifi_chan_change_event_handler },
		{ "wifi.radio", wifi_cac_event_handler},
	};

	str = blobmsg_format_json(msg, true);
	if (!str)
		return;

	info("[ &agent = %p ] Received [event = %s]  [val = %s]\n",
			a, type, str);

	for (i = 0; i < ARRAY_SIZE(evs); i++) {
		if (!strcmp(type, evs[i].ev_type)) {
			evs[i].handler(a, msg);
		}
	}

	free(str);
}

static void ieee1905_cmdu_event_handler(void *c, struct blob_attr *msg)
{
	struct agent *a = (struct agent *)c;
	char *tlvstr = NULL;
	uint8_t *tlv = NULL;
	char in_ifname[16] = {0};
	char src[18] = { 0 }, src_origin[18] = { 0 };
	uint8_t srcmac[6], origin[6];
	int len = 0;
	uint16_t type;
	uint16_t mid = 0;
	struct blob_attr *tb[6];
	static const struct blobmsg_policy cmdu_attrs[6] = {
		[0] = { .name = "type", .type = BLOBMSG_TYPE_INT16 },
		[1] = { .name = "mid", .type = BLOBMSG_TYPE_INT16 },
		[2] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
		[3] = { .name = "source", .type = BLOBMSG_TYPE_STRING },
		[4] = { .name = "origin", .type = BLOBMSG_TYPE_STRING },
		[5] = { .name = "cmdu", .type = BLOBMSG_TYPE_STRING },
	};

	blobmsg_parse(cmdu_attrs, 6, tb, blob_data(msg), blob_len(msg));

	trace("%s: --->\n", __func__);

	if (!tb[0] || !tb[1]) {
		trace("%s: no type or mid.\n", __func__);
		return;
	}

	if (tb[0]) {
		type = (uint16_t)blobmsg_get_u16(tb[0]);
		if (!is_cmdu_for_us(a, type)) {
			trace("%s: type: 0x%x is_cmdu_for_us false.\n", __func__, type);
			return;
		}
	}

	if (tb[1])
		mid = (uint16_t)blobmsg_get_u16(tb[1]);

	if (tb[2])
		strncpy(in_ifname, blobmsg_data(tb[2]), 15);

	if (tb[3]) {
		strncpy(src, blobmsg_data(tb[3]), 17);
		hwaddr_aton(src, srcmac);
	}

	if (tb[4]) {
		strncpy(src_origin, blobmsg_data(tb[4]), 17);
		hwaddr_aton(src_origin, origin);
	}

	if (tb[5]) {
		len = blobmsg_data_len(tb[5]) - 16;
		tlvstr = calloc(len + 1, sizeof(char));
		if (!tlvstr)
			return;

		strncpy(tlvstr, blobmsg_data(tb[5]) + 16, len);
		len = (len - 1) / 2;
		tlv = calloc(len, sizeof(uint8_t));
		if (!tlv) {
			free(tlvstr);
			return;
		}

		strtob(tlvstr, len, tlv);

		free(tlvstr);

	}

	agent_handle_map_event(a, type, mid, in_ifname, srcmac, origin, tlv, len);
	free(tlv);
}

static void sync_neighbor_lists(struct netif_fh *fh)
{
	struct nbr nbr[64] = {};
	int nbr_num = 64;
	struct neighbor *n;
	bool found;
	int ret;
	int i;

	/* Update new & changed nbr entries in driver */
	list_for_each_entry(n, &fh->nbrlist, list) {

		if (n->flags & NBR_FLAG_DRV_UPDATED)
			continue;

		/* update nbr in wifi driver */
		dbg("[%s] Update neighbor "
		    MACFMT " entry in driver\n",
		    fh->name,
		    MAC2STR(n->nbr.bssid));
		wifi_del_neighbor(fh->name, n->nbr.bssid);
		wifi_add_neighbor(fh->name, &n->nbr);
		n->flags |= NBR_FLAG_DRV_UPDATED;
	}

	/* Trigger removal of dead entries from list in driver */
	ret = wifi_get_neighbor_list(fh->name, nbr, &nbr_num);
	if (ret)
		return;

	for (i = 0; i < nbr_num; i++) {
		found = false;
		list_for_each_entry(n, &fh->nbrlist, list) {
			if (!memcmp(nbr[i].bssid, n->nbr.bssid, 6)) {
				found = true;
				break;
			}
		}

		if (!found) {
			/* Remove dead entry from driver list */
			dbg("[%s] Delete neighbor "
			    MACFMT " entry in driver\n",
			    fh->name, MAC2STR(nbr[i].bssid));
			wifi_del_neighbor(fh->name, nbr[i].bssid);
		}
	}
}

static void refresh_neighbor_list(atimer_t *t)
{
	struct netif_fh *fh = container_of(t, struct netif_fh, nbr_timer);

	trace("%s: fh = %s\n", __func__, fh->name);

	/* First remove aged out entries from FH's nbrlist */
	delete_expired_entries(fh, struct neighbor, &fh->nbrlist, list,
				tsp, NBR_AGEOUT_INTERVAL, NULL,
				fh->nbr_nr);

	/* Now update list in driver so that it matches FH's nbrlist */
	sync_neighbor_lists(fh);

	/* Check again in couple of minutes */
	timer_set(&fh->nbr_timer, NBR_REFRESH_INTERVAL);
}

static void refresh_bssinfo(atimer_t *t)
{
	struct netif_fh *vif = container_of(t, struct netif_fh, bss_timer);
	struct agent *a = vif->agent;
	struct wifi_ap_status ap_status = {};
	uint8_t sta[128 * 6] = {};
	int num_sta = 128;
	int i;

	dbg("%s: vif = %s\n", __func__, vif->name);
	if (!wifi_ap_status(vif->name, &ap_status)) {
		vif->channel = ap_status.ap.bss.channel;
		memcpy(vif->bssid, ap_status.ap.bss.bssid, 6);
		memcpy(vif->ssid, ap_status.ap.bss.ssid, 32);
		/* others.. */
		if (ap_status.ap.bss.load.utilization != 0xff)
			vif->bssload = ap_status.ap.bss.load.utilization;

		dbg("ap: %s   bssid: " MACFMT
				"  channel: %d   bssload: %d\n",
				vif->name, MAC2STR(vif->bssid),
				vif->channel, vif->bssload);

		if (!wifi_get_assoclist(vif->name, sta, &num_sta)) {
			for (i = 0; i < num_sta; i++)
				wifi_add_sta(a, vif->name, &sta[i * 6]);
		}
	}

	timer_set(&vif->bss_timer, BSS_REFRESH_INTERVAL);
}

#if 0
static int run_agent(struct agent *a)
{
	struct netif_fh *fh;
	int i = 0;

	return 0;	// TODO: remove

	if (a->cfg.runfreq == AGENT_RUN_OFF)
		return 0;

	/* for each enabled wifi(life) fh interface, */
	list_for_each_entry(fh, &a->fhlist, list) {
		if (!fh->cfg->enabled)
			continue;

		trace("Agent: Set up refresh timers for '%s'...\n", fh->name);
		/* do ... */
		timer_set(&fh->bss_timer, (2 + i++) * 1000);
		timer_set(&fh->nbr_timer, (5 + i++) * 1000);
	}
	return 0;
}
#endif

static void parse_radio_stats(struct ubus_request *req, int type,
			      struct blob_attr *msg)
{
	struct wifi_radio_element *re = (struct wifi_radio_element *)req->priv;
	static const struct blobmsg_policy stats_attr[] = {
		[0] = { .name = "tx_bytes", .type = BLOBMSG_TYPE_INT64 },
		[1] = { .name = "tx_packets", .type = BLOBMSG_TYPE_INT64 },
		[2] = { .name = "tx_error_packets", .type = BLOBMSG_TYPE_INT64 },
		[3] = { .name = "tx_dropped_packets", .type = BLOBMSG_TYPE_INT64 },
		[4] = { .name = "rx_bytes", .type = BLOBMSG_TYPE_INT64 },
		[5] = { .name = "rx_packets", .type = BLOBMSG_TYPE_INT64 },
		[6] = { .name = "rx_error_packets", .type = BLOBMSG_TYPE_INT64 },
		[7] = { .name = "rx_dropped_packets", .type = BLOBMSG_TYPE_INT64 },
		[8] = { .name = "rx_plcp_error_packets", .type = BLOBMSG_TYPE_INT64 },
		[9] = { .name = "rx_fcs_error_packets", .type = BLOBMSG_TYPE_INT64 },
		[10] = { .name = "rx_mac_error_packets", .type = BLOBMSG_TYPE_INT64 },
		[11] = { .name = "rx_unknown_packets", .type = BLOBMSG_TYPE_INT64 },
	};
	struct blob_attr *tb[ARRAY_SIZE(stats_attr)];

	blobmsg_parse(stats_attr, ARRAY_SIZE(stats_attr), tb, blobmsg_data(msg), blob_len(msg));

	if (tb[0])
		re->tx_bytes = blobmsg_get_u64(tb[0]);

	if (tb[1])
		re->tx_packets = blobmsg_get_u64(tb[1]);

	if (tb[2])
		re->tx_error_packets = blobmsg_get_u64(tb[2]);

	if (tb[3])
		re->tx_dropped_packets = blobmsg_get_u64(tb[3]);

	if (tb[4])
		re->rx_bytes = blobmsg_get_u64(tb[4]);

	if (tb[5])
		re->rx_packets = blobmsg_get_u64(tb[5]);

	if (tb[6])
		re->rx_error_packets = blobmsg_get_u64(tb[6]);

	if (tb[7])
		re->rx_dropped_packets = blobmsg_get_u64(tb[7]);

	if (tb[8])
		re->rx_plcp_error_packets = blobmsg_get_u64(tb[8]);

	if (tb[9])
		re->rx_fcs_error_packets = blobmsg_get_u64(tb[9]);

	if (tb[10])
		re->rx_mac_error_packets = blobmsg_get_u64(tb[10]);

	if (tb[11])
		re->rx_unknown_packets = blobmsg_get_u64(tb[11]);
}

static void parse_radio(struct ubus_request *req, int type,
		struct blob_attr *msg)
{
	struct wifi_radio_element *re = (struct wifi_radio_element *)req->priv;
	static const struct blobmsg_policy radio_attr[] = {
		[0] = { .name = "isup", .type = BLOBMSG_TYPE_BOOL },
		[1] = { .name = "band", .type = BLOBMSG_TYPE_STRING },
		[2] = { .name = "noise", .type = BLOBMSG_TYPE_INT32 },
		[3] = { .name = "rx_streams", .type = BLOBMSG_TYPE_INT8 },
		[4] = { .name = "tx_streams", .type = BLOBMSG_TYPE_INT8 },
		[5] = { .name = "supp_channels", .type = BLOBMSG_TYPE_ARRAY },
		[6] = { .name = "opclass", .type = BLOBMSG_TYPE_INT32 },
		[7] = { .name = "channel", .type = BLOBMSG_TYPE_INT32 },
		[8] = { .name = "regdomain", .type = BLOBMSG_TYPE_STRING },
		[9] = { .name = "txpower", .type = BLOBMSG_TYPE_INT32 },
		[10] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
		[11] = { .name = "diagnostics", .type = BLOBMSG_TYPE_TABLE },
		[12] = { .name = "bandwidth", .type = BLOBMSG_TYPE_INT32 },
		[13] = { .name = "vendor_id", .type = BLOBMSG_TYPE_STRING },
		[14] = { .name = "stats", .type = BLOBMSG_TYPE_TABLE }
	};
	struct blob_attr *tb[ARRAY_SIZE(radio_attr)];

	dbg("%s ---> %s\n", __func__, re->name);

	blobmsg_parse(radio_attr, ARRAY_SIZE(radio_attr), tb, blob_data(msg), blob_len(msg));

	if (tb[0])
		re->enabled = blobmsg_get_bool(tb[0]);

	if (tb[1]) {
		char *band;

		band = blobmsg_get_string(tb[1]);
		if (!strncmp(band, "2.4GHz", strlen("2.4GHz")))
			re->band = BAND_2;
		else if (!strncmp(band, "5GHz", strlen("5GHz")))
			re->band = BAND_5;
		else if (!strncmp(band, "6GHz", strlen("6GHz")))
			re->band = BAND_6;
		else
			re->band = BAND_UNKNOWN;
	}

	if (tb[2])
		re->anpi = wifi_noise_to_anpi((int)blobmsg_get_u32(tb[2]));

	if (tb[3])
		re->rx_streams = blobmsg_get_u8(tb[3]);

	if (tb[4])
		re->tx_streams = blobmsg_get_u8(tb[4]);
	if (tb[6])
		re->current_opclass = (uint8_t) blobmsg_get_u32(tb[6]);

	if (tb[7])
		re->current_channel = (uint8_t) blobmsg_get_u32(tb[7]);

	if (tb[8])
		memcpy(re->country_code, blobmsg_data(tb[8]), 2);

	if (tb[9])
		re->current_txpower_percent = (uint8_t) blobmsg_get_u32(tb[9]);

	if (tb[10]) {
		char macaddr[18] = {0};

		strncpy(macaddr, blobmsg_data(tb[10]), 17);
		if (!hwaddr_aton(macaddr, re->macaddr))
			return;
	}

	if (tb[11]) {
		struct blob_attr *tb1[4];
		static const struct blobmsg_policy radio_diag_attr[4] = {
			[0] = { .name = "tx_airtime", .type = BLOBMSG_TYPE_INT64 },
			[1] = { .name = "rx_airtime", .type = BLOBMSG_TYPE_INT64 },
			[2] = { .name = "channel_busy", .type = BLOBMSG_TYPE_INT64 },
			[3] = { .name = "obss_airtime", .type = BLOBMSG_TYPE_INT64 },
		};

		blobmsg_parse(radio_diag_attr, 4, tb1, blobmsg_data(tb[11]), blob_len(tb[11]));

		/* get percentage of utilization and scale linearly with 255 */
		if (tb1[0])
			re->tx_utilization =
				(int)((float)((float)blobmsg_get_u64(tb1[0]) / (float)1000000) * 255) & 0xff;

		if (tb1[1])
			re->rx_utilization =
				(int)((float)((float)blobmsg_get_u64(tb1[1]) / (float)1000000) * 255) & 0xff;

		if (tb1[2])
			re->total_utilization =
				(int)((float)((float)blobmsg_get_u64(tb1[2]) / (float)1000000) * 255) & 0xff;

		if (tb1[3])
			re->other_utilization =
				(int)((float)((float)blobmsg_get_u64(tb1[3]) / (float)1000000) * 255) & 0xff;

	}

	if (tb[12])
		re->current_bandwidth = blobmsg_get_u32(tb[12]);

	if (tb[13])
		strncpy(re->vendor, blobmsg_data(tb[13]),
				sizeof(re->vendor) - 1);

	if (tb[14])
		parse_radio_stats(req, type, tb[14]);

	//Put the preference as per the config file
	agent_config_opclass(re);
}

struct wifi_scanres_channel_element *wifi_get_scanres_ch_element(
		struct wifi_radio_element *re, uint8_t ch)
{
	int i, j;

	if (!re || !re->scanlist)
		return NULL;

	for (i = 0; i < re->scanlist->num_opclass_scanned; i++) {
		struct wifi_scanres_opclass_element *op_el;

		op_el = &re->scanlist->opclass_scanlist[i];
		for (j = 0; j < op_el->num_channels_scanned; j++) {
			if (op_el->channel_scanlist[j].channel == ch
					&& op_el->bandwidth == 20)
				return &op_el->channel_scanlist[j];
		}
	}

	dbg("No operating class with channel %d\n", ch);
	return NULL;
}

static void free_scanresults(struct wifi_radio_element *re)
{
	trace("agent: %s: --->\n", __func__);

	struct wifi_scanres_element *scanres_el;
	int j;

	/* return if no scanresults to free */
	if (!re || !re->scanlist || re->num_scanresult == 0)
		return;

	scanres_el = re->scanlist;
	for (j = 0; j < scanres_el->num_opclass_scanned; j++) {
		int k;
		struct wifi_scanres_opclass_element *opclass;

		opclass = &scanres_el->opclass_scanlist[j];
		if (!opclass)
			continue;

		for (k = 0; k < opclass->num_channels_scanned; k++) {
			struct wifi_scanres_channel_element *ch_el;

			ch_el = &opclass->channel_scanlist[k];
			if (!ch_el)
				continue;

			free(ch_el->nbrlist);
			ch_el->nbrlist = NULL;
		}

		free(opclass->channel_scanlist);
		opclass->channel_scanlist = NULL;
	}

	free(scanres_el->opclass_scanlist);
	scanres_el->opclass_scanlist = NULL;
	free(scanres_el);
	scanres_el = NULL;
	re->num_scanresult = 0;
}

#define ADD_NBR_TIMER 10
void reschedule_nbrlist_update(struct netif_fh *fh)
{
	int elapsed = 0;
	int remaining = timer_remaining_ms(&fh->nbr_timer);

	if (remaining < ADD_NBR_TIMER)
		elapsed = ADD_NBR_TIMER - (remaining == -1 ? 0 : remaining);

	timer_set(&fh->nbr_timer, (ADD_NBR_TIMER - elapsed) * 1000);
}

void free_scanresults_neighbors(struct wifi_radio_element *re)
{
	struct wifi_scanres_element *scanres_el;
	int j;

	scanres_el = re->scanlist;
	if (!scanres_el)
		return;

	for (j = 0; j < scanres_el->num_opclass_scanned; j++) {
		int k;
		struct wifi_scanres_opclass_element *opclass = &scanres_el->opclass_scanlist[j];

		for (k = 0; k < opclass->num_channels_scanned; k++) {
			struct wifi_scanres_channel_element *ch_el = &opclass->channel_scanlist[k];

			if (ch_el->nbrlist)
				free(ch_el->nbrlist);
			ch_el->nbrlist = NULL;
			ch_el->num_neighbors = 0;
		}
	}
}

static int init_scanlist(struct agent *a, const char *radio)
{
	struct wifi_radio_opclass *opclass;
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *channel;
	struct wifi_radio_element *re;
	int num_channels_scanned;
	int opclass_supported;
	int i, j, k;

	trace("agent: %s: --->\n", __func__);

	re = wifi_radio_to_radio_element(a, radio);
	if (WARN_ON(!re))
		return -1;

	opclass = &re->opclass;
	k = 0;

	if (re->num_scanresult)
		free_scanresults(re);

	re->num_scanresult = 1;

	re->scanlist = calloc(re->num_scanresult, sizeof(*re->scanlist));
	if (!re->scanlist) {
		dbg("|%s:%d| out of memory!\n", __func__, __LINE__);
		re->num_scanresult = 0;
		return -1;
	}

	/* FIXME: contains all supported opclasses from start */
	opclass_supported = wifi_opclass_num_supported(opclass);
	re->scanlist->opclass_scanlist =
		calloc(opclass_supported,
			sizeof(struct wifi_scanres_opclass_element));

	if (!re->scanlist->opclass_scanlist) {
		dbg("|%s:%d| out of memory!\n", __func__, __LINE__);
		goto error;
	}

	re->scanlist->num_opclass_scanned = 0;
	for (i = 0; i < opclass->entry_num; i++) {
		entry = &opclass->entry[i];

		if (!wifi_opclass_id_supported(opclass, entry->id))
			continue;

		re->scanlist->opclass_scanlist[k].opclass = entry->id;
		re->scanlist->opclass_scanlist[k].bandwidth = entry->bandwidth;
		/* FIXME contains all supported channels from start */
		num_channels_scanned = entry->channel_num;;
		re->scanlist->opclass_scanlist[k].num_channels_scanned =
				num_channels_scanned;

		re->scanlist->opclass_scanlist[k].channel_scanlist =
			calloc(num_channels_scanned,
				sizeof(struct wifi_scanres_channel_element));

		if (!re->scanlist->opclass_scanlist[k].channel_scanlist) {
			dbg("|%s:%d| out of memory!\n", __func__, __LINE__);
			goto error;
		}
		/* FIXME list stores all supported opclasses */
		re->scanlist->num_opclass_scanned++;

		for (j = 0; j < entry->channel_num; j++) {
			channel = &entry->channel[j];
			re->scanlist->opclass_scanlist[k].channel_scanlist[j].channel =
							channel->channel;
		}

		k++;
	}

	return 0;

error:
	free_scanresults(re);
	return -1;
}

static void agent_available_scan_timeout(atimer_t *t)
{
	dbg("[Status code] SCAN NOT COMPLETED\n\n");

	struct wifi_netdev *ndev;
	int ret;

	ndev = container_of(t, struct wifi_netdev, available_scan_timer);

	if (WARN_ON(!ndev))
		return;

	if (WARN_ON(!ndev->re))
		return;

	if (ndev->re->scan_state != SCAN_REQUESTED || !ndev->scan_req.mid)
		return;

	// TODO: revisit - maybe redundant
	ndev->scan_req.status = CH_SCAN_STATUS_SCAN_NOT_COMPLETED;

	ret = agent_send_ch_scan_response(ndev->agent, ndev, &ndev->scan_req);
	if (ret)
		return;

	ndev->scan_req = (const struct wifi_scan_request_radio){ 0 };
}

static void _enumerate_wifi_objects(struct ubus_request *req, int type,
		struct blob_attr *msg)
{
	trace("%s: --->\n", __func__);
	struct radio_apcfg_state {
		char name[16];
		enum autocfg_state state;
		uint16_t mid;
		uint16_t wsc_mid;
	} apcfg_state[WIFI_DEVICE_MAX_NUM] = {0};
	struct agent *a = (struct agent *)req->priv;
	struct json_object *json_msg;
	struct json_object *radio_array;
	char *json_str;
	int i, j, k, len, prev_len = 0;

	json_str = blobmsg_format_json(msg, true);
	if (!json_str)
		return;

	json_msg = json_tokener_parse(json_str);
	if (!json_msg)
		goto out_str;

	if (!json_object_is_type(json_msg, json_type_object))
		goto out_json;

	json_object_object_get_ex(json_msg, "radios", &radio_array);
	len = json_object_array_length(radio_array);
	if (len > WIFI_DEVICE_MAX_NUM)
		len = WIFI_DEVICE_MAX_NUM;

	trace("%s: num_radios(len) = %d\n", __func__, len);
	if (len) {
		/* store current radio apcfg states */
		for (i = 0; i < a->num_radios; i++) {
			strncpy(apcfg_state[i].name, a->radios[i].name,
				IFNAMSIZ - 1);
			apcfg_state[i].state = a->radios[i].state;
			apcfg_state[i].mid = a->radios[i].mid;
			apcfg_state[i].wsc_mid = a->radios[i].wsc_mid;
		}
		prev_len = a->num_radios;
		/* clears radio apcfg states */
		agent_free_radios(a);
		clear_fhlist(a);
		a->num_radios = len;
	}

	for (i = 0; i < len; i++) {
		struct json_object *radio_obj, *radio_obj_name;
		struct json_object *fh_obj, *fh_obj_name;
		struct json_object *bk_obj, *bk_obj_name;
		struct json_object *fh_array;
		struct json_object *bk_array;
		int fh_len, bk_len;
		const char *radio_name;
		char r_objname[32] = {0};
		//const char *r_fmt = "wifi.radio.%s";
		wifi_object_t r_wobj = WIFI_OBJECT_INVALID;
		struct agent_config_radio *r_cfg;
		radio_obj = json_object_array_get_idx(radio_array, i);
		json_object_object_get_ex(radio_obj, "name", &radio_obj_name);
		radio_name = json_object_get_string(radio_obj_name);
		strncpy(a->ifs[i].radio, radio_name, 15);
		strncpy(a->radios[i].name, radio_name, 15);
		timer_init(&a->ifs[i].available_scan_timer,
				agent_available_scan_timeout);
		a->ifs[i].agent = a;
		a->ifs[i].re = &a->radios[i];

		for (j = 0; j < prev_len; j++) {
			/* write back apcfg state if any */
			if (!strncmp(apcfg_state[j].name, a->radios[i].name,
				     IFNAMSIZ - 1)) {
				a->radios[i].state = apcfg_state[j].state;
				a->radios[i].mid = apcfg_state[j].mid;
				a->radios[i].wsc_mid = apcfg_state[j].wsc_mid;
			}
		}

		list_for_each_entry(r_cfg, &a->cfg.radiolist, list) {
			if (strncmp(r_cfg->name, a->radios[i].name, 15))
				continue;

			a->radios[i].onboarded = r_cfg->onboarded;
			a->radios[i].dedicated_backhaul = r_cfg->dedicated_backhaul;
			break;
		}

		// parse channel range
		// if channel range is stricly beneath <= 64, assign low
		// else if channel rangei stricly above 100, >= 100, assign high
		// else if both ranges, no assignation

		json_object_object_get_ex(radio_obj, "accesspoints", &fh_array);
		fh_len = json_object_array_length(fh_array);
		for (j = 0; j < fh_len; j++) {
			const char *fh_name;

			fh_obj = json_object_array_get_idx(fh_array, j);
			json_object_object_get_ex(fh_obj, "ifname",
					&fh_obj_name);
			fh_name = json_object_get_string(fh_obj_name);
			strncpy(a->ifs[i].iface[j].name, fh_name, 15);
			a->ifs[i].iface[j].mode = WIFI_IFACE_FH;
		}

		json_object_object_get_ex(radio_obj, "backhauls", &bk_array);
		bk_len = json_object_array_length(bk_array);
		for (k = 0; k < bk_len; k++) {
			const char *bk_name;

			bk_obj = json_object_array_get_idx(bk_array, k);
			json_object_object_get_ex(bk_obj, "ifname",
					&bk_obj_name);
			bk_name = json_object_get_string(bk_obj_name);
			strncpy(a->ifs[i].iface[k + j].name, bk_name, 15);
			a->ifs[i].iface[k + j].mode = WIFI_IFACE_BK;
		}

		snprintf(r_objname, 31, "wifi.radio.%s", radio_name);
		r_wobj = ubus_get_object(a->ubus_ctx, r_objname);
		if (r_wobj == WIFI_OBJECT_INVALID) {
			//dbg("%s not present! skipping '%s' from config\n",
			//			r_objname, f->name);
			continue;
		}
		// On-boot channel scan
		// ubus call wifi.radio.wl0 status
		dbg("%s: getting radio status = radios[%d]\n", __func__, i);
		ubus_call_object(a, r_wobj, "status", parse_radio, &a->radios[i]);

		/* Get fresh opclass preferences after scan */
		wifi_radio_update_opclass_preferences(a, radio_name, 1);
		agent_set_post_scan_action_pref(a, radio_name, true);

		/* Allocate radio_element's scanlist */
		init_scanlist(a, radio_name);

		// struct scan_param param = {};
		// wifi_scan(radio_name, &param);
		// fprintf(stderr, "Scaning neighbors.....");
		// sleep(5); // TODO : week 8
		// fprintf(stderr, "DONE\n");
		// agent_radio_scanresults(a, &a->radios[i]);
	}

	agent_init_wsc_attributes(a);
out_json:
	json_object_put(json_msg);
out_str:
	free(json_str);
}

static int enumerate_wifi_objects(struct agent *a)
{
	trace("%s: --->\n", __func__);

	struct blob_buf bb = {};
	int ret, retry = 0;

	blob_buf_init(&bb, 0);
	while ((ret = ubus_invoke(a->ubus_ctx, a->wifi, "status", bb.head,
			_enumerate_wifi_objects, a, 20 * 1000) || !a->num_radios)
			&& retry < 5) {

		err("|%s:%d| Failed to get wifi status(ret = %d), OR "\
		    "num_radios is 0 (%d) retry in 0.5s, wifi object:%u, "\
		    "retry:%d\n", __func__, __LINE__, ret, a->num_radios,
		    a->wifi, retry);
		usleep(500 * 1000); /* 0.5s sleep */
		retry++;
		a->wifi = ubus_get_object(a->ubus_ctx, "wifi");
	}
	trace("%s: num of retries = %d\n", __func__, retry);

	if (ret)
		timer_set(&a->init_ifaces_scheduler, 30 * 1000);

	blob_buf_free(&bb);
	return 0;
}

/* TODO: global visibility */
int agent_get_wifi_interfaces(struct wifi_netdev *wifi)
{
	struct agent *a = this_agent;

	if (!wifi || !a)
		return -1;

	memcpy(wifi, a->ifs, sizeof(a->ifs));

	return 0;
}

struct netif_fh *netif_alloc_fh(const char *ifname)
{
	struct netif_fh *n = NULL;

	n = calloc(1, sizeof(struct netif_fh));
	if (!n)
		return NULL;

	INIT_LIST_HEAD(&n->stalist);
	INIT_LIST_HEAD(&n->nbrlist);
	INIT_LIST_HEAD(&n->restrict_stalist);
	snprintf(n->name, 15, "%s", ifname);

	timer_init(&n->nbr_timer, refresh_neighbor_list);
	timer_init(&n->bss_timer, refresh_bssinfo);

	return n;
}

static struct netif_bk *netif_alloc_bk(const char *ifname)
{
	struct netif_bk *n = NULL;

	n = calloc(1, sizeof(struct netif_bk));
	if (!n)
		return NULL;

	snprintf(n->name, 15, "%s", ifname);
	timer_init(&n->connect_timer, bsta_steer_cb);
	n->wifi = WIFI_OBJECT_INVALID;
	n->radio = WIFI_OBJECT_INVALID;

	return n;
}

/* get first ap on the radio */
// TODO: fixme: get base interface based on macaddr instead?
struct netif_fh *wifi_radio_to_ap(struct agent *a, const char *radio)
{
	struct netif_fh *p;

	list_for_each_entry(p, &a->fhlist, list) {
		const char *fh_radio;

		fh_radio = wifi_ifname_to_radio(a, p->name);
		if (!fh_radio)
			continue;

		if (strncmp(radio, fh_radio, 15))
			continue;

		return p;
	}

	return NULL;
}

static void parse_dot11n(struct netif_fh *fh, struct blob_attr *arg)
{
	int supp_mcs = 0;
	struct blob_attr *tb[4];
	static const struct blobmsg_policy ap_attr[4] = {
		[0] = { .name = "dot11n_sgi20", .type = BLOBMSG_TYPE_BOOL },
		[1] = { .name = "dot11n_sgi40", .type = BLOBMSG_TYPE_BOOL },
		[2] = { .name = "dot11n_40", .type = BLOBMSG_TYPE_BOOL },
		[3] = { .name = "dot11n_supp_max_mcs", .type = BLOBMSG_TYPE_INT32 }
	};

	blobmsg_parse(ap_attr, 4, tb, blobmsg_data(arg), blobmsg_data_len(arg));

	// TODO: cleaner way?
	supp_mcs = blobmsg_get_u32(tb[3]);
	supp_mcs = supp_mcs/8;
	fh->caps.ht |= (supp_mcs & 0x3) << 6;
	fh->caps.ht |= (supp_mcs & 0x3) << 4;
	fh->caps.ht |= ((blobmsg_get_bool(tb[0]) ? 1 : 0) << 3);
	fh->caps.ht |= ((blobmsg_get_bool(tb[1]) ? 1 : 0) << 2);
	fh->caps.ht |= ((blobmsg_get_bool(tb[2]) ? 1 : 0) << 1);
}

#define VHT_CAP_MAX_MCS	8
void parse_dot11ac_mcs(uint8_t *supp_mcs, int mcs, int nss)
{
	int i;
	int octel;
	int shift;
	uint8_t mask[4] = {0xfc, 0xf3, 0xcf, 0x3f};
	int nss_cnt = min(nss, VHT_CAP_MAX_MCS);

	for (i = 0; i < nss_cnt; i++) {
		octel = (2 * i) / 8;
		shift = (2 * i) % 8;

		if (mcs == 9)
			supp_mcs[octel] &= (mask[i%4] | (0x02 << shift));
		else if (mcs == 8)
			supp_mcs[octel] &= (mask[i%4] | (0x01 << shift));
		else if (mcs == 7)
			supp_mcs[octel] &= (mask[i%4] | (0x00 << shift));
	}
}

static void parse_dot11ac(struct netif_fh *fh, struct blob_attr *arg)
{
	struct blob_attr *tb[10];
	int tx_mcs = 0, tx_nss = 0;
	int rx_mcs = 0, rx_nss = 0;
	uint8_t tx_supp_mcs[2] = {0xff, 0xff};
	uint8_t rx_supp_mcs[2] = {0xff, 0xff};
	static const struct blobmsg_policy ap_attr[10] = {
		[0] = { .name = "dot11ac_sgi80", .type = BLOBMSG_TYPE_BOOL },
		[1] = { .name = "dot11ac_sgi160", .type = BLOBMSG_TYPE_BOOL },
		[2] = { .name = "dot11ac_8080", .type = BLOBMSG_TYPE_BOOL },
		[3] = { .name = "dot11ac_160", .type = BLOBMSG_TYPE_BOOL },
		[4] = { .name = "dot11ac_su_beamformer", .type = BLOBMSG_TYPE_BOOL },
		[5] = { .name = "dot11ac_mu_beamformer", .type = BLOBMSG_TYPE_BOOL },
		[6] = { .name = "dot11ac_supp_max_rx_mcs", .type = BLOBMSG_TYPE_INT32 },
		[7] = { .name = "dot11ac_supp_max_rx_nss", .type = BLOBMSG_TYPE_INT32 },
		[8] = { .name = "dot11ac_supp_max_tx_mcs", .type = BLOBMSG_TYPE_INT32 },
		[9] = { .name = "dot11ac_supp_max_tx_nss", .type = BLOBMSG_TYPE_INT32 },
	};

	blobmsg_parse(ap_attr, 10, tb, blobmsg_data(arg), blobmsg_data_len(arg));

	rx_mcs = blobmsg_get_u32(tb[6]);
	rx_nss = blobmsg_get_u32(tb[7]);
	tx_mcs = blobmsg_get_u32(tb[8]);
	tx_nss = blobmsg_get_u32(tb[9]);
	fh->caps.vht[4] |= ((blobmsg_get_bool(tb[0]) ? 1 : 0) << 1);
	fh->caps.vht[4] |= ((blobmsg_get_bool(tb[1]) ? 1 : 0) << 0);
	fh->caps.vht[5] |= ((blobmsg_get_bool(tb[2]) ? 1 : 0) << 7);
	fh->caps.vht[5] |= ((blobmsg_get_bool(tb[3]) ? 1 : 0) << 6);
	fh->caps.vht[5] |= ((blobmsg_get_bool(tb[4]) ? 1 : 0) << 5);
	fh->caps.vht[5] |= ((blobmsg_get_bool(tb[5]) ? 1 : 0) << 4);

	fh->caps.vht[4] |= ((tx_nss - 1) & 0x07) << 5;
	fh->caps.vht[4] |= ((rx_nss - 1) & 0x07) << 2;

	parse_dot11ac_mcs(tx_supp_mcs, tx_mcs, tx_nss);
	memcpy(&fh->caps.vht[0], tx_supp_mcs, 2);
	parse_dot11ac_mcs(rx_supp_mcs, rx_mcs, rx_nss);
	memcpy(&fh->caps.vht[2], rx_supp_mcs, 2);
}

#define HE_CAP_MAX_MCS	8
static void parse_dot11ax_mcs(uint8_t *he, int *he_mcs_len, int mcs,
			int nss, int *max_nss)
{
	int i;
	int octel;
	int shift;
	int offset = 1 + *he_mcs_len;
	uint8_t supp_mcs[2] = {0xff, 0xff};
	uint8_t mask[4] = {0xfc, 0xf3, 0xcf, 0x3f};
	int nss_cnt = min(nss, HE_CAP_MAX_MCS);

	for (i = 0; i < nss_cnt; i++) {
		octel = (2 * i) / 8;
		shift = (2 * i) % 8;

		if (mcs == 11)
			supp_mcs[octel] &= (mask[i%4] | (0x02 << shift));
		else if (mcs == 9)
			supp_mcs[octel] &= (mask[i%4] | (0x01 << shift));
		else if (mcs == 7)
			supp_mcs[octel] &= (mask[i%4] | (0x00 << shift));
	}

	memcpy(he + offset, supp_mcs, 2);
	*he_mcs_len += 2;
	*max_nss = max(*max_nss, nss);
}

static void parse_dot11ax(struct netif_fh *fh, struct blob_attr *arg)
{
	int max_rx_nss = 0;
	int max_tx_nss = 0;
	int mcs_len = 0;
	int offset = 0;
	struct blob_attr *tb[29];
	struct wifi_wifi6_capabilities *wifi6_caps = &fh->caps.wifi6;
	static const struct blobmsg_policy ap_attr[ARRAY_SIZE(tb)] = {
		[0] = { .name = "dot11ax_5g_160_and_8080", .type = BLOBMSG_TYPE_BOOL },
		[1] = { .name = "dot11ax_5g_160", .type = BLOBMSG_TYPE_BOOL },
		[2] = { .name = "dot11ax_su_beamformer", .type = BLOBMSG_TYPE_BOOL },
		[3] = { .name = "dot11ax_mu_beamformer", .type = BLOBMSG_TYPE_BOOL },
		[4] = { .name = "dot11ax_ul_mumimo_full", .type = BLOBMSG_TYPE_BOOL },
		[5] = { .name = "dot11ax_ofdma_ra", .type = BLOBMSG_TYPE_BOOL },
		[6] = { .name = "dot11ax_supp_max_rx_mcs_20", .type = BLOBMSG_TYPE_INT32 },
		[7] = { .name = "dot11ax_supp_max_rx_nss_20", .type = BLOBMSG_TYPE_INT32 },
		[8] = { .name = "dot11ax_supp_max_tx_mcs_20", .type = BLOBMSG_TYPE_INT32 },
		[9] = { .name = "dot11ax_supp_max_tx_nss_20", .type = BLOBMSG_TYPE_INT32 },
		[10] = { .name = "dot11ax_supp_max_rx_mcs_40", .type = BLOBMSG_TYPE_INT32 },
		[11] = { .name = "dot11ax_supp_max_rx_nss_40", .type = BLOBMSG_TYPE_INT32 },
		[12] = { .name = "dot11ax_supp_max_tx_mcs_40", .type = BLOBMSG_TYPE_INT32 },
		[13] = { .name = "dot11ax_supp_max_tx_nss_40", .type = BLOBMSG_TYPE_INT32 },
		[14] = { .name = "dot11ax_supp_max_rx_mcs_80", .type = BLOBMSG_TYPE_INT32 },
		[15] = { .name = "dot11ax_supp_max_rx_nss_80", .type = BLOBMSG_TYPE_INT32 },
		[16] = { .name = "dot11ax_supp_max_tx_mcs_80", .type = BLOBMSG_TYPE_INT32 },
		[17] = { .name = "dot11ax_supp_max_tx_nss_80", .type = BLOBMSG_TYPE_INT32 },
		[18] = { .name = "dot11ax_supp_max_rx_mcs_160", .type = BLOBMSG_TYPE_INT32 },
		[19] = { .name = "dot11ax_supp_max_rx_nss_160", .type = BLOBMSG_TYPE_INT32 },
		[20] = { .name = "dot11ax_supp_max_tx_mcs_160", .type = BLOBMSG_TYPE_INT32 },
		[21] = { .name = "dot11ax_supp_max_tx_nss_160", .type = BLOBMSG_TYPE_INT32 },
		[22] = { .name = "dot11ax_supp_max_rx_mcs_8080", .type = BLOBMSG_TYPE_INT32 },
		[23] = { .name = "dot11ax_supp_max_rx_nss_8080", .type = BLOBMSG_TYPE_INT32 },
		[24] = { .name = "dot11ax_supp_max_tx_mcs_8080", .type = BLOBMSG_TYPE_INT32 },
		[25] = { .name = "dot11ax_supp_max_tx_nss_8080", .type = BLOBMSG_TYPE_INT32 },
		[26] = { .name = "dot11ax_su_beamformee", .type = BLOBMSG_TYPE_BOOL },
		[27] = { .name = "dot11ax_twt_requester", .type = BLOBMSG_TYPE_BOOL },
		[28] = { .name = "dot11ax_twt_responder", .type = BLOBMSG_TYPE_BOOL },
	};

	blobmsg_parse(ap_attr, ARRAY_SIZE(ap_attr), tb, blobmsg_data(arg), blobmsg_data_len(arg));

	if (tb[6])
		parse_dot11ax_mcs(fh->caps.he, &mcs_len,
				blobmsg_get_u32(tb[6]),
				blobmsg_get_u32(tb[7]), &max_rx_nss);
	else if (tb[10])
		parse_dot11ax_mcs(fh->caps.he, &mcs_len,
				blobmsg_get_u32(tb[10]),
				blobmsg_get_u32(tb[11]), &max_rx_nss);
	else if (tb[14])
		parse_dot11ax_mcs(fh->caps.he, &mcs_len,
				blobmsg_get_u32(tb[14]),
				blobmsg_get_u32(tb[15]), &max_rx_nss);

	if (tb[8])
		parse_dot11ax_mcs(fh->caps.he, &mcs_len,
				blobmsg_get_u32(tb[8]),
				blobmsg_get_u32(tb[9]), &max_tx_nss);
	else if (tb[12])
		parse_dot11ax_mcs(fh->caps.he, &mcs_len,
				blobmsg_get_u32(tb[12]),
				blobmsg_get_u32(tb[13]), &max_tx_nss);
	else if (tb[16])
		parse_dot11ax_mcs(fh->caps.he, &mcs_len,
				blobmsg_get_u32(tb[16]),
				blobmsg_get_u32(tb[17]), &max_tx_nss);

	if (tb[18])
		parse_dot11ax_mcs(fh->caps.he, &mcs_len,
				blobmsg_get_u32(tb[18]),
				blobmsg_get_u32(tb[19]), &max_rx_nss);

	if (tb[20])
		parse_dot11ax_mcs(fh->caps.he, &mcs_len,
				blobmsg_get_u32(tb[20]),
				blobmsg_get_u32(tb[21]), &max_tx_nss);

	if (tb[22])
		parse_dot11ax_mcs(fh->caps.he, &mcs_len,
				blobmsg_get_u32(tb[22]),
				blobmsg_get_u32(tb[23]), &max_rx_nss);

	if (tb[24])
		parse_dot11ax_mcs(fh->caps.he, &mcs_len,
				blobmsg_get_u32(tb[24]),
				blobmsg_get_u32(tb[25]), &max_tx_nss);

	fh->caps.he[0] = mcs_len;
	offset = 1 + mcs_len;
	fh->caps.he[offset] |= (((max_tx_nss - 1) & 0x07) << 5);
	fh->caps.he[offset] |= (((max_rx_nss - 1) & 0x07) << 2);
	fh->caps.he[offset] |= ((blobmsg_get_bool(tb[0]) ? 1 : 0) << 1);
	fh->caps.he[offset] |= ((blobmsg_get_bool(tb[1]) ? 1 : 0) << 0);

	offset++;
	fh->caps.he[offset] |= ((blobmsg_get_bool(tb[2]) ? 1 : 0) << 7);
	fh->caps.he[offset] |= ((blobmsg_get_bool(tb[3]) ? 1 : 0) << 6);
	fh->caps.he[offset] |= ((blobmsg_get_bool(tb[4]) ? 1 : 0) << 5);
	fh->caps.he[offset] |= ((blobmsg_get_bool(tb[5]) ? 1 : 0) << 4);
	fh->caps.he[offset] |= ((blobmsg_get_bool(tb[5]) ? 1 : 0) << 3);
	fh->caps.he[offset] |= ((blobmsg_get_bool(tb[5]) ? 1 : 0) << 2);
	fh->caps.he[offset] |= ((blobmsg_get_bool(tb[5]) ? 1 : 0) << 1);

	/* Populate Wi-Fi 6 caps structure */
	/* HE 160 supported when HE160 TX & RX supported */
	wifi6_caps->he160 = tb[19] && blobmsg_get_u32(tb[19]) &&
			    tb[21] && blobmsg_get_u32(tb[21]);

	wifi6_caps->he8080 = tb[23] && blobmsg_get_u32(tb[23]) &&
			     tb[25] && blobmsg_get_u32(tb[25]);

	/* 4, 8 or 12 bytes of supported MCS & NSS */
	wifi6_caps->mcs_nss_len = mcs_len;
	memcpy(wifi6_caps->mcs_nss_12, &fh->caps.he[1], mcs_len);

	wifi6_caps->su_beamformer = tb[2] && blobmsg_get_bool(tb[2]);
	wifi6_caps->su_beamformee = tb[26] && blobmsg_get_bool(tb[26]);
	wifi6_caps->mu_beamformer = tb[3] && blobmsg_get_bool(tb[3]);
	wifi6_caps->beamformee_le80 = false; // todo: ?
	wifi6_caps->beamformee_gt80 = false; // todo: ?
	wifi6_caps->ul_mumimo = tb[4] && blobmsg_get_bool(tb[4]);
	wifi6_caps->ul_ofdma = tb[5] && blobmsg_get_bool(tb[5]);
	wifi6_caps->dl_ofdma = tb[5] && blobmsg_get_bool(tb[5]);
	wifi6_caps->max_dl_mumimo = 0;       // todo: ?
	wifi6_caps->max_ul_mumimo = 0;       // todo: ?
	wifi6_caps->max_dl_ofdma = 0;        // todo: ?
	wifi6_caps->max_ul_ofdma = 0;        // todo: ?
	wifi6_caps->rts = false;             // todo: ?
	wifi6_caps->mu_rts = false;          // todo: ?
	wifi6_caps->multi_bssid = false;     // todo: ?
	wifi6_caps->mu_edca = false;         // todo: ?
	wifi6_caps->twt_requester = tb[27] && blobmsg_get_bool(tb[27]);
	wifi6_caps->twt_responder = tb[28] && blobmsg_get_bool(tb[28]);
	wifi6_caps->spatial_reuse = false;   // todo: ?
	wifi6_caps->anticipated_ch_usage = false; // todo: ?
}

static void parse_bk(struct ubus_request *req, int type,
		struct blob_attr *msg)
{
	struct netif_bk *bk = (struct netif_bk *)req->priv;
	struct agent *a = bk->agent;
	char bssid_str[18] = {0}, macaddr[18] = {0};
	uint8_t bssid[6] = {0};
	struct blob_attr *tb[2];
	static const struct blobmsg_policy ap_attr[2] = {
		[0] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING }
	};

	blobmsg_parse(ap_attr, 2, tb, blob_data(msg), blob_len(msg));

	if (!tb[0])
		return;

	strncpy(macaddr, blobmsg_data(tb[0]), 17);
	hwaddr_aton(macaddr, bk->bssid);

	if (tb[1]) {
		strncpy(bssid_str, blobmsg_data(tb[1]), 17);
		hwaddr_aton(bssid_str, bssid);
	}

	if (!hwaddr_is_zero(bssid) && memcmp(bk->bssid, bssid, 6)) {
		char fmt[64] = {0};

		snprintf(fmt, sizeof(fmt),
			 "bsta_disable_lower_priority %s", bk->name);

		agent_exec_platform_scripts(fmt);

		/* if connected and previously unconnected */
		if (!bk->connected) {
			wifi_bsta_connect(a, bk, bssid);
			timer_set(&a->disable_unconnected_bstas_scheduler, 0);
			timer_del(&a->bh_lost_timer);
			timer_del(&a->bh_reconf_timer);
		}
	} else {
		bk->connected = false;
		/* if disconnected - check if it is a part of the bridge */
		if (if_isbridge_interface(bk->name)) {
			wifi_mod_bridge(a, bk->name, "remove");

			if (bk->cfg->enabled) {
				char ul_ifname[16] = {0};
				agent_handle_bh_lost(a);

				if (agent_get_backhaul_ifname(a, ul_ifname)) {
					if (!strncmp(ul_ifname, bk->name, IFNAMSIZ))
						agent_exec_platform_scripts("unset_uplink wifi");
				}
			}
		}
	}

}

static void parse_esp_params(struct ubus_request *req, int type,
		struct blob_attr *msg)
{
	struct wifi_bss_element *bss = (struct wifi_bss_element *)req->priv;
	int rem;
	struct blob_attr *cur;
	struct blob_attr *data[1];
	static const struct blobmsg_policy beacon_attr[1] = {
		[0] = { .name = "beacon-ies", .type = BLOBMSG_TYPE_ARRAY },
	};

	blobmsg_parse(beacon_attr, 1, data, blob_data(msg), blob_len(msg));

	if (!data[0])
		return;

	blobmsg_for_each_attr(cur, data[0], rem) {
		char *iestr = strdup(blobmsg_get_string(cur));

		if (!iestr)
			return;

		/*
		 * esp string having this format: "ff xx 0b"
		 * where xx: 4 or 7 or 10 or 13
		 */
		if ((!strncmp(iestr, "ff", 2)) &&
			(!strncmp(iestr+4, "0b", 2))) {
			uint8_t *ie, *ie1;
			int i, slen, esp_len;
			int ac;		/* Access Category */

			slen = strlen(iestr);
			ie = calloc(slen/2, sizeof(uint8_t));
			if (!ie) {
				free(iestr);
				return;
			}

			strtob(iestr, slen, ie);
			esp_len = ie[1];
			/*
			 * esp data payload start after 3 bytes;
			 * bypass 3 bytes, (1btye: ff, 1 byte: len, 1byte:0b)
			 */
			ie1 = ie + 3;
			for (i = 1; i < esp_len; i += 3) {
				ac = (*ie1) & 0x03;
				switch (ac) {
				case BK:
					bss->is_ac_bk = 1;
					memcpy(bss->est_wmm_bk, ie1, 3);
					break;
				case BE:
					bss->is_ac_be = 1;
					memcpy(bss->est_wmm_be, ie1, 3);
					break;
				case VI:
					bss->is_ac_vi = 1;
					memcpy(bss->est_wmm_vi, ie1, 3);
					break;
				case VO:
					bss->is_ac_vo = 1;
					memcpy(bss->est_wmm_vo, ie1, 3);
					break;
				}
				ie1 += 3;
			}

			free(ie);
			free(iestr);
			return;
		}

		free(iestr);
	}
}

static void parse_ap_stats(struct ubus_request *req, int type,
		struct blob_attr *msg)
{
	int bss_index;
	struct wifi_radio_element *radio;
	struct wifi_bss_element *bss;
	struct wifi_bss_element *bsslist;
	struct netif_fh *fh = (struct netif_fh *)req->priv;
	struct blob_attr *tb[6];
	static const struct blobmsg_policy ap_stats_attr[6] = {
		[0] = { .name = "tx_unicast_packets", .type = BLOBMSG_TYPE_INT64},
		[1] = { .name = "rx_unicast_packets", .type = BLOBMSG_TYPE_INT64},
		[2] = { .name = "tx_multicast_packets", .type = BLOBMSG_TYPE_INT64},
		[3] = { .name = "rx_multicast_packets", .type = BLOBMSG_TYPE_INT64},
		[4] = { .name = "tx_broadcast_packets", .type = BLOBMSG_TYPE_INT64},
		[5] = { .name = "rx_broadcast_packets", .type = BLOBMSG_TYPE_INT64},
	};


	radio = wifi_ifname_to_radio_element(fh->agent, fh->name);
	if (!radio)
		return;

	bsslist = (struct wifi_bss_element *)realloc(radio->bsslist,
			(radio->num_bss + 1) * sizeof(struct wifi_bss_element));

	if (bsslist) {
		radio->bsslist = bsslist;
		radio->num_bss++;
	} else
		return;

	bss_index = radio->num_bss - 1;
	bss = radio->bsslist + bss_index;
	memset(bss, 0, sizeof(struct wifi_bss_element));
	memcpy(bss->bssid, fh->bssid, 6);
	strncpy(bss->ssid, fh->ssid, sizeof(bss->ssid) - 1);
	bss->enabled = fh->enabled;

	blobmsg_parse(ap_stats_attr, 6, tb, blob_data(msg), blob_len(msg));

	if (tb[0])
		bss->tx_ucast_bytes = blobmsg_get_u64(tb[0]);

	if (tb[1])
		bss->rx_ucast_bytes = blobmsg_get_u64(tb[1]);

	if (tb[2])
		bss->tx_mcast_bytes = blobmsg_get_u64(tb[2]);

	if (tb[3])
		bss->rx_mcast_bytes = blobmsg_get_u64(tb[3]);

	if (tb[4])
		bss->tx_bcast_bytes = blobmsg_get_u64(tb[4]);

	if (tb[5])
		bss->rx_bcast_bytes = blobmsg_get_u64(tb[5]);

	/* Fill ESP params for bss */
	ubus_call_object(fh->agent, fh->wifi, "dump_beacon",
			parse_esp_params, bss);
}

static void parse_ap(struct ubus_request *req, int type,
		struct blob_attr *msg)
{
	struct netif_fh *fh = (struct netif_fh *)req->priv;
	char bssid[18] = { 0 }, ifname[16] = { 0 };
	struct blob_attr *tb[10];
	static const struct blobmsg_policy ap_attr[10] = {
		[0] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING },
		[2] = { .name = "capabilities", .type = BLOBMSG_TYPE_TABLE },
		[3] = { .name = "channel", .type = BLOBMSG_TYPE_INT32 },
		[4] = { .name = "ssid", .type = BLOBMSG_TYPE_STRING },
		[5] = { .name = "standard", .type = BLOBMSG_TYPE_STRING },
		[6] = { .name = "bandwidth", .type = BLOBMSG_TYPE_INT32 },
		[7] = { .name = "status", .type = BLOBMSG_TYPE_STRING },
		[8] = { .name = "num_stations", .type = BLOBMSG_TYPE_INT32 },
		[9] = { .name = "enabled", .type = BLOBMSG_TYPE_BOOL },
	};

	blobmsg_parse(ap_attr, 10, tb, blob_data(msg), blob_len(msg));

	if (!tb[0] || !tb[1])
		return;

	strncpy(ifname, blobmsg_data(tb[0]), 15);
	strncpy(fh->name, blobmsg_data(tb[0]), 15);

	strncpy(bssid, blobmsg_data(tb[1]), 17);
	if (!hwaddr_aton(bssid, fh->bssid))
		return;

	if (tb[2]) { /* capabilities */
		struct blob_attr *data[4];
		static const struct blobmsg_policy cap_attr[4] = {
			[0] = { .name = "dot11n", .type = BLOBMSG_TYPE_TABLE },
			[1] = { .name = "dot11ac", .type = BLOBMSG_TYPE_TABLE },
			[2] = { .name = "wmm", .type = BLOBMSG_TYPE_BOOL },
			[3] = { .name = "dot11ax", .type = BLOBMSG_TYPE_TABLE }
		};

		blobmsg_parse(cap_attr, 4, data, blobmsg_data(tb[2]),
				blobmsg_data_len(tb[2]));

		if (data[0])
			parse_dot11n(fh, data[0]);
		if (data[1])
			parse_dot11ac(fh, data[1]);
		if (data[2])
			fh->caps.wmm = blobmsg_get_bool(data[2]);
		if (data[3])
			parse_dot11ax(fh, data[3]);
	}

	if (tb[3])
		fh->channel = blobmsg_get_u32(tb[3]);

	if (tb[4])
		strncpy(fh->ssid, blobmsg_data(tb[4]), sizeof(fh->ssid) - 1);

	if (tb[5])
		strncpy(fh->standard, blobmsg_data(tb[5]), sizeof(fh->standard) - 1);

	if (tb[6])
		fh->bandwidth = blobmsg_get_u32(tb[6]);

	if (tb[9])
		fh->enabled = blobmsg_get_bool(tb[9]);

	if (tb[8])
		fh->nbr_sta = blobmsg_get_u32(tb[8]);


	if (!fh->enabled && may_enable_fhs(fh->agent))
		/* Enable fronthauls */
		timer_set(&fh->agent->enable_fhs_scheduler,
				  (IFACE_TIMEOUT + 1) * 1000);

}

static int agent_radio_update_scanlist(struct agent *a,
		struct wifi_radio_element *re, struct wifi_bss *bsss, int bss_num)
{
	int i, idx;
	struct wifi_scanres_channel_element *scanres_el;

	for (i = 0; i < bss_num; i++) {

		scanres_el = wifi_get_scanres_ch_element(re, bsss[i].channel);
		if (!scanres_el)
			continue;

		// no neighbors, allocate first
		if (!scanres_el->num_neighbors) {
			scanres_el->nbrlist = calloc(1, sizeof(*(scanres_el->nbrlist)));
			if (!scanres_el->nbrlist)
				continue;

			scanres_el->num_neighbors = 1;
		}
		// at least one neighbor, allocate one more
		else {
			struct wifi_scanres_neighbor_element *nbr;
			int size;

			size = (scanres_el->num_neighbors + 1) * sizeof(*nbr);
			nbr = (struct wifi_scanres_neighbor_element *)realloc(
						scanres_el->nbrlist, size);

			if (!nbr)
				continue;

			scanres_el->num_neighbors++;
			scanres_el->nbrlist = nbr;
		}

		idx = scanres_el->num_neighbors - 1; // fill index

		/* Fill in the neighbour data */
		memcpy(scanres_el->nbrlist[idx].bssid, bsss[i].bssid, 6);

		strncpy(scanres_el->nbrlist[idx].ssid, (char *) bsss[i].ssid,
				sizeof(scanres_el->nbrlist->ssid) - 1);

		scanres_el->nbrlist[idx].rssi = bsss[i].rssi;

		switch (bsss[i].curr_bw) {
		case BW20:
			scanres_el->nbrlist[idx].bw = 20;
			break;
		case BW40:
			scanres_el->nbrlist[idx].bw = 40;
			break;
		case BW80:
			scanres_el->nbrlist[idx].bw = 80;
			break;
		case BW160:
			scanres_el->nbrlist[idx].bw = 160;
			break;
		case BW8080:
			scanres_el->nbrlist[idx].bw = 8080;
			break;
		default:
			scanres_el->nbrlist[idx].bw = 20;
			break;
		}

		scanres_el->nbrlist[idx].utilization = bsss[i].load.utilization;
		scanres_el->nbrlist[idx].num_stations = bsss[i].load.sta_count;
	}

	return 0;
}

int agent_radio_scanresults(struct agent *a, struct wifi_radio_element *re)
{
	struct wifi_bss bss[128];
	int bss_num = ARRAY_SIZE(bss);
	int ret;

	if (!re || !re->name || !strlen(re->name))
		return -1;

	trace("[%s] radio scanresults\n", re->name);

	/* Get scan results from the driver */
	ret = wifi_get_scan_results(re->name, bss, &bss_num);

	if (ret) {
		dbg("[%s] failed to get scanresults\n", re->name);
		return -1;
	}

	/* Update scan cache */
	ret = wifi_scanresults_add(&re->scanresults, &re->opclass, bss, bss_num);
	if (ret) {
		dbg("[%s] failed to update scan cache\n", re->name);
		return -1;
	}

	/* TODO: update scanlist using fresh results from the cache */

	/* Empty scanlist & add most recent results for reporting */
	free_scanresults_neighbors(re);
	ret = agent_radio_update_scanlist(a, re, bss, bss_num);

	return ret;
}

void agent_init_interfaces_post_actions(struct agent *a)
{
	trace("%s: --->\n", __func__);

	struct netif_fh *p = NULL;
	uint8_t sta[128 * 6] = {};
	int num_sta = 128;
	int i;

	list_for_each_entry(p, &a->fhlist, list) {
		if (wifi_get_assoclist(p->name, sta, &num_sta))
			continue;

		for (i = 0; i < num_sta; i++)
			wifi_add_sta(a, p->name, &sta[i * 6]);
	}

	/* request scan results from the driver, etc */
	for (i = 0; i < WIFI_DEVICE_MAX_NUM; i++) {
		struct wifi_radio_element *re = &a->radios[i];

		if (re && re->name[0] != '\0' && strlen(re->name)) {
			/* Make sure scanlist is initialized */
			if (!re->scanlist)
				init_scanlist(a, re->name);
			/* Get & store scan results */
			agent_radio_scanresults(a, re);
			/* Finally update neighbor data */
			update_neighbors_from_scancache(a, &re->scanresults);
		}
	}
}

/* Fetch Device Info
 * serail_number, software_version, environment_variable
 * using 'router.system info' method
 */
int agent_get_router_system_info(struct agent *a)
{
	int ret;
	uint32_t rsys_obj = 0;

	ret = ubus_lookup_id(a->ubus_ctx, "router.system", &rsys_obj);
	if (ret)
		return -1;

	ubus_call_object(a, rsys_obj, "info", router_system_info_cb, a);
	return 0;
}

/* Initialize netif_fh/bk structs from ubus wifi objects */
int agent_init_interfaces(struct agent *a)
{
	struct agent_config *cfg = &a->cfg;
	struct netif_fhcfg *f;
	struct netif_bkcfg *b;
	wifi_object_t wifi_obj;
	uint32_t ieee1905_obj = 0;
	int ret, retry = 0;

	ret = ubus_lookup_id(a->ubus_ctx, "ieee1905", &ieee1905_obj);
	if (ret)
		return -1;

	ubus_call_object(a, ieee1905_obj, "info", parse_i1905_info, a);

	wifi_obj = ubus_get_object(a->ubus_ctx, "wifi");
	while (wifi_obj == WIFI_OBJECT_INVALID && retry < 5) {
		err("|%s:%d| Failed to get wifi object (%u) retry in 0.5s, try num:%d\n", __func__, __LINE__, wifi_obj, retry);
		usleep(500 * 1000); /* 0.5s sleep */
		wifi_obj = ubus_get_object(a->ubus_ctx, "wifi");
		retry++;
	}

	if (wifi_obj == WIFI_OBJECT_INVALID) {
		warn("|%s:%d| Object 'wifi' not present!\n", __func__, __LINE__);
		timer_set(&a->init_ifaces_scheduler, 30 * 1000);
		return -1;
	}

	a->wifi = wifi_obj;
	enumerate_wifi_objects(a);

	a->connected = false;

	list_for_each_entry(f, &cfg->fhlist, list) {
		wifi_object_t r_wobj = WIFI_OBJECT_INVALID;
		wifi_object_t wobj = WIFI_OBJECT_INVALID;
		//const char *r_fmt = "wifi.radio.%s";
		//const char *fmt = "wifi.ap.%s";
		const char *radio_name = NULL;
		struct netif_fh *fn = NULL;
		char r_objname[32] = {0};
		char objname[32] = {0};
		struct subscribe_fr {
			uint8_t type;
			uint8_t stype;
		} subfr[] = {{0, 0}, {0, 2}, {0, 13}};
		int num_subfr = ARRAY_SIZE(subfr);
		int k;

		radio_name = wifi_ifname_to_radio(a, f->name);
		if (!radio_name)
			continue;

		fn = netif_alloc_fh(f->name);
		if (fn) {
			/* subscribe following frames
			 * WIFI_FRAME_ASSOC_REQ,
			 * WIFI_FRAME_REASSOC_REQ,
			 * WIFI_FRAME_ACTION
			 */
			// TODO: call unsubscribe_frame method on cleanup.

			fn->wifi = wobj;
			fn->radio = r_wobj;
			fn->cfg = f;
			fn->agent = a;
			strncpy(fn->radio_name, radio_name, IFNAMSIZ-1);

			list_add(&fn->list, &a->fhlist);
		}

		snprintf(r_objname, 31, "wifi.radio.%s", radio_name);
		fn->radio = ubus_get_object(a->ubus_ctx, r_objname);
		if (fn->radio == WIFI_OBJECT_INVALID) {
			dbg("%s not present! skipping '%s' from config\n",
						r_objname, f->name);
			continue;
		}

		snprintf(objname, 31, "wifi.ap.%s", f->name);
		fn->wifi = ubus_get_object(a->ubus_ctx, objname);
		if (fn->wifi == WIFI_OBJECT_INVALID) {
			dbg("%s not present! skipping '%s' from config\n",
							objname, f->name);
			continue;
		}

		ubus_call_object(a, fn->wifi, "status", parse_ap, fn);

		for (k = 0; k < num_subfr; k++)
			wifi_subscribe_frame(f->name, subfr[k].type, subfr[k].stype);

		ubus_call_object(a, fn->wifi, "stats", parse_ap_stats, fn);
	}

	list_for_each_entry(b, &cfg->bklist, list) {
		wifi_object_t r_wobj = WIFI_OBJECT_INVALID;
		wifi_object_t wobj = WIFI_OBJECT_INVALID;
		//const char *r_fmt = "wifi.radio.%s";
		//const char *bk_fmt = "wifi.backhaul.%s";
		const char *radio_name = NULL;
		struct netif_bk *bn = NULL;
		char r_objname[32] = {0};
		char objname[32] = {0};


		bn = find_bkhaul_by_ifname(a, b->name);
		if (!bn) {
			bn = netif_alloc_bk(b->name);
			if (bn) {
				list_add(&bn->list, &a->bklist);
				bn->cfg = b;
				bn->agent = a;
			}
		} else {
			bn->cfg = b;
			bn->agent = a;
			memset(bn->bssid, 0, 6);
		}

		radio_name = wifi_ifname_to_radio(a, b->name);
		if (!radio_name)
			continue;

		snprintf(r_objname, 31, "wifi.radio.%s", radio_name);
		r_wobj = ubus_get_object(a->ubus_ctx, r_objname);
		if (r_wobj == WIFI_OBJECT_INVALID) {
			dbg("%s not present! skipping '%s' from config\n",
						r_objname, f->name);
			continue;
		}

		snprintf(objname, 31, "wifi.backhaul.%s", b->name);
		wobj = ubus_get_object(a->ubus_ctx, objname);
		if (wobj == WIFI_OBJECT_INVALID) {
			dbg("%s not present! skipping '%s' from config\n",
							objname, b->name);
			continue;
		}

		if (bn) {
			bn->wifi = wobj;
			bn->radio = r_wobj;

			ubus_call_object(a, wobj, "status", parse_bk, bn);
			if (bn->connected)
				a->connected = true;
		}

		if (b->onboarded) {
			struct wifi_radio_element *re;

			re = wifi_ifname_to_radio_element(a, b->name);
			if (!re)
				continue;

			re->onboarded = 1;
			trace("radio (%s) has been onboarded\n", re->name);
		}

	}

	if (!agent_has_active_backhaul(a) && timer_remaining_ms(&a->bh_lost_timer) == -1) {
		if (a->cfg.ap_follow_sta_dfs) {
			struct netif_bk *sta;

			list_for_each_entry(sta, &a->bklist, list) {
				dbg("[%s] connect %s bsta\n", sta->name, sta->cac_time ? "disable" : "enable");
				if (sta->cac_time)
					config_disable_bsta(sta->cfg);
				else
					config_enable_bsta(sta->cfg);
			}

			agent_exec_platform_scripts("bsta_scan_on_enabled");
		} else {
			agent_exec_platform_scripts("bsta_enable_all");
		}
	} else {
		timer_set(&a->upgrade_backhaul_scheduler, 30 * 1000);
	}

	agent_config_reload(a);

	agent_init_interfaces_post_actions(a);
	a->reconfig_reason |= AGENT_RECONFIG_REASON_VLAN_SETUP;
	timer_set(&a->reload_scheduler, 5 * 1000);
	return 0;
}

static void agent_enable_fhs_cb(atimer_t *t)
{
	trace("%s: --->\n", __func__);

	struct agent *a = container_of(t, struct agent, enable_fhs_scheduler);

	agent_enable_fronthauls(a);
}

static void agent_boot_scan_cb(atimer_t *t)
{
	trace("%s: --->\n", __func__);

	struct agent *a = container_of(t, struct agent, boot_scan_scheduler);
	bool radio_missing = false;
	int i;

	if (!a)
		return; /* err */

	dbg("|%s:%d| boot scan %s", __func__, __LINE__,
	    a->cfg.scan_on_boot_only ? "enabled" : "disabled");

	if (!a->cfg.scan_on_boot_only)
		/* On boot scan disabled */
		return;

	for (i = 0; i < a->num_radios; i++) {
		struct wifi_radio_element *re = &a->radios[i];

		if (!re || !re->enabled) {
			radio_missing = true;
			continue;
		}

		if (re->scan_state != SCAN_DONE)
			wifi_radio_scan_req_all(a, re->name);
	}

	if (a->boot_scan_tries++ < BOOT_UP_SCAN_MAX_TRY
			&& radio_missing)
		/* one or more radio not available yet, re-try again later */
		timer_set(&a->boot_scan_scheduler, BOOT_UP_SCAN_ITV * 1000);
}

static void agent_radio_stats_cb(atimer_t *t)
{
	trace("%s: --->\n", __func__);

	int i;
	struct agent *a = container_of(t, struct agent, radio_stats_scheduler);

	for (i = 0; i < a->num_radios; i++) {
		char r_objname[32] = {0};
		wifi_object_t r_wobj = WIFI_OBJECT_INVALID;
		struct wifi_radio_element *r = &a->radios[i];

		/* mark outdated scanresults */
		wifi_scanresults_mark_expired(&r->scanresults);

		/* get radio status and update stats */
		snprintf(r_objname, 31, "wifi.radio.%s", r->name);
		r_wobj = ubus_get_object(a->ubus_ctx, r_objname);

		if (r_wobj == WIFI_OBJECT_INVALID)
			continue;

		ubus_call_object(a, r_wobj, "status", parse_radio, r);
	}

	timer_set(&a->radio_stats_scheduler, RADIO_STATS_TIMER);
}

static void agent_init_ifaces_cb(atimer_t *t)
{
	struct agent *a = container_of(t, struct agent, init_ifaces_scheduler);

	if (!a)
		return;

	agent_init_interfaces(a);
}


#define RELOAD_TIMEOUT 10

static void agent_reload_cb(atimer_t *t)
{
	trace("%s: --->\n", __func__);
	struct agent *a = container_of(t, struct agent, reload_scheduler);

	if (a->cfg.eth_onboards_wifi_bhs) {
		/* re-sync any credentials passed with AP-Autoconfig */
		agent_exec_platform_scripts("bsta_to_wireless");
	}

	agent_exec_platform_scripts("sync_credentials");

	dbg("|%s:%d| reconfig_reason = %d\n", __func__, __LINE__, a->reconfig_reason);

	if (!!(a->reconfig_reason & AGENT_RECONFIG_REASON_VLAN_TEARDOWN)) {
		dbg("|%s:%d| ts teardown\n", __func__, __LINE__);
		agent_clear_traffic_sep(a);
	}

	if (!!(a->reconfig_reason & AGENT_RECONFIG_REASON_VLAN_SETUP)) {
		dbg("|%s:%d| ts setup\n", __func__, __LINE__);
		agent_apply_traffic_separation(a);
	}

	if (!!(a->reconfig_reason & AGENT_RECONFIG_REASON_AP_AUTOCONF)) {
		dbg("|%s:%d| apconf reload wireless\n", __func__, __LINE__);
		uci_reload_services("wireless");
	}

	a->reconfig_reason = 0;
}

/* send the steering compled message this function also resets the value of
 * steering opportunity
 */
static void agent_steering_opp_timeout(atimer_t *t)
{
	trace("agent: %s: --->\n", __func__);
	struct agent *a = container_of(t, struct agent, sta_steer_req_timer);
	char ifname[16] = { 0 };
	uint8_t origin[6] = { 0 };


	strncpy(ifname, a->cfg.al_bridge, sizeof(ifname));
	memcpy(origin, a->cntlr_almac, 6);
	send_sta_steer_complete((void *)a, origin, ifname);
}

#define max_val(a,b) \
	({ typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a > _b ? _a : _b; })

static void agent_start_controller_conditionally(struct agent *a)
{
	uint8_t max_retries = a->cntlr_select.retry_int;
	uint16_t probe_int = a->cntlr_select.probe_int;
	int try = a->cntlr_miss_count + 1;
	int max_misstime = max_val((max_retries * probe_int),
				HEARTBEAT_AUTOCFG_INTERVAL + 5);

	trace("|%s:%d| Entry max_misstime %d\n", __func__, __LINE__, max_misstime);

	if (!timestamp_expired(&a->observed_time, (try * probe_int) * 1000)
			|| is_local_cntlr_running()) {
		dbg("|%s:%d| Active controller available\n",
			__func__, __LINE__);
		a->cntlr_miss_count = 0;
		a->active_cntlr = true;
		return;
	}

	if (!timestamp_expired(&a->observed_time, max_misstime * 1000)) {
		a->cntlr_miss_count++;
		return;
	}

	a->active_cntlr = false;

	memset(a->cntlr_almac, 0, sizeof(a->cntlr_almac));

	dbg("|%s:%d| No controller observed for over %d seconds\n",
	    __func__, __LINE__, max_misstime);

	if (a->cntlr_select.autostart || a->cntlr_select.local) {
		if (is_local_cntlr_available()) {
			time_t now;
			/* Schedule start of local Controller after
			 * random time chosen from a 10s time window
			 * to reduce chance of multiple MAP-Agents
			 * starting own controller at the same time.
			 */
			srand(time(&now));
			agent_schedule_cntlr_start(a, rand() % 10);
		} else {
			warn("Local cntlr unavailable: skip start\n");
		}
	} else if (a->cntlr_miss_count) {
		/* Report controller absence to the user first time
		 * it goes missing
		 */
		wifiagent_log_cntlrinfo(a);
	}

	a->cntlr_miss_count = 0;
}

static void agent_check_bsta_connections(struct agent *a)
{
	struct netif_bk *bk;
	bool connected = false;

	list_for_each_entry(bk, &a->bklist, list)
		ubus_call_object(a, bk->wifi, "status", parse_bk, bk);

	/* reloading is costly - only do it once after all parsing is done */
	agent_config_reload(a);

	list_for_each_entry(bk, &a->bklist, list) {
		agent_manage_bsta(a, bk);
		if (bk->connected)
			connected = true;
	}

	a->connected = connected;
}

/* TODO: is it possible to pass private 'reason'? i.e. switch case (reason) */
static void agent_dispatch_autoconfig(atimer_t *t)
{
	struct agent *a = container_of(t, struct agent, autocfg_dispatcher);
	int i;

	trace("|%s:%d| Triggering AP-Autoconfig Search\n", __func__, __LINE__);

	agent_start_controller_conditionally(a);
	a->autocfg_interval = a->cntlr_select.probe_int;

	if (!a->active_cntlr) {
		/* Cntlr missing - fall back to active autoconfig probing */
		trace("|%s:%d| No active Controller present!\n", __func__, __LINE__);
		for (i = 0; i < a->num_radios; i++)
			a->radios[i].state = AUTOCFG_ACTIVE;
	}

	agent_check_bsta_connections(a);

	for (i = 0; i < a->num_radios; i++) {
		struct cmdu_buff *cmdu;
		struct wifi_radio_element *radio = &a->radios[i];
		//int mid;

		cmdu = agent_gen_ap_autoconfig_search(a, radio, 0x02);
		if (!cmdu)
			continue;
		trace("|%s:%d| Sending Autoconfig Search for radio %s(%s)\n",
				__func__, __LINE__, radio->name,
				(radio->band == BAND_2 ? "2.4GHz" : "5GHz"));
		radio->mid = agent_send_cmdu(a, cmdu);

		cmdu_free(cmdu);
	}

	dbg("|%s:%d| Scheduling next autoconfig search in %u seconds\n",
				__func__, __LINE__, a->autocfg_interval);
	timer_set(&a->autocfg_dispatcher, a->autocfg_interval * 1000);
}

/* TODO:re-visit */
void clear_stalist(struct netif_fh *p)
{
	struct sta *s, *tmp;

	list_for_each_entry_safe(s, tmp, &p->stalist, list) {
		dbg("Delete STA " MACFMT "\n", MAC2STR(s->macaddr));
		timer_del(&s->sta_finalize_timer);
		timer_del(&s->sta_steer_timer);
		timer_del(&s->sta_bcn_req_timer);
		timer_del(&s->sta_timer);
		list_del(&s->list);
		list_flush(&s->pref_nbrlist, struct pref_neighbor, list);
		list_flush(&s->sta_nbrlist, struct sta_neighbor, list);
		if (s->assoc_frame) {
			free(s->assoc_frame->frame);
			free(s->assoc_frame);
		}
		free(s);
	}
}

void clear_nbrlist(struct netif_fh *p)
{
	struct neighbor *n, *tmp;

	list_for_each_entry_safe(n, tmp, &p->nbrlist, list) {
		dbg("Delete NBR " MACFMT "\n", MAC2STR(n->nbr.bssid));
		list_del(&n->list);
		free(n);
	}
}

void clear_restrict_stalist(struct netif_fh *p)
{
	struct neighbor *n, *tmp;

	list_for_each_entry_safe(n, tmp, &p->restrict_stalist, list) {
		list_del(&n->list);
		free(n);
	}
}

static void netif_free(struct agent *a, struct netif_fh *n)
{
	/* clear stalist */
	clear_stalist(n);

	/* clear nbrlist */
	clear_nbrlist(n);

	/* clear restricted sta list */
	clear_restrict_stalist(n);

	/* cancel timers */
	timer_del(&n->rdr_timer);
	timer_del(&n->nbr_timer);
	timer_del(&n->bss_timer);
	timer_del(&n->util_threshold_timer);
	timer_del(&n->una_sta_meas_timer);

	list_del(&n->list);

	free(n);
}

void clear_fhlist(struct agent *a)
{
	struct netif_fh *p, *tmp;

	list_for_each_entry_safe(p, tmp, &a->fhlist, list) {
		netif_free(a, p);
	}
}

void clear_bklist(struct agent *a)
{
	struct netif_bk *p, *tmp;

	list_for_each_entry_safe(p, tmp,  &a->bklist, list) {
		list_del(&p->list);
		free(p);
	}
}


int agent_map_sub_cb(void *bus, void *priv, void *data)
{
	struct blob_attr *msg = (struct blob_attr *)data;
	char *str;


	str = blobmsg_format_json(msg, true);
	trace("Received notification '%s'\n", str);
	free(str);

	ieee1905_cmdu_event_handler(priv, msg);

	return 0;
}

int agent_map_del_cb(void *bus, void *priv, void *data)
{
	struct agent *a = (struct agent *)priv;
	uint32_t *obj = (uint32_t *)data;

	a->subscribed = false;
	fprintf(stdout, "Object 0x%x no longer present\n", *obj);

	return 0;
}

static int agent_subscribe_for_cmdus(struct agent *a)
{
	mapmodule_cmdu_mask_t cmdu_mask = {0};
	uint32_t map_id;
	int ret;


	map_prepare_cmdu_mask(cmdu_mask,
			CMDU_TYPE_TOPOLOGY_DISCOVERY,
			CMDU_TYPE_TOPOLOGY_NOTIFICATION,
			CMDU_TYPE_TOPOLOGY_QUERY,
			CMDU_TYPE_TOPOLOGY_RESPONSE,
			CMDU_TYPE_VENDOR_SPECIFIC,
			CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH,
			CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE,
			CMDU_TYPE_AP_AUTOCONFIGURATION_WSC,
			CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW,
			CMDU_1905_ACK,
			CMDU_BEACON_METRICS_QUERY,
			CMDU_BACKHAUL_STEER_REQUEST,
			CMDU_AP_METRICS_QUERY,
			CMDU_ASSOC_STA_LINK_METRICS_QUERY,
			CMDU_UNASSOC_STA_LINK_METRIC_QUERY,
			CMDU_CHANNEL_SCAN_REQUEST,
			CMDU_CHANNEL_SCAN_REPORT,
			CMDU_POLICY_CONFIG_REQ,
			CMDU_BACKHAUL_STA_CAPABILITY_QUERY,
			CMDU_BACKHAUL_STA_CAPABILITY_REPORT,
			CMDU_CHANNEL_PREFERENCE_QUERY,
			CMDU_CHANNEL_SELECTION_REQ,
			CMDU_CLIENT_STEERING_REQUEST,
			CMDU_CLIENT_ASSOC_CONTROL_REQUEST,
			CMDU_AP_CAPABILITY_QUERY,
			CMDU_AP_CAPABILITY_REPORT,
			CMDU_HIGHER_LAYER_DATA,
			CMDU_CLIENT_CAPABILITY_QUERY,
			CMDU_CAC_REQUEST,
			CMDU_CAC_TERMINATION,
#if (EASYMESH_VERSION > 2)
			CMDU_BSS_CONFIG_RESPONSE,
			CMDU_DPP_CCE_INDICATION,
			CMDU_AGENT_LIST,
#endif
			-1);

	memcpy(a->cmdu_mask, cmdu_mask, sizeof(a->cmdu_mask));

	trace("<----------------------------------- %s\n", __func__);
	for (;;) {
		ret = ubus_lookup_id(a->ubus_ctx, map_plugin, &map_id);
		if (!ret)
			break;

		trace("ieee1905.map not up yet, sleeping for 2s!\n");
		sleep(2);
	}

	a->map_oid = map_id;

	ret = map_subscribe(a->ubus_ctx,
			    &a->map_oid,
			    "mapagent", &cmdu_mask, a,
			    agent_map_sub_cb,
			    agent_map_del_cb,
			    &a->subscriber);
	if (!ret) {
		a->subscribed = true;
	} else {
		trace("mapagent: Failed to 'register' with %s (err = %s)\n",
		      map_plugin, ubus_strerror(ret));
	}

	return ret;
}

int agent_init_defaults(struct agent *a)
{
	INIT_LIST_HEAD(&a->fhlist);
	INIT_LIST_HEAD(&a->bklist);
	INIT_LIST_HEAD(&a->ethlist);
	INIT_LIST_HEAD(&a->framelist);
	INIT_LIST_HEAD(&a->nodelist);


	a->cntlr_select.local = CONTROLLER_SELECT_LOCAL;
	a->cntlr_select.auto_detect = CONTROLLER_SELECT_AUTODETECT;
	a->cntlr_select.probe_int = CONTROLLER_SELECT_PROBE_INT;
	a->cntlr_select.retry_int = CONTROLLER_SELECT_RETRY_INT;
	a->cntlr_select.autostart = CONTROLLER_SELECT_AUTOSTART;

	/* don't try to start cntlr right away */
	timestamp_update(&a->observed_time);
	timestamp_update(&a->last_unassoc);

	a->cntlr_miss_count = 0;
	a->active_cntlr = false;
	a->multiple_cntlr = false;
	a->autocfg_interval = CONTROLLER_SELECT_PROBE_INT;


	a->is_sta_steer_start = 0;
	a->sta_steerlist_count = 0;
	timer_init(&a->sta_steer_req_timer, agent_steering_opp_timeout);

	return 0;
}

static int agent_ackq_timeout_cb(struct cmdu_ackq *q, struct cmdu_ackq_entry *e)
{
	struct agent *a = container_of(q, struct agent, cmdu_ack_q);
	struct cmdu_buff *cmdu = (struct cmdu_buff *) e->cookie;
	int ret;
	uint16_t msgid;

	trace("%s: ---> cmdu = %04x to "MACFMT" \n", __func__,
		cmdu_get_type(cmdu), MAC2STR(cmdu->origin));

	if (e->resend_cnt-- > 0) {
		ret = ieee1905_ubus_send_cmdu(a->ubus_ctx, cmdu, &msgid, a->pvid);
		if (ret)
			err("%s fail to send cmdu\n", __func__);
		dbg("%s CMDU sent, msgid = %d\n", __func__, msgid);
		return CMDU_ACKQ_TMO_REARM;
	}

	return CMDU_ACKQ_TMO_DELETE;
}

static void agent_ackq_delete_cb(struct cmdu_ackq *q, struct cmdu_ackq_entry *e)
{
	struct cmdu_buff *cmdu = (struct cmdu_buff *) e->cookie;

	trace("%s: ---> cmdu = %04x to "MACFMT" \n", __func__,
		cmdu_get_type(cmdu), MAC2STR(cmdu->origin));

	cmdu_free(cmdu);
}

void run_agent(void)
{
	struct agent *w;
	struct ubus_context *ctx;

	set_sighandler(SIGHUP, agent_sighandler);
	set_sighandler(SIGPIPE, SIG_IGN);

	w = calloc(1, sizeof(*w));
	if (!w)
		return;

	this_agent = w;
	dbg("Starting wifi_agent... (&agent = %p)\n", w);

	agent_init_defaults(w);

	cmdu_ackq_init(&w->cmdu_ack_q);
	w->cmdu_ack_q.timeout_cb = agent_ackq_timeout_cb;
	w->cmdu_ack_q.delete_cb = agent_ackq_delete_cb;

	uloop_init();
	ctx = ubus_connect(NULL);
	if (!ctx) {
		err("Failed to connect to ubus\n");
		free(w);
		return;
	}

	w->ts.nl_main_sk = nl_init_main_sock(w);
	if (!w->ts.nl_main_sk)
		goto out_ubus;

	w->ts.nl_sk.cb = nl_event_uloop_cb;
	w->ts.nl_sk.fd = nl_socket_get_fd(w->ts.nl_main_sk);


	uloop_fd_add(&w->ts.nl_sk, ULOOP_READ);

	w->ubus_ctx = ctx;
	w->evh.cb = agent_event_handler;

	ubus_add_uloop(ctx);

	agent_config_init(w, &w->cfg);

	/* used by some ts script handling */
	setenv("AL_BRIDGE", w->cfg.al_bridge, 1);

	agent_init_wsc_attributes(w);

	//agent_handle_netlink_events();

	//agent_config_get_ethwan(w->ethwan);
	//memcpy(w->cntlr_almac, w->cfg.cntlr_almac, 6);

	//agent_config_dump(&w->cfg);

	get_registered_steer_rules();	/* TODO: return rule list and improve */

	//agent_switch_according_to_pref(w); /*switch to the channel according to the prefrence*/

	ubus_register_event_handler(ctx, &w->evh, "ethport");
	ubus_register_event_handler(ctx, &w->evh, "wifi.*");
	ubus_register_event_handler(ctx, &w->evh, "wps_credentials");
	ubus_register_event_handler(ctx, &w->evh, "ubus.object.*");

	timer_init(&w->autocfg_dispatcher, agent_dispatch_autoconfig);
	timer_init(&w->reload_scheduler, agent_reload_cb);
	timer_init(&w->cntlr_scheduler, agent_enable_local_cntlr);
	timer_init(&w->rcpi_threshold_timer, agent_rcpi_thresold_timer_cb);
	timer_init(&w->onboarding_scheduler, agent_trigger_bsta_sync);
	timer_init(&w->bh_lost_timer, agent_bh_lost_cb);
	timer_init(&w->bh_reconf_timer, agent_bh_reconf_cb);
#ifdef AGENT_ISLAND_PREVENTION
	timer_init(&w->sta_disconnect_timer, agent_sta_disconnnect_cb);
	timer_init(&w->fh_disable_timer, agent_fh_disable_cb);
#endif /* AGENT_ISLAND_PREVENTION */
	timer_init(&w->disable_unconnected_bstas_scheduler, agent_disable_unconnected_bsta_cb);
	timer_init(&w->upgrade_backhaul_scheduler, agent_upgrade_backhaul_cb);
	timer_init(&w->init_ifaces_scheduler, agent_init_ifaces_cb);
	timer_init(&w->enable_fhs_scheduler, agent_enable_fhs_cb);
	timer_init(&w->radio_stats_scheduler, agent_radio_stats_cb);
	timer_init(&w->boot_scan_scheduler, agent_boot_scan_cb);

	agent_init_interfaces(w);
	/* switch to the channel according to the prefrence */
	//agent_switch_according_to_pref(w);

	agent_get_router_system_info(w);

	/* w->cfg.enabled */
	agent_publish_object(w, MAPAGENT_OBJECT);
	agent_publish_dbg_object(w, MAPAGENT_DBG_OBJECT);
	agent_load_plugins(w);

	//run_agent(w);

	timer_set(&w->rcpi_threshold_timer, RCPI_THRESHOLD_TIMER);
	timer_set(&w->autocfg_dispatcher, 0 * 1000);
	timer_set(&w->radio_stats_scheduler, RADIO_STATS_TIMER);
	w->boot_scan_tries = 0;
	timer_set(&w->boot_scan_scheduler, BOOT_UP_SCAN_TIME * 1000);

	agent_subscribe_for_cmdus(w);

	uloop_run();

/* out_and_exit: */
	map_unsubscribe(w->ubus_ctx, w->subscriber);
	agent_free_radios(w);
	agent_remove_object(w);
	agent_remove_dbg_object(w);
	agent_config_clean(&w->cfg);
	agent_free_cntlr_sync(w);
	cmdu_ackq_free(&w->cmdu_ack_q);
	clear_fhlist(w);
	clear_bklist(w);
	ubus_unregister_event_handler(ctx, &w->evh);
	plugins_unload(&w->pluginlist);
	uloop_done();
	nl_free_main_sock(w->ts.nl_main_sk);
out_ubus:
	ubus_free(ctx);
	free(w);
}

struct wsc_data *agent_free_wsc_data(struct wsc_data *wsc)
{
	if (wsc->m1_frame)
		free(wsc->m1_frame);
	if (wsc->key) {
		free(wsc->key->key);
		free(wsc->key);
	}

	return NULL;
}

void agent_free_radios(struct agent *a)
{
	int i;

	trace("%s: a->num_radios to free = %d\n", __func__, a->num_radios);
	for (i = 0; i < a->num_radios; i++) {
		struct wifi_radio_element *re;

		re = &a->radios[i];

		free_scanresults(re);

		free(re->bsslist);
		re->bsslist = NULL;
		free(re->unassoc_stalist);
		re->unassoc_stalist = NULL;
		re->num_unassoc_sta = 0;
		agent_free_wsc_data(&re->autconfig);
		re->autconfig.key = NULL;
		re->autconfig.m1_frame = NULL;
		re->num_bss = 0;
	}
	a->num_radios = 0;
	memset(&a->radios, 0, sizeof(a->radios));
}

void agent_free_cntlr_sync(struct agent *a)
{
	if (a->sync_config_req)
		free(a->sync_config_req);

	if (a->privkey) {
		struct wsc_key *k = (struct wsc_key *) a->privkey;

		free(k->key);
		free(k);
	}
}

static void wifi_sta_restrict_timeout(atimer_t *t)
{
	struct restrict_sta_entry *s =
		container_of(t, struct restrict_sta_entry, restrict_timer);

	wifi_restrict_sta(s->fh_ifname, s->sta, 0);
	list_del(&s->list);
	free(s);
}

/* following implements 'wifi.agent' ubus methods */
int wifiagent_assoc_control_sta(char *fh_ifname, unsigned char *sta,
							int enable, int tmo)
{
	struct agent *a = this_agent;
	int ret = -1;

	if (!a) {
		dbg("this wifiagent is NULL\n");
		return -1;
	}

	if (fh_ifname && fh_ifname[0]) {
		struct netif_fh *p;

		p = get_netif_by_name(a, fh_ifname);
		if (!p || !p->cfg)
			return -1;

		if (!enable) {
			struct restrict_sta_entry *s, *tmp;
			char stastr[18] = {0};

			ret = wifi_restrict_sta(fh_ifname, sta, 0);

			list_for_each_entry_safe(s, tmp,
					&p->restrict_stalist, list) {
				if (!memcmp(s->sta, sta, 6)) {
					timer_del(&s->restrict_timer);
					list_del(&s->list);
					free(s);
				}
			}

			/* remove from config, if there is one */
			hwaddr_ntoa(sta, stastr);
			ret |= config_update2("wifiagent", &a->cfg,
					"ap", "ifname", fh_ifname,
					"restrict", enable, stastr, 18);

			return ret;
		}

		/* If timeout is positive, create a timed sta assoc-control
		 * entry but don't update config. At the timer expiry, remove
		 * sta from assoc-control list.
		 *
		 * If timeout is 0 or negetive, permanently add sta to the
		 * ap's assoc control list by creating a config entry.
		 */
		ret = wifi_restrict_sta(fh_ifname, sta, 1);

		if (tmo > 0) {
			struct restrict_sta_entry *s;

			s = calloc(1, sizeof(struct restrict_sta_entry));
			if (s) {
				memcpy(s->sta, sta, 6);
				snprintf(s->fh_ifname, 16, "%s", fh_ifname);
				timer_init(&s->restrict_timer, wifi_sta_restrict_timeout);
				timer_set(&s->restrict_timer, tmo * 1000);
				list_add_tail(&s->list, &p->restrict_stalist);
			}
		} else {
			char stastr[18] = {0};

			/* make entry persistent as no timeout is specified */
			hwaddr_ntoa(sta, stastr);
			ret |= config_update2("wifiagent", &a->cfg,
					"ap", "ifname", fh_ifname,
					"restrict", enable, stastr, 18);
		}
	}

	return ret;
}

int wifiagent_steer_sta(struct ubus_context *ctx,
			char *ifname,
			unsigned char *sta,
			int bsscnt, unsigned char *bsss, int optime)
{
	struct agent *a = this_agent;
	struct sta *s;

	UNUSED(ctx);

	if (!a) {
		dbg("this wifiagent is NULL\n");
		return -1;
	}

	s = find_sta_by_mac(a, sta);
	if (!s) {
		dbg("STA not found!\n");
		return -1;
	}

	if (optime) {
		s->steer_policy |= STA_STEER_OPPORTUNITY;
		if (!timer_pending(&s->sta_steer_timer)) {
			rebuild_cntlr_preflist(a, s, bsscnt, bsss);
			/* (Re)start steer opportunity timer.
			 * In the opportunity time window constantly check
			 * every second for this sta's steering opportinity.
			 */
			s->steer_opportunity_tmo = optime * 1000;
			clock_gettime(CLOCK_MONOTONIC, &s->steer_opportunity);
			timer_set(&s->sta_steer_timer, 1000);
			return 0;
		}
	}

	/* steer mandate */
	s->steer_policy &= ~STA_STEER_OPPORTUNITY;
	if (/* !(s->caps & STA_CAP_11V_BSS_TRANS) || */   /* TODO */
			!(s->steer_policy & STEER_BTM)) {
		return steer_sta_legacy(s);
	}

	if (wifi_req_bss_transition(ifname, s->macaddr, bsscnt, bsss, 0) != 0) {
		dbg("Failed to send BTM request to " MACFMT "\n",
						MAC2STR(s->macaddr));
		return -1;
	}

	return 0;
}

int wifiagent_process_cmd(struct ubus_context *ctx,
			struct ubus_request_data *req,
			int cmd_id, char *cmd_data, int len)
{
	struct agent *a = this_agent;
	int ret = 0;


	ret = agent_handle_map_cmd(a, cmd_data, len);

	return ret;
}

int wifiagent_get_status(struct ubus_context *ctx,
		struct ubus_request_data *req)
{
	struct agent *agent = this_agent;
	struct netif_fh *p = NULL;
	struct netif_bk *bk = NULL;
	struct neighbor *n;
	struct blob_buf bb;
	void *a, *b, *c, *t;
	int i;

	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);

	a = blobmsg_open_array(&bb, "radios");
	for (i = 0; i < agent->num_radios; i++) {
		struct wifi_radio_element *re = &agent->radios[i];
		char macaddrstr[18] = {0};

		hwaddr_ntoa(re->macaddr, macaddrstr);
		t = blobmsg_open_table(&bb, "");
		blobmsg_add_string(&bb, "name", re->name);
		blobmsg_add_string(&bb, "macaddr", macaddrstr);
		blobmsg_add_u32(&bb, "channel", re->current_channel);
		blobmsg_add_u32(&bb, "bandwidth", re->current_bandwidth);
		blobmsg_add_u32(&bb, "opclass", re->current_opclass);
		b = blobmsg_open_table(&bb, "autoconfig");
		blobmsg_add_string(&bb, "state", (re->state ? "ACTIVE":"HEARTBEAT"));
		c = blobmsg_open_table(&bb, "message_identifier");
		blobmsg_add_u32(&bb, "search", re->mid);
		blobmsg_add_u32(&bb, "wsc", re->wsc_mid);
		blobmsg_add_u32(&bb, "renew", re->renew_mid);
		blobmsg_close_table(&bb, c);
		blobmsg_close_table(&bb, b);
		blobmsg_close_table(&bb, t);
	}
	blobmsg_close_array(&bb, a);

	a = blobmsg_open_array(&bb, "fronthaul");
	list_for_each_entry(p, &agent->fhlist, list) {
		struct sta *s;
		char bssidstr[18] = {0};
		void *tt;

		if (!p->cfg)
			continue;

		hwaddr_ntoa(p->bssid, bssidstr);
		t = blobmsg_open_table(&bb, "");
		blobmsg_add_string(&bb, "name", p->name);
		blobmsg_add_u8(&bb, "enabled", p->enabled);
		blobmsg_add_string(&bb, "bssid", bssidstr);
		blobmsg_add_string(&bb, "ssid", p->ssid);
		blobmsg_add_u32(&bb, "channel", p->channel);
		blobmsg_add_u32(&bb, "load", p->bssload);

		b = blobmsg_open_array(&bb, "neighbor");
		list_for_each_entry(n, &p->nbrlist, list) {
			char nbr_bssidstr[18] = {0};

			hwaddr_ntoa(n->nbr.bssid, nbr_bssidstr);
			tt = blobmsg_open_table(&bb, "");
			blobmsg_add_string(&bb, "bssid", nbr_bssidstr);
			blobmsg_add_u32(&bb, "channel", n->nbr.channel);
			blobmsg_close_table(&bb, tt);
		}
		blobmsg_close_array(&bb, b);

		b = blobmsg_open_array(&bb, "stations");
		list_for_each_entry(s, &p->stalist, list) {
			void *aa, *ttt, *tttt;
			char stastr[18] = {0};
			struct pref_neighbor *pn;

			hwaddr_ntoa(s->macaddr, stastr);

			ttt = blobmsg_open_table(&bb, "");
			blobmsg_add_string(&bb, "addr", stastr);
			/* blobmsg_add_u32(&bb, "conn_time", s->connected_ms / 1000); */
			blobmsg_add_u32(&bb, "rssi", s->rssi[0]);
			blobmsg_add_u32(&bb, "bcnreport_capable",
					s->supports_bcnreport);
			blobmsg_add_u32(&bb, "btmreq_steers",
					s->steer_btm_cnt);
			blobmsg_add_u32(&bb, "legacy_steers",
					s->legacy_steered);
			aa = blobmsg_open_array(&bb, "neighbor");
			list_for_each_entry(pn, &s->pref_nbrlist, list) {
				char pn_bssidstr[18] = {0};

				hwaddr_ntoa(pn->bssid, pn_bssidstr);
				tttt = blobmsg_open_table(&bb, "");
				blobmsg_add_string(&bb, "bssid", pn_bssidstr);
				blobmsg_add_u32(&bb, "rssi", pn->rssi);
				blobmsg_close_table(&bb, tttt);
			}
			blobmsg_close_array(&bb, aa);
			blobmsg_close_table(&bb, ttt);
		}
		blobmsg_close_array(&bb, b);
		blobmsg_close_table(&bb, t);
	}
	blobmsg_close_array(&bb, a);

	a = blobmsg_open_array(&bb, "backhauls");
	list_for_each_entry(bk, &agent->bklist, list) {
		char bssidstr[18] = {0};
		char bssidwanstr[18] = {0};
		char bssidcfgstr[18] = {0};

		if (!bk->cfg)
			continue;

		hwaddr_ntoa(bk->bssid, bssidstr);
		hwaddr_ntoa(bk->wan_bssid, bssidwanstr);
		hwaddr_ntoa(bk->cfg->bssid, bssidcfgstr);
		t = blobmsg_open_table(&bb, "");
		blobmsg_add_string(&bb, "name", bk->name);
		blobmsg_add_u8(&bb, "enabled", bk->enabled);
		blobmsg_add_u8(&bb, "connected", bk->connected);
		blobmsg_add_string(&bb, "bssid", bssidstr);
		blobmsg_add_string(&bb, "wan_bssid", bssidwanstr);
		blobmsg_add_string(&bb, "ssid", bk->ssid);
		blobmsg_add_u32(&bb, "channel", bk->channel);

		b = blobmsg_open_table(&bb, "cfg");
		blobmsg_add_string(&bb, "name", bk->cfg->name);
		blobmsg_add_u8(&bb, "enabled", bk->cfg->enabled);
		blobmsg_add_u32(&bb, "band", bk->cfg->band);
		blobmsg_add_string(&bb, "device", bk->cfg->device);
		blobmsg_add_string(&bb, "ssid", bk->cfg->ssid);
		blobmsg_add_string(&bb, "key", bk->cfg->key);
		blobmsg_add_string(&bb, "encryption", bk->cfg->encryption);
		blobmsg_add_u8(&bb, "onboarded", bk->cfg->onboarded);
		blobmsg_add_string(&bb, "bssid", bssidcfgstr);
		blobmsg_add_u16(&bb, "priority", (uint16_t) bk->cfg->priority);
		blobmsg_close_table(&bb, b);
		blobmsg_close_table(&bb, t);
	}
	blobmsg_close_array(&bb, a);


	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

int wifiagent_get_nodes(struct ubus_context *ctx,
		struct ubus_request_data *req)
{
	struct agent *agent = this_agent;
	struct node *n;
	struct blob_buf bb;
	void *a;

	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);
	blobmsg_add_u32(&bb, "num_nodes", agent->num_nodes);

	a = blobmsg_open_array(&bb, "nodes");
	list_for_each_entry(n, &agent->nodelist, list) {
		char aladdrstr[18] = {0};
		void *t;

		hwaddr_ntoa(n->alid, aladdrstr);
		t = blobmsg_open_table(&bb, "");

		blobmsg_add_string(&bb, "almac", aladdrstr);
		blobmsg_add_u16(&bb, "profile", n->map_profile);
		blobmsg_close_table(&bb, t);
	}
	blobmsg_close_array(&bb, a);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

int wifiagent_get_info(struct ubus_context *ctx,
		struct ubus_request_data *req)
{
	char almac_str[18] = {};
	struct blob_buf bb;
	struct agent *a = this_agent;

	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);
	blobmsg_add_u32(&bb, "active_cntlr", a->active_cntlr);
	hwaddr_ntoa(a->cntlr_almac, almac_str);
	blobmsg_add_string(&bb, "cntlr_almac", almac_str);
	blobmsg_add_u32(&bb, "local_cntlr", is_local_cntlr_running());
	blobmsg_add_u32(&bb, "multiple_cntlr_found", a->multiple_cntlr);
	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

int wifiagent_get_bk_info(struct ubus_context *ctx,
		struct ubus_request_data *req)
{
	struct blob_buf bk = { 0 };
	struct blob_attr *tb[4];
	static const struct blobmsg_policy bk_attr[4] = {
		[0] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
		[2] = { .name = "backhaul_device_id", .type = BLOBMSG_TYPE_TABLE },
		[3] = { .name = "backhaul_device_macaddr", .type = BLOBMSG_TYPE_TABLE },
	};
	int ret;

	blob_buf_init(&bk, 0);

	if (!blobmsg_add_json_from_file(&bk, MAP_UPLINK_PATH)) {
		dbg("Failed to parse %s\n", MAP_UPLINK_PATH);
		goto out;
	}

	ret = blobmsg_parse(bk_attr, 4, tb, blob_data(bk.head), blob_len(bk.head));
	if (ret)
		goto out;

	ubus_send_reply(ctx, req, bk.head);
	blob_buf_free(&bk);

	return UBUS_STATUS_OK;
out:
	blob_buf_free(&bk);
	return UBUS_STATUS_UNKNOWN_ERROR;
}


int agent_switch_according_to_pref(struct agent *a)
{
	uint32_t channel = 0;
	uint32_t opclass = 0;
	int ret = 0;
	int l = 0;
	struct wifi_radio_element *radio;

	trace("agent: %s: --->\n", __func__);

	for (l = 0; l < a->num_radios; l++) {
		radio = a->radios + l;
		ret = agent_get_highest_preference(radio, radio->current_opclass, &channel,
			&opclass);

		/* The operating class channel preference has been set
		 * now we want to switch the channel to the max preference */
		trace("agent|%s: %d|: opclass is %d channel is %d--->\n",
				__func__, __LINE__, opclass, channel);

		if ((radio->current_opclass == opclass) && (radio->current_channel == channel))
			continue;

		if (channel != 0 && opclass != 0) {
			ret = agent_channel_switch(a, radio->macaddr, channel, opclass);
			if (ret == -1) {
				/* Here we need to set the default preference for all the
				 * channels in that operating class also set the response
				 * code as rejected*/
				agent_set_channel_preference_to_default(radio);
			}
		}
	}
	return 0;
}

void agent_set_post_scan_action_pref(struct agent *agent, const char *radio, bool opclass_preferences)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(agent->radios); i++) {
		if (radio && strcmp(radio, agent->radios[i].name))
			continue;

		agent->radios[i].post_scan_action.opclass_preferences = opclass_preferences;
	}
}

/* Allocates channel scan report CMDU and puts Timestamp TLV into it */
struct cmdu_buff *agent_prepare_scan_cmdu(struct agent *a, struct tlv *tsp)
{
	trace("%s --->\n", __func__);

	struct cmdu_buff *cmdu_data;

	/* Allocate new fragment CMDU */
	cmdu_data = cmdu_alloc_frame(CH_SCAN_RESP_CMDU_MAX_LEN);
	if (!cmdu_data) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}
	cmdu_set_type(cmdu_data, CMDU_CHANNEL_SCAN_REPORT);
	memcpy(cmdu_data->origin, a->cntlr_almac, 6);

	/* Put timestamp TLV to the fragment CMDU */
	if (cmdu_copy_tlvs(cmdu_data, &tsp, 1)) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return NULL;
	}
	dbg("|%s:%d| added MAP_TLV_TIMESTAMP\n", __func__, __LINE__);

	return cmdu_data;
}

/* Splits Channel Scan Report TLVs into fragment CMDUs.
 * Sends fragmet CMDUs to controller.
 */
static int agent_send_ch_scan_rsp_frag(struct agent *a, struct cmdu_buff *cmdu)
{
	trace("agent: %s: --->\n", __func__);

	struct tlv_policy d_policy_scan[] = {
		[0] = {
			.type = MAP_TLV_CHANNEL_SCAN_RES,
			.present = TLV_PRESENT_MORE,
			.minlen = 9
		}
	};
	struct tlv *tv_tsp[1][16];	/* Timestamp TLV */
	struct tlv *tv_scan[256];	/* Channel Scan Results TLVs */
	int i;
	int num_tlv = 256, num_tlv_copied = 0;
	int ret = 0;
	struct cmdu_buff *frag_cmdu = NULL;

	if (cmdu->datalen < CH_SCAN_RESP_CMDU_MAX_LEN)
		/* No fragmentation required, just send the CMDU as is */
		return agent_send_cmdu(a, cmdu);

	/* If the number of neighbors detected during a channel scan would
	 * mean that the channel scan report message would not fit within
	 * one 1905 CMDU, the Multi-AP Agent shall split the channel scan
	 * report across multiple Channel Scan Result TLVs by splitting
	 * the information related to sets of neighbor BSSs into separate
	 * Channel Scan Result TLVs and setting the NumberofNeighbors field
	 * to the number of neighbors contained in the corresponding TLV.
	 */

	/* Note: assuming neighbors are already evenly split between TLVs */

	ret = map_cmdu_parse_tlvs(cmdu, tv_tsp, 2, a->cfg.map_profile);
	if (ret) {
		dbg("%s: cmdu_parse_tlvs(profile=%d) failed, err = (%d) '%s'\n",
		    __func__, a->cfg.map_profile, ieee1905_error,
		    ieee1905_strerror(ieee1905_error));
		return -1;
	}

	if (!tv_tsp[0][0]) {
		dbg("%s: Missing TIMESTAMP_TLV!\n", __func__);
		return -1;
	}

	ret = cmdu_parse_tlv_single(cmdu, tv_scan, d_policy_scan, &num_tlv);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n",
		    __func__, map_error, map_strerror(map_error));
		return -1;
	}

	if (!tv_scan[0]) {
		dbg("%s: Missing CHANNEL SCAN RESULT_TLV!\n", __func__);
		return -1;
	}

	tv_tsp[0][0]->len = tlv_length(tv_tsp[0][0]); // FIXME
	frag_cmdu = agent_prepare_scan_cmdu(a, tv_tsp[0][0]);
	if (WARN_ON(!frag_cmdu))
		return -1;

	for (i = 0; i < num_tlv; i++) {
		uint16_t tlv_len = tlv_length(tv_scan[i]);

		if (tlv_total_length(tv_scan[i]) > frag_cmdu->end - frag_cmdu->tail) {
			/* No space left for current TLV in CMDU buffer */
			cmdu_put_eom(frag_cmdu);
			agent_send_cmdu(a, frag_cmdu);
			cmdu_free(frag_cmdu);

			num_tlv_copied = 0;

			/* Create next fragment and put next TLVs into it */
			frag_cmdu = agent_prepare_scan_cmdu(a, tv_tsp[0][0]);
		}

		/* Add TLV to CMDU & continue */
		tv_scan[i]->len = tlv_len; // FIXME: assign len smwhr else
		if (cmdu_copy_tlvs(frag_cmdu, &tv_scan[i], 1)) {
			dbg("%s:%d copy TLVs failed, end = %p, tail = %p, len = %d\n",
			    __func__, __LINE__,
			    frag_cmdu->end, frag_cmdu->tail, tv_scan[i]->len);
			return -1;
		}
		num_tlv_copied++;
	}

	if (num_tlv_copied) { /* avoid sending timestamp alone */
		cmdu_put_eom(frag_cmdu);
		agent_send_cmdu(a, frag_cmdu);
	}

	cmdu_free(frag_cmdu);

	return 0;
}

int agent_send_ch_scan_response(struct agent *a, struct wifi_netdev *ndev,
		struct wifi_scan_request_radio *req)
{
	struct cmdu_buff *cmdu_data = NULL;
	int ret = 0;

	dbg("%s: called.\n", __func__);

	/* Generate the response cmdu */
	if (WARN_ON(!ndev))
		return -1;

	if (!req)
		/* Independent channel scan response */
		cmdu_data = agent_gen_independent_ch_scan_response(a, ndev);
	else
		cmdu_data = agent_gen_ch_scan_response_radio(a,
						ndev, req, req->status);

	if (!cmdu_data)
		return -1;

	if (req && req->status == CH_SCAN_STATUS_SCAN_ABORTED) {

		/* Replace old request data with the new one */
		ndev->scan_req = *req;

		/* Will mark as success when results available */
		ndev->scan_req.status = CH_SCAN_STATUS_SCAN_NOT_COMPLETED;

		/* Reset the timer of available time (5min) */
		timer_set(&ndev->available_scan_timer, 300000);
	}

	/* Send the response cmdu */
	ret = agent_send_ch_scan_rsp_frag(a, cmdu_data);

	cmdu_free(cmdu_data);

	return ret;
}

bool agent_ch_scan_succesful(struct agent *a)
{
	if (a->scan_status_code == CH_SCAN_STATUS_SUCCESS)
		return true;

	return false;
}
