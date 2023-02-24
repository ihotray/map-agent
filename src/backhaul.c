#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <netlink/netlink.h>
#include <linux/if_bridge.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <uci.h>
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>

#include <i1905_wsc.h>
#ifdef AGENT_SYNC_DYNAMIC_CNTLR_CONFIG
#include <cntlrsync.h>
#endif
#include <timer_impl.h>
#include <cmdu.h>
#include <cmdu_ackq.h>
#include <1905_tlvs.h>
#include <easymesh.h>
#include <easy/easy.h>
#include <easy/utils.h>
#include <map_module.h>

//#include "map_module.h"
#include "utils/utils.h"
#include "utils/debug.h"
#include "utils/liblist.h"
#include "steer_rules.h"
#include "config.h"
#include "nl.h"
#include "agent.h"
#include "backhaul.h"

void backhaul_bssid_clear(struct agent *a, struct netif_bk *bk)
{
	char fmt[64] = {0};

	strncpy(fmt, "bsta_clear_bssid", sizeof(fmt) - 1);

	if (bk) {
		memset(bk->cfg->bssid, 0, 6);

		snprintf(fmt + strlen(fmt), sizeof(fmt) - strlen(fmt),
			" %s", bk->name);
	}

	agent_exec_platform_scripts(fmt);
}

void backhaul_blacklist_clear(struct agent *a)
{
	struct netif_bk *bk = NULL;

	list_for_each_entry(bk, &a->bklist, list) {
		memset(bk->blacklist_bssid, 0, sizeof(bk->blacklist_bssid));
		bk->num_blacklist_bssids = 0;
	}

	agent_exec_platform_scripts("bsta_blacklist_bssid_clear");
}

bool backhaul_blacklist_update_ifname(struct agent *a, char *ifname)
{
	struct netif_bk *bk = NULL;

	list_for_each_entry(bk, &a->bklist, list) {
		char cmd[258] = {0};
		int i;

		if (ifname) {
			/* if ifname is passed, only update that ifname */
			if (strncmp(ifname, bk->name, 16))
				continue;
		}

		snprintf(cmd, sizeof(cmd), "bsta_blacklist_bssid_set %s", bk->name);
		for (i = 0; i < bk->num_blacklist_bssids; i++) {
			snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd),
				 " " MACFMT, MAC2STR(bk->blacklist_bssid[i]));
		}

		agent_exec_platform_scripts(cmd);
	}

	return false;
}

bool backhaul_blacklist_update(struct agent *a) {
	return backhaul_blacklist_update_ifname(a, NULL);
}


bool backhaul_blacklist_contains(struct agent *a, struct netif_bk *bk,
				   uint8_t *bssid)
{
	int i;

	for (i = 0; i < bk->num_blacklist_bssids; i++) {
		if (!memcmp(bssid, bk->blacklist_bssid[i], 6))
			return true;
	}

	return false;
}

/* add bssid to bk blacklist */
bool backhaul_blacklist_add(struct agent *a, struct netif_bk *bk,
			      uint8_t *bssid)
{
	int num = bk->num_blacklist_bssids;

	if (num >= BSTA_BLACKLIST_MAX_NUM)
		return false;

	if (backhaul_blacklist_contains(a, bk, bssid))
		return false;

	memcpy(bk->blacklist_bssid[num], bssid, 6);

	bk->num_blacklist_bssids++;

	return true;
}

/* del bssid from bk blacklist */
bool backhaul_blacklist_del(struct agent *a, struct netif_bk *bk,
			      uint8_t *bssid)
{
	bool rc = false;
	int i;

	if (!backhaul_blacklist_contains(a, bk, bssid))
		return false;

	for (i = 0; i < bk->num_blacklist_bssids; i++) {
		int j;

		if (memcmp(bssid, bk->blacklist_bssid[i], 6))
			continue;

		for (j = i; j < bk->num_blacklist_bssids - 1; j++)
			memcpy(bk->blacklist_bssid[j], bk->blacklist_bssid[(j + 1)], 6);

		bk->num_blacklist_bssids--;
		rc = true;
		break;
	}

	return rc;
}

/* check if ssid matches any bk configuration and add or del from blacklist
 * accordingly */
bool backhaul_mod_blacklist(struct agent *a, char *port, char *ssid,
			     uint8_t ssidlen, uint8_t *bssid)
{
	struct netif_bk *bk = NULL;
	char bk_ifname[16] = {0};
	bool downstream = false;
	int rc = false;

	if (!timestamp_expired(&a->eth_connect_t, 5000) ||
	    !timestamp_expired(&a->backhaul_change_t, 5000)) {
		dbg("|%s:%d| [bsta blacklist algo] Learning topology, " \
		    "discard topology response from port:%s\n",
		    __func__, __LINE__, port);
		return false;
	}


	if (!agent_get_backhaul_ifname(a, bk_ifname))
		return false;

	if (strlen(port) == 0)
		return false;

	/* backhaul ports are always treated as upstream */
	if (!agent_get_netif_bk_by_name(a, port))
		downstream = !!strncmp(bk_ifname, port, 16);

	list_for_each_entry(bk, &a->bklist, list) {
		char *bk_ssid;
		uint8_t maxlen = 0;
		bool modified;

		if (!bk->cfg)
			continue;

		bk_ssid = bk->cfg->ssid;

		maxlen = (strlen(bk_ssid) > ssidlen ?
			  strlen(bk_ssid) : ssidlen);

		if (strncmp(ssid, bk_ssid, maxlen))
			continue;

		if (downstream) {
			modified = backhaul_blacklist_add(a, bk, bssid);
			if (!memcmp(bk->cfg->bssid, bssid, 6))
				backhaul_bssid_clear(a, bk);
		} else
			modified = backhaul_blacklist_del(a, bk, bssid);

		rc |= modified;
	}

	if (rc)
		backhaul_blacklist_update(a);

	return rc;
}
