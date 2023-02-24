#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <net/if.h>
#include <uci.h>
#include <string.h>
#include <errno.h>

#include <netlink/netlink.h>
#include <netlink/route/rtnl.h>
#include <netlink/socket.h>
#include <netlink/msg.h>

#include <linux/if_bridge.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include <libubus.h>

#include <easy/easy.h>

#include <easymesh.h>
#include <i1905_wsc.h>

#include "timer.h"
#include "config.h"
#include "nl.h"
#include "agent.h"

#define dbg(...) fprintf(stderr, __VA_ARGS__)
#define warn(...) fprintf(stderr, __VA_ARGS__)

static bool ts_is_our_vid(struct ts_context *ts, uint16_t vid)
{
	int i;

	for (i = 0; i < ts->num_vids; i++) {
		if (ts->all_vids[i] == vid)
			return true;
	}

	return false;
}

static struct ts_iface *ts_find_iface(struct ts_context *ts,
				      const char *ifname)
{
	int i;

	for (i = 0; i < TS_IFACE_MAX_NUM; i++) {
		if (strncmp(ts->iface_array[i].name, ifname , 16) == 0)
			return &ts->iface_array[i];
	}

	return NULL;
}

static struct ts_iface *ts_configure_iface(struct ts_context *ts,
					   const char *ifname,
					   uint16_t vid)
{
	struct ts_iface *tsif;
	int i;

	for (i = 0; i < TS_IFACE_MAX_NUM; i++) {
		tsif = &ts->iface_array[i];
		if (tsif->name[0] == '\0') {
			strncpy(tsif->name, ifname, IFNAMSIZ);
			ts->check_tags = true;
			break;
		}

		if (strncmp(tsif->name, ifname, IFNAMSIZ) == 0)
			break;
	}

	if (i >= TS_IFACE_MAX_NUM) {
		warn("Number of TS interfaces too small\n");
		return NULL;
	}

	if (tsif->vid != vid) {
		tsif->vid = vid;
		ts->check_tags = true;
	}

	if (vid != 0 && !ts_is_our_vid(ts, tsif->vid)) {
		if (ts->num_vids < MAX_VIDS)
			ts->all_vids[ts->num_vids++] = tsif->vid;
		else
			warn("Too many vids\n");
	}

	return tsif;
}

void ts_read_bridge_vlan(struct ts_context *ts, const char *br_name)
{
	char ifnames[32][16] = {0};
	int n = 32;
	int ret;
	int i;

	if (!br_name || !if_isbridge(br_name))
		return;

	ret = br_get_iflist(br_name, &n, ifnames);
	if (ret)
		return;

	for (i = 0; i < n; i++) {
		struct ts_iface *tsif;
		uint32_t ifindex = 0;

		tsif = ts_find_iface(ts, ifnames[i]);
		if (!tsif)
			continue;

		ifindex = if_nametoindex(ifnames[i]);
		if (ifindex == 0)
			continue;

		tsif->ifi_index = ifindex;
	}
}

static int send_bridge_vlan_info(struct ts_context *ts, int nlmsg_type,
				 struct ifinfomsg *ifi,
				 struct bridge_vlan_info *vinfo, int n)
{
	struct nl_msg *nlmsg;
	struct nlattr *attr;
	int ret = -1;
	int i;

	nlmsg = nlmsg_alloc_simple(nlmsg_type, NLM_F_REQUEST);
	if (!nlmsg)
		return -1;

	nlmsg_append(nlmsg, ifi, sizeof(*ifi), 0);

	attr = nla_nest_start(nlmsg, IFLA_AF_SPEC);
	if (!attr)
		goto err;

	for (i = 0; i < n; i++)
		nla_put(nlmsg, IFLA_BRIDGE_VLAN_INFO, sizeof(vinfo[i]), &vinfo[i]);

	nla_nest_end(nlmsg, attr);

	ret = nl_send_auto_complete(ts->nl_main_sk, nlmsg);

err:
	nlmsg_free(nlmsg);

	return ret < 0 ? ret : 0;
}

/*
Mod: false = dellink
     true = setlink
*/
static void ts_set_mod_vlan(struct ts_context *ts, struct ts_iface *tsif,
			    struct ifinfomsg *ifi, int n_mod,
			    struct bridge_vlan_info *mod_vinfo, bool mod)
{
	uint8_t action = (mod ?  RTM_SETLINK : RTM_DELLINK);

	if (n_mod > 0) {
		int ret;

		ret = send_bridge_vlan_info(ts, action, ifi, mod_vinfo, n_mod);
		if (ret < 0)
			warn("Failed to %s vlan info for %s\n",
			     (mod ? "add" : "del"), tsif->name);
	}
}

void ts_teardown(struct agent *a, struct ts_context *ts)
{
	int i;
	struct ifinfomsg ifi = { .ifi_family = PF_BRIDGE };
	int n_del = 0;
	struct bridge_vlan_info del_vinfo[MAX_VIDS];
	char *bridge = a->cfg.al_bridge;

	for (i = 0; i < ts->num_vids; i++) {
		if (!ts->all_vids[i])
			continue;

		del_vinfo[n_del++].vid = ts->all_vids[i];
	}

	if (n_del == 0)
		return;

	ts_read_bridge_vlan(ts, bridge);

	for (i = 0; i < TS_IFACE_MAX_NUM; i++) {
		struct ts_iface *tsif = &ts->iface_array[i];

		if (tsif->name[0] == '\0')
			break;

		ifi.ifi_index = tsif->ifi_index;
		if (ifi.ifi_index <= 0) {
			warn("|%s:%d| Wrong index %d for %s\n", __func__,
			     __LINE__, tsif->ifi_index, tsif->name);
			continue;
		}

		ts_set_mod_vlan(ts, tsif, &ifi, n_del, del_vinfo, false);
	}
}

static void ts_set_iface_vlan(struct ts_context *ts, struct ts_iface *tsif)
{
	const uint16_t prim_flags = BRIDGE_VLAN_INFO_PVID | BRIDGE_VLAN_INFO_UNTAGGED;
	struct ifinfomsg ifi = { .ifi_family = PF_BRIDGE };
	struct bridge_vlan_info add_vinfo[MAX_VIDS];
	struct bridge_vlan_info del_vinfo[MAX_VIDS];
	int n_del, n_add;
	int i, ret;

	ifi.ifi_index = tsif->ifi_index;
	if (ifi.ifi_index <= 0) {
		warn("Wrong index %d for %s\n", tsif->ifi_index, tsif->name);
		return;
	}

	n_del = 0;
	n_add = 0;

	dbg("|%s:%d| ifname:%s type:%s vid:%d primary:%d\n", __func__, __LINE__,
	    tsif->name, tsif->vid ? "fronthaul" : "backhaul",
	    tsif->vid, ts->primary_vid);

	if (tsif->vid) {
		/* APs - fronthaul/backhaul bss */

		add_vinfo[n_add].vid = tsif->vid;
		add_vinfo[n_add].flags = prim_flags;
		n_add++;

		/* Add additional primary vid untagged */
		if (tsif->vid != ts->primary_vid) {
			add_vinfo[n_add].vid = ts->primary_vid;
			add_vinfo[n_add].flags = BRIDGE_VLAN_INFO_UNTAGGED;
			n_add++;
		}

	} else {
		/* APVLAN (wdsX.X.X or wlanX.staY) and backhaul STA - trunk between bridges/devices */
		for (i = 0; i < ts->num_vids; i++) {
			add_vinfo[i].vid = ts->all_vids[i];
			add_vinfo[i].flags = 0;
		}
		n_add = i;
	}

	if (n_add == 0)
		return;

	dbg("add %d del %d vids for %s iface %s %d\n", n_add, n_del,
	    tsif->vid ? "fronthaul" : "backhaul", tsif->name, tsif->ifi_index);

	/* BRIDGE_VLAN_FILTERING will come up with VID 1 as default primary
	 * if it is not used as pvid, get rid of it.
	 */
	if (ts->primary_vid != 1) {
		del_vinfo[n_del++].vid = (uint16_t )1;
	}

	if (n_del > 0) {
		ret = send_bridge_vlan_info(ts, RTM_DELLINK, &ifi, del_vinfo, n_del);
		if (ret < 0)
			warn("Failed to remove vlan info %s\n", tsif->name);
	}

	if (n_add > 0) {
		ret = send_bridge_vlan_info(ts, RTM_SETLINK, &ifi, add_vinfo, n_add);
		if (ret < 0)
			warn("Failed to add vlan info for %s\n", tsif->name);
	}
}

static void ts_set_system(struct ts_context *ts)
{
	char buf[16] = {0};
	uint16_t vid;
	int i;

	if (ts->primary_vid == 0)
		return;

	for (i = 0; i < ts->num_vids; i++) {
		vid = ts->all_vids[i];
		warn("/lib/wifi/multiap ts create %u\n",vid);
		Cmd(buf, sizeof(buf), "/lib/wifi/multiap ts create %u", vid);
	}

	warn("/lib/wifi/multiap ts reload\n");
	Cmd(buf, sizeof(buf), "/lib/wifi/multiap ts reload");
}

static void ts_check_ifi(struct ts_context *ts, struct ifinfomsg *ifi, const char *ifname)
{
	struct ts_iface *tsif;


	if (ts->primary_vid == 0)
		return;

/*
	if (ifi->ifi_family == AF_BRIDGE)
		return;
*/

	if (!(ifi->ifi_flags & IFF_UP))
		return;

	tsif = ts_find_iface(ts, ifname);
	if (tsif) {
		ts->check_tags = true;
		dbg("found %s tsif %p ifi_index %d\n", ifname, tsif, tsif->ifi_index);
		return;
	}

	if (!strstr(ifname, "wds") && !strstr(ifname, "sta"))
		return;

	tsif = ts_configure_iface(ts, ifname, 0);
	if (tsif) {
		tsif->ifi_index = ifi->ifi_index;
		ts->check_tags = true;
		dbg("added %s tsif %p ifi_index %d\n", ifname, tsif, tsif->ifi_index);
	} else {
		warn("Fail to add %s interface to ts array\n", ifname);
	}
}

int if_updown(const char *ifname, bool up)
{
	int fd;
	struct ifreq ifr;
	short flags;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
		close(fd);
		return -1;
	}

	flags = ifr.ifr_flags;

	if (up && !(flags & IFF_UP))
		ifr.ifr_flags |= IFF_UP;

	if (!up && (flags & IFF_UP))
		ifr.ifr_flags &= ~IFF_UP;

	if ((flags != ifr.ifr_flags) && (0 != ioctl(fd, SIOCSIFFLAGS, &ifr))) {
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

int nl_main_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct agent *a = (struct agent *) arg;
	struct ts_context *ts = &a->ts;
	const char *bridge = a->cfg.al_bridge;
	bool brcm_setup = a->cfg.brcm_setup;

	a->ts.check_tags = false;

	switch (nlh->nlmsg_type) {
	case RTM_GETLINK:
	case RTM_NEWLINK:
	//case RTM_DELLINK:
		{
			struct ifinfomsg *ifi;
			char ifname[16] = {0};
			int ret;

			ifi = NLMSG_DATA(nlh);

			if (if_indextoname(ifi->ifi_index, ifname) == NULL)
				break;

			fprintf(stderr, "ifname = %s  ifindex = %d family = %u status = %s  action = %s\n",
			       ifname,
			       ifi->ifi_index,
			       ifi->ifi_family,
			       !!(ifi->ifi_flags & IFF_UP) ? "up" : "down",
			       nlh->nlmsg_type == RTM_GETLINK ? "RTM_GETLINK" :
			       nlh->nlmsg_type == RTM_NEWLINK ? "RTM_NEWLINK" :
			       "RTM_DELLINK");

/*
			if (!(ifi->ifi_flags & IFF_UP))
				break;
*/
			ts_check_ifi(ts, ifi, ifname);

			if (!brcm_setup)
				break;

			if (!strstr(ifname, "wds"))
				break;

			if (if_isbridge_interface(ifname)) {
				int i, num, max = 32;
				char if_list[max][16];
				bool found = false;

				if (br_get_iflist(bridge, &num, if_list)) {
					printf("Failed to check bridge affiliation\n");
					break;
				}
				max = (num < max) ? num : max;
				for (i = 0; i < max; i++) {
					if (!strncmp(ifname, if_list[i], 15)) {
						printf("Interface %s is already a part of bridge\n",
						       ifname);
						found = true;

						if (!(ifi->ifi_flags & IFF_UP)) {
							ret = if_updown(ifname, true);
							if (!ret)
								printf("|%s:%d| Successfully brought up interface %s\n",
								       __func__, __LINE__, ifname);
						}
						break;
					}
				}
				if (found)
					break;
			}

			printf("Adding interface %s to bridge %s!\n", ifname, bridge);

			/* add wds iface to bridge */
			ret = br_addif(bridge, ifname);
			if (!ret)
				printf("Successfully added interface %s to bridge %s\n",
				       ifname, bridge);

			/* bring up wds interface */
			//ret = if_setflags(ifname, IFF_UP);
			ret = if_updown(ifname, true);
			if (!ret)
				printf("|%s:%d| Successfully brought up interface %s\n",
					__func__, __LINE__, ifname);
			break;
		}
	default:
		break;

	}

	nl_check_vlan(a, false);
	return 0;
}

static inline bool is_vid_valid(unsigned int vid)
{
#if 0
	dbg("%s: vid %u\n", __func__,  vid);

	if (vid > TS_VID_INVALID)
		abort();
#endif
	return (vid < TS_VID_INVALID) && (vid > 0);
}

static void ts_configure(struct agent *a)
{
	struct ts_context *ts = &a->ts;
	struct netif_fh *fh = NULL;
	struct netif_bk *bk = NULL;
	struct ts_iface *tsif;
	uint16_t vid;
	char buf[16];

	/* TODO remove interfaces */

	ts->primary_vid = a->cfg.pcfg->pvid;
	ts_teardown(a, ts);
	memset(ts->all_vids, 0, sizeof(ts->all_vids));
	ts->num_vids = 0;

	if (is_vid_valid(a->cfg.pcfg->pvid)) {
		snprintf(buf, sizeof(buf), "%u", ts->primary_vid);
		setenv("PRIMARY_VID", buf, ts->primary_vid);
		ts->all_vids[0] = ts->primary_vid;
		ts->num_vids++;
	} else
		unsetenv("PRIMARY_VID");

	/* Fronthaul/Backhaul APs */
	list_for_each_entry(fh, &a->fhlist, list) {
		char fif_prefix[IFNAMSIZ] = {0}; /* 4addr ifname prefix */
		bool add = false;

		dbg("FH/BH AP name %s multi_ap %d\n", fh->name, fh->cfg->multi_ap);
		vid = fh->cfg->vid;
		if (!is_vid_valid(vid))
			vid = ts->primary_vid;

		ts_configure_iface(ts, fh->name, vid);
		if (a->cfg.brcm_setup)
			strncpy(fif_prefix, "wds", sizeof(fif_prefix) - 1);
		else
			strncpy(fif_prefix, "TODO", sizeof(fif_prefix) - 1); /* FIXME: non brcm platforms, one for each bbss */

		add = (a->cfg.guest_isolation && (vid != 1) ? true : false);

		if (a->cfg.brcm_setup) {
			dbg("/lib/wifi/multiap ts isolate %s %d %s %s\n", (add ? "add" : "del"), ts->primary_vid, fh->name, fif_prefix);
			runCmd("/lib/wifi/multiap ts isolate %s %d %s %s", (add ? "add" : "del"), ts->primary_vid, fh->name, fif_prefix);
		}
	}

	/* Backhaul stations */
	list_for_each_entry(bk, &a->bklist, list) {
		dbg("BK name %s\n", bk->name);

		tsif = ts_configure_iface(ts, bk->name, 0);
		if (tsif)
			tsif->is_bsta = true;
	}
}

struct nl_sock *nl_init_main_sock(struct agent *a)
{
	struct nl_sock *sk;

	sk = nl_socket_alloc();
	if (!sk)
		return NULL;

	nl_socket_disable_seq_check(sk);
	nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, nl_main_cb, a);

	nl_connect(sk, NETLINK_ROUTE);
	nl_socket_add_memberships(sk, RTNLGRP_LINK, 0);
	nl_rtgen_request(sk, RTM_GETLINK, AF_UNSPEC, NLM_F_DUMP);
	nl_socket_set_nonblocking(sk);

	return sk;
}

void nl_free_main_sock(struct nl_sock *sk)
{
	nl_socket_free(sk);
}

void nl_check_vlan(struct agent *a, bool reconf)
{
	struct ts_context *ts = &a->ts;
	char *bridge = a->cfg.al_bridge;
	int ret, i;

	if (reconf) {
		ts->check_tags = false;

		ts_configure(a);
		ts_set_system(ts);
	}

	if (ts->check_tags) {
		dbg("Reading bridge %s vlan config\n", bridge);
		for (i = 0; i < TS_IFACE_MAX_NUM; i++) {
			int j;

			for (j = 0; j < MAX_VIDS; j++) {
				ts->iface_array[i].cur_vinfo[j].vid = 0;
			}

			ts->iface_array[i].ifi_index = 0;
		}
		ts_read_bridge_vlan(ts, bridge);

		for (i = 0; i < TS_IFACE_MAX_NUM; i++) {
			struct ts_iface *tsif = &ts->iface_array[i];

			if (tsif->name[0] == '\0')
				break;

			dbg("checking vlan settings for %s tsif %p index %d\n",
				tsif->name, tsif, tsif->ifi_index);

			/* Add to the bridge if not added already and if not backhaul sta,
			 * bsta bridging is done by dynamically by other entities.
			 */
			if (ts->iface_array[i].ifi_index <= 0 && !tsif->is_bsta) {
				ret = br_addif(bridge, tsif->name);
				dbg("(re)added %s interface to %s with status %d\n",
					tsif->name, bridge, ret);

				ts->iface_array[i].ifi_index = if_nametoindex(tsif->name);
				dbg("get %s index %d\n", tsif->name, tsif->ifi_index);

			}

			if (ts->iface_array[i].ifi_index <= 0)
				continue;
			ts_set_iface_vlan(ts, &ts->iface_array[i]); /* uses main-socket DEL/SET link */
		}
	}
}


void nl_event_uloop_cb(struct uloop_fd *fd, unsigned int events)
{
	struct ts_context *ts = container_of(fd, struct ts_context, nl_sk);
	int ret;

	ret = nl_recvmsgs_default(ts->nl_main_sk);

        if (ret < 0) {
                dbg("read error ENETDOWN - rearm uloop fd monitor\n");
                uloop_fd_delete(fd);
                uloop_fd_add(fd, ULOOP_READ);
        }
}
