/*
 * i1905_netlink.c - netlink interface to kernel.
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <netlink/netlink.h>
#include <netlink/utils.h>

#include <netlink/route/rtnl.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/attr.h>

#include <netlink/route/link/bridge.h>
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>


#include <easy/easy.h>
#include "../wifidefs.h"
#include "../timer.h"

#include "dynbh.h"
#include "dbh_nl.h"

struct i1905_nlevent {
	struct uloop_fd uloop;
	void (*error_cb)(struct i1905_nlevent *e, int error);
	void (*event_cb)(struct i1905_nlevent *e);
};

struct event_socket {
	struct i1905_nlevent ev;
	struct nl_sock *sock;
	int sock_bufsize;
};

static int i1905_nlevents_cb(struct nl_msg *msg, void *arg);

static void handle_error(struct i1905_nlevent *e, int error)
{
	struct event_socket *ev_sock = container_of(e, struct event_socket, ev);

	if (error != ENOBUFS)
		goto err;

	ev_sock->sock_bufsize *= 2;
	if (nl_socket_set_buffer_size(ev_sock->sock, ev_sock->sock_bufsize, 0))
		goto err;

	return;

err:
	e->uloop.cb = NULL;
	uloop_fd_delete(&e->uloop);
}

static void recv_nlevents(struct i1905_nlevent *e)
{
	struct event_socket *ev_sock = container_of(e, struct event_socket, ev);

	nl_recvmsgs_default(ev_sock->sock);
}

static struct event_socket rtnl_event = {
	.ev = {
		.uloop = {.fd = - 1, },
		.error_cb = handle_error,
		.event_cb = recv_nlevents,
	},
	.sock = NULL,
	.sock_bufsize = 0x20000,
};

#if 0
static int if_openlink(const char *ifname, struct nl_sock **s, struct rtnl_link **l)
{
        struct rtnl_link *link;
        struct nl_sock *sk;
        int ret = 0;

        sk = nl_socket_alloc();
        if (sk == NULL) {
                ret = -errno;
                return ret;
        }

        nl_connect(sk, NETLINK_ROUTE);
        if (rtnl_link_get_kernel(sk, 0, ifname, &link) < 0) {
                ret = -1;
                goto out;
        }

        *l = link;
        *s = sk;
        return 0;

out:
        nl_socket_free(sk);
        return ret;
}

static int if_closelink(struct nl_sock *s, struct rtnl_link *l)
{
        rtnl_link_put(l);
        nl_socket_free(s);

        return 0;
}

static int if_get_bridge_interface_port(char *ifname, uint8_t *state)
{
	struct nl_sock *s;
	struct rtnl_link *l;

	if_openlink(ifname, &s, &l);
	if (!s || !l) {
		fprintf(stderr, "fail due to init of s & l\n");
		return -1;
	}

	fprintf(stderr, "%s ifname", ifname);

	*state = rtnl_link_bridge_get_port_state(l);

	if_closelink(s, l);
	return 0;
}
#endif

static int i1905_handle_nlevents_link(struct mapclient_private *priv,
				      struct nlmsghdr *hdr, bool add)
{
	struct ifinfomsg *ifi = nlmsg_data(hdr);
	struct nlattr *nla[__IFLA_MAX];
	struct ethport *ap;
	uint8_t macaddr[6] = {0};
	char ifname[16] = {0};
	int br_ifindex = 0;
	uint8_t operstate, state = 0;

	fprintf(stderr, "%s: ------------->\n", __func__);

	if (!nlmsg_valid_hdr(hdr, sizeof(*ifi)))
		return NL_SKIP;

	nlmsg_parse(hdr, sizeof(*ifi), nla, __IFLA_MAX - 1, NULL);
	if (!nla[IFLA_IFNAME])
		return NL_SKIP;

	nla_memcpy(ifname, nla[IFLA_IFNAME], 15);
	nla_memcpy(macaddr, nla[IFLA_ADDRESS], sizeof(macaddr));
	nla_memcpy(&operstate, nla[IFLA_OPERSTATE], 1);

#if 0
	if (strstr(ifname, "br-lan")) {
		if_get_bridge_interface_port("br-lan", &state);
		fprintf(stderr, "%s: %s operstate:%u, state:%u\n", __func__, ifname, operstate, state);
	}
#endif
	if (!strstr(ifname, "eth"))
		return NL_SKIP;


	fprintf(stderr, "%s: %s operstate:%u, state:%u\n", __func__, ifname, operstate, state);

	ap = ethport_by_ifname(priv, ifname);
	if (!ap || ap->active_uplink || !ap->loop) {
		/*  */
		/* if link is in propagating state AND is not link_trigger */
			/* then; trigger loop_detection */
				/* toggle link_trigger = true */
				/* return NL_OK */
		/* else */
			/* toggle link_trigger = false */
			/* return NL_SKIP; */
		return NL_SKIP;
	}

	if (!!(ifi->ifi_flags & IFF_RUNNING)) {
		fprintf(stderr, "%s: %s is UP RUNNING\n", __func__, ifname);
	}

	if (!(ifi->ifi_flags & IFF_UP)) {
		fprintf(stderr, "%s: %s is down. skip..\n", __func__, ifname);
		return NL_OK;
	}

	br_ifindex = if_isbridge_interface(ifname);
	if (br_ifindex < 0) {
		fprintf(stderr, "%s: %s error getting br_ifindex\n", __func__, ifname);
		return NL_SKIP;
	}

	fprintf(stderr, "%s: %s : %s (" MACFMT ", %d), master = %d, fam = %d, flags = 0x%x\n",
	    __func__, (add ? "NEWLINK" : "DELLINK"),
	    ifname, MAC2STR(macaddr), ifi->ifi_index,
	    br_ifindex, ifi->ifi_family,
	    ifi->ifi_flags);


	if (add && br_ifindex > 0 && ifi->ifi_family == AF_BRIDGE) {
		fprintf(stderr, "%s: %s <----------\n", __func__, ifname);
		delif(ap);
		return NL_OK;
	}

	return NL_OK;
}

static int i1905_nlevents_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct mapclient_private *priv = arg;
	int ret = NL_SKIP;

	switch (hdr->nlmsg_type) {
	case RTM_NEWLINK:
		fprintf(stderr, "newlink!\n");
		ret = i1905_handle_nlevents_link(priv, hdr, true);
		break;
	default:
		break;
	}

	return ret;
}


static void i1905_receive_nlevents(struct uloop_fd *u, unsigned int events)
{
	struct i1905_nlevent *e = container_of(u, struct i1905_nlevent, uloop);

	if (u->error) {
		int ret = -1;
		socklen_t ret_len = sizeof(ret);

		u->error = false;
		if (e->error_cb &&
		    getsockopt(u->fd, SOL_SOCKET, SO_ERROR, &ret, &ret_len) == 0) {
			e->error_cb(e, ret);
		}
	}

	if (e->event_cb) {
		e->event_cb(e);
		return;
	}
}

int i1905_register_nlevents(struct mapclient_private *priv)
{
	struct nl_sock *sk;

	fprintf(stderr, "Opening netlink!\n");

	sk = nl_socket_alloc();
	if (!sk) {
		fprintf(stderr, "Unable to open nl event socket: %m");
		return -1;
	}

	if (nl_connect(sk, NETLINK_ROUTE) < 0) {
		nl_socket_free(sk);
		return -1;
	}

	rtnl_event.sock = sk;

	if (nl_socket_set_buffer_size(rtnl_event.sock, rtnl_event.sock_bufsize, 0)) {
		fprintf(stderr, "%s: %d\n", __func__, __LINE__);
		goto out_err;
	}

	nl_socket_disable_seq_check(rtnl_event.sock);

	nl_socket_modify_cb(rtnl_event.sock, NL_CB_VALID, NL_CB_CUSTOM,
			    i1905_nlevents_cb, priv);

	if (nl_socket_add_memberships(rtnl_event.sock,
				      RTNLGRP_NEIGH, RTNLGRP_LINK, 0))
		goto out_err;

	rtnl_event.ev.uloop.fd = nl_socket_get_fd(rtnl_event.sock);
	rtnl_event.ev.uloop.cb = i1905_receive_nlevents;
	uloop_fd_add(&rtnl_event.ev.uloop, ULOOP_READ |
		     ((rtnl_event.ev.error_cb) ? ULOOP_ERROR_CB : 0));
	fprintf(stderr, "netlink success!\n");

	return 0;

out_err:
	if (rtnl_event.sock) {
		nl_socket_free(rtnl_event.sock);
		rtnl_event.sock = NULL;
		rtnl_event.ev.uloop.fd = -1;
	}
	fprintf(stderr, "netlink fail!\n");
	return -1;
}

void i1905_unregister_nlevents(struct mapclient_private *priv)
{
	UNUSED(priv);

	if (rtnl_event.sock) {
		uloop_fd_delete(&rtnl_event.ev.uloop);
		rtnl_event.ev.uloop.fd = -1;
		nl_socket_free(rtnl_event.sock);
		rtnl_event.sock = NULL;
	}
}

