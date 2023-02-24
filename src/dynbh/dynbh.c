
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/stat.h>

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
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <libubus.h>

#include <easy/easy.h>
#include <easy/utils.h>

#include "../timer.h"
#include <cmdu.h>
#include <1905_tlvs.h>
#include <easymesh.h>
#include <map_module.h>

#include "dynbh.h"
#include "dbh_nl.h"

#ifndef BIT
#define BIT(n)	(1U << (n))
#endif

const char *objname;

#define map_plugin			IEEE1905_OBJECT_MULTIAP
#define HEARTBEAT_PROBE_TIMEOUT 	30
#define APCONF_MAX_RETRIES 		5
#define APCONF_INTERVAL 		2

/**
 * disconnect & disable bstas
 * create /var/run/multiap/map.agent.bsta_global_disable
 * write active iface to /var/run/multiap/ file
 */
static void link_up(struct ethport *ap)
{
	fprintf(stderr, "|%s:%d|\n", __func__, __LINE__);
	runCmd("/lib/wifi/dynbhd/api up %s", ap->ifname);
	fprintf(stderr, "|%s:%d|\n", __func__, __LINE__);
	runCmd("/lib/wifi/multiap set_uplink eth %s", ap->ifname);
	fprintf(stderr, "|%s:%d|\n", __func__, __LINE__);
}

/**
 * remove /var/run/multiap/map.agent.bsta_global_disable
 * enable all bstas
 */
static void link_down(void)
{
	fprintf(stderr, "|%s:%d|\n", __func__, __LINE__);
	runCmd("/lib/wifi/dynbhd/api down");
}

void delif(struct ethport *ap)
{
	runCmd("/lib/wifi/dynbhd/api bridge_delif %s", ap->ifname);
	runCmd("ubus call ieee1905 add_interface '{\"ifname\":\"%s\"}'", ap->ifname);
	fprintf(stderr, "brctl delif %s %s\n", ap->ctx->al_bridge, ap->ifname);
}

void addif(struct ethport *ap)
{
	if (if_isbridge_interface(ap->ifname))
		return;

	runCmd("ubus call ieee1905 del_interface '{\"ifname\":\"%s\"}'", ap->ifname);
	runCmd("/lib/wifi/dynbhd/api bridge_addif %s", ap->ifname);  /* add back to bridge */
	fprintf(stderr, "cmd: brctl addif %s %s\n", ap->ctx->al_bridge, ap->ifname); /* add back to bridge */
}

struct ethport *ethport_by_ifname(struct mapclient_private *p,
		const char *ifname)
{
	struct ethport *ap = NULL;

	list_for_each_entry(ap, &p->ethportlist, list) {
		if (!strncmp(ap->ifname, ifname, 16))
			return ap;
	}

	return NULL;
}

struct ethport *ethport_by_mid(struct mapclient_private *p, uint16_t mid)
{
	struct ethport *ap = NULL;

	fprintf(stderr, "%s %d mid %d\n", __func__, __LINE__, mid);

	list_for_each_entry(ap, &p->ethportlist, list) {
		int i;

		for (i = 0; i < ap->num_mid; i++) {
			fprintf(stderr, "%s %d mid[%d] %d\n", __func__, __LINE__, i, ap->mid[i]);

			if (ap->mid[i] == mid)
				return ap;
		}
	}

	return NULL;
}

/* if link times out, no loop was found */
static void bridge_readd(atimer_t *t)
{
	struct ethport *ap = container_of(t, struct ethport,
			bridge_add);
	int timeout = 5 * ap->retries;

	if (ap->active_uplink)
		link_down();

	fprintf(stderr, "|%s:%d| link timed out for iface:%s mid:%d, %d, add back to bridge\n", __func__, __LINE__, ap->ifname, ap->mid[0], ap->mid[1]);
	ap->loop = false;
	ap->active_uplink = false;
	addif(ap);

	ap->num_mid = 0;

	if (timeout > HEARTBEAT_PROBE_TIMEOUT)
		timeout = HEARTBEAT_PROBE_TIMEOUT;

	fprintf(stderr, "|%s:%d| timeout = %d\n", __func__, __LINE__, timeout);

	ap->retries++;
	timer_set(&ap->send_query, timeout * 1000);
	timer_set(&ap->bridge_add,
			((APCONF_MAX_RETRIES * APCONF_INTERVAL) + timeout) * 1000);
}

/* callback to send ap autoconfig search */
static void send_query_cb(atimer_t *t)
{
	struct ethport *ap = container_of(t, struct ethport,
			send_query);
	char mid[16] = {0};

	fprintf(stderr, "|%s:%d| sending query num %d for ifname:%s alid:%s \n", __func__, __LINE__, (ap->num_mid+1), ap->ifname, ap->ctx->alidstr);
	runCmd("[ -n \"$(ubus list ieee1905.al.%s)\" ] || ubus call ieee1905 add_interface '{\"ifname\":\"%s\"}'", ap->ifname, ap->ifname);

/*
ubus call ieee1905 cmdu '{"ifname":"eth0", "dst":"01:80:C2:00:00:13", "type":7, "mid":0, "data":"010006A6CEDA6DAF8412s0d0001000e00010080000201018100020100b3000102000000"}'
*/
	chrCmd(mid, 16, "ubus call ieee1905.al.%s cmdu '{\"dst\":\"01:80:C2:00:00:13\", \"type\":7, \"mid\":0, \"data\":\"010006%12s0d0001000e00010080000201018100020100b3000102000000\"}' | grep mid | cut -d' ' -f2", ap->ifname, ap->ctx->alidstr);
	runCmd("ubus list ieee1905.al.%s", ap->ifname);
	fprintf(stderr, "mid = %s\n", mid);
	ap->mid[ap->num_mid] = (uint16_t) atoi(mid);
	fprintf(stderr, "mid[%d] = %d\n", ap->num_mid, ap->mid[ap->num_mid]);
	if (ap->num_mid < 31)
		ap->num_mid++;

	if (ap->num_mid < APCONF_MAX_RETRIES)
		timer_set(&ap->send_query, 2000);
}

/* check for eth uplink existence */
static bool is_backhaul_type_eth(void)
{
	struct blob_buf bk = { 0 };
	char *type;
	struct blob_attr *tb[4];
	static const struct blobmsg_policy bk_attr[4] = {
		[0] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
		[2] = { .name = "backhaul_device_id", .type = BLOBMSG_TYPE_TABLE },
		[3] = { .name = "backhaul_device_macaddr", .type = BLOBMSG_TYPE_TABLE },
	};

	blob_buf_init(&bk, 0);

	if (!blobmsg_add_json_from_file(&bk, MAP_UPLINK_PATH)) {
		fprintf(stderr, "Failed to parse %s\n", MAP_UPLINK_PATH);
		goto out;
	}

	blobmsg_parse(bk_attr, 4, tb, blob_data(bk.head), blob_len(bk.head));

	if (!tb[0])
		goto out;

	type = blobmsg_data(tb[0]);

	fprintf(stderr, "---- type = %s ------\n", type);

	blob_buf_free(&bk);

	return !strncmp(type, "eth", 4);
out:
	blob_buf_free(&bk);
	return false;
}

struct ethport *alloc_ethport_search(struct mapclient_private *priv,
		char *ifname)
{
	struct ethport *ap;

	ap = calloc(1, sizeof(struct ethport));
	if (!ap)
		return NULL;

	strncpy(ap->ifname, ifname, 16);
	timer_init(&ap->send_query, send_query_cb);
	timer_init(&ap->bridge_add, bridge_readd);
	list_add_tail(&ap->list, &priv->ethportlist);
	ap->ctx = priv;
	return ap;
}

void free_ethport_search(struct ethport *ap)
{
	timer_del(&ap->send_query);
	timer_del(&ap->bridge_add);
	list_del(&ap->list);
	free(ap);
}


/* eth event handler */
static void ethport_event_handler(void *agent, struct blob_attr *msg)
{
	char ifname[16] = {0}, link[8] = {0};
	struct mapclient_private *a = (struct mapclient_private *) agent;
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

	strncpy(ifname, blobmsg_data(tb[0]), sizeof(ifname) - 1);
	strncpy(link, blobmsg_data(tb[1]), sizeof(link) - 1);

	up = !strcmp(link, "up");
	down = !strcmp(link, "down");

	if (up) {
		struct ethport *ap;

		ap = ethport_by_ifname(a, ifname);
		if (!ap) {
			ap = alloc_ethport_search(a, ifname);
			if (!ap)
				return;
		}

		ap->connected = true;

		/* immediately send apconf search */
		ap->retries = 1;
		timer_set(&ap->send_query, 0);
		/* re-add iface to bridge in 1s if no answer */
		timer_set(&ap->bridge_add, (APCONF_MAX_RETRIES * APCONF_INTERVAL) * 1000);

		/* remove iface from brdige */
		delif(ap);
	} else if (down) {
		struct ethport *ethport;

		ethport = ethport_by_ifname(a, ifname);
		if (!ethport)
			return;

		timer_del(&ethport->send_query);
		timer_del(&ethport->bridge_add);
		ethport->connected = false;
		ethport->loop = false;

		if (!if_isbridge_interface(ifname))
			addif(ethport);

		if (ethport->active_uplink) {
			struct ethport *ap = NULL;
			bool found = false;

			ethport->active_uplink = false;

			list_for_each_entry(ap, &a->ethportlist, list) {
				if (!ap->loop)
					continue;

				addif(ap);
				runCmd("/lib/wifi/multiap set_uplink eth %s", ap->ifname);
				ap->loop = false;
				ap->active_uplink = true;
				found = true;
			}

			if (!found) {
				link_down();
				runCmd("/lib/wifi/multiap unset_uplink eth");
			}
		}
	}
}

static void agent_event_handler(struct ubus_context *ctx,
		struct ubus_event_handler *ev,
		const char *type, struct blob_attr *msg)
{
	int i;
	char *str;
	struct mapclient_private *a = container_of(ev, struct mapclient_private, evh);
	struct wifi_ev_handler {
		const char *ev_type;
		void (*handler)(void *ctx, struct blob_attr *ev_data);
	} evs[] = {
		{ "ethport", ethport_event_handler },
	};

	str = blobmsg_format_json(msg, true);
	if (!str)
		return;

	fprintf(stderr, "[ &agent = %p ] Received [event = %s]  [val = %s]\n",
			a, type, str);
	for (i = 0; i < ARRAY_SIZE(evs); i++) {
		if (!strcmp(type, evs[i].ev_type)) {
			evs[i].handler(a, msg);
			break;
		}
	}

	free(str);
}

static int handle_topology_query(const char *ifname, uint8_t *src,
				 uint8_t *from, uint16_t mid,
				 struct cmdu_buff *rxdata, size_t rxlen,
				 void *priv, void *cookie)
{
	fprintf(stderr, "mapclient: %s ===>\n", __func__);

	return 0;
}

static char *agent_get_backhaul_ifname(char *ifname)
{
	struct blob_buf bk = { 0 };
	struct blob_attr *tb[1];
	static const struct blobmsg_policy bk_attr[1] = {
		[0] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	};

	blob_buf_init(&bk, 0);

        if (!blobmsg_add_json_from_file(&bk, MAP_UPLINK_PATH)) {
		fprintf(stderr, "Failed to parse %s\n", MAP_UPLINK_PATH);
		goto out;
        }

	blobmsg_parse(bk_attr, 1, tb, blob_data(bk.head), blob_len(bk.head));

	if (!tb[0])
		goto out;

	strncpy(ifname, blobmsg_data(tb[0]), 16);

	blob_buf_free(&bk);
	return ifname;
out:
	blob_buf_free(&bk);
	return NULL;
}

static int handle_autoconfig_response(const char *ifname, uint8_t *src,
				      uint8_t *from, uint16_t mid,
				      struct cmdu_buff *rxdata, size_t rxlen,
				      void *priv, void *cookie)
{
	struct mapclient_private *p = (struct mapclient_private *) priv;
	char almac_str[18] = {0};
	struct ethport *ap;
	struct tlv_policy a_policy[] = {
		[0] = {
			.type = TLV_TYPE_SUPPORTED_ROLE,
			.present = TLV_PRESENT_ONE
		},
		[1] = {
			.type = MAP_TLV_SUPPORTED_SERVICE,
			.present = TLV_PRESENT_OPTIONAL_ONE
		},
		[2] = {
			.type = MAP_TLV_MULTIAP_PROFILE,
			.present = TLV_PRESENT_ONE
		},
		[3] = {
			.type = TLV_TYPE_SUPPORTED_FREQ_BAND,
			.present = TLV_PRESENT_ONE
		}
	};
	struct tlv *tv[4][16] = {0};
	bool has_cntlr = false;
	int timeout = HEARTBEAT_PROBE_TIMEOUT;
	int ret;

	fprintf(stderr, "mapclient: %s ===>\n", __func__);

	ret = cmdu_parse_tlvs(rxdata, tv, a_policy, 4);
	if (ret) {
		fprintf(stderr, "%s: parse_tlv failed\n", __func__);
		return -1;
	}

	if (!tv[0][0] || !tv[1][0] || !tv[2][0] || !tv[3][0]) {
		fprintf(stderr, "malformed data %d %d %d %d\n", !!tv[0][0], !!tv[1][0], !!tv[2][0], !!tv[3][0]);
		return -1;
	}

	if (tv[1][0]->data[0] > 0) {
		int i;

		for (i = 0; i < tv[1][0]->data[0]; i++) {
			if (tv[1][0]->data[(i+1)] ==
					SUPPORTED_SERVICE_MULTIAP_CONTROLLER) {
				has_cntlr = true;
				break;
			}
		}
	}
	if (!has_cntlr) {
		fprintf(stderr, "Response did not support controller!\n");
		return -1;
	}


	ap = ethport_by_mid(p, mid);
	if (!ap) {
		fprintf(stderr, "No matching mid found\n");

		ap = ethport_by_ifname(p, ifname);
		if (!ap) {
			fprintf(stderr, "No interface matching %s found - no action\n", ifname);
			return -1;
		} else if (ap->active_uplink || ap->loop) {
			fprintf(stderr, "Interface %s already known to be connected to a controller - no action\n", ifname);
			return -1;
		} else {
			fprintf(stderr, "Interface %s is not known to have a controller\n", ifname);
		}
	}

	//backhaul_diff = !!memcmp(ap->backhaul_mac, src, 6) || !!memcmp(ap->backhaul_device_id, from, 6);
	memcpy(ap->backhaul_mac, src, 6);
	memcpy(ap->backhaul_device_id, from, 6);

	if (!is_backhaul_type_eth()) {
		ap->active_uplink = true;
		ap->loop = false;
		link_up(ap);
		fprintf(stderr, "|%s:%d| Interface %s is active uplink\n", __func__, __LINE__, ap->ifname);
		addif(ap);
		goto out;
	} else if (ap->active_uplink) {
		char ul_ifname[16] = {0};

		if (agent_get_backhaul_ifname(ul_ifname)) {
			if (strncmp(ul_ifname, ap->ifname, 16))
				link_up(ap);
		} else
			link_up(ap);

		fprintf(stderr, "|%s:%d| Interface %s is already known as active uplink\n", __func__, __LINE__, ap->ifname);
		goto out;
	}

#if 0
	chrCmd(almac_str, 18, "uci -q get mapagent.agent.controller_macaddr");
	if (strlen(almac_str) == 0) {
		/* TODO: add back to bridge */
		fprintf(stderr, "|%s:%d| error reading almac str from agent, add back to bridge\n", __func__, __LINE__);
		return -1;
	}

	if (!hwaddr_aton(almac_str, almac)) {
		/* TODO: add back to bridge */
		fprintf(stderr, "|%s:%d| invalid alid format in mapagent config, add back to bridge\n", __func__, __LINE__);
		return -1;
	}

	fprintf(stderr, "%s %d almac = %s, from = " MACFMT "\n", __func__, __LINE__, almac_str, MAC2STR(from));
	if (memcmp(almac, from, 6)) {
		/* TODO: add back to bridge */
		fprintf(stderr, "|%s:%d| alid differed from mapanget config, add back to bridge\n", __func__, __LINE__);
		return -1;
	}
#endif

	fprintf(stderr, "|%s:%d| active controller (%s) found for iface:%s mid:%d, keep out of bridge\n",
			__func__, __LINE__, almac_str, ap->ifname, mid);

	if (if_isbridge_interface(ap->ifname))
		runCmd("/lib/wifi/dynbhd/api bridge_delif %s", ap->ifname);  /* add back to bridge */

	runCmd("ubus call ieee1905 del_interface '{\"ifname\":\"%s\"}'", ap->ifname);
	ap->loop = true;
out:
	ap->retries = ap->num_mid = 0;
	ap->retries++;
	timer_set(&ap->send_query, timeout * 1000);
	timer_set(&ap->bridge_add,
			((APCONF_INTERVAL * APCONF_MAX_RETRIES) + timeout) * 1000);
	return 0;
}

static int handle_1905_ack(const char *ifname, uint8_t *src,
			   uint8_t *from, uint16_t mid,
			   struct cmdu_buff *rxdata, size_t rxlen, void *priv,
			   void *cookie)
{
	fprintf(stderr, "mapclient: %s ===>\n", __func__);
	return 0;
}

static int handle_ap_caps_query(const char *ifname, uint8_t *src,
				uint8_t *from, uint16_t mid,
				struct cmdu_buff *rxdata, size_t rxlen, void *priv,
				void *cookie)
{
	fprintf(stderr, "mapclient: %s ===>\n", __func__);
	return 0;
}


typedef int (*cmdu_handler_t)(const char *ifname, uint8_t *src, uint8_t *from,
			      uint16_t mid, struct cmdu_buff *rxdata,
			      size_t rxlen, void *priv, void *cookie);


static const cmdu_handler_t i1905ftable[] = {
	[0x00] = NULL,
	[0x01] = NULL,
	[0x02] = handle_topology_query,
	[0x03] = NULL,
	[0x04] = NULL,
	[0x05] = NULL,
	[0x06] = NULL,
	[0x07] = NULL,
	[0x08] = handle_autoconfig_response,
	[0x09] = NULL,
	[0x0a] = NULL,
};

#define CMDU_TYPE_MAP_START	0x8000
#define CMDU_TYPE_MAP_END	0x8001

static const cmdu_handler_t mapclient_ftable[] = {
	[0x00] = handle_1905_ack,
	[0x01] = handle_ap_caps_query,
};


static int mapclient_handle_cmdu_notification(struct blob_attr *msg, struct mapclient_private *priv)
{
	static const struct blobmsg_policy cmdu_attrs[6] = {
		[0] = { .name = "type", .type = BLOBMSG_TYPE_INT16 },
		[1] = { .name = "mid", .type = BLOBMSG_TYPE_INT16 },
		[2] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
		[3] = { .name = "source", .type = BLOBMSG_TYPE_STRING },
		[4] = { .name = "origin", .type = BLOBMSG_TYPE_STRING },
		[5] = { .name = "cmdu", .type = BLOBMSG_TYPE_STRING },
	};
	char in_ifname[16] = {0};
	struct blob_attr *tb[6];
	char src[18] = { 0 }, src_origin[18] = { 0 };
	uint8_t *tlv = NULL;
	char *tlvstr = NULL;
	uint16_t type;
	uint8_t srcmac[6], origin[6];
	uint16_t mid = 0;
	int len = 0;
	sigset_t waiting_mask;
	struct cmdu_buff *cmdu;
	int ret = 0;
	int idx;
	const cmdu_handler_t *f;

	sigpending(&waiting_mask);
	if (sigismember(&waiting_mask, SIGINT) ||
			sigismember(&waiting_mask, SIGTERM))
		return -1;

	blobmsg_parse(cmdu_attrs, 6, tb, blob_data(msg), blob_len(msg));

	if (!tb[0] || !tb[1])
		return -1;

	if (tb[0]) {
		int t;

		t = blobmsg_get_u16(tb[0]);
		if (t < 0)
			return -1;

		type = (uint16_t)t;
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

		tlvstr = calloc(1, len + 1);

		if (!tlvstr)
			return -1;

		strncpy(tlvstr, (blobmsg_data(tb[5]) + 16), len);
		len = (len - 1) / 2;
		tlv = calloc(1, len);
		if (!tlv) {
			free(tlvstr);
			return -1;
		}

		strtob(tlvstr, len, tlv);
		free(tlvstr);
	}

	cmdu = cmdu_alloc_custom(type, &mid, in_ifname, srcmac, tlv, len);
	if (!cmdu) {
		fprintf(stderr, "%s: cmdu_alloc_custom() failed!\n", __func__);
		if (tlv)
			free(tlv);
		return -1;
	}
	memcpy(cmdu->origin, origin, 6);
	fprintf(stderr, "%s: cmdu_alloc_custom() succeeded! cmdu->cdata->hdr.mid %u\n", __func__, cmdu_get_mid(cmdu));


	if (type >= CMDU_TYPE_MAP_START) {
		idx = type - CMDU_TYPE_MAP_START;
		f = mapclient_ftable;
		if (ARRAY_SIZE(mapclient_ftable) < idx)
			goto error;
	} else {
		idx = type;
		f = i1905ftable;
		if (ARRAY_SIZE(i1905ftable) < idx)
			goto error;
	}

	if (f[idx]) {
		ret = f[idx](in_ifname, srcmac, origin, mid, cmdu, len, priv, NULL);
	}



error:
	if (tlv)
		free(tlv);
	cmdu_free(cmdu);
	return ret;
}

int dynbh_map_sub_cb(void *bus, void *priv, void *data)
{
	struct blob_attr *msg = (struct blob_attr *)data;
	char *str;


	str = blobmsg_format_json(msg, true);
	fprintf(stderr, "Received notification '%s'\n", str);
	free(str);

	mapclient_handle_cmdu_notification(msg, priv);

	return 0;
}

int dynbh_map_del_cb(void *bus, void *priv, void *data)
{
	uint32_t *obj = (uint32_t *)data;

	fprintf(stderr, "Object 0x%x no longer present\n", *obj);
	return 0;
}

static int dynbh_subscribe_for_cmdus(struct mapclient_private *priv)
{
	mapmodule_cmdu_mask_t cmdu_mask = {0};
	int ret;
	uint32_t map_id;


	map_prepare_cmdu_mask(cmdu_mask,
			      CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE,
			      -1);

	ret = ubus_lookup_id(priv->ctx, map_plugin, &map_id);
	if (ret) {
		fprintf(stderr, "%s: %s\n", map_plugin, ubus_strerror(ret));
		return -1;
	}

	priv->map_oid = map_id;
	ret = map_subscribe(priv->ctx,
			    &priv->map_oid,
			    "dynbhd", &cmdu_mask, priv,
			    dynbh_map_sub_cb,
			    dynbh_map_del_cb,
			    &priv->subscriber);
	if (ret) {
		fprintf(stderr, "dynbh: Failed to 'register' with %s (err = %s)\n",
			map_plugin, ubus_strerror(ret));
	}

	return ret;
}

void remove_newline(char *buf)
{
        int len;

        len = strlen(buf) - 1;
        if (buf[len] == '\n')
                buf[len] = 0;
}

int read_queries(struct mapclient_private *priv)
{
	FILE *fp;
	char *ifname = NULL;
	size_t len = 0;
	ssize_t read;

	fp = fopen("/var/run/multiap/map.connected.ports", "r");
	if (!fp)
		return -1;

	while ((read = getline(&ifname, &len, fp)) != -1) {
		struct ethport *ap;

		remove_newline(ifname);

		//fprintf(stderr, "Retrieved ifname of length %lu:\n", read);
		fprintf(stderr, "|%s:%d| %s\n", __func__, __LINE__, ifname);

		ap = alloc_ethport_search(priv, ifname);
		if (!ap) {
			//free(ifname);
			continue;
		}

		ap->connected = true;
		ap->retries = 1;
		/* immediately send apconf search */
		timer_set(&ap->send_query, 0);
		/* re-add iface to bridge in 1s if no answer */
		timer_set(&ap->bridge_add,
				(APCONF_MAX_RETRIES * APCONF_INTERVAL) * 1000);

		/* remove iface from brdige */
		delif(ap);
		//free(ifname);
	}

	fclose(fp);
	free(ifname);
	return 0;
}

static int dynbhd_status(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct mapclient_private *c = container_of(obj, struct mapclient_private, obj);
	struct blob_buf bb;
	struct ethport *n;
	void *a;

	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);

	a = blobmsg_open_array(&bb, "ports");
	list_for_each_entry(n, &c->ethportlist, list) {
		void *t;

		t = blobmsg_open_table(&bb, "");
		blobmsg_add_string(&bb, "ifname", n->ifname);
		blobmsg_add_u8(&bb, "connected", n->connected);
		blobmsg_add_u8(&bb, "active_uplink", n->active_uplink);
		blobmsg_add_u8(&bb, "loop", n->loop);

		blobmsg_close_table(&bb, t);
	}

	blobmsg_close_array(&bb, a);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);
	return UBUS_STATUS_OK;
}



int cntlr_publish_object(struct mapclient_private *c, const char *objname)
{
	struct ubus_object *obj;
	struct ubus_object_type *obj_type;
	struct ubus_method *obj_methods;
	struct ubus_method m[] = {
		UBUS_METHOD_NOARG("status", dynbhd_status),
	};
	int num_methods = ARRAY_SIZE(m);
	int ret;

	obj = &c->obj;
	memset(obj, 0, sizeof(*obj));

	obj_type = calloc(1, sizeof(struct ubus_object_type));
	if (!obj_type)
		return -1;

	obj_methods = calloc(num_methods, sizeof(struct ubus_method));
	if (!obj_methods) {
		free(obj_type);
		return -1;
	}

	obj->name = objname;
	memcpy(obj_methods, m, num_methods * sizeof(struct ubus_method));
	obj->methods = obj_methods;
	obj->n_methods = num_methods;

	obj_type->name = obj->name;
	obj_type->n_methods = obj->n_methods;
	obj_type->methods = obj->methods;
	obj->type = obj_type;

	ret = ubus_add_object(c->ctx, obj);
	if (ret) {
		fprintf(stderr, "Failed to add '%s' err = %s\n",
				objname, ubus_strerror(ret));
		free(obj_methods);
		free(obj_type);
		return ret;
	}

	fprintf(stderr, "Published '%s' object\n", objname);

	return 0;
}


int main(int argc, char **argv)
{
	struct mapclient_private *priv;
	const char *ubus_socket = NULL;
	int ch;
	int ret;

	while ((ch = getopt(argc, argv, "s:o:")) != -1) {
		switch (ch) {
		case 's':
			ubus_socket = optarg;
			break;
		case 'o':
			objname = optarg;
			break;
		default:
			break;
		}
	}

	priv = calloc(1, sizeof(*priv));
	if (!priv)
		return -1;

	uloop_init();
	priv->ctx = ubus_connect(ubus_socket);
	if (!priv->ctx) {
		fprintf(stderr, "Failed to connect to ubus\n");
		free(priv);
		return -1;
	}

	INIT_LIST_HEAD(&priv->ethportlist);

	ubus_add_uloop(priv->ctx);

	priv->oid = 0xdeadbeaf;

	priv->evh.cb = agent_event_handler;
	ubus_register_event_handler(priv->ctx, &priv->evh, "ethport");
	chrCmd(priv->alidstr, 16, "uci get ieee1905.ieee1905.macaddress | tr -d :");
	chrCmd(priv->al_bridge, 16, "uci get mapagent.agent.al_bridge");

	ret = dynbh_subscribe_for_cmdus(priv);
	if (!ret) {
		i1905_register_nlevents(priv);
		read_queries(priv);
		cntlr_publish_object(priv, "dynbh");
		uloop_run();
	}

	map_unsubscribe(priv->ctx, priv->subscriber);
	ubus_free(priv->ctx);
	uloop_done();
	free(priv);

	return 0;
}
