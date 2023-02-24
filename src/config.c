/*
 * config.c - configurations handling
 *
 * Copyright (C) 2019 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <netlink/netlink.h>
#include <linux/if_bridge.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

//Security and encryption
#define WPS_AUTH_OPEN          (0x0001)
#define WPS_AUTH_WPAPSK        (0x0002) /* deprecated */
#define WPS_AUTH_SHARED        (0x0004) /* deprecated */
#define WPS_AUTH_WPA           (0x0008) /* deprecated */
#define WPS_AUTH_WPA2          (0x0010)
#define WPS_AUTH_WPA2PSK       (0x0020)
#define WPS_AUTH_SAE           (0x0040)
#define WPS_AUTH_WPA3_T        (WPS_AUTH_WPA2PSK | WPS_AUTH_SAE)

#define ATTR_ENCR_TYPE_FLAGS   (0x1010)
#define WPS_ENCR_NONE          (0x0001)
#define WPS_ENCR_WEP           (0x0002) /* deprecated */
#define WPS_ENCR_TKIP          (0x0004)
#define WPS_ENCR_AES           (0x0008)

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <uci.h>

#include <i1905_wsc.h>
#include <1905_tlvs.h>
#include <easymesh.h>
#include <easy/easy.h>
#include <map_module.h>
#include <bufutil.h>

#include <easy/easy.h>

#include "timer.h"
#include "utils/debug.h"
#include "utils/utils.h"
#include "steer_rules.h"
#include "config.h"
#include "nl.h"
#include "agent.h"

// UCI sections
#define UCI_BK_AGENT "bsta"
#define UCI_FH_AGENT "ap"
#define UCI_WLAN_IFACE "wifi-iface"
#define UCI_WL_DEVICE "wifi-device"
#define UCI_WIRELESS "wireless"
#define UCI_IEEE1905 "ieee1905"
#define UCI_AGENT "mapagent"
#define UCI_POLICY "policy"

struct device_band {
	char device[16];
	uint8_t band;
};

struct band_mapping {
	struct device_band dev_band[WIFI_DEVICE_MAX_NUM];
	int count;
};

static void config_update_entry(struct uci_context *ctx, struct uci_package *p,
				struct uci_section *s, const char *optname,
				int add, void *val, int len);

int del_value_list(struct uci_context *ctx, struct uci_package *pkg,
		struct uci_section *s, const char *option,
		enum uci_option_type type);

char *replace_char(char *str, char find, char replace)
{
	char *current_pos = strchr(str, find);

	while (current_pos) {
		*current_pos = replace;
		current_pos = strchr(current_pos, find);
	}

	return str;
}

int set_value(struct uci_context *ctx, struct uci_package *pkg,
		struct uci_section *section, const char *key,
		const char *value, enum uci_option_type type)
{
	struct uci_ptr ptr = {0};

	ptr.p = pkg;
	ptr.s = section;
	ptr.option = key;
	ptr.value = value;

	if (type == UCI_TYPE_STRING)
		return uci_set(ctx, &ptr);

	if (type == UCI_TYPE_LIST)
		return uci_add_list(ctx, &ptr);

	return -1;
}

int set_value_by_string(const char *package, const char *section,
		const char *key, const char *value, enum uci_option_type type)
{
	struct uci_ptr ptr = {0};
	struct uci_context *ctx;
	int rv = 0;

	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	ptr.package = package;
	ptr.section = section;
	ptr.option = key;
	ptr.value = value;

	if (type == UCI_TYPE_STRING)
		rv = uci_set(ctx, &ptr);

	if (type == UCI_TYPE_LIST)
		rv = uci_add_list(ctx, &ptr);

	uci_commit(ctx, &ptr.p, false);

	uci_free_context(ctx);
	return rv;
}

struct uci_section *config_get_section(struct uci_context *ctx,
		struct uci_package *pkg, const char *type, const char *key,
		const char *value)
{
	struct uci_element *e;
	struct uci_section *section;

	/* get the wet iface section */
	uci_foreach_element(&pkg->sections, e) {
		const char *c_value;

		section = uci_to_section(e);
		if (strcmp(section->type, type))
			continue;

		c_value = uci_lookup_option_string(ctx, section, key);
		if (c_value && !strcmp(c_value, value))
			return section;
	}

	return NULL;
}

struct uci_package *uci_load_pkg(struct uci_context **ctx, const char *config)
{
	struct uci_package *pkg;

	if (!*ctx) {
		*ctx = uci_alloc_context();
		if (!*ctx)
			return NULL;
	}

	if (uci_load(*ctx, config, &pkg) != UCI_OK) {
		uci_free_context(*ctx);
		*ctx = NULL;
		return NULL;
	}

	return pkg;
}

#if 0
int wifi_get_iface_bssid(char *ifname, uint8_t *bssid)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg;
	struct uci_section *section;
	struct uci_ptr ptr = {0};
	int ret = -1;

	if (!bssid)
		return ret;

	pkg = uci_load_pkg(&ctx, "wireless");
	if (!pkg)
		return ret;

	section = config_get_section(ctx, pkg, "wifi-iface", "ifname", ifname);
	if (!section)
		goto out_pkg;

	ptr.p = pkg;
	ptr.s = section;
	ptr.option = "bssid";
	ptr.target = UCI_TYPE_OPTION;

	ret = uci_lookup_ptr(ctx, &ptr, NULL, false);
	if (!ret && ptr.o)
		hwaddr_aton(ptr.o->v.string, bssid);
	else
		memset(bssid, 0, 6);

out_pkg:
	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return ret;
}
#endif

/* expects buf to len 2 */
char *agent_get_controller_enabled(struct agent *a, char *buf)
{
	struct uci_context *ctx;
	struct uci_ptr ptr = {0};
	int ret;

	ctx = uci_alloc_context();
	if (!ctx)
		return NULL;

	ptr.package = "mapcontroller";
	ptr.section = "controller";
	ptr.option = "enabled";
	ptr.target = UCI_TYPE_OPTION;

	ret = uci_lookup_ptr(ctx, &ptr, NULL, false);
	if (ret != UCI_OK ||!(ptr.flags & UCI_LOOKUP_DONE)) {
		goto error;
	}

	if (ptr.flags & UCI_LOOKUP_COMPLETE) {
		/* option found */
		strncpy(buf, ptr.o->v.string, 1);
	}

	uci_unload(ctx, ptr.p);
error:
	uci_free_context(ctx);
	return buf;
}


int wifi_get_iface_bssid(char *ifname, uint8_t *bssid)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg;
	struct uci_section *section;
	struct uci_ptr ptr = {0};
	int ret = -1;

	if (!bssid)
		return ret;

	pkg = uci_load_pkg(&ctx, "mapagent");
	if (!pkg)
		return ret;

	section = config_get_section(ctx, pkg, UCI_BK_AGENT, "ifname", ifname);
	if (!section)
		goto out_pkg;

	ptr.p = pkg;
	ptr.s = section;
	ptr.option = "bssid";
	ptr.target = UCI_TYPE_OPTION;

	ret = uci_lookup_ptr(ctx, &ptr, NULL, false);
	if (!ret && ptr.o)
		hwaddr_aton(ptr.o->v.string, bssid);
	else
		memset(bssid, 0, 6);

out_pkg:
	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return ret;
}


/* buf must be allocated buffer of len size, len must be greater than 0 */
int wifi_get_section_option(const char *package, const char *sec_type,
			    const char *sec_key, const char *sec_value,
			    const char *get_key, char *buf, int len)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg;
	struct uci_section *section;
	struct uci_ptr ptr = {0};
	int ret = -1;

	pkg = uci_load_pkg(&ctx, package);
	if (!pkg)
		return ret;

	section = config_get_section(ctx, pkg, sec_type, sec_key, sec_value);
	if (!section)
		goto out_pkg;

	ptr.p = pkg;
	ptr.s = section;
	ptr.option = get_key;
	ptr.target = UCI_TYPE_OPTION;

	ret = uci_lookup_ptr(ctx, &ptr, NULL, false);
	if (ret != UCI_OK || !(ptr.flags & UCI_LOOKUP_DONE)) {
		goto out_pkg;
	}

	/* only return 0 if option is found */
	ret = -1;

	if (ptr.flags & UCI_LOOKUP_COMPLETE) {
		/* option found */
		strncpy(buf, ptr.o->v.string, len - 1);
		ret = 0;
	}

out_pkg:
	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return ret;
}


int wifi_set_iface_bssid(struct netif_bk *bk, uint8_t *bssid)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg;
	struct uci_section *section;
	char bssid_str[18] = {0};
	int ret = -1;

	pkg = uci_load_pkg(&ctx, "mapagent");
	if (!pkg)
		return ret;

	section = config_get_section(ctx, pkg, UCI_BK_AGENT, "ifname", bk->name);
	if (!section)
		goto out_pkg;

	if (bssid && !hwaddr_is_zero(bssid))
		hwaddr_ntoa(bssid, bssid_str);

	dbg("|%s:%d| setting bssid to %s\n", __func__, __LINE__, bssid_str);

	ret = set_value(ctx, pkg, section, "bssid", bssid_str, UCI_TYPE_STRING);
	uci_commit(ctx, &pkg, false);

	/* keep in memory copy in sync without reload */
	memcpy(bk->bssid, bssid, 6);
out_pkg:
	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return ret;
}

#if 0 /* strive to not touch /etc/config/wireless upon bsta steer */
/* TODO: can it be generalized? */
int wifi_set_iface_bssid(struct netif_bk *bk, uint8_t *bssid)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg;
	struct uci_section *section;
	struct uci_ptr ptr = {0};
	char bssid_str[18] = {0};
	int ret = -1;

	pkg = uci_load_pkg(&ctx, "wireless");
	if (!pkg)
		return ret;

	section = config_get_section(ctx, pkg, "wifi-iface", "ifname", bk->name);
	if (!section)
		goto out_pkg;

	if (bssid && !hwaddr_is_zero(bssid))
		hwaddr_ntoa(bssid, bssid_str);

	dbg("|%s:%d| setting bssid to %s\n", __func__, __LINE__, bssid_str);

	ret = set_value(ctx, pkg, section, "bssid", bssid_str, UCI_TYPE_STRING);

	uci_commit(ctx, &pkg, false);

	uci_reload_services("wireless");
out_pkg:
	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return ret;
}
#endif

int config_del_iface(const char *config, const char *type, const char *ifname)
{
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_section *section;
	struct uci_ptr ptr = {0};
	int rv = -1;

	ctx = uci_alloc_context();
	if (!ctx)
		goto out;

	if (uci_load(ctx, config, &pkg) != UCI_OK) {
		dbg("config file 'wireless' not found!\n");
		goto out_uci;
	}

	section = config_get_section(ctx, pkg, type, "ifname", ifname);
	if (!section)
		goto out_pkg;

	ptr.p = pkg;
	ptr.s = section;

	uci_delete(ctx, &ptr);
	uci_commit(ctx, &pkg, false);
out_pkg:
	uci_unload(ctx, pkg);
out_uci:
	uci_free_context(ctx);
out:
	return rv;
}

int wifi_apply_iface_cfg(const char *ifname, const char *encryption,
		const char *ssid, const char *key)
{
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_section *section;
	int rv = -1;

	ctx = uci_alloc_context();
	if (!ctx)
		goto out;

	if (uci_load(ctx, UCI_AGENT, &pkg) != UCI_OK) {
		dbg("config file 'wireless' not found!\n");
		goto out_uci;
	}

	section = config_get_section(ctx, pkg, UCI_BK_AGENT, "ifname", ifname);
	if (!section)
		goto out_pkg;

	set_value(ctx, pkg, section, "encryption", encryption, UCI_TYPE_STRING);
	set_value(ctx, pkg, section, "ssid", ssid, UCI_TYPE_STRING);
	set_value(ctx, pkg, section, "key", key, UCI_TYPE_STRING);
	set_value(ctx, pkg, section, "onboarded", "1", UCI_TYPE_STRING);
	//set_value(ctx, pkg, section, "wds", "1", UCI_TYPE_STRING);

	uci_commit(ctx, &pkg, false);
out_pkg:
	uci_unload(ctx, pkg);
out_uci:
	uci_free_context(ctx);
out:
	return rv;
}

#if 0
char *agent_config_get_ethwan(char *ifname)
{
	struct uci_context *ctx;
	struct uci_ptr ptr = {0};

	ctx = uci_alloc_context();
	if (!ctx)
		return NULL;

	//ptr.value = value;
	ptr.package = "ports";
	ptr.section = "WAN";
	ptr.option = "ifname";
	ptr.target = UCI_TYPE_OPTION;

	if (uci_lookup_ptr(ctx, &ptr, NULL, false)) {
		uci_free_context(ctx);
		return NULL;
	}

	if (ptr.flags != UCI_LOOKUP_COMPLETE) {
		uci_free_context(ctx);
		return NULL;
	}

	strncpy(ifname, ptr.o->v.string, 15);

	uci_free_context(ctx);
	return ifname;
}
#endif

struct uci_section *config_add_section(struct uci_context *ctx,
		struct uci_package *pkg, const char *config, const char *type,
		const char *key, const char *value)
{
	struct uci_section *section = NULL;
	struct uci_ptr ptr = {0};
	int rv = -1;

	section = config_get_section(ctx, pkg, type, key, value);
	if (!section) {
		rv = uci_add_section(ctx, pkg, type, &section);
		if (rv)
			goto out_pkg;

		rv = uci_save(ctx, pkg);
		if (rv)
			goto out_pkg;
	}

	ptr.value = value;
	ptr.package = config;
	ptr.section = section->e.name;
	ptr.option = key;
	ptr.target = UCI_TYPE_OPTION;

	uci_lookup_ptr(ctx, &ptr, NULL, false);
	uci_set(ctx, &ptr);
	uci_save(ctx, ptr.p);

out_pkg:
	return section;
}

int config_add_default_wifi_iface(const char *config, const char *type,
		const char *ifname, const char *device, const char *network,
		const char *mode)
{
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_section *section;

	ctx = uci_alloc_context();
	if (!ctx)
		goto out;

	if (uci_load(ctx, config, &pkg) != UCI_OK) {
		dbg("config file 'wireless' not found!\n");
		goto out_uci;
	}

	section = config_add_section(ctx, pkg, config, type, "ifname", ifname);
	if (!section)
		return -1;


	set_value(ctx, pkg, section, "device", device, UCI_TYPE_STRING);
	set_value(ctx, pkg, section, "network", network, UCI_TYPE_STRING);
	//set_value(ctx, pkg, section, "mode", mode, UCI_TYPE_STRING);

	uci_commit(ctx, &pkg, false);

	uci_unload(ctx, pkg);
out_uci:
	uci_free_context(ctx);
out:
	return 0;
}

int config_add_default_agent_iface(const char *config, const char *type,
		const char *ifname, enum wifi_band band)
{
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_section *section;

	ctx = uci_alloc_context();
	if (!ctx)
		goto out;

	if (uci_load(ctx, config, &pkg) != UCI_OK) {
		dbg("config file 'wireless' not found!\n");
		goto out_uci;
	}

	section = config_add_section(ctx, pkg, config, type, "ifname", ifname);
	if (!section)
		return -1;

	trace("band = %d\n", band);

	if (band == BAND_5)
		set_value(ctx, pkg, section, "band", "5", UCI_TYPE_STRING);
	if (band == BAND_2)
		set_value(ctx, pkg, section, "band", "2", UCI_TYPE_STRING);
	if (band == BAND_6)
		set_value(ctx, pkg, section, "band", "6", UCI_TYPE_STRING);

	uci_commit(ctx, &pkg, false);

	uci_unload(ctx, pkg);
out_uci:
	uci_free_context(ctx);
out:
	return 0;
}

/* below functions are mostly taken from ieee1905d */
bool uci_check_wifi_iface(char *package_name, char *ifname,
		char *section)
{
	bool ret;
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_element *e;

	if (!package_name || !ifname)
		return false;

	ctx = uci_alloc_context();
	if (!ctx)
		return false;

	if (uci_load(ctx, package_name, &pkg)) {
		uci_free_context(ctx);
		return false;
	}

	ret = false;
	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, section)) {
			struct uci_option *opt = uci_lookup_option(ctx, s,
					"ifname");

			if (!opt || opt->type != UCI_TYPE_STRING)
				continue;
			if (strcmp(opt->v.string, ifname) == 0) {
				ret = true;
				break;
			}
		}
	}
	uci_unload(ctx, pkg);
	uci_free_context(ctx);

	return ret;
}

bool uci_set_wireless_interface_option(char *package_name,
		char *section_type, char *search_key, char *search_val,
		char *option, char *value)
{
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_element *e;

	if (!package_name || !search_val || !option || !value)
		return false;

	ctx = uci_alloc_context();
	if (!ctx)
		return false;

	if (uci_load(ctx, package_name, &pkg)) {
		uci_free_context(ctx);
		return false;
	}

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, section_type)) {
			struct uci_option *opt = uci_lookup_option(ctx, s,
					search_key);

			if (!opt || opt->type != UCI_TYPE_STRING)
				continue;
			if (strcmp(opt->v.string, search_val) == 0) {
				struct uci_ptr ptr = {0};

				ptr.value = value;
				ptr.package = package_name;
				ptr.section = s->e.name;
				ptr.option = option;
				ptr.target = UCI_TYPE_OPTION;
				if (uci_lookup_ptr(ctx, &ptr, NULL, false) ||
						!UCI_LOOKUP_COMPLETE)
					break;
				if (uci_set(ctx, &ptr) == UCI_OK)
					uci_save(ctx, ptr.p);
				break;
			}
		}
	}
	uci_commit(ctx, &pkg, false);
	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return false;
}

static bool get_encryption_value(uint16_t auth_type, uint16_t encryption_type,
		char *encrypt_val, size_t elen, int *mfp)
{
	if (!encrypt_val)
		return false;

	*mfp = 0;

	if ((auth_type & WPS_AUTH_WPA2PSK) && (auth_type & WPS_AUTH_SAE)) {
		strncat(encrypt_val, "sae-mixed", elen);
		*mfp = 1;
	} else if (auth_type & WPS_AUTH_SAE) {
		strncat(encrypt_val, "sae", elen);
		*mfp = 2;
	} else if ((auth_type & WPS_AUTH_WPAPSK) && (auth_type & WPS_AUTH_WPA2PSK))
		strncat(encrypt_val, "psk-mixed", elen);
	else if ((auth_type & WPS_AUTH_WPA) && (auth_type & WPS_AUTH_WPA2))
		strncat(encrypt_val, "wpa-mixed", elen);
	else if (auth_type & WPS_AUTH_WPAPSK)
		strncat(encrypt_val, "psk", elen);
	else if (auth_type & WPS_AUTH_WPA2PSK)
		strncat(encrypt_val, "psk2", elen);
	else if (auth_type & WPS_AUTH_WPA)
		strncat(encrypt_val, "wpa", elen);
	else if (auth_type & WPS_AUTH_WPA2)
		strncat(encrypt_val, "wpa2", elen);
	else if (auth_type & WPS_AUTH_OPEN)
		strncat(encrypt_val, "none", elen);
	else
		return false;

	//Check for the encryption type
	if ((encryption_type & WPS_ENCR_TKIP) &&
			(encryption_type & WPS_ENCR_AES))
		strncat(encrypt_val, "+tkip+aes", elen);
	else if (encryption_type & WPS_ENCR_TKIP)
		strncat(encrypt_val, "+tkip", elen);
	else if (encryption_type & WPS_ENCR_AES)
		strncat(encrypt_val, "+aes", elen);

	return true;
}

bool uci_add_wireless_iface_sec(char *package_name, char *interface_name,
		char *section_type, char *section_name)
{
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_section *s = NULL;
	struct uci_ptr ptr = {0};
	bool ret = false;

	if (!interface_name || !package_name)
		return false;

	ctx = uci_alloc_context();
	if (!ctx)
		return false;

	if (uci_load(ctx, package_name, &pkg))
		goto out_ctx;

	ptr.p = pkg;

	if (section_name) {
		ptr.section = section_name;
		ptr.value = section_type;
		ptr.option = NULL;
		uci_set(ctx, &ptr);
		if (uci_save(ctx, ptr.p) != UCI_OK)
			goto out_unload;
	} else {
		if (uci_add_section(ctx, pkg, section_type, &s) != UCI_OK)
			goto out_unload;

		if (uci_save(ctx, pkg) != UCI_OK)
			goto out_unload;

		ptr.section = s->e.name;
	}

	ptr.value = interface_name;
	ptr.option = "ifname";
	ptr.target = UCI_TYPE_OPTION;
	uci_lookup_ptr(ctx, &ptr, NULL, false);

	uci_set(ctx, &ptr);
	uci_save(ctx, ptr.p);
	uci_commit(ctx, &pkg, false);

	ret = true;
out_unload:
	uci_unload(ctx, pkg);
out_ctx:
	uci_free_context(ctx);
	return ret;
}

static int ubus_call(const char *object, const char *method,
		struct blob_buf *data, void *callback, void *cb_arg)
{
	uint32_t id;
	struct ubus_context *ctx = ubus_connect(NULL);

	if (!ctx) {
		err("ubus_connect failed\n");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (ubus_lookup_id(ctx, object, &id)) {
		err("(%s) not present\n", object);
		ubus_free(ctx);
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	// Invoke Ubus to get data from uspd
	if (ubus_invoke(ctx, id, method, data->head, callback, cb_arg, 10000)) {
		err("ubus call failed\n");
		ubus_free(ctx);
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	ubus_free(ctx);
	return UBUS_STATUS_OK;
}

bool uci_reload_services(char *services)
{
	struct blob_buf bb;
	int rv = 0;
	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	blobmsg_add_string(&bb, "config", services);

	rv = ubus_call("uci", "commit", &bb, NULL, NULL);

	info("## Reloading uci config %d\n", rv);
	//if (!ubus_call("uci", "reload_config", &bb, NULL, NULL))
	//	return true;

	//ubus_call("uci", "reload_config", &bb, NULL, NULL);

	blob_buf_free(&bb);

	return false;
}

#if 0 /* Deprecated for 6.1 - Possibly bring back in 6.2 with modifications */
/* TODO: introduce option and vendor extension to make this logic redundant */
int uci_apply_wps_credentials(struct agent_config *cfg, enum wifi_band band)
{
	struct netif_bkcfg *bk;
	struct netif_fhcfg *fh;

	list_for_each_entry(bk, &cfg->bklist, list) {
		if (bk->band != band)
			continue;

		list_for_each_entry(fh, &cfg->fhlist, list) {
			if (fh->band != band)
				continue;

			dbg("Applying bBSS credentials to %s:\n", fh->name);
			dbg("  - SSID            : %s\n", bk->ssid);
			dbg("  - NETWORK_KEY     : %s\n", bk->key);

			uci_set_wireless_interface_option(UCI_WIRELESS,
					UCI_WLAN_IFACE,
					"ifname",
					fh->name,
					"multi_ap_backhaul_ssid",
					bk->ssid);
			uci_set_wireless_interface_option(UCI_WIRELESS,
					UCI_WLAN_IFACE,
					"ifname",
					fh->name,
					"multi_ap_backhaul_key",
					bk->key);
			uci_set_wireless_interface_option(UCI_WIRELESS,
					UCI_WLAN_IFACE,	"ifname", fh->name, "wps", "1");
			uci_set_wireless_interface_option(UCI_WIRELESS,
					UCI_WLAN_IFACE,	"ifname", fh->name,
					"wps_pushbutton", "1");
		}

		break;
	}

	return 0;
}
#endif

int uci_clear_traffic_sep(struct agent_config *cfg)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg;
	struct uci_element *e, *tmp;
	struct uci_section *section = NULL;
	struct uci_ptr ptr = {0};
	struct netif_fhcfg *fh;



	/* TODO: do we need this considering wifi_teardown_map_ifaces_by_radio? */
	dbg("Clearing previous TS VIDs\n");

	/* remove from cfg */
	list_for_each_entry(fh, &cfg->fhlist, list) {
		fh->vid = 0;
		uci_set_wireless_interface_option(UCI_AGENT, UCI_FH_AGENT, "ifname",
			fh->name, "vid", "");
	}

	if (cfg && cfg->pcfg)
		cfg->pcfg->pvid = 0;

	/* remove from uci */
	pkg = uci_load_pkg(&ctx, UCI_AGENT);
	if (!pkg)
		return -1;

	uci_foreach_element_safe(&pkg->sections, tmp, e) {
	        struct uci_option *option;

		section = uci_to_section(e);

		if (!strcmp(section->type, "policy")) {
			option = uci_lookup_option(ctx, section, "pvid");
			if (option) {
				ptr.p = pkg;
				ptr.s = section;
				ptr.o = option;
				uci_delete(ctx, &ptr);
				uci_save(ctx, pkg);
				break;
			}
		}

	}

	uci_commit(ctx, &pkg, false);
	uci_unload(ctx, pkg);
	uci_free_context(ctx);

	return 0;
}

/* duplicate implementation
 * use
 * agent_fill_8021q_setting
 * and
 * agent_fill_traffic_sep_policy
 */
#if 0
int uci_apply_default_8021q_settings(struct tlv_default_8021q_settings *tlv)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg;
	struct uci_element *e;
	struct uci_section *section = NULL;
	int rv;
	char buf[16] = {0};

	pkg = uci_load_pkg(&ctx, UCI_AGENT);
	if (!pkg)
		return -1;

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		if (strcmp(s->type, UCI_POLICY))
			continue;

		/* There is only one policy section */
		section = s;
		break;
	}
	if (!section) {
		rv = uci_add_section(ctx, pkg, UCI_POLICY, &section);
		if (rv)
			goto out_pkg;
	}

	dbg("Applying Default 802.1Q Settings:\n");
	dbg("  - VID             : %u\n", tlv->pvid);
	dbg("  - PCP             : %u\n", tlv->pcp);

	snprintf(buf, sizeof(buf), "%u", tlv->pvid);
	set_value(ctx, pkg, section, "pvid", buf, UCI_TYPE_STRING);
	snprintf(buf, sizeof(buf), "%u", tlv->pcp);
	set_value(ctx, pkg, section, "pcp_default", buf, UCI_TYPE_STRING);

	rv = uci_save(ctx, pkg);
	if (rv)
		goto out_pkg;

	uci_commit(ctx, &pkg, false);
out_pkg:
	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return 0;
}

/*
 * Will only be successful if uci_apply_m2 is done prior, or interfaces already
 * exist and are configured through other means
 */
void uci_apply_traffic_sep(struct tlv_traffic_sep_policy *tlv)
{
	int i;
	uint8_t *ptr;

	ptr = (uint8_t *)tlv;

	/* TODO: error handling - valid vid range is 0x0003->0x0FFE */

	ptr++;
	for (i = 0; i < tlv->num_ssid; i++) {
		char ssid[33] = {0};
		char vid[8] = {0};
		uint8_t len = 0;

		len = *ptr;
		ptr++;

		memcpy(ssid, ptr, len);
		ptr += len;

		snprintf(vid, sizeof(vid), "%u", buf_get_be16(ptr));
		ptr += 2;
		uci_set_wireless_interface_option(UCI_AGENT, UCI_FH_AGENT,
				"ssid",	ssid, "vid", vid);
	}
}
#endif

/* buf is expected to be 512byte empty buf */
bool config_find_uuid(struct agent_config *cfg, char *buf)
{
	struct uci_package *pkg;
	struct uci_context *ctx = NULL;
	struct uci_element *e;
	bool found = false;

	pkg = uci_load_pkg(&ctx, UCI_WIRELESS);
	if (!pkg)
		return false;

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		struct uci_element *x, *tmp;
		struct uci_option *op;

		if (strcmp(s->type, "wifi-iface"))
			continue;

		uci_foreach_element_safe(&s->options, tmp, x) {
			if (strcmp(x->name, "uuid"))
				continue;

			op = uci_to_option(x);
			strncpy(buf, op->v.string, 511);
			found = true;
			break;
		}

		if (found)
			break;
	}

	uci_unload(ctx, pkg);
	uci_free_context(ctx);

	return found;
}

static char *get_separator(char *netdev)
{
	char separators[] = { '_', '.', '-', '\0' };
	size_t i = 0;
	char *pos = NULL;

	while (separators[i] != '\0') {
		pos = strchr(netdev, separators[i++]);
		if (pos)
			break;
	}

	return pos;
}

/* TODO: batch the changes arther than commit oneby one */
int uci_apply_m2(struct agent_config *cfg, char *interface_name, char *device,
		struct wps_credential *out, bool onboarded, struct wsc_ext *exts)
{
	bool ret;
	char auth_type_str[20] = {0};
	char multiap_type[16] = {0};
	char multiap_str[16] = {0};
	uint8_t multi_ap = 0;
	char band_str[2] = {0};
	char ssid[33] = {0}, network_key[65] = {0}, *bridge;
	int mfp = 0;
	/* step past br- prefix if present*/

	bridge = cfg->al_bridge;

	if (!strncmp("br-", bridge, 3))
		bridge += 3;

	dbg("%s %d band = %d\n", __func__, __LINE__, out->band);
	if (out->band == BAND_5)
		strcpy(band_str, "5");
	else if (out->band == BAND_2)
		strcpy(band_str, "2");
	else if (out->band == BAND_6)
		strcpy(band_str, "6");
	else /* TODO: 60 */
		return M2_PROCESS_ERROR;

	memcpy(ssid, out->ssid, out->ssidlen);
	memcpy(network_key, out->key, out->keylen);

	dbg("Applying WSC configuration (%s):\n", interface_name);
	dbg("  - SSID            : %s\n", ssid);
	dbg("  - AUTH_TYPE       : 0x%04x\n", out->auth_type);
	dbg("  - ENCRYPTION_TYPE : 0x%04x\n", out->enc_type);
	dbg("  - NETWORK_KEY     : %s\n", network_key);
	dbg("  - MAPIE_EXTENSION : 0x%02x\n", out->mapie);
	dbg("  - BAND            : %s\n", band_str);
	dbg("  - ENABLED        : %d\n", exts->enabled);

	// if teardown bit is set, return
	if (BIT(4, out->mapie))
		return M2_PROCESS_TEARDOWN;

	multi_ap |= (BIT(5, out->mapie) << 1);
	multi_ap |= BIT(6, out->mapie);

	snprintf(multiap_str, sizeof(multiap_str), "%d", multi_ap);

	if (multi_ap == 1)
		strncpy(multiap_type, "backhaul", 15);
	else if (multi_ap == 3)
		strncpy(multiap_type, "combined", 15);
	else
		strncpy(multiap_type, "fronthaul", 15);

	if (!get_encryption_value(out->auth_type, out->enc_type,
			auth_type_str, 20, &mfp)) {
		info("Unsupported encryption or cipher received!!\n");
		return M2_PROCESS_ERROR;
	}

	// Set uci in agent
	ret = uci_check_wifi_iface(UCI_AGENT, interface_name,
			UCI_FH_AGENT);
	if (!ret) {
		ret = uci_add_wireless_iface_sec(UCI_AGENT, interface_name,
				UCI_FH_AGENT, NULL);
		if (!ret)
			return M2_PROCESS_ERROR;
	}

	uci_set_wireless_interface_option(UCI_AGENT, UCI_FH_AGENT, "ifname",
			interface_name, "band",	band_str);
	uci_set_wireless_interface_option(UCI_AGENT, UCI_FH_AGENT, "ifname",
			interface_name,	"device", device);
	uci_set_wireless_interface_option(UCI_AGENT, UCI_FH_AGENT, "ifname",
			interface_name,	"ssid", ssid);
	uci_set_wireless_interface_option(UCI_AGENT, UCI_FH_AGENT, "ifname",
			interface_name,	"key", network_key);
	uci_set_wireless_interface_option(UCI_AGENT, UCI_FH_AGENT, "ifname",
			interface_name,	"encryption", auth_type_str);
	uci_set_wireless_interface_option(UCI_AGENT, UCI_FH_AGENT, "ifname",
			interface_name, "type", multiap_type);
	uci_set_wireless_interface_option(UCI_AGENT, UCI_FH_AGENT, "ifname",
			interface_name, "enabled", (exts->enabled ? "1" : "0"));
	if (multi_ap & 0x01) {
		char disallow_str[2] = {0};

		snprintf(disallow_str, sizeof(disallow_str), "%d",
				((out->mapie >> 2) & 0x03));
		uci_set_wireless_interface_option(UCI_AGENT,
				UCI_FH_AGENT, "ifname",
				interface_name,
				"disallow_bsta", disallow_str);
	}

	do {
		struct uci_context *ctx = NULL;
		struct uci_package *pkg;
		struct uci_section *section;
		int i;

		pkg = uci_load_pkg(&ctx, "mapagent");
		if (!pkg)
			break;

		section = config_get_section(ctx, pkg, UCI_FH_AGENT, "ifname",
				interface_name);
		if (!section) {
			uci_free_context(ctx);
			break;
		}

		del_value_list(ctx, pkg, section, "vendor_ie", UCI_TYPE_LIST);
		uci_commit(ctx, &pkg, false);
		uci_free_context(ctx);

		for (i = 0; i < exts->num_ven_ies; i++) {
			char *buf, *p;
			struct wsc_vendor_ie *ext = &exts->ven_ies[i];
			int len = (3 * 2) /* oui */ +
				  (1 * 2) /* len */ +
				  (ext->len * 2) /* payload */ +
				  1 /* '\0' */;

			buf = p = calloc(1, len);
			if (!buf)
				continue;

			btostr((uint8_t *)ext->oui, 3, p);
			p+= 3 * 2; /* oui */
			btostr(ext->payload, ext->len, p);

			config_update2(UCI_AGENT, cfg, UCI_FH_AGENT, "ifname",
				       interface_name, "vendor_ie", true, buf,
				       strlen(buf));
			free(buf);
		}

	} while(0);

	// Set uci in wireless
	ret = uci_check_wifi_iface(UCI_WIRELESS, interface_name,
			UCI_WLAN_IFACE);
	if (!ret) {
		char section_name[32] = {0};
		char *psep;

		snprintf(section_name, sizeof(section_name),
				 "%s_ap", interface_name);

		psep = get_separator(interface_name);
		if (psep && *psep != '_') /* e.g.: '.' or '-' */
			/* only '_' allowed in section names */
			replace_char(section_name, *psep, '_');

		ret = uci_add_wireless_iface_sec(UCI_WIRELESS, interface_name,
				UCI_WLAN_IFACE, section_name);

		if (!ret)
			return M2_PROCESS_ERROR;

		uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE,	"ifname",
				interface_name, "ieee80211k", "1");

		uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE,	"ifname",
				interface_name, "bss_transition", "1");

		if (multi_ap == 0x01) {
			uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE,
				"ifname", interface_name, "hidden", "1");
		} else {
			if (out->band == BAND_2 || out->band == BAND_5) {
				char buf[2] = {0};

				if (wifi_get_section_option(UCI_WIRELESS, UCI_WLAN_IFACE,
								"ifname", interface_name,
								"wps_pushbutton", buf,
								sizeof(buf))) {
					uci_set_wireless_interface_option(UCI_WIRELESS,
							UCI_WLAN_IFACE,	"ifname", interface_name,
							"wps_pushbutton", "1");
				}
				//TODO: write WPS attributes from M1 to the fronthaul interfaces
			}
		}

		do {
			char buf[512] = {0};
			char basemacstr[18] = {0};
			uint8_t basemac[6] = {0};
			//uint8_t uuid[16] = {0};

			if (!config_find_uuid(cfg, buf)) {
				chrCmd(buf, sizeof(buf), "db -q get hw.board.basemac");
				if (buf[0] != '\0' && strlen(buf) == 17)
					strncpy(basemacstr, buf, 17);

				dbg("basemac: %s\n", basemacstr);
				hwaddr_aton(buf, basemac);

				memset(buf, 0, sizeof(buf));
				chrCmd(buf, sizeof(buf), "uuidgen -s -r | cut -c 1-24");

				if (buf[0] == '\0' || strlen(buf) != 36) {
					dbg("uuidgen error!\n");
					//TODO
				}

				snprintf(buf + 24, 13, "%02X%02X%02X%02X%02X%02X",
					MAC2STR(basemac));
			}

			dbg("UUID: %s\n", buf);
			uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE,
					"ifname", interface_name, "uuid", buf);
		} while(0);
	}

	uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE, "ifname",
			interface_name, "network", bridge);
	uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE, "ifname",
			interface_name, "ssid", (char *) ssid);
	uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE, "ifname",
			interface_name, "key", (char *) network_key);
	uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE, "ifname",
			interface_name, "encryption", auth_type_str);
	uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE, "ifname",
			interface_name, "mode", "ap");
	uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE, "ifname",
			interface_name, "device", device);
	uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE, "ifname",
			interface_name, "multi_ap", multiap_str);
	if (mfp > 0) {
		uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE,
				"ifname", interface_name,
				"ieee80211w", mfp == 1 ? "1" : "2");
	} else
		uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE,
				"ifname", interface_name, "ieee80211w", "0");

	uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE, "ifname",
			interface_name, "disabled", (exts->enabled ? "0" : "1"));

	uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE, "ifname",
			interface_name, "mbo", "1");

	if (multi_ap != 0x01) {
		char device_type[32] = {0};
		uint16_t category, sub_category;

		category = buf_get_be16(out->device_type);
		sub_category = buf_get_be16(&out->device_type[6]);

		snprintf(device_type, sizeof(device_type),
			 "%d-%02x%02x%02x%02x-%d",
			 category,
			 out->device_type[2], out->device_type[3],
			 out->device_type[4], out->device_type[5],
			 sub_category);

		uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE, "ifname",
				interface_name, "wps_device_name", out->device_name);
		uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE, "ifname",
				interface_name, "wps_manufacturer", out->manufacturer);
		uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE, "ifname",
				interface_name, "wps_device_type", device_type);
		uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE, "ifname",
				interface_name, "wps_model_name", out->model_name);
		uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE, "ifname",
				interface_name, "wps_model_number", out->model_number);
		uci_set_wireless_interface_option(UCI_WIRELESS, UCI_WLAN_IFACE, "ifname",
				interface_name, "wps_serial_number", out->serial_number);
	}

	if (multi_ap == 0x01) {
		if (cfg->eth_onboards_wifi_bhs) {
			struct netif_bkcfg *bk;

			list_for_each_entry(bk, &cfg->bklist, list) {
				if (bk->band != out->band)
					continue;

				wifi_apply_iface_cfg(bk->name, auth_type_str,
							ssid, network_key);
				uci_set_wireless_interface_option("mapagent",
								  "radio",
								  "device",
								  bk->device,
								  "onboarded",
								  "1");
			}
		}
	}

	do {
		char buf[2] = {0};

		if (wifi_get_section_option(UCI_WIRELESS, UCI_WLAN_IFACE,
					    "ifname", interface_name,
					    "multicast_to_unicast", buf,
					    sizeof(buf))) {
			/* if option was not found - fh = enabled, bh = disabled */
			uci_set_wireless_interface_option(UCI_WIRELESS,
							  UCI_WLAN_IFACE,
							  "ifname",
							  interface_name,
							  "multicast_to_unicast",
							  multi_ap == 1 ? "0" : "1");
		}

		if (wifi_get_section_option(UCI_WIRELESS, UCI_WLAN_IFACE,
					    "ifname", interface_name,
					    "isolate", buf,
					    sizeof(buf))) {
			uci_set_wireless_interface_option(UCI_WIRELESS,
							  UCI_WLAN_IFACE,
							  "ifname",
							  interface_name,
							  "isolate", "0");
		}
	} while(0);

	dbg("|%s:%d| Enabled interface %s\n", __func__, __LINE__,
			interface_name);

	return M2_PROCESS_OK;
}
/* end of functions taken from ieee1905d */

static struct netif_bkcfg *get_netif_bkcfg_by_name(struct agent_config *c,
		const char *name)
{
	struct netif_bkcfg *p;

	list_for_each_entry(p, &c->bklist, list) {
		if (!strcmp(name, p->name))
			return p;
	}

	return NULL;
}

static struct netif_fhcfg *get_netif_fhcfg_by_name(struct agent_config *c,
							const char *name)
{
	struct netif_fhcfg *p;

	list_for_each_entry(p, &c->fhlist, list) {
		if (!strcmp(name, p->name))
			return p;
	}

	return NULL;
}

static struct steer_policy *get_steer_policy_by_name(struct netif_fhcfg *c,
							const char *name)
{
	struct steer_policy *p;

	if (!c)
		return NULL;

	list_for_each_entry(p, &c->steer_policylist, list) {
		if (!strcmp(name, p->name))
			return p;
	}

	return NULL;
}

struct agent_config_radio *get_agent_config_radio(struct agent_config *c,
							const char *ifname)
{
	struct agent_config_radio *p;

	list_for_each_entry(p, &c->radiolist, list) {
		if (!strcmp(ifname, p->name))
			return p;
	}

	return NULL;
}

void stax_add_entry(struct list_head *h, char *sta_macstr)
{
	struct stax *n;

	n = calloc(1, sizeof(struct stax));
	if (n) {
		snprintf(n->macstring, 18, "%s", sta_macstr);
		list_add(&n->list, h);
	}
}

void stax_del_entry(struct list_head *h, char *sta_macstr)
{
	struct stax *s, *tmp;

	list_for_each_entry_safe(s, tmp, h, list) {
		if (!strncmp(s->macstring, sta_macstr, sizeof(s->macstring))) {
			list_del(&s->list);
			free(s);
			return;
		}
	}
}

static int clean_steer_btm_excl(struct policy_cfg *p)
{
	struct stax *n, *tmp;

	list_for_each_entry_safe(n, tmp, &p->steer_btm_excludelist, list) {
		list_del(&n->list);
		free(n);
	}

	return 0;
}
static int clean_steer_excl(struct policy_cfg *p)
{
	struct stax *n, *tmp;

	list_for_each_entry_safe(n, tmp, &p->steer_excludelist, list) {
		list_del(&n->list);
		free(n);
	}

	return 0;
}

void agent_config_dump(struct agent_config *cfg)
{
	struct netif_fhcfg *n;
	struct steer_policy *pol;
	struct policy_cfg *c;
	struct stax *x;

	if (!cfg)
		return;

	c = cfg->pcfg;
	if (!c)
		return;

	dbg("  Steer Exclude Lists -------\n");
	list_for_each_entry(x, &c->steer_excludelist, list) {
		dbg("    mac: %s\n", x->macstring);
	}

	dbg("  Steer BTM Exclude Lists -------\n");
	list_for_each_entry(x, &c->steer_btm_excludelist, list) {
		dbg("    mac: %s\n", x->macstring);
	}

	list_for_each_entry(n, &cfg->fhlist, list) {
		dbg("name: %s\n", n->name);
		dbg("  enabled  : %s\n", n->enabled ? "true" : "false");
		dbg("  assocctrl: %s\n", n->assoc_control ? "true" : "false");

		dbg("  Policies -------\n");
		list_for_each_entry(pol, &n->steer_policylist, list) {
			dbg("    name: %s\n", pol->name);
			dbg("    enabled  : %s\n",
					pol->enabled ? "true" : "false");
			/* if (pol->dump_config)
			 *	pol->dump_config(pol, pol->policy);
			 */
		}

		dbg("  Assoc Ctrl Lists -------\n");
		list_for_each_entry(x, &n->assoc_ctrllist, list) {
			dbg("    mac: %s\n", x->macstring);
		}
	}
}

/* create ap config and initialize with default values */
struct netif_fhcfg *create_fronthaul_iface_config(struct agent_config *cfg,
							const char *ifname)
{
	struct netif_fhcfg *new;
	struct steer_rule *r;

	if (!cfg)
		return NULL;

	new = calloc(1, sizeof(struct netif_fhcfg));
	if (!new) {
		warn("OOM! config\n");
		return NULL;
	}

	snprintf(new->name, 16, "%s", ifname);
	new->enabled = true;
	new->fallback_legacy = STEER_LEGACY_FALLBACK_INT;
	new->steer_btm_retry_secs = STEER_BTM_RETRY_INT;
	new->steer_legacy_reassoc_secs = STEER_LEGACY_REASSOC_INT;
	new->steer_legacy_retry_secs = STEER_LEGACY_RETRY_INT;
	new->assoc_control_time = ASSOC_CONTROL_INT;
	new->band = BAND_UNKNOWN;
	INIT_LIST_HEAD(&new->steer_policylist);
	/* nrules = get_registered_steer_rules(&pollist); */ /* TODO */
	list_for_each_entry(r, &regd_steer_rules, list) {
		struct steer_policy *pol;

		pol = calloc(1, sizeof(struct steer_policy));
		if (!pol)
			goto err_oom;

		snprintf(pol->name, 16, "%s", r->name);
		pol->enabled = false;
		if (r->init_config)
			r->init_config(r, &pol->policy);
		list_add(&pol->list, &new->steer_policylist);
	}

	INIT_LIST_HEAD(&new->assoc_ctrllist);

	/* f->cfg = new; */
	dbg("%s: %s netif_fh->cfg = %p\n", __func__, new->name, new);

	list_add(&new->list, &cfg->fhlist);

	return new;

err_oom:
	list_flush(&new->steer_policylist, struct steer_policy, list);
	free(new);
	return NULL;
}

/* create ap config and initialize with default values */
struct netif_bkcfg *create_backhaul_iface_config(struct agent_config *cfg,
							const char *ifname)
{
	struct netif_bkcfg *new;

	if (!cfg)
		return NULL;

	new = calloc(1, sizeof(struct netif_bkcfg));
	if (!new) {
		warn("OOM! config\n");
		return NULL;
	}

	snprintf(new->name, 16, "%s", ifname);
	new->enabled = true;
	new->onboarded = false;
	new->band = BAND_UNKNOWN;

	/* f->cfg = new; */
	dbg("%s: %s netif_fh->cfg = %p\n", __func__, new->name, new);

	list_add(&new->list, &cfg->bklist);

	return new;
}

static void config_update_entry(struct uci_context *ctx, struct uci_package *p,
				struct uci_section *s, const char *optname,
				int add, void *val, int len)
{
	struct uci_ptr ptr;

	memset(&ptr, 0, sizeof(struct uci_ptr));
	ptr.p = p;
	ptr.s = s;
	ptr.package = p->e.name;
	ptr.section = s->e.name;
	ptr.option = optname;
	ptr.target = UCI_TYPE_OPTION;
	ptr.flags |= UCI_LOOKUP_EXTENDED;
	ptr.value = (char *)val;

	if (add) {
		dbg("config: add list option: %s\n", (char *)val);
		uci_add_list(ctx, &ptr);
	} else {
		dbg("config: del list option: %s\n", (char *)val);
		uci_del_list(ctx, &ptr);
	}
	uci_commit(ctx, &p, false);
}

int config_update(const char *confname, struct agent_config *cfg,
			const char *section, const char *option,
			int add,
			void *value, int len)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg = NULL;
	struct uci_element *e;

	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	if (uci_load(ctx, confname, &pkg) != UCI_OK) {
		dbg("config file '%s' not found!\n", confname);
		uci_free_context(ctx);
		return -1;
	}

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		struct uci_element *x, *tmp;
		struct uci_option *op;

		if (strcmp(s->type, section))
			continue;

		/* iter through matched 'section' for the 'option' */
		uci_foreach_element_safe(&s->options, tmp, x) {
			if (strcmp(x->name, option))
				continue;

			op = uci_to_option(x);
			if (op->type == UCI_TYPE_LIST) {
				uci_foreach_element(&op->v.list, x) {
					if (!strncmp(x->name, value, len)) {
						if (!add)
							config_update_entry(ctx,
								pkg, s,
								option, 0,
								value, len);

						goto out_exit;
					}
				}
				/* add new exclude at end of list */
				if (add)
					config_update_entry(ctx, pkg, s, option,
							1, value, len);

				goto out_exit;
			}
		}
		/* 'option' name not present in 'section'
		 * Create a new one at end of 'section'.
		 */
		if (add)
			config_update_entry(ctx, pkg, s, option, 1, value, len);

		goto out_exit;
	}
out_exit:
	uci_free_context(ctx);
	return 0;
}

int config_update2(const char *confname, struct agent_config *cfg,
		const char *section_type,
		const char *match_option,
		const char *match_option_value,
		const char *option,
		int add,
		void *value, int len)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg = NULL;
	struct uci_element *e;

	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	if (uci_load(ctx, confname, &pkg) != UCI_OK) {
		dbg("config file '%s' not found!\n", confname);
		uci_free_context(ctx);
		return -1;
	}

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		struct uci_element *x, *tmp;
		struct uci_option *op;
		const char *optstring;

		if (strcmp(s->type, section_type))
			continue;

		if (match_option && match_option_value) {
			optstring = uci_lookup_option_string(ctx, s,
				match_option);
			if (!optstring || strcmp(optstring, match_option_value))
				continue;
		}

		/* iter through matched 'section' for the 'option' */
		uci_foreach_element_safe(&s->options, tmp, x) {
			if (strcmp(x->name, option))
				continue;

			op = uci_to_option(x);
			if (op->type == UCI_TYPE_LIST) {
				uci_foreach_element(&op->v.list, x) {
					if (!strncmp(x->name, value, len)) {
						if (!add) {
							config_update_entry(ctx,
								pkg, s, option,
								0, value, len);
						}

						goto out_exit;
					}
				}
				/* add new 'option' at end of list */
				if (add) {
					config_update_entry(ctx, pkg, s, option,
								1, value, len);
				}

				goto out_exit;
			}
		}
		/* 'option' name not present in 'section'
		 * Create a new one at end of 'section'.
		 */
		if (add)
			config_update_entry(ctx, pkg, s, option,
							1, value, len);

		goto out_exit;
	}
out_exit:
	uci_free_context(ctx);
	return 0;
}


#if 0
struct config uci_config = {
	.name = "uci",
	.priv = uci_ctx;
	.get = uci_get_config,
	.set = uci_set_config,
	.init = uci_setup,
	.exit = uci_exit,
};

#define priv_get_config(priv)	container_of(priv, struct config, priv)

void register_config(struct config *c)
{
	static struct uci_context *ctx;
	static struct uci_package *pkg;
	struct uci_element *e;
	int ret = 0;

	if (uci_ctx)
		return priv_get_config(uci_ctx);

	ctx = uci_alloc_context();
	if (ctx) {
		uci_ctx = ctx;
		memcpy(c, &uci_config, sizeof(*cfg));
	}
	if (uci_load(ctx, "wifiagent", &pkg))
		return -1;

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		const char *option_val;

		if (strcmp(s->type, "wifiagent"))
			continue;

		option_val = uci_lookup_option_string(ctx, s, name);
		//if (option_val)
		//	sprintf(val, "%s", option_val);
		//else
		//	ret = -1;
	}
	uci_free_context(ctx);
	return ret;

}
#endif

static int agent_config_get_wifi_agent(struct agent_config *a,
		struct uci_section *s)
{
	enum {
		A_ENABLED,
		A_DEBUG,
		A_PROFILE,
		A_BRCM_SETUP,
		/*A_CONFIGURED,*/
		A_CNTLR_MAC,
		A_AL_BRIDGE,
		A_NETDEV,
		A_IFPREFIX,
		A_RESEND_NUM,
		A_DYN_CNTLR_SYNC,
		A_ISL_PREV,
		A_ETH_ONBOARD,
		A_FOLLOW_STA_DFS,
		A_GUEST_ISOLATION,
		A_ON_BOOT_ONLY_SCAN,
		NUM_POLICIES
	};
	const struct uci_parse_option opts[] = {
		{ .name = "enabled", .type = UCI_TYPE_STRING },
		{ .name = "debug", .type = UCI_TYPE_STRING },
		{ .name = "profile", .type = UCI_TYPE_STRING },
		{ .name = "brcm_setup", .type = UCI_TYPE_STRING },
		/*{ .name = "configured", .type = UCI_TYPE_STRING },*/
		{ .name = "controller_macaddr", .type = UCI_TYPE_STRING },
		{ .name = "al_bridge", .type = UCI_TYPE_STRING },
		{ .name = "netdev", .type = UCI_TYPE_STRING },
		{ .name = "ifprefix", .type = UCI_TYPE_STRING },
		{ .name = "resend_num", .type = UCI_TYPE_STRING },
		{ .name = "dyn_cntlr_sync", .type = UCI_TYPE_STRING },
		{ .name = "island_prevention", .type = UCI_TYPE_STRING },
		{ .name = "eth_onboards_wifi_bhs", .type = UCI_TYPE_STRING },
		{ .name = "ap_follow_sta_dfs", .type = UCI_TYPE_STRING },
		{ .name = "guest_isolation", .type = UCI_TYPE_STRING },
		{ .name = "scan_on_boot_only", .type = UCI_TYPE_STRING },
	};
	struct uci_option *tb[NUM_POLICIES];
	int prefix_idx = 0;

	uci_parse_section(s, opts, NUM_POLICIES, tb);

	if (tb[A_ENABLED])
		a->enabled = atoi(tb[A_ENABLED]->v.string) == 1 ? true : false;

	if (tb[A_DEBUG]) {
		a->debug_level = atoi(tb[A_DEBUG]->v.string);
		if (verbose < a->debug_level)
			verbose = a->debug_level;
	}

	if (tb[A_PROFILE])
		a->map_profile = atoi(tb[A_PROFILE]->v.string);

	if (tb[A_BRCM_SETUP])
		a->brcm_setup = atoi(tb[A_BRCM_SETUP]->v.string);

	/*if (tb[A_CONFIGURED])
		a->configured = atoi(tb[A_CONFIGURED]->v.string);*/

	if (tb[A_CNTLR_MAC])
		hwaddr_aton(tb[A_CNTLR_MAC]->v.string, a->cntlr_almac);

	if (tb[A_AL_BRIDGE]) {
		const char *iface;

		iface = tb[A_AL_BRIDGE]->v.string;
		strncpy(a->al_bridge, iface, sizeof(a->al_bridge) - 1);
	} else /* Default to br-lan if non-specfied */
		strncpy(a->al_bridge, "br-lan", sizeof(a->al_bridge) - 1);

	if (tb[A_IFPREFIX])
		prefix_idx = A_IFPREFIX;
	else if (tb[A_NETDEV])
		prefix_idx = A_NETDEV;

	if (prefix_idx) {
		const char *netdev = NULL;

		netdev = tb[prefix_idx]->v.string;
		strncpy(a->netdev, netdev, sizeof(a->netdev) - 1);
	} else { /* Default to wl/wlan if not specfied */
		strncpy(a->netdev, (a->brcm_setup) ? "wl%." : "wlan%_",
				sizeof(a->netdev) - 1);
	}

	if (tb[A_RESEND_NUM]) {
		const char *val = tb[A_RESEND_NUM]->v.string;

		a->resend_num = atoi(val);
	}

	if (tb[A_DYN_CNTLR_SYNC])
		a->dyn_cntlr_sync = !!atoi(tb[A_DYN_CNTLR_SYNC]->v.string);
	else
		a->dyn_cntlr_sync = true;

	if (tb[A_ISL_PREV])
		a->island_prevention = !!atoi(tb[A_ISL_PREV]->v.string);
	else
		a->island_prevention = true;

	if (tb[A_ETH_ONBOARD])
		a->eth_onboards_wifi_bhs = !!atoi(tb[A_ETH_ONBOARD]->v.string);
	else
		a->eth_onboards_wifi_bhs = false;

	if (tb[A_FOLLOW_STA_DFS])
		a->ap_follow_sta_dfs = !!atoi(tb[A_FOLLOW_STA_DFS]->v.string);
	else
		a->ap_follow_sta_dfs = false;

	if (tb[A_GUEST_ISOLATION])
		a->guest_isolation = !!atoi(tb[A_GUEST_ISOLATION]->v.string);
	else
		a->guest_isolation = false;

	if (tb[A_ON_BOOT_ONLY_SCAN])
		a->scan_on_boot_only = !!atoi(tb[A_ON_BOOT_ONLY_SCAN]->v.string);
	else
		a->scan_on_boot_only = false;

	return 0;
}

static int agent_config_get_controller_select(struct agent_config *a,
				       struct uci_section *s)
{
	enum {
		CTRL_SELECT_LOCAL,
		CTRL_SELECT_ID,
		CTRL_SELECT_PROBE_INT,
		CTRL_SELECT_RETRY_INT,
		CTRL_SELECT_AUTOSTART,
		NUM_CTRL_SELECT_POLICIES,
	};

	const struct uci_parse_option opts[] = {
		{ .name = "local", .type = UCI_TYPE_STRING },
		{ .name = "id", .type = UCI_TYPE_STRING },
		{ .name = "probe_int", .type = UCI_TYPE_STRING },
		{ .name = "retry_int", .type = UCI_TYPE_STRING },
		{ .name = "autostart", .type = UCI_TYPE_STRING },
	};

	struct uci_option *tb[NUM_CTRL_SELECT_POLICIES];
	struct ctrl_select_cfg *cscfg;

	uci_parse_section(s, opts, NUM_CTRL_SELECT_POLICIES, tb);

	cscfg = (struct ctrl_select_cfg *)calloc(1, sizeof(struct ctrl_select_cfg));
	if (!cscfg)
		return -1;

	if (!tb[CTRL_SELECT_LOCAL]) {
		warn("Required option 'local' not found!\n");
		free(cscfg);
		return -1;
	}
	cscfg->local = atoi(tb[CTRL_SELECT_LOCAL]->v.string);

	if (tb[CTRL_SELECT_ID]) {
		cscfg->auto_detect = true;
		if (strncmp(tb[CTRL_SELECT_ID]->v.string, "auto", 4)) {
			cscfg->auto_detect = false;
			hwaddr_aton(tb[CTRL_SELECT_ID]->v.string, cscfg->alid);
		}
	}
	if (tb[CTRL_SELECT_PROBE_INT])
		cscfg->probe_int = atoi(tb[CTRL_SELECT_PROBE_INT]->v.string);
	if (tb[CTRL_SELECT_RETRY_INT])
		cscfg->retry_int = atoi(tb[CTRL_SELECT_RETRY_INT]->v.string);
	if (tb[CTRL_SELECT_AUTOSTART])
		cscfg->autostart = atoi(tb[CTRL_SELECT_AUTOSTART]->v.string);

	if (a->cscfg)
		free(a->cscfg);
	a->cscfg = cscfg;

	return 0;
}

#define DEFAULT_BH_MISS_TMO 60
#define DEFAULT_BH_RECONF_TMO (60 * 5) /* 5 minutes */
static void agent_config_get_dynamic_backhaul(struct agent_config *cfg,
				       struct uci_section *s)
{
	enum {
		DYN_BH_MISS_TMO,
		DYN_BH_RECONF_TMO,
		NUM_DYN_BH_POLICIES,
	};

	const struct uci_parse_option opts[] = {
		{ .name = "missing_bh_timer", .type = UCI_TYPE_STRING },
		{ .name = "missing_bh_reconfig_timer", .type = UCI_TYPE_STRING },
	};

	struct uci_option *tb[NUM_DYN_BH_POLICIES];

	uci_parse_section(s, opts, NUM_DYN_BH_POLICIES, tb);

	memset(&cfg->dbhcfg, 0, sizeof(struct dyn_bh_cfg));

	if (tb[DYN_BH_MISS_TMO])
		cfg->dbhcfg.bh_miss_tmo = atoi(tb[DYN_BH_MISS_TMO]->v.string);
	else
		cfg->dbhcfg.bh_miss_tmo = DEFAULT_BH_MISS_TMO;

	if (tb[DYN_BH_RECONF_TMO])
		cfg->dbhcfg.bh_reconf_tmo = atoi(tb[DYN_BH_RECONF_TMO]->v.string);
	else
		cfg->dbhcfg.bh_reconf_tmo = DEFAULT_BH_RECONF_TMO;
}

static int agent_config_get_wifi_radio(struct agent_config *a,
				       struct uci_section *s)
{
	enum {
		WIFI_RADIO_DEVICE,
		WIFI_RADIO_BAND,
		WIFI_RADIO_ENCRYPTION,
		WIFI_RADIO_ONBOARDED,
		WIFI_RADIO_DEDICATED,
		WIFI_RADIO_STEER_POLICY,
		WIFI_RADIO_UTIL_THRESHOLD,
		WIFI_RADIO_RCPI_THRESHOLD,
		WIFI_RADIO_REPORT_RCPI_THRESHOLD,
		WIFI_RADIO_INCLUDE_STA_STATS,
		WIFI_RADIO_INCLUDE_STA_METRIC,
#if (EASYMESH_VERSION > 2)
		WIFI_RADIO_INCLUDE_WIFI6_STA_STATUS,
#endif
		WIFI_RADIO_RCPI_HYSTERESIS_MARGIN,
		WIFI_RADIO_REPORT_UTIL_THRESHOLD,
		NUM_WIFI_RADIO_POLICIES,
	};
	const struct uci_parse_option opts[] = {
		{ .name = "device", .type = UCI_TYPE_STRING },
		{ .name = "band", .type = UCI_TYPE_STRING },
		{ .name = "encryption", .type = UCI_TYPE_LIST },
		{ .name = "onboarded", .type = UCI_TYPE_STRING },
		{ .name = "dedicated_backhaul", .type = UCI_TYPE_STRING },
		{ .name = "steer_policy", .type = UCI_TYPE_STRING },
		{ .name = "util_threshold", .type = UCI_TYPE_STRING },
		{ .name = "rcpi_threshold", .type = UCI_TYPE_STRING },
		{ .name = "report_rcpi_threshold", .type = UCI_TYPE_STRING },
		{ .name = "include_sta_stats", .type = UCI_TYPE_STRING },
		{ .name = "include_sta_metric", .type = UCI_TYPE_STRING },
#if (EASYMESH_VERSION > 2)
		{ .name = "include_wifi6_sta_status", .type = UCI_TYPE_STRING },
#endif
		{ .name = "rcpi_hysteresis_margin", .type = UCI_TYPE_STRING },
		{ .name = "report_util_threshold", .type = UCI_TYPE_STRING },
	};
	struct uci_option *tb[NUM_WIFI_RADIO_POLICIES];
	const char *ifname = NULL;
	uint32_t band = 0;
	struct agent_config_radio *n;

	uci_parse_section(s, opts, NUM_WIFI_RADIO_POLICIES, tb);

	if (!tb[WIFI_RADIO_DEVICE] || !tb[WIFI_RADIO_BAND]) {
		warn("No radio name or band option found!\n");
		return -1;
	}

	if (tb[WIFI_RADIO_DEVICE])
		ifname = tb[WIFI_RADIO_DEVICE]->v.string;

	if (tb[WIFI_RADIO_BAND]) {
		band = atoi(tb[WIFI_RADIO_BAND]->v.string);
		if (band != 2 && band != 5 && band != 6) {
			warn("Incorrect band '%d' in config\n", band);
			return -1;
		}
	}

	if (ifname && band) {
		uint8_t rcpi_threshold = 0, report_rcpi_threshold = 0;

		n = get_agent_config_radio(a, ifname);
		if (!n) {
			n = calloc(1, sizeof(*n));
			if (!n) {
				warn("-ENOMEM!\n");
				return -1;
			}

			list_add_tail(&n->list, &a->radiolist);
		}

		strncpy(n->name, ifname, 16);
		n->name[15] = '\0';
		if (band == 2) {
			n->band = BAND_2;
			rcpi_threshold = 70;
			report_rcpi_threshold = 80;
		} else if (band == 5) {
			n->band = BAND_5;
			rcpi_threshold = 86;
			report_rcpi_threshold = 96;
		} else if (band == 6) {
			/* TODO check/set this */
			n->band = BAND_6;
			rcpi_threshold = 86;
			report_rcpi_threshold = 96;
		}
		else
			n->band = BAND_UNKNOWN;

		if (tb[WIFI_RADIO_ONBOARDED]) {
			n->onboarded = atoi(tb[WIFI_RADIO_ONBOARDED]->v.string) == 1 ?
									true : false;
		}

		if (tb[WIFI_RADIO_ENCRYPTION]) {
			struct uci_element *xi;

			uci_foreach_element(&tb[WIFI_RADIO_ENCRYPTION]->v.list, xi) {
				if (!strcmp(xi->name, "sae-mixed")) {
					n->encryption |= WPS_AUTH_WPA2PSK;
					n->encryption |= WPS_AUTH_SAE;
				} else if (!strcmp(xi->name, "sae")) {
					n->encryption |= WPS_AUTH_SAE;
				} else if (!strcmp(xi->name, "psk2")) {
					n->encryption |= WPS_AUTH_WPA2PSK;
				} else if (!strcmp(xi->name, "none")) {
					n->encryption |= WPS_AUTH_OPEN;
				} else if (!strcmp(xi->name, "psk-mixed")) {
					n->encryption |= WPS_AUTH_WPAPSK;
					n->encryption |= WPS_AUTH_WPA2PSK;
				} else if (!strcmp(xi->name, "psk")) {
					n->encryption |= WPS_AUTH_WPAPSK;
				} else if (!strcmp(xi->name, "wpa")) {
					n->encryption |= WPS_AUTH_WPA;
				} else if (!strcmp(xi->name, "wpa2")) {
					n->encryption |= WPS_AUTH_WPA2;
				}
			}
		} else {
			n->encryption |= WPS_AUTH_WPA2PSK;
			n->encryption |= WPS_AUTH_SAE;
			n->encryption |= WPS_AUTH_OPEN;
			n->encryption |= WPS_AUTH_WPA;
			n->encryption |= WPS_AUTH_WPA2;
			n->encryption |= WPS_AUTH_WPAPSK;
		}

		if (tb[WIFI_RADIO_DEDICATED]) {
			n->dedicated_backhaul = atoi(tb[WIFI_RADIO_DEDICATED]->v.string) == 1 ?
									true : false;
		}

		if (tb[WIFI_RADIO_RCPI_THRESHOLD])
			n->rcpi_threshold = atoi(tb[WIFI_RADIO_RCPI_THRESHOLD]->v.string);
		else
			n->rcpi_threshold = rcpi_threshold;

		if (tb[WIFI_RADIO_REPORT_RCPI_THRESHOLD])
			n->report_rcpi_threshold =
				atoi(tb[WIFI_RADIO_REPORT_RCPI_THRESHOLD]->v.string);
		else
			n->report_rcpi_threshold = report_rcpi_threshold;

		if (tb[WIFI_RADIO_STEER_POLICY])
			n->steer_policy = atoi(tb[WIFI_RADIO_STEER_POLICY]->v.string);

		if (tb[WIFI_RADIO_UTIL_THRESHOLD])
			n->util_threshold = atoi(tb[WIFI_RADIO_UTIL_THRESHOLD]->v.string);

		if (tb[WIFI_RADIO_RCPI_HYSTERESIS_MARGIN])
			n->rcpi_hysteresis_margin =
				atoi(tb[WIFI_RADIO_RCPI_HYSTERESIS_MARGIN]->v.string);

		if (tb[WIFI_RADIO_REPORT_UTIL_THRESHOLD])
			n->report_util_threshold =
				atoi(tb[WIFI_RADIO_REPORT_UTIL_THRESHOLD]->v.string);

		if (tb[WIFI_RADIO_INCLUDE_STA_STATS])
			n->include_sta_stats =
				atoi(tb[WIFI_RADIO_INCLUDE_STA_STATS]->v.string);

		if (tb[WIFI_RADIO_INCLUDE_STA_METRIC])
			n->include_sta_metric =
				atoi(tb[WIFI_RADIO_INCLUDE_STA_METRIC]->v.string);

#if (EASYMESH_VERSION > 2)
		if (tb[WIFI_RADIO_INCLUDE_WIFI6_STA_STATUS])
			n->include_wifi6_sta_status =
				atoi(tb[WIFI_RADIO_INCLUDE_WIFI6_STA_STATUS]->v.string);
#endif
	}

	return 0;
}

static int agent_config_get_bk_iface(struct agent_config *a,
		struct uci_section *s)
{
	enum {
		BK_IFNAME,
		BK_DEVICE,
		BK_BAND,
		BK_ENABLED,
		BK_ONBOARDED,
		BK_SSID,
		BK_KEY,
		BK_ENCRYPTION,
		BK_BSSID,
		BK_PRIORITY,
		NUM_POLICIES
	};
	const struct uci_parse_option opts[] = {
		{ .name = "ifname", .type = UCI_TYPE_STRING },
		{ .name = "device", .type = UCI_TYPE_STRING },
		{ .name = "band", .type = UCI_TYPE_STRING },
		{ .name = "enabled", .type = UCI_TYPE_STRING },
		{ .name = "onboarded", .type = UCI_TYPE_STRING },
		{ .name = "ssid", .type = UCI_TYPE_STRING },
		{ .name = "key", .type = UCI_TYPE_STRING },
		{ .name = "encryption", .type = UCI_TYPE_STRING },
		{ .name = "bssid", .type = UCI_TYPE_STRING },
		{ .name = "priority", .type = UCI_TYPE_STRING }
	};
	struct uci_option *tb[NUM_POLICIES];
	struct netif_bkcfg *bk;
	const char *ifname;

	uci_parse_section(s, opts, NUM_POLICIES, tb);

	if (tb[BK_IFNAME]) {
		ifname = tb[BK_IFNAME]->v.string;
		bk = get_netif_bkcfg_by_name(a, ifname);
		if (!bk) {
			bk = create_backhaul_iface_config(a, ifname);
			if (!bk) {
				warn("%s: OOM!\n", __func__);
				return -1;
			}
		} else {
			warn("Duplicate 'bsta %s' config!! ignore\n",
					ifname);
		}
	} else {
		warn("No ifname in bsta section!\n");
		return -1;
	}

	if (tb[BK_DEVICE]) {
		const char *device;

		device = tb[BK_DEVICE]->v.string;
		strncpy(bk->device, device, sizeof(bk->device) - 1);
	}

	if (tb[BK_ENABLED])
		bk->enabled = atoi(tb[BK_ENABLED]->v.string);

	if (tb[BK_ONBOARDED])
		bk->onboarded = atoi(tb[BK_ONBOARDED]->v.string);

	if (tb[BK_BAND]) {
		int band = atoi(tb[BK_BAND]->v.string);

		if (band == 2)
			bk->band = BAND_2;
		else if (band == 5)
			bk->band = BAND_5;
		else if (band == 6)
			bk->band = BAND_6;
	}

	if (tb[BK_SSID]) {
		const char *ssid;

		ssid = tb[BK_SSID]->v.string;
		strncpy(bk->ssid, ssid, sizeof(bk->ssid) - 1);
	}

	if (tb[BK_KEY]) {
		const char *key;

		key = tb[BK_KEY]->v.string;
		strncpy(bk->key, key, sizeof(bk->key) - 1);
	}

	if (tb[BK_ENCRYPTION]) {
		const char *encryption;

		encryption = tb[BK_ENCRYPTION]->v.string;
		strncpy(bk->encryption, encryption, sizeof(bk->encryption) - 1);
	}

	if (tb[BK_BSSID])
		hwaddr_aton(tb[BK_BSSID]->v.string, bk->bssid);

	if (tb[BK_PRIORITY])
		bk->priority = atoi(tb[BK_PRIORITY]->v.string);
	else {
		if (bk->band == 2)
			bk->priority = 2;
		else if (bk->band == 5)
			bk->priority = 1;
		else if (bk->band == 6)
			bk->priority = 0;
	}


	return 0;
}

static int agent_config_get_ap(struct agent_config *a,
		struct uci_section *s)
{
	enum {
		FH_IFNAME,
		FH_BAND,
		FH_STEER,
		FH_DEVICE,
		FH_ASSOC_CTRL,
		FH_BTM_RETRY,
		FH_BTM_RETRY_SECS,
		FH_FLBK_LEGACY,
		FH_STEER_LEGACY_RASSOC_SECS,
		FH_STEER_LEGACY_RETRY_SECS,
		FH_ASSOC_CTRL_SECS,
		FH_SSID,
		FH_KEY,
		FH_ENCRYPTION,
		FH_ENABLED,
		FH_VID,
		FH_TYPE,
		FH_BSTA_DISALLOW,
		NUM_POLICIES,
	};
	const struct uci_parse_option opts[] = {
		{ .name = "ifname", .type = UCI_TYPE_STRING },
		{ .name = "band", .type = UCI_TYPE_STRING },
		{ .name = "steer", .type = UCI_TYPE_LIST },
		{ .name = "device", .type = UCI_TYPE_STRING },
		{ .name = "assoc_ctrl", .type = UCI_TYPE_LIST },
		{ .name = "btm_retry", .type = UCI_TYPE_STRING },
		{ .name = "btm_retry_secs", .type = UCI_TYPE_STRING },
		{ .name = "fallback_legacy", .type = UCI_TYPE_STRING },
		{ .name = "steer_legacy_reassoc_secs", .type = UCI_TYPE_STRING },
		{ .name = "steer_legacy_retry_secs", .type = UCI_TYPE_STRING },
		{ .name = "assoc_ctrl_secs", .type = UCI_TYPE_STRING },
		{ .name = "ssid", .type = UCI_TYPE_STRING },
		{ .name = "key", .type = UCI_TYPE_STRING },
		{ .name = "encryption", .type = UCI_TYPE_STRING },
		{ .name = "enabled", .type = UCI_TYPE_STRING },
		{ .name = "vid", .type = UCI_TYPE_STRING },
		{ .name = "type", .type = UCI_TYPE_STRING },
		{ .name = "disallow_bsta", .type = UCI_TYPE_STRING }
	};
	struct uci_option *tb[NUM_POLICIES];
	struct netif_fhcfg *fh;

	uci_parse_section(s, opts, NUM_POLICIES, tb);

	if (tb[FH_IFNAME]) {
		const char *ifname;

		ifname = tb[FH_IFNAME]->v.string;

		fh = get_netif_fhcfg_by_name(a, ifname);
		if (!fh) {
			fh = create_fronthaul_iface_config(a, ifname);
			if (!fh) {
				warn("%s: OOM!\n", __func__);
				return -1;
			}
		} else {
			warn("Duplicate 'ap %s' config!! ignore\n",
					ifname);
		}
	} else {
		warn("No ifname in ap section!\n");
		return -1;
	}

	if (tb[FH_BAND]) {
		int band = atoi(tb[FH_BAND]->v.string);

		if (band == 2)
			fh->band = BAND_2;
		else if (band == 5)
			fh->band = BAND_5;
		else if (band == 6)
			fh->band = BAND_6;
	} else {
		dbg("|%s:%d| FH:%s is missing band option, discarding!\n",
		    __func__, __LINE__, fh->name);
		clean_fh(fh);
		return -1;
	}

	if (tb[FH_STEER]) {
		struct uci_element *xi;

		dbg("Steer: param: ");
		uci_foreach_element(&tb[FH_STEER]->v.list, xi) {
			struct steer_policy *p = NULL;
			struct steer_rule *r;

			dbg("%s ", xi->name);
			p = get_steer_policy_by_name(fh, xi->name);
			if (!p) {
				/* TODO? */
				dbg("TODO!! steer before ifname\n");
				continue;
			}
			p->enabled = true;
			r = get_steer_rule_by_name(xi->name);
			if (r)
				r->enabled = true;
		}
		dbg("\n");
	}

	if (tb[FH_DEVICE]) {
		const char *device;

		device = tb[FH_DEVICE]->v.string;

		strncpy(fh->device, device, sizeof(fh->device) - 1);
	} else {
		dbg("|%s:%d| FH:%s is missing device option, discarding!\n",
		    __func__, __LINE__, fh->name);
		clean_fh(fh);
		return -1;
	}

	if (tb[FH_BTM_RETRY])
		fh->steer_btm_retry = atoi(tb[FH_BTM_RETRY]->v.string);

	if (tb[FH_BTM_RETRY_SECS])
		fh->steer_btm_retry_secs = atoi(tb[FH_BTM_RETRY_SECS]->v.string);

	if (tb[FH_FLBK_LEGACY])
		fh->fallback_legacy = atoi(tb[FH_FLBK_LEGACY]->v.string);

	if (tb[FH_STEER_LEGACY_RASSOC_SECS])
		fh->steer_legacy_reassoc_secs =
				atoi(tb[FH_STEER_LEGACY_RASSOC_SECS]->v.string);

	if (tb[FH_STEER_LEGACY_RETRY_SECS])
		fh->steer_legacy_retry_secs =
				atoi(tb[FH_STEER_LEGACY_RETRY_SECS]->v.string);

	if (tb[FH_ASSOC_CTRL_SECS])
		fh->assoc_control_time =
				atoi(tb[FH_ASSOC_CTRL_SECS]->v.string);

	if (tb[FH_SSID]) {
		const char *ssid;

		ssid = tb[FH_SSID]->v.string;
		strncpy(fh->ssid, ssid, sizeof(fh->ssid) - 1);
	}

	if (tb[FH_KEY]) {
		const char *key;

		key = tb[FH_KEY]->v.string;
		strncpy(fh->key, key, sizeof(fh->key) - 1);
	}

	if (tb[FH_ENCRYPTION]) {
		const char *encryption;

		encryption = tb[FH_ENCRYPTION]->v.string;
		strncpy(fh->encryption, encryption, sizeof(fh->encryption) - 1);
	}

	if (tb[FH_ENABLED])
		fh->enabled = atoi(tb[FH_ENABLED]->v.string);

	if (tb[FH_VID])
		fh->vid = atoi(tb[FH_VID]->v.string);
	else
		fh->vid = 0;

	if (tb[FH_TYPE]) {
		const char *type = tb[FH_TYPE]->v.string;

		if (!strcmp(type, "backhaul"))
			fh->multi_ap = 1;
		else if (!strcmp(type, "fronthaul"))
			fh->multi_ap = 2;
		else if (!strcmp(type, "combined"))
			fh->multi_ap = 3;
		else {
			clean_fh(fh);
			return -1;
		}
	}

	if (tb[FH_BSTA_DISALLOW])
		fh->bsta_disallow = atoi(tb[FH_BSTA_DISALLOW]->v.string);

	return 0;
}

static int agent_config_get_steer_param(struct agent_config *a,
		struct uci_section *s)
{
	struct steer_rule *r;

	dbg("Steer-param: %s\n", s->e.name);
	r = get_steer_rule_by_name(s->e.name);
	if (!r)
		return -1;

	dbg("Rule to handle steer-param '%s' available\n", s->e.name);
	r->config(r, a, s);

	return 0;
}

static int agent_config_get_policy_param(struct agent_config *a,
		struct uci_section *s)
{
	enum {
		POL_REPORT_INTERVAL,
		POL_PVID,
		POL_PCP_DEFAULT,
		POL_REPORT_SCAN,
		POL_REPORT_STA_ASSOCFAILS,
		POL_REPORT_STA_ASSOCFAILS_RATE,
		POL_EXCLUDE,
		POL_EXCLUDE_BTM,
		NUM_POLICIES
	};
	const struct uci_parse_option opts[] = {
		{ .name = "report_interval", .type = UCI_TYPE_STRING },
		{ .name = "pvid", .type = UCI_TYPE_STRING },
		{ .name = "pcp_default", .type = UCI_TYPE_STRING },
		{ .name = "report_scan", .type = UCI_TYPE_STRING },
		{ .name = "report_sta_assocfails", .type = UCI_TYPE_STRING },
		{ .name = "report_sta_assocfails_rate", .type = UCI_TYPE_STRING },
		{ .name = "steer_exclude", .type = UCI_TYPE_LIST },
		{ .name = "steer_exclude_btm", .type = UCI_TYPE_LIST },
	};

	struct uci_option *tb[NUM_POLICIES];
	struct policy_cfg *cfg;

	uci_parse_section(s, opts, NUM_POLICIES, tb);

	cfg = (struct policy_cfg *)calloc(1, sizeof(struct policy_cfg));
	if (!cfg)
		return -1;

	INIT_LIST_HEAD(&cfg->steer_excludelist);
	INIT_LIST_HEAD(&cfg->steer_btm_excludelist);

	if (tb[POL_REPORT_INTERVAL])
		cfg->report_interval = atoi(tb[POL_REPORT_INTERVAL]->v.string);

	if (tb[POL_PVID])
		cfg->pvid = atoi(tb[POL_PVID]->v.string);

	if (tb[POL_PCP_DEFAULT])
		cfg->pcp_default = atoi(tb[POL_PCP_DEFAULT]->v.string);

	if (tb[POL_REPORT_SCAN])
		cfg->report_scan = atoi(tb[POL_REPORT_SCAN]->v.string);

	if (tb[POL_REPORT_STA_ASSOCFAILS])
		cfg->report_sta_assocfails =
			atoi(tb[POL_REPORT_STA_ASSOCFAILS]->v.string);

	if (tb[POL_REPORT_STA_ASSOCFAILS_RATE])
		cfg->report_sta_assocfails_rate =
			atoi(tb[POL_REPORT_STA_ASSOCFAILS_RATE]->v.string);

	if (tb[POL_EXCLUDE]) {
		struct uci_element *xi;

		dbg("Steer: exclude: ");
		uci_foreach_element(&tb[POL_EXCLUDE]->v.list, xi) {
			dbg("%s ", xi->name);
			stax_add_entry(&cfg->steer_excludelist, xi->name);
		}
		dbg("\n");
	}

	if (tb[POL_EXCLUDE_BTM]) {
		struct uci_element *xi;

		dbg("Steer: exclude_btm: ");
		uci_foreach_element(&tb[POL_EXCLUDE_BTM]->v.list, xi) {
			dbg("%s ", xi->name);
			stax_add_entry(&cfg->steer_btm_excludelist, xi->name);
		}
		dbg("\n");
	}

	if (a->pcfg) {
		free(a->pcfg);
	}

	a->pcfg = cfg;

	return 0;
}

int agent_config_load(struct agent_config *cfg)
{
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_element *e;

	cfg->enabled = false;
	cfg->runfreq = AGENT_RUN_AUTO;

	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	if (uci_load(ctx, "mapagent", &pkg)) {
		uci_free_context(ctx);
		return -1;
	}

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, "agent"))
			agent_config_get_wifi_agent(cfg, s);
		else if (!strcmp(s->type, "controller_select"))
			agent_config_get_controller_select(cfg, s);
		else if (!strcmp(s->type, "dynamic_backhaul"))
			agent_config_get_dynamic_backhaul(cfg, s);
		else if (!strcmp(s->type, "radio"))
			agent_config_get_wifi_radio(cfg, s);
		else if (!strcmp(s->type, "ap"))
			agent_config_get_ap(cfg, s);
		else if (!strcmp(s->type, "bsta"))
			agent_config_get_bk_iface(cfg, s);
		else if (!strcmp(s->type, "steer"))
			agent_config_get_steer_param(cfg, s);
		else if (!strcmp(s->type, "policy"))
			agent_config_get_policy_param(cfg, s);
	}

	uci_free_context(ctx);
	return 0;
}

int config_generate_radio(struct agent_config *cfg, struct uci_context *ctx,
			  const char *device, uint8_t band)
{
	struct uci_package *pkg;
	struct uci_section *s;
	int rv;

	rv = uci_load(ctx, UCI_AGENT, &pkg);
	if (rv)
		return -1;

	s = config_add_section(ctx, pkg, UCI_AGENT, "radio", "device", device);
	if (!s)
		return -1;

	if (band == BAND_2)
		set_value(ctx, pkg, s, "band", "2", UCI_TYPE_STRING);
	else if (band == BAND_5)
		set_value(ctx, pkg, s, "band", "5", UCI_TYPE_STRING);
	else if (band == BAND_6)
		set_value(ctx, pkg, s, "band", "6", UCI_TYPE_STRING);

	//TODO: read from ieee1905 uci config and add he

	uci_commit(ctx, &pkg, false);
	uci_unload(ctx, pkg);
	return 0;
}

int config_generate_bsta_agent(struct agent_config *cfg, struct uci_context *ctx,
		const char *device, const char *ifname,
		uint8_t band)
{
	struct uci_section *s;
	struct uci_package *pkg;
	int rv;

	rv = uci_load(ctx, UCI_AGENT, &pkg);
	if (rv)
		return -1;

	s = config_add_section(ctx, pkg, UCI_AGENT, UCI_BK_AGENT, "device",
			device);
	if (!s)
		return -1;

	if (band == BAND_2)
		set_value(ctx, pkg, s, "band", "2", UCI_TYPE_STRING);
	else if (band == BAND_5)
		set_value(ctx, pkg, s, "band", "5", UCI_TYPE_STRING);
	else if (band == BAND_6)
		set_value(ctx, pkg, s, "band", "6", UCI_TYPE_STRING);

	set_value(ctx, pkg, s, "ifname", ifname, UCI_TYPE_STRING);
	uci_commit(ctx, &pkg, false);
	uci_unload(ctx, pkg);
	return 0;
}

int config_generate_ap_agent(struct agent_config *cfg, struct uci_context *ctx,
		const char *device, const char *ifname,
		int multi_ap, uint8_t band)
{
	struct uci_section *s;
	struct uci_package *pkg;
	int rv;

	rv = uci_load(ctx, UCI_AGENT, &pkg);
	if (rv)
		return -1;

	s = config_add_section(ctx, pkg, UCI_AGENT, UCI_FH_AGENT, "ifname",
		ifname);
	if (!s) {
		uci_unload(ctx, pkg);
		return -1;
	}

	if (multi_ap == 2)
		set_value(ctx, pkg, s, "type", "fronthaul", UCI_TYPE_STRING);
	else if (multi_ap == 1)
		set_value(ctx, pkg, s, "type", "backhaul", UCI_TYPE_STRING);
	else if (multi_ap == 3)
		set_value(ctx, pkg, s, "type", "combined", UCI_TYPE_STRING);

	set_value(ctx, pkg, s, "device", device, UCI_TYPE_STRING);

	if (band == BAND_2)
		set_value(ctx, pkg, s, "band", "2", UCI_TYPE_STRING);
	else if (band == BAND_5)
		set_value(ctx, pkg, s, "band", "5", UCI_TYPE_STRING);
	else if (band == BAND_6)
		set_value(ctx, pkg, s, "band", "6", UCI_TYPE_STRING);
	uci_commit(ctx, &pkg, false);
	uci_unload(ctx, pkg);
	return 0;
}

int config_find_radio(struct agent_config *cfg, struct uci_context *ctx,
		      const char *radio)
{
	struct uci_package *pkg;
	struct uci_section *s;
	bool found = false;
	int rv;

	rv = uci_load(ctx, UCI_AGENT, &pkg);
	if (rv)
		return found;

	s = config_get_section(ctx, pkg, "radio", "device", radio);
	if (s)
		found = true;

	uci_unload(ctx, pkg);
	return found;
}

void config_disable_bstas(struct agent_config *cfg)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg;
	struct uci_section *section;
	struct netif_bkcfg *bk;
	bool reload = false;


	list_for_each_entry(bk, &cfg->bklist, list) {
		/* only disable onboarded bsta */
//		if (!bk->cfg->onboarded)
//			continue;

		/* disable from wireless config */
		pkg = uci_load_pkg(&ctx, UCI_WIRELESS);
		if (!pkg)
			continue;

		section = config_get_section(ctx, pkg, UCI_WLAN_IFACE, "ifname", bk->name);
		if (!section) {
			uci_unload(ctx, pkg);
			continue;
		}

		set_value(ctx, pkg, section, "disabled", "1", UCI_TYPE_STRING);
		uci_save(ctx, pkg);
		reload = true;
	}

	if (reload) {
		uci_commit(ctx, &pkg, false);
		uci_unload(ctx, pkg);
	}


	list_for_each_entry(bk, &cfg->bklist, list) {
		pkg = uci_load_pkg(&ctx, UCI_AGENT);
		if (!pkg)
			continue;

		section = config_get_section(ctx, pkg, UCI_BK_AGENT, "ifname", bk->name);
		if (!section) {
			uci_unload(ctx, pkg);
			continue;
		}

		set_value(ctx, pkg, section, "enabled", "0", UCI_TYPE_STRING);
		uci_save(ctx, pkg);
		bk->enabled = 0;
	}

	if (reload) {
		uci_commit(ctx, &pkg, false);
		uci_reload_services("wireless");
	}

	uci_free_context(ctx);
}

int config_set_bsta(struct netif_bkcfg *bk, int enable)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg;
	struct uci_section *section;
	int ret = -1;

	/* disable mapagent bsta section */
	pkg = uci_load_pkg(&ctx, UCI_AGENT);
	if (!pkg)
		return -1;

	section = config_get_section(ctx, pkg, UCI_BK_AGENT, "ifname", bk->name);
	if (!section)
		goto out_pkg;

	if (enable)
		set_value(ctx, pkg, section, "enabled", "1", UCI_TYPE_STRING);
	else
		set_value(ctx, pkg, section, "enabled", "0", UCI_TYPE_STRING);
	uci_save(ctx, pkg);
	bk->enabled = !!enable;
	uci_commit(ctx, &pkg, false);

out_pkg:
	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return ret;
}

int config_disable_bsta(struct netif_bkcfg *bk)
{
	return config_set_bsta(bk, 0);
}

int config_enable_bsta(struct netif_bkcfg *bk)
{
	return config_set_bsta(bk, 1);
}

bool config_find_bsta_agent(struct agent_config *cfg, struct uci_context *ctx,
			    const char *device)
{
	struct uci_package *pkg;
	struct uci_element *e;
	bool found = false;
	int rv;


	rv = uci_load(ctx, UCI_AGENT, &pkg);
	if (rv)
		return found;

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		const char *c_device;

		if (strncmp(s->type, UCI_BK_AGENT, strlen(UCI_BK_AGENT)))
			continue;

		c_device = uci_lookup_option_string(ctx, s, "device");
		if (!c_device)
			continue;

		if (strncmp(device, c_device, 16))
			continue;

		found = true;
		break;
	}

	uci_unload(ctx, pkg);
	return found;
}

bool config_find_ap_agent(struct agent_config *cfg, struct uci_context *ctx,
				const char *ifname)
{
	struct uci_package *pkg;
	struct uci_element *e;
	bool found = false;
	int rv;

	rv = uci_load(ctx, UCI_AGENT, &pkg);
	if (rv)
		return found;

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		const char *c_ifname;

		if (strncmp(s->type, UCI_FH_AGENT, strlen(UCI_FH_AGENT)))
			continue;

		c_ifname = uci_lookup_option_string(ctx, s, "ifname");
		if (!c_ifname)
			continue;

		if (strncmp(ifname, c_ifname, 16))
			continue;

		found = true;
		break;
	}

	uci_unload(ctx, pkg);
	return found;
}


struct uci_section *config_find_bsta_wireless(struct agent_config *cfg,
					      struct uci_context *ctx,
					      struct uci_package *pkg,
					      const char *device)
{
	struct uci_element *e;

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		const char *c_device, *mode;

		if (strncmp(s->type, UCI_WLAN_IFACE, strlen(UCI_WLAN_IFACE)))
			continue;

		c_device = uci_lookup_option_string(ctx, s, "device");
		if (!c_device || strncmp(device, c_device, 16))
			continue;

		mode = uci_lookup_option_string(ctx, s, "mode");
		if (!mode || strcmp(mode, "sta"))
			continue;

		return s;
	}

	return NULL;
}

int agent_init_wsc_attributes(struct agent *a)
{
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_element *e;


	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	if (uci_load(ctx, UCI_IEEE1905, &pkg)) {
		uci_free_context(ctx);
		return -1;
	}

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, "ap")) {
			uint8_t default_dev_type[8] = { 0x00, 0x06, 0x00, 0x50, 0xf2, 0x04, 0x00, 0x01 }; /* default WPS oui */
			const char *manufacturer, *model_name, *device_name;
			const char *model_number, *serial_number, *device_type;
			bool found = false;
			uint32_t freqband;
			const char *band;
			int i;
			struct wifi_radio_element *radio;


			band = uci_lookup_option_string(ctx, s, "band");
			if (!band || atoi(band) == 0)
				continue;

			if (atoi(band) == 5)
				freqband = BAND_5;
			else if (atoi(band) == 2)
				freqband = BAND_2;
			else if (atoi(band) == 6)
				freqband = BAND_6;
			else
				continue;

			for (i = 0; i < a->num_radios; i++) {
				radio = a->radios + i;

				if (radio->band == freqband) {
					found = true;
					break;
				}
			}

			if (!found)
				continue;

			manufacturer = uci_lookup_option_string(ctx, s, "manufacturer");
			if (manufacturer)
				strncpy(radio->manufacturer, manufacturer, 63);

			model_name = uci_lookup_option_string(ctx, s, "model_name");
			if (model_name)
				strncpy(radio->model_name, model_name, 32);

			device_name = uci_lookup_option_string(ctx, s, "device_name");
			if (device_name)
				strncpy(radio->device_name, device_name, 32);

			model_number = uci_lookup_option_string(ctx, s, "model_number");
			if (model_number)
				strncpy(radio->model_number, model_number, 32);

			serial_number = uci_lookup_option_string(ctx, s, "serial_number");
			if (serial_number)
				strncpy(radio->serial_number, serial_number, 32);

			memcpy(radio->device_type, default_dev_type, 8);
			device_type = uci_lookup_option_string(ctx, s, "device_type");
			if (device_type) {
				int ret;
				uint8_t oui[4] = {0};
				uint16_t category = 0, sub_category = 0;

				ret = sscanf(device_type, "%02hu-%02hhx%02hhx%02hhx%02hhx-%02hu",
					     &category,
					     &oui[0], &oui[1], &oui[2], &oui[3],
					     &sub_category);
				if (ret == 6) {
					buf_put_be16(&radio->device_type[0], category);
					memcpy(&radio->device_type[2], oui, 4);
					buf_put_be16(&radio->device_type[6], sub_category);
				}
			}

		}
	}

	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return 0;
}

static void agent_wifi_bands_cb(struct ubus_request *req, int type,
		struct blob_attr *msg)
{
	struct band_mapping *band_map = (struct band_mapping *)req->priv;
	struct json_object *json_msg;
	struct json_object *radio_array;
	char *json_str;
	int i, len = 0;

	dbg("%s: --->\n", __func__);

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

	dbg("%s: num_radios(len) = %d\n", __func__, len);
	band_map->count = len;
	for (i = 0; i < len; i++) {
		struct json_object *radio_obj, *radio_obj_name;
		const char *radio_name, *band_str;

		radio_obj = json_object_array_get_idx(radio_array, i);
		json_object_object_get_ex(radio_obj, "name", &radio_obj_name);
		radio_name = json_object_get_string(radio_obj_name);
		strncpy(band_map->dev_band[i].device, radio_name, 15);

		json_object_object_get_ex(radio_obj, "band", &radio_obj_name);
		band_str = json_object_get_string(radio_obj_name);

		if (!strncmp(band_str, "5GHz", 7))
			band_map->dev_band[i].band = BAND_5;
		else if (!strncmp(band_str, "2.4GHz", 7))
			band_map->dev_band[i].band = BAND_2;
		else if (!strncmp(band_str, "6GHz", 7))
			band_map->dev_band[i].band = BAND_6;
		else
			band_map->dev_band[i].band = BAND_UNKNOWN;
	}

out_json:
	json_object_put(json_msg);
out_str:
	free(json_str);
}

int agent_config_prepare(struct agent_config *cfg)
{
	// TODO: iterate through 'wifi-device' sections in wireless config.
	// If corresponding 'radio <device-name>' section is not available
	// in 'mapagent' config, create one. Check supported bands of the new
	// wifi-device and add option 'band' to the radio section.
	struct uci_context *ctx = NULL;
	struct uci_package *pkg;
	struct uci_element *e;
	struct blob_buf bb = {0};
	struct band_mapping band_map = {0};

	int rv = 0;
	int i = 0;

	pkg = uci_load_pkg(&ctx, UCI_WIRELESS);
	if (!pkg)
		return -1;

	blob_buf_init(&bb, 0);

	rv = ubus_call("wifi", "status", &bb,
			agent_wifi_bands_cb, &band_map);
	if (rv)
		return -1;

	for (i = 0; i < band_map.count; i++)
		dbg("[%s %d] device = %s band = %d count = %d\n", __func__, __LINE__,
			band_map.dev_band[i].device, band_map.dev_band[i].band, band_map.count);


	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		struct uci_section *wl_s;
		const char *device, *ifname;
		uint8_t band = BAND_UNKNOWN;
		int i = 0;

		const char *wifname = NULL, *wmode = NULL;
		const char *wdevice = NULL, *wmulti_ap = NULL;
		int multi_ap;

		if (!(strncmp(s->type, UCI_WL_DEVICE, strlen(UCI_WL_DEVICE)))) {

			device = s->e.name;

			for (i = 0; i < band_map.count; i++) {
				if (!(strncmp(band_map.dev_band[i].device, device, 15))) {
					band = band_map.dev_band[i].band;
					break;
				}
			}
			if (band == BAND_UNKNOWN)
				continue;

			if (!config_find_radio(cfg, ctx, device))
				config_generate_radio(cfg, ctx, device, band);

			if (config_find_bsta_agent(cfg, ctx, device))
				continue;

			wl_s = config_find_bsta_wireless(cfg, ctx, pkg, device);
			if (!wl_s)
				continue;

			ifname = uci_lookup_option_string(ctx, wl_s, "ifname");
			if (!ifname)
				continue;

			config_generate_bsta_agent(cfg, ctx, device, ifname, band);

		} else if (!(strncmp(s->type, UCI_WLAN_IFACE, strlen(UCI_WLAN_IFACE)))) {

			wmode = uci_lookup_option_string(ctx, s, "mode");
			if (!wmode || strcmp(wmode, "ap"))
				continue;

			wifname = uci_lookup_option_string(ctx, s, "ifname");
			if (!wifname)
			       continue;

			wdevice = uci_lookup_option_string(ctx, s, "device");
			if (!wdevice)
				continue;

			wmulti_ap = uci_lookup_option_string(ctx, s, "multi_ap");
			if (!wmulti_ap)
				continue;

			if (config_find_ap_agent(cfg, ctx, wifname))
				continue;

			multi_ap = atoi(wmulti_ap);

			for (i = 0; i < band_map.count; i++) {
				if (!(strncmp(band_map.dev_band[i].device, wdevice, 15))) {
					band = band_map.dev_band[i].band;
					break;
				}
			}
			dbg("[%s %d] device = %s band = %d \n", __func__, __LINE__,
				wdevice, band);

			if (band == BAND_UNKNOWN)
				continue;

			config_generate_ap_agent(cfg, ctx, wdevice, wifname, multi_ap, band);
		}
	}

	blob_buf_free(&bb);
	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return 0;
}

int agent_config_init(struct agent *a, struct agent_config *cfg)
{
	INIT_LIST_HEAD(&cfg->fhlist);
	INIT_LIST_HEAD(&cfg->bklist);
	INIT_LIST_HEAD(&cfg->radiolist);

	agent_config_prepare(cfg);
	agent_config_load(cfg);

	if (a->cfg.cscfg) {
		a->cntlr_select.local = a->cfg.cscfg->local;
		a->cntlr_select.auto_detect = a->cfg.cscfg->auto_detect;
		a->cntlr_select.probe_int = a->cfg.cscfg->probe_int;
		a->cntlr_select.retry_int = a->cfg.cscfg->retry_int;
		a->cntlr_select.autostart = a->cfg.cscfg->autostart;
		memcpy(a->cntlr_select.alid, a->cfg.cscfg->alid, 6);
	}

	if (!a->cfg.dbhcfg.bh_miss_tmo)
		a->cfg.dbhcfg.bh_miss_tmo = DEFAULT_BH_MISS_TMO;

	if (!a->cfg.dbhcfg.bh_reconf_tmo)
		a->cfg.dbhcfg.bh_reconf_tmo = DEFAULT_BH_RECONF_TMO;

	//agent_config_get_ethwan(a->ethwan);

	//memcpy(a->cntlr_almac, a->cfg.cntlr_almac, 6);

	return 0;
}

void clean_bk(struct netif_bkcfg *p)
{
	list_del(&p->list);
	free(p);
}

int clean_all_bk(struct agent_config *cfg)
{
	struct netif_bkcfg *p, *tmp;

	list_for_each_entry_safe(p, tmp, &cfg->bklist, list)
		clean_bk(p);

	return 0;
}

void clean_fh(struct netif_fhcfg *p)
{
	list_del(&p->list);
	free(p);
}

int clean_all_fh(struct agent_config *cfg)
{
	struct netif_fhcfg *p, *tmp;

	list_for_each_entry_safe(p, tmp, &cfg->fhlist, list)
		clean_fh(p);

	return 0;
}

void clean_radio_cfg(struct agent_config_radio *p)
{
	list_del(&p->list);
	free(p);
}

int clean_all_radios(struct agent_config *cfg)
{
	struct agent_config_radio *p, *tmp;

	list_for_each_entry_safe(p, tmp, &cfg->radiolist, list)
		clean_radio_cfg(p);

	return 0;
}

int agent_config_clean(struct agent_config *cfg)
{
	clean_all_fh(cfg);
	clean_all_bk(cfg);
	clean_all_radios(cfg);
	if (cfg->pcfg) {
		clean_steer_btm_excl(cfg->pcfg);
		clean_steer_excl(cfg->pcfg);
		free(cfg->pcfg);
	}
	if (cfg->cscfg)
		free(cfg->cscfg);
	return 0;
}

/* config_calc_name - depending on the netdev option in UCI
 * wl : wl0, wl0.1, wl0.2
 * wl%. : wl0, wl0.1, wl0.2
 * wlan%_ : wlan0, wlan0_1, wlan0_2
 * wlan%_% : wlan0_0, wlan0_1, wlan0_2
 */
int config_calc_ifname(struct agent_config *cfg,
		uint8_t dev_num, uint8_t index, char *ifname)
{
	char fmt[IFNAMSIZ] = { 0 };
	char *posX, *posS, *posY;


	posX = strstr(cfg->netdev, "%");

	if (posX) {
		strncpy(fmt, cfg->netdev, labs(cfg->netdev - posX));
		strncat(fmt, "%hhu", sizeof(fmt) - strlen(fmt) - 1);
	} else {
		/* legacy: option netdev 'wl' (or 'wlan') */
		strncpy(fmt, cfg->netdev, sizeof(fmt));
		snprintf(ifname, IFNAMSIZ, "%s", cfg->netdev);
		snprintf(ifname + strlen(ifname), IFNAMSIZ, "%hhu", dev_num);
		if (index > 0) {
			snprintf(ifname + strlen(ifname), IFNAMSIZ, "%s",
					cfg->brcm_setup ? "." : "_");
			snprintf(ifname + strlen(ifname), IFNAMSIZ, "%hhu", index);
		}
		return 0;
	}

	posS = get_separator(cfg->netdev);

	if (posS) {
		posY = strchr(posS, '%');
		if (posY || index != 0) {
			if (sizeof(fmt) > strlen(fmt) + 1)
				/* add separator, e.g: '.' or '_' */
				strncat(fmt, posS, 1);
			strncat(fmt, "%hhu", sizeof(fmt) - strlen(fmt) - 1);
			snprintf(ifname, sizeof(fmt), fmt, dev_num, index);
		} else {
			snprintf(ifname, sizeof(fmt), fmt, dev_num);
		}
	}

	return 0;
}

int del_value_list(struct uci_context *ctx, struct uci_package *pkg,
		struct uci_section *s, const char *option,
		enum uci_option_type type)
{

	//struct uci_element *x, *x1, *tmp, *tmp1;
	//struct uci_option *op;
	struct uci_ptr ptr = {0};

	trace("Inside %s %d\n", __func__, __LINE__);

	ptr.p = pkg;
	ptr.s = s;
	ptr.option = option;
	uci_delete(ctx, &ptr);

	return 0;
}

int wifi_set_opclass_preference(char *radio_name, uint32_t opclass_id,
	uint32_t preference, uint8_t *channel_list, int channel_num)
{
	struct uci_section *s;
	struct uci_package *pkg;
	int ret = 0, i = 0;
	char pref_str[20];
	char opclassid_str[20];
	char channel_str[200];
	struct uci_context *ctx;

	trace("Inside %s %d\n", __func__, __LINE__);

	ctx = uci_alloc_context();
	if (!ctx)
		goto out;

	if (uci_load(ctx, UCI_AGENT, &pkg) != UCI_OK) {
		err("config file 'mapagent' not found!\n");
		ret = -1;
		goto out;
	}

	snprintf(opclassid_str, 20, "%u", opclass_id);
	trace("|%s %d| opclass [ %s] channel no. [%d]\n", __func__, __LINE__,
		opclassid_str, channel_num);
	s = config_add_section(ctx, pkg, UCI_AGENT, "opclass", "opclassid",
		opclassid_str);
	if (!s) {
		ret = -1;
		goto out;
	}
	memset(channel_str, 0, sizeof(channel_str));
	snprintf(pref_str, 20, "%u", preference);

	set_value(ctx, pkg, s, "preference", pref_str, UCI_TYPE_STRING);
	set_value(ctx, pkg, s, "radio", radio_name, UCI_TYPE_STRING);
	del_value_list(ctx, pkg, s, "channel", UCI_TYPE_LIST);

	for (i = 0; i < channel_num; i++) {
		char chan_str[8] = {0};

		snprintf(chan_str, 8, "%u", channel_list[i]);
		set_value(ctx, pkg, s, "channel", chan_str, UCI_TYPE_LIST);
	}

out:
	uci_commit(ctx, &pkg, false);
	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return ret;
}

struct uci_section *config_get_name_section(struct uci_context *ctx,
	struct uci_package *pkg, const char *type, const char *value)
{
	struct uci_element *e;
	struct uci_section *section;
	int ret = 0;

	trace("Inside %s %d\n", __func__, __LINE__);

	/* get the wet iface section */
	uci_foreach_element(&pkg->sections, e) {
		section = uci_to_section(e);
		if (strcmp(section->type, type))
			continue;

		ret = strcmp(section->e.name, value);
		dbg("Inside %s %d section name %s value %s \n", __func__, __LINE__,
			section->e.name, value);
		if (ret == 0)
			return section;
	}
	return NULL;
}

int wifi_set_transmit_power(char *ifname, uint32_t tx_power)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg;
	struct uci_section *section;
	char txpower_str[18] = {0};
	int ret = -1;

	trace("Inside %s %d\n", __func__, __LINE__);
	pkg = uci_load_pkg(&ctx, UCI_WIRELESS);
	if (!pkg)
		return ret;

	section = config_get_name_section(ctx, pkg, UCI_DEVICE, ifname);
	if (!section)
		goto out_pkg;

	if (tx_power)
		snprintf(txpower_str, 18, "%u", tx_power);

	dbg("|%s:%d| setting tx_power to %s\n",  __func__, __LINE__, txpower_str);

	ret = set_value(ctx, pkg, section, "txpower", txpower_str, UCI_TYPE_STRING);

	uci_commit(ctx, &pkg, false);

out_pkg:
	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return ret;
}

static int agent_config_get_opclass(struct  wifi_radio_element *radio,
		struct uci_section *s)
{
	enum {
		OP_CLASSID,
		OP_PREF,
		OP_RADIO,
		OP_CHANNEL,
		NUM_POLICIES
	};

	const struct uci_parse_option opts[] = {
		{ .name = "opclassid", .type = UCI_TYPE_STRING },
		{ .name = "preference", .type = UCI_TYPE_STRING },
		{ .name = "radio", .type = UCI_TYPE_STRING },
		{ .name = "channel", .type = UCI_TYPE_LIST },
	};

	struct uci_option *tb[NUM_POLICIES];
	struct wifi_radio_opclass_entry entry = {};
	struct wifi_radio_opclass_channel chan = {};
	int opclassid = 0;
	int pref = 0;
	int ret = 0;

	trace("Inside %s %d\n", __func__, __LINE__);

	uci_parse_section(s, opts, NUM_POLICIES, tb);

	if (tb[OP_RADIO]) {
		const char *ifname;

		ifname = tb[OP_RADIO]->v.string;
		trace("radio name [%s] ifname [%s]\n", radio->name, ifname);
		ret = strcmp(radio->name, ifname);
		if (ret != 0)
			return 0;
	}

	if (tb[OP_CLASSID])
		opclassid = atoi(tb[OP_CLASSID]->v.string);

	if (tb[OP_PREF])
		pref = atoi(tb[OP_PREF]->v.string);

	entry.id = opclassid;

	if (tb[OP_CHANNEL]) {
		struct uci_element *xi;

		dbg("Channel: param: classid %d pref %d\n", opclassid, pref);
		uci_foreach_element(&tb[OP_CHANNEL]->v.list, xi) {
			uint32_t channel = 0;

			channel = atoi(xi->name);
			chan.channel = channel;
			chan.preference = pref;

			wifi_opclass_add_channel(&entry, &chan);
		}
	}

	wifi_opclass_add_entry(&radio->req_opclass, &entry);
	return 0;
}

int agent_config_opclass(struct  wifi_radio_element *radio)
{
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_element *e;

	trace("Inside %s %d\n", __func__, __LINE__);

	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	if (uci_load(ctx, "mapagent", &pkg)) {
		uci_free_context(ctx);
		return -1;
	}

	memcpy(&radio->req_opclass, &radio->opclass, sizeof(radio->opclass));
	wifi_opclass_set_preferences(&radio->req_opclass, 0x0);

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, "opclass"))
			agent_config_get_opclass(radio, s);
	}

	uci_free_context(ctx);
	return 0;
}

