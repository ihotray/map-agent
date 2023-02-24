/*
 * 1905_ubus.c - implements ieee1905 ubus interface functions
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 */

#include <stdio.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <uci.h>

#include <cmdu.h>

#include <map_module.h>
#include <easymesh.h>

#include "utils.h"
#include "debug.h"

struct buildcmdu_ctx {
	struct cmdu_buff *buff;
	int status;
};

static void ieee1905_ubus_buildcmdu_cb(struct ubus_request *req,
			  int type, struct blob_attr *msg)
{
	struct blob_attr *tb[2];
	static const struct blobmsg_policy ev_attr[2] = {
		[0] = { .name = "type", .type = BLOBMSG_TYPE_INT32 },
		[1] = { .name = "data", .type = BLOBMSG_TYPE_STRING }
	};
	uint16_t cmdu_type = 0, mid = 0;
	char *data;
	uint8_t origin[6] = { 0 };
	uint8_t *tlv;
	uint32_t b_len;
	struct buildcmdu_ctx *ctx = req->priv;
	struct cmdu_buff **buff = NULL;

	if (!ctx) {
		err("%s: No priv\n", __func__);
		return;
	}

	buff = &ctx->buff;

	if (!msg) {
		err("%s: Message NULL\n", __func__);
		ctx->status = -1;
		return;
	}


	blobmsg_parse(ev_attr, 2, tb, blob_data(msg), blob_len(msg));

	if (!tb[0] || !tb[1])
		return;

	cmdu_type = blobmsg_get_u32(tb[0]);
	data = blobmsg_get_string(tb[1]);
	if (!data) {
		err("%s: No data\n", __func__);
		ctx->status = -1;
		return;
	}

	dbg("|%s:%d| type = %u data = %s\n", __func__, __LINE__,
			cmdu_type, data);

	b_len = (strlen(data)/2) - 3;

	tlv = (uint8_t *) calloc(1, b_len);
	if (!tlv) {
		err("%s: No memory\n", __func__);
		ctx->status = -1;
		return;
	}

	strtob(data, b_len, tlv);

	*buff = cmdu_alloc_custom(cmdu_type, &mid, NULL, origin,
			tlv, b_len);
	free(tlv);

	if (!*buff) {
		err("%s: Couldn't allocate cmdu buff\n", __func__);
		ctx->status = -1;
		return;
	}

	ctx->status = 0;
}

struct cmdu_buff *ieee1905_ubus_buildcmdu(struct ubus_context *ubus_ctx,
			  uint16_t msg_type)
{
	struct blob_buf b = { 0 };
	int ret = 0;
	uint32_t id;
	struct buildcmdu_ctx ctx = {
		.buff = NULL,
		.status = -1,
	};


	dbg("|%s:%d| Entry\n", __func__, __LINE__);

	blob_buf_init(&b, 0);

	blobmsg_add_u32(&b, "type", (uint32_t)msg_type);

	if (ubus_lookup_id(ubus_ctx, "ieee1905", &id)) {
		dbg("|%s:%d| not present ieee1905", __func__, __LINE__);
		goto out;
	}

	ret = ubus_invoke(ubus_ctx, id, "buildcmdu",
			b.head, ieee1905_ubus_buildcmdu_cb,
			&ctx, 20000);

	if (ctx.status)
		ret = ctx.status;

	if (ret) {
		dbg("|%s:%d| ubus call failed for |ieee1905 buildcmdu|",
					__func__, __LINE__);
		goto out;
	}
out:
	blob_buf_free(&b);
	return ctx.buff;
}

struct send_cmdu_ctx {
	uint16_t mid;
	int status;
};

static void ieee1905_ubus_send_cmdu_cb(struct ubus_request *req,
			  int type, struct blob_attr *msg)
{
	struct json_object *jobj = NULL;
	char *str;
	struct send_cmdu_ctx *ctx = req->priv;
	int mid;

	if (!ctx) {
		err("%s: Missing UBUS request priv\n", __func__);
		return;
	}

	if (!msg) {
		err("%s: Message recieved is NULL\n", __func__);
		ctx->status = -1;
		return;
	}

	str = (char *)blobmsg_format_json_indent(msg, true, -1);

	if (str) {
		jobj = json_tokener_parse(str);
		free(str);
	}

	if (jobj == NULL) {
		ctx->status = -1;
		return;
	}

	mid = json_get_int(jobj, "mid");
	dbg("[%s:%d] agent map-mid:%d\n", __func__, __LINE__, mid);

	if (mid > 0)
		ctx->mid = (uint16_t)mid;

	json_object_put(jobj);
	ctx->status = 0;
}

int ieee1905_ubus_send_cmdu(struct ubus_context *ubus_ctx,
			    struct cmdu_buff *cmdu, uint16_t *msgid,
			    uint16_t vid)
{
	struct blob_buf bb = {};
	char dst_addr[18] = {};
	uint32_t id;
	struct send_cmdu_ctx ctx = {
		.mid = 0,
		.status = -1,
	};
	int ret = 0;

	ret = ubus_lookup_id(ubus_ctx, "ieee1905", &id);
	if (ret != UBUS_STATUS_OK)
		return -1;

	blob_buf_init(&bb, 0);

	blobmsg_add_u32(&bb, "type", cmdu_get_type(cmdu));

	hwaddr_ntoa(cmdu->origin, dst_addr);

	blobmsg_add_string(&bb, "dst", dst_addr);

	if (strlen(cmdu->dev_ifname))
		blobmsg_add_string(&bb, "ifname", cmdu->dev_ifname);

	blobmsg_add_u32(&bb, "mid", (uint32_t)cmdu_get_mid(cmdu));

	if (vid)
		blobmsg_add_u32(&bb, "vid", (uint32_t)vid);

	trace("|%s:%d|cmdu:%d|egress:%s|dst:%s|mid:%u|datalen:%u|ifname:%s|vid:%u\n",
	      __func__, __LINE__, cmdu_get_type(cmdu), "TODO", dst_addr,
	      cmdu_get_mid(cmdu), cmdu->datalen, cmdu->dev_ifname, vid);
	if (cmdu->datalen) {
		char *tlv_str = NULL;
		uint16_t len = 0;

		//char tlv_str[1500] = {0};

		len = (cmdu->datalen * 2) + 1;

		tlv_str = (char *)calloc(1, len);
		if (!tlv_str)
			goto out;
		btostr(cmdu->data, cmdu->datalen, tlv_str);

		tlv_str[len-1] = '\0';

		blobmsg_add_string(&bb, "data", tlv_str);
		trace("|%s:%d|data:%s|\n", __func__, __LINE__, tlv_str);
		free(tlv_str);
	}

	ret = ubus_invoke(ubus_ctx, id, "cmdu", bb.head,
			ieee1905_ubus_send_cmdu_cb, &ctx, 20 * 1000);

	if (ctx.status)
		ret = ctx.status;

	if (ret) {
		trace("[%s:%d] ubus call failed for |ieee1905 send| rc: %d\n",
					__func__, __LINE__, ret);
		goto out;
	}

	*msgid = ctx.mid;
	trace("|%s:%d| msgid = %d\n", __func__, __LINE__, *msgid);

out:
	blob_buf_free(&bb);
	trace("%s ret %d\n", __func__, ret);
	return ret;
}

int ieee1905_ubus_set_vid(struct ubus_context *ubus_ctx,
					uint16_t vid)
{
	struct blob_buf b = { 0 };
	int ret = 0;
	uint32_t id;


	dbg("|%s:%d| Entry\n", __func__, __LINE__);

	blob_buf_init(&b, 0);

	blobmsg_add_u32(&b, "vid", (uint32_t)vid);

	if (ubus_lookup_id(ubus_ctx, "ieee1905", &id)) {
		dbg("|%s:%d| not present ieee1905", __func__, __LINE__);
		goto out;
	}

	ret = ubus_invoke(ubus_ctx, id, "vlan", b.head, NULL, NULL, 20000);
	if (ret) {
		dbg("|%s:%d| ubus call failed for |ieee1905 vlan|",
					__func__, __LINE__);
		goto out;
	}
out:
	blob_buf_free(&b);
	return ret;
}
