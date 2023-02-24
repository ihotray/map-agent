/*
 * 1905_ubus.h - ieee1905 ubus interface
 *
 * Copyright (C) 2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 */

#ifndef IEEE1905_UBUS_H
#define IEEE1905_UBUS_H

struct cmdu_buff *ieee1905_ubus_buildcmdu(struct ubus_context *ubus_ctx,
			  uint16_t msg_type);
int ieee1905_ubus_send_cmdu(struct ubus_context *ubus_ctx,
			    struct cmdu_buff *cmdu, uint16_t *msgid,
			    uint16_t vid);
struct cmdu_buff *ieee1905_ubus_set_vid(struct ubus_context *ubus_ctx,
					uint16_t vid);
#endif /* IEEE1905_UBUS_H */

