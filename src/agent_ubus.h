/*
 * agent_ubus.h - wifi agent's ubus object header
 *
 * Copyright (C) 2019 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#ifndef AGENT_UBUS_H
#define AGENT_UBUS_H

/* wifi agent ubus objects */
//extern struct ubus_object wifiagent_object;

int agent_publish_object(struct agent *a, const char *objname);
void agent_remove_object(struct agent *a);
void agent_notify_event(struct agent *a, void *ev_type, void *ev_data);

#endif /* AGENT_UBUS_H */
