/*
 * agent_ubus_dbg.h - for testing purpose only
 *
 * Copyright (C) 2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 */

#ifndef AGENT_UBUS_DBG_H
#define AGENT_UBUS_DBG_H

int agent_publish_dbg_object(struct agent *a, const char *objname);
void agent_remove_dbg_object(struct agent *a);

#endif /* AGENT_UBUS_H */
