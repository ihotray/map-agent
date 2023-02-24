/*
 * plugin.h
 * Plugin manager header
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef __PLUGIN_H
#define __PLUGIN_H

#include <stdint.h>
#include <libubox/list.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	PLUGIN_FUNC_1,
	PLUGIN_FUNC_2,
	PLUGIN_FUNC_NUM,
};

typedef int (*plugin_init_t)(void **priv, void *cfg);
typedef int (*plugin_exit_t)(void *priv);
typedef int (*plugin_func_t)(void *priv);

struct plugin {
	char name[128];
	uint8_t id[16];
	void *priv;
	plugin_init_t init;
	plugin_exit_t exit;
	plugin_func_t ops[PLUGIN_FUNC_NUM];
	void *handle;
	struct list_head list;
};

#ifdef __cplusplus
}
#endif

#endif /* __PLUGIN_H */
