/*
 * plugin.c
 * Plugin manager utility functions
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

//#include "list.h"
#include "plugin.h"

#define PLUGIN_PATH	"/usr/lib/map-plugins/"

static int plugin_load(const char *path, const char *name, void **handle)
{
	void *h;
	char abspath[256] = {0};
	int flags = 0;

	if (!handle || !name || !path)
		return -1;

	flags |= RTLD_NOW | RTLD_GLOBAL;

	snprintf(abspath, sizeof(abspath) - 1, "%s/%s", path, name);

	h = dlopen(abspath, flags);
	if (!h) {
		fprintf(stderr, "%s: Error: %s\n", __func__, dlerror());
		return -1;
	}

	*handle = h;
	return 0;
}

static int plugin_unload(void *handle)
{
	if (!handle)
		return -1;

	return dlclose(handle);
}

int plugins_load(int argc, char *argv[], struct list_head *plugins)
{
	struct plugin *p;
	int i;

	for (i = 0; i < argc && argv[i]; i++) {
		char plugin_file[128] = {0};
		void *handle;
		struct plugin *pp = NULL;
		int ret;

		snprintf(plugin_file, 127, "%s.so", argv[i]);
		ret = plugin_load(PLUGIN_PATH, plugin_file, &handle);
		if (ret)
			continue;

		pp = dlsym(handle, argv[i]);
		if (!pp) {
			fprintf(stderr, "Symbol '%s' not found\n", argv[i]);
			continue;
		}

		p = calloc(1, sizeof(struct plugin));
		if (!p) {
			ret = plugin_unload(handle);
			continue;
		}

		memcpy(p, pp, sizeof(struct plugin));
		list_add_tail(&p->list, plugins);
		if (p->init)
			p->init(&p->priv, NULL);
	}

	return 0;
}

int plugins_unload(struct list_head *plugins)
{
	struct plugin *p = NULL, *tmp;
	int ret = 0;

	list_for_each_entry_safe(p, tmp, plugins, list) {
		if (p->exit)
			p->exit(p->priv);

		list_del(&p->list);
		ret |= plugin_unload(p->handle);
		free(p);
	}

	return ret;
}
