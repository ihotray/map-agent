/*
 * rules.c - rules wrapper functions
 *
 * Copyright (C) 2019 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <libubox/list.h>

#include "utils/debug.h"
#include "steer_rules.h"

LIST_HEAD(regd_steer_rules);

int get_registered_steer_rules(void)
{
	struct steer_rule *r;
	int nr = 0;

	info("Registered steering rules: ");
	list_for_each_entry(r, &regd_steer_rules, list) {
		info("%s ", r->name);
		nr++;
	}
	info("\n");

	return nr;
}

struct steer_rule *get_steer_rule_by_name(const char *name)
{
	struct steer_rule *r = NULL;

	list_for_each_entry(r, &regd_steer_rules, list) {
		if (!strcmp(name, r->name))
			return r;
	}

	return NULL;
}
