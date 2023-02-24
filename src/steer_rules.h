/*
 * steer_rules.h - STA steering rule template
 *
 * Copyright (C) 2019 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#ifndef STEER_RULES_H
#define STEER_RULES_H

/** the order in which steering rules will be evaluated */
#define STEER_POLICY_ORDER_AUTO		0  /* auto */
#define STEER_POLICY_ORDER_STRICT	1  /* strictly in order */

enum steer_verdict {
	STEER_OK,
	STEER_NOK,
	STEER_SKIP,
};
typedef enum steer_verdict steer_verdict_t;

struct sta;
struct pref_neighbor;

struct steer_rule {
	char name[16];
	bool enabled;
	char ifname[16];
	void *priv;
	void (*init)(struct steer_rule *rule);
	void (*exit)(struct steer_rule *rule);
	void (*config)(struct steer_rule *rule, void *cfg, void *c_ctx);
	void (*init_config)(struct steer_rule *rule, void **cfg);
	steer_verdict_t (*check)(struct steer_rule *rule, struct sta *sta,
						struct pref_neighbor **nbr);

	/* rest for internal use */
	int id;
	int weight;
	struct list_head list;
	struct netif *vif;
};

extern struct list_head regd_steer_rules;

#define register_steer_rule(name)				\
void __attribute__ ((constructor)) steer_logic_##name(void)	\
{								\
	struct steer_rule *_r = &(name);			\
	if (_r && _r->check)					\
		list_add_tail(&_r->list, &regd_steer_rules);	\
}

int get_registered_steer_rules(void);
struct steer_rule *get_steer_rule_by_name(const char *name);


#endif /* STEER_RULES_H */
