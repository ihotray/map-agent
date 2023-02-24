/*
 * utils.h - utility functions header
 *
 * Copyright (C) 2019 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#ifndef UTILS_H
#define UTILS_H

#include <arpa/inet.h>
#include <time.h>
#include <stdbool.h>
#include <json-c/json.h>
#include <libubox/list.h>

#define _S(v)	#v
#define S(v)	_S(v)

#define hwaddr_hash(a)	(a[0] ^ a[1] ^ a[2] ^ a[3] ^ a[4] ^ a[5])

#define BIT(m, x)      ((x >> m) & 0x0001)

unsigned char *hwaddr_aton(const char *macstr, unsigned char *mac);
char *hwaddr_ntoa(const unsigned char *mac, char *macstr);
int hwaddr_from_ip(char *ifname, char *ipstr, unsigned char *hw);

void timestamp_update(struct timespec *ts);

static inline int timestamp_invalid(struct timespec *ts)
{
	return ts->tv_sec == 0 && ts->tv_nsec == 0;
}

uint32_t timestamp_diff_ms(struct timespec ts_1,
		struct timespec ts_2);

uint32_t timestamp_elapsed_sec(struct timespec *ts);
int timestamp_expired(struct timespec *a, unsigned int tmo_ms);

/* bytes from-to hexstring helper functions */
int hex2byte(const char *hex);
unsigned char *strtob(char *str, int len, unsigned char *bytes);

/* utility wrappers over json-c functions */
int json_get_bool(struct json_object *object, const char *key);
int json_get_int(struct json_object *object, const char *key);
const char *json_get_string(struct json_object *object, const char *key);


/* list utility functions and macros */

#define dbg_list_print(label, h, type, l, member)		\
do {								\
	type *e;						\
	char _bl[256] = {0};					\
								\
	snprintf(_bl + strlen(_bl), 256, "%s = [", label);	\
	list_for_each_entry(e, h, l) {				\
		char _mstr[18] = {0};                           \
		hwaddr_ntoa(e->member, _mstr);                  \
		strncat(_bl, _mstr, 18);			\
	}							\
	snprintf(_bl + strlen(_bl), 256, "%s\n", "]");		\
	fprintf(stderr, "%s", _bl);				\
} while (0)



#define list_flush(head, type, member)					\
do {									\
	type *__p, *__tmp;						\
									\
	if (!list_empty(head))						\
		list_for_each_entry_safe(__p, __tmp, head, member) {	\
			list_del(&__p->member);				\
			free(__p);					\
		}							\
} while (0)

/**
 * list_func - pointer to private list function type for list manipulation
 */
typedef int (*list_func)(struct list_head *a, struct list_head *b);

/**
 * list_join - joins two sorted lists
 * @a:		head of the first list
 * @b:		head of second list
 * @join:	private join function of type @list_func, which defines the
 *		criteria how the final list is going to be ordered.
 *		The resultant list is stored in @a
 */
#define list_join(a, b, join)						\
do {									\
	struct list_head *p, *q, *t1, *t2;				\
	typeof((list_func) join) __join = (join);			\
									\
	list_for_each_safe(p, t1, a) {					\
		list_for_each_safe(q, t2, b) {				\
			if (__join && __join(p, q) <= 0)		\
				list_move(q, p->prev);			\
		}							\
	}								\
	if (!list_empty(b))						\
		list_splice_tail(b, a);					\
} while (0)

/**
 * list_uniq - remove duplicate entries from a list
 * @a:		head of the list
 * @match:	private match function of type @list_func for duplicate checking
 * @merge:	private merge function of type @list_func for merging duplicate
 *		entries
 */
#define list_uniq(a, match, merge)				\
do {								\
	struct list_head *e, *p, *t, *n;			\
	typeof((list_func) match) __match = (match);		\
	typeof((list_func) merge) __merge = (merge);		\
								\
	list_for_each(e, a) {					\
		p = e;						\
		list_for_each_safe(n, t, p) {			\
			if (__match && __match(e, n)) {		\
				list_del(n);			\
				if (__merge)			\
					__merge(e, n);		\
				/* break; */			\
			}					\
		}						\
	}							\
} while (0)

int list_join_uniq(void *priv, struct list_head *a, struct list_head *b,
		struct list_head *out,
		int (*match)(void *priv, struct list_head *a, struct list_head *b),
		struct list_head *(*create_jentry)(void *priv, struct list_head *a, struct list_head *b),
		void (*free_jentry)(void *priv, struct list_head *),
		void (*free_entry_a)(struct list_head *),
		void (*free_entry_b)(struct list_head *));


int list_dup(struct list_head *h, struct list_head *new,
		void *(*alloc_entry)(void),
		void (*free_entry)(struct list_head *n),
		void (*copy_entry)(struct list_head *from, struct list_head *to));


int set_sighandler(int sig, void (*handler)(int));
int unset_sighandler(int sig);
void do_daemonize(const char *pidfile);
uint8_t wifi_band_to_ieee1905band(uint8_t band);
uint8_t get_device_num_from_name(char *device);

bool is_local_cntlr_available(void);
bool is_local_cntlr_running(void);

int writeto_configfile(const char *filename, void *in, size_t len);
int readfrom_configfile(const char *filename, uint8_t **out, size_t *olen);

#endif /* UTILS_H */
