/*
 * debug.h - debug and logging header file
 *
 * Copyright (C) 2019 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#ifndef DEBUG_H
#define DEBUG_H


void start_logging(void);
void stop_logging(void);
void start_test_logging(void);
void stop_test_logging(void);
void log_message(int level, const char *fmt, ...)
#ifdef __GNUC__
	__attribute__((__format__(__printf__, 2, 3)));
#endif
void log_test(int level, void *var, int len);
void log_cmdu(int level, void *var);

#define DEBUG_COLOR	1

#ifdef DEBUG_COLOR
#define red             "\033[0;31m"
#define green           "\033[0;32m"
#define yellow          "\033[1;33m"
#define brown           "\033[0;33m"
#define blue            "\033[0;34m"
#define magenta         "\033[0;35m"
#define bgred           "\033[48;5;196m"
#define bggreen         "\033[48;5;046m"
#define bgyellow        "\033[48;5;226m"
#define bgblue          "\033[48;5;037m"
#define nocl            "\033[0m"

#define logrec(fmt, ...)      log_message(-1, __VA_ARGS__)
#define err(fmt, ...)         log_message(0, red fmt nocl, ## __VA_ARGS__)
#define warn(fmt, ...)        log_message(1, red fmt nocl, ## __VA_ARGS__)
#define info(fmt, ...)        log_message(2, blue fmt nocl, ## __VA_ARGS__)
#define dbg(fmt, ...)         log_message(3, nocl fmt nocl, ## __VA_ARGS__)
#define trace(fmt, ...)       log_message(4, fmt, ## __VA_ARGS__)
#define trace_cmd(fmt, ...)   log_message(4, brown fmt nocl, ## __VA_ARGS__)
#define loud(fmt, ...)        log_message(5, fmt, ## __VA_ARGS__)
//#define test(fmt, ...)        log_test(6, fmt, ## __VA_ARGS__)
#define test(var, len)        log_test(6, var, len)
#define test_cmdu(var)   log_cmdu(6, var)
#else

#define logrec(...)	log_message(-1, __VA_ARGS__)
#define err(...)	log_message(0, __VA_ARGS__)
#define warn(...)	log_message(1, __VA_ARGS__)
#define info(...)	log_message(2, __VA_ARGS__)
#define dbg(...)	log_message(3, __VA_ARGS__)
#define trace(...)	log_message(4, __VA_ARGS__)
#define trace_cmd(...)	log_message(4, __VA_ARGS__)
#define loud(...)	log_message(5, __VA_ARGS__)
#define test(var, len)        log_test(6, var, len)
#define test_cmdu(var)   log_cmdu(6, var)
#endif /* DEBUG_COLOR */

#ifdef WARN_ON
#undef WARN_ON
#endif

#define WARN_ON(cond) \
({ \
	typeof(cond) __c = (cond); \
	if (__c) \
		err("%sL%d@%s: [%s] failed\n", __FILE__, __LINE__, __func__, #cond); \
	__c; \
})

void dump(const unsigned char *buf, int len, char *label);

#endif /* DEBUG_H */
