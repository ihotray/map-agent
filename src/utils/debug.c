/*
 * debug.c - for debug and logging
 *
 * Copyright (C) 2019 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "utils.h"
#include "debug.h"


static int ffd;
extern const char *outfile_path;
const char *testfile_path = "/var/run/multiap/agent.test.log";
static FILE *outfile;
extern const char *PROG_NAME;
extern int verbose;
extern bool syslogging;
extern bool usefifo;
static const int syslog_level[] = { LOG_ERR, LOG_WARNING, LOG_INFO, LOG_DEBUG };

void start_logging(void)
{
	if (syslogging)
		openlog(PROG_NAME, 0, LOG_DAEMON);

	if (!outfile) {
		if (outfile_path) {
			if (usefifo) {
				struct stat st;
				int rfd;

				if (stat(outfile_path, &st))
					unlink(outfile_path);

				mkfifo(outfile_path, 0600);
				if (stat(outfile_path, &st) == -1 ||
						!S_ISFIFO(st.st_mode))
					return;
				rfd = open(outfile_path,
						O_RDONLY | O_NONBLOCK);
				if (rfd) {
					ffd = open(outfile_path,
							O_WRONLY | O_NONBLOCK);
					close(rfd);
				}
			} else {
				outfile = fopen(outfile_path, "w+");
			}
		} else {
			outfile = stderr;
		}
	}
}

void stop_logging(void)
{
	if (syslogging)
		closelog();

	if (outfile)
		fclose(outfile);

	if (ffd) {
		close(ffd);
		unlink(outfile_path);
	}
}

void log_message(int level, const char *fmt, ...)
{
	va_list args;

	if (level > verbose) {
		if (usefifo && ffd) {
			time_t now = time(NULL);
			struct tm *tm_now = localtime(&now);
			const char *tm_fmt = "[%d-%02d-%02d %02d:%02d:%02d] ";

			va_start(args, fmt);
			dprintf(ffd, tm_fmt,
				tm_now->tm_year + 1900,
				tm_now->tm_mon + 1,
				tm_now->tm_mday,
				tm_now->tm_hour,
				tm_now->tm_min,
				tm_now->tm_sec);
			vdprintf(ffd, fmt, args);
			va_end(args);
		}
		return;
	}

	int len = 0;
	char *fmtptr = NULL;

	va_start(args, fmt);
	len = vsnprintf(fmtptr, 0, fmt, args);	/* Flawfinder: ignore */
	va_end(args);
	if (len < 0 || len > 1023)
		return;

	char fmtstr[len + 1];

	va_start(args, fmt);
	len = vsnprintf(fmtstr, len + 1, fmt, args);	/* Flawfinder: ignore */
	if (len < 0 || len > 1023)
		goto out;

	if (syslogging && level >= 0) {
		unsigned int max_level = sizeof(syslog_level) / sizeof(int) - 1;

		vsyslog(syslog_level[(level <= max_level) ? level : max_level],
				fmtstr, args);
	}

	if (outfile)
		vfprintf(outfile, fmtstr, args);	/* Flawfinder: ignore */

	if (usefifo && ffd)
		vdprintf(ffd, fmtstr, args);
out:
	va_end(args);
}

void dump(const unsigned char *buf, int len, char *label)
{
	int i;

	if (label)
		printf("---- %s ----", label);

	for (i = 0; i < len; i++) {
		if (!(i % 4))
			printf("  ");
		if (!(i % 16))
			printf("\n ");
		printf("%02x ", buf[i] & 0xff);
	}

	if (label)
		printf("\n--------------\n");
}
