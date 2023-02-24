/*
 * main.c - Agent main
 *
 * Copyright (C) 2019 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdbool.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "utils/debug.h"
#include "utils/utils.h"

extern void run_agent(void);

const char *PROG_NAME = "mapagent";
int verbose = 2;
bool syslogging;
bool usefifo;
int trace_alloc;
const char *ubus_socket;
const char *outfile_path;
const char *pidfile;
bool daemonize = true;

void usage(char *prog)
{
	fprintf(stderr, "Usage: %s [options]\n", prog);
	fprintf(stderr, "\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "   -s <socket path>     ubus socket\n");
	fprintf(stderr, "   -v,                  debug verbosity; more 'v's mean more verbose\n");
	fprintf(stderr, "   -l,                  log to syslog\n");
	fprintf(stderr, "   -d,                  debug mode; i.e. don't daemonize\n");
	fprintf(stderr, "   -m,                  in debug mode trace alloc/free calls\n");
	fprintf(stderr, "   -p <pidfile>         pid file path\n");
	fprintf(stderr, "   -o <file>,           log to file\n");
	fprintf(stderr, "   -f,                  treat above file as fifo\n");
	fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
	int ch;

	while ((ch = getopt(argc, argv, "hlfcdvms:o:p:")) != -1) {
		switch (ch) {
		case 's':
			ubus_socket = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case 'l':
			syslogging = true;
			break;
		case 'd':
			daemonize = false;
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 'o':
			outfile_path = optarg;
			break;
		case 'm':
			trace_alloc = 1;
			break;
		case 'f':
			usefifo = true;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			break;
		}
	}

	if (daemonize && !outfile_path)
		syslogging = true;

	if (daemonize)
		do_daemonize(pidfile);

	start_logging();
	run_agent();
	stop_logging();

	return 0;
}
