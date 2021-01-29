/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include <stddef.h>
#include "globals.h"

/* global defaults */

int (*action)(int *argc, char *argv[]) = &succeed;
int DELAY = 0;
int dryrun = 0;
int hex = 0;
size_t PKTS = SIZE_MAX;
int quiet = 0;
int verbose = 0;
char *progname;
size_t blocksize = 1024;
uint8_t net_send_channels = 3;

int succeed(int *argc, char *argv[])
{
	(void) argc; (void) argv;
	return 0;
}
