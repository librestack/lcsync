/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020-2022 Brett Sheffield <bacs@librecast.net> */

#include <stddef.h>
#include "globals.h"

/* global defaults */

int (*action)(int *argc, char *argv[]) = &succeed;
int DELAY = 0;
int dryrun = 0;
int hex = 0;
int mld_enabled = 1;
int g_archive = 0;
int g_perms = 0;
int quiet = 0;
int verbose = 0;
char *progname;
size_t blocksize = 16384;
uint8_t net_send_channels = 3;

int succeed(int *argc, char *argv[])
{
	(void) argc; (void) argv;
	return 0;
}
