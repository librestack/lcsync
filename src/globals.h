/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _GLOBALS_H
#define _GLOBALS_H 1

#include <stdint.h>
#include "job.h"

#define THREAD_MAX 128

extern int (*action)(int *argc, char *argv[]);
extern int dryrun;
extern int hex;
extern int PKTS;
extern int quiet;
extern int verbose;
extern char *progname;

extern size_t blocksize;

/* maximum number of channels to use when sending - expressed as a power of 2
 * eg. 8 = 256 channels */
extern uint8_t net_send_channels;

/* default action is to do nothing, successfully */
int succeed(int *argc, char *argv[]);
#endif /* _GLOBALS_h */
