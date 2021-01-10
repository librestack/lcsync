/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _GLOBALS_H
#define _GLOBALS_H 1

extern int (*action)(int *argc, char *argv[]);
extern int hex;
extern char *progname;

/* maximum number of channels to use when sending - expressed as a power of 2
 * eg. 8 = 256 channels */
extern size_t net_send_channels;

#endif /* _GLOBALS_h */
