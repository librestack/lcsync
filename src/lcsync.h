/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _LSYNC_H
#define _LSYNC_H 1

#include "file.h"

int (*action)(int *argc, char *argv[]);
int hex;
char *progname;

#endif /* _LSYNC_H */
