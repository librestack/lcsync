/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020-2022 Brett Sheffield <bacs@librecast.net> */

#ifndef _ARG_H
#define _ARG_H

#include "opt.h"

/* return 1 if file is local, 0 if not */
int arg_islocal(char *filename);

/* parse commandline args, return 0 on success, nonzero on error */
int arg_parse(int *argc, char **argv[]);

#endif /* _ARG_H */
