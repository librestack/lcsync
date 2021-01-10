/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include <libgen.h>
#include <stdio.h>
#include "help.h"
#include "lcsync.h"

void help_usage(void)
{
	fprintf(stderr, "usage: '%s source destination'\n", basename(progname));
}

void help_usage_hex(void)
{
	fprintf(stderr, "usage: '%s --hex filename'\n", basename(progname));
}
