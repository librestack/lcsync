/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include <libgen.h>
#include <stdio.h>
#include "globals.h"
#include "help.h"
#include "log.h"

void help_usage(void)
{
	INFO("usage: '%s source destination'\n", basename(progname));
}

void help_usage_hex(void)
{
	INFO("usage: '%s --hex filename'\n", basename(progname));
}
