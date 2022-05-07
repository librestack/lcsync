/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020-2022 Brett Sheffield <bacs@librecast.net> */

#include <libgen.h>
#include <stdio.h>
#include "globals.h"
#include "help.h"
#include "log.h"

void help_usage(void)
{
	WARN("usage: '%s source [destination]'", basename(progname));
}

void help_usage_hex(void)
{
	WARN("usage: '%s --hex filename'", basename(progname));
}
