/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include <stdlib.h>
#include "arg.h"
#include "help.h"
#include "lcsync.h"

int arg_parse(int *argc, char **argv[])
{
	int rc = 0;
	opt_t ohex = { .var = &hex, .olong = "hex" };
	opt_parser_t *parser = opt_init(1);
	opt_new(parser, &ohex);
	rc = opt_parse(parser, argc, argv);
	opt_free(parser);
	if (rc) help_usage();
	else if (hex) {
		if (*argc != 1) {
			help_usage_hex();
			rc = EXIT_FAILURE;
		}
		else
			action = &file_dump;
	}
	else {
		if (*argc != 2) {
			help_usage();
			rc = EXIT_FAILURE;
		}
		else
			action = &file_sync;
	}
	return rc;
}
