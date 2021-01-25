/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include <stdlib.h>
#include <string.h>
#include "arg.h"
#include "file.h"
#include "globals.h"
#include "help.h"
#include "log.h"
#include "net.h"

int arg_islocal(char *filename)
{
	return !!strchr(filename, '/');
}

int arg_parse(int *argc, char **argv[])
{
	int rc = 0;
	opt_t ohex = { .var = &hex, .olong = "hex" };
	opt_t ologlevel = { .olong = "loglevel", .var = &loglevel, .type = OTYPE_INT };
	opt_t oquiet = { .oshort = 'q', .olong = "quiet", .var = &quiet, .type = OTYPE_BOOL };
	opt_t overbose = { .oshort = 'v', .olong = "verbose", .var = &verbose, .type = OTYPE_BOOL };
	opt_parser_t *parser = opt_init(4);
	opt_new(parser, &ohex);
	opt_new(parser, &ologlevel);
	opt_new(parser, &oquiet);
	opt_new(parser, &overbose);
	rc = opt_parse(parser, argc, argv);
	opt_free(parser);
	if (verbose) {
		loglevel = LOG_LOGLEVEL_VERBOSE;
	}
	if (quiet) {
		loglevel = 0;
	}
	if (rc) help_usage();
	else if (hex) {
		if (*argc != 1) {
			help_usage_hex();
			rc = EXIT_FAILURE;
		}
		else action = &file_dump;
	}
	else if (*argc == 1 && arg_islocal((*argv)[0])) {
		action = &net_send;
	}
	else if (*argc == 1 && !arg_islocal((*argv)[0])) {
		action = &net_recv;
	}
	else if (*argc == 2 && !arg_islocal((*argv)[0]) && arg_islocal((*argv)[1])) {
		action = &net_sync;
	}
	else if (*argc == 2 && arg_islocal((*argv)[0]) && arg_islocal((*argv)[1])) {
		action = &file_sync;
	}
	else {
		help_usage();
		rc = EXIT_FAILURE;
	}
	return rc;
}
