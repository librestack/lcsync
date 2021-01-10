/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/lcsync.h"
#include "../src/opt.h"
#include <errno.h>

int main()
{
	char program[] = "lcsync";
	char **arg;
	opt_parser_t *parser;

	test_name("opt_init() / opt_free() / opt_new() / opt_parse()");

	test_assert(opt_init(0) == NULL, "opt_init(0)");
	test_assert((parser = opt_init(3)) != NULL, "opt_init(3)");

	char *arg0[] = { program, NULL };
	int len = (int) sizeof arg0 / sizeof arg0[0] - 1;
	arg = arg0;
	test_assert(opt_parse(parser, &len, &arg) == 0, "parse program with no arguments");

	test_assert(progname == program, "progname set to '%s'", progname);

	char *arg1[] = { program, "--invalid", NULL };
	arg = arg1;
	len = (int) sizeof arg1 / sizeof arg1[0] - 1;
	test_assert(opt_parse(parser, &len, &arg) == -1, "--invalid");

	char *arg2[] = { program, "-v", NULL };
	arg = arg2;
	len = (int) sizeof arg2 / sizeof arg2[0] - 1;
	int verbose = 0;
	opt_t overbose = { .oshort = 'v', .var = &verbose };
	test_assert(opt_new(parser, &overbose) == 0, "opt_new() -v");
	test_assert(opt_parse(parser, &len, &arg) == 0, "-v");


	char *arg3[] = { program, "-q", NULL };
	arg = arg3;
	len = (int) sizeof arg3 / sizeof arg3[0] - 1;
	int olen = len;
	int quiet = 0;
	test_assert(opt_parse(parser, &len, &arg) == -1, "-q (not added)");
	opt_t oquiet = { .oshort = 'q', .var = &quiet };
	test_assert(opt_new(parser, &oquiet) == 0, "opt_new() -q");
	test_assert(quiet == 0, "quiet == 0 (default)");
	arg = arg3;
	test_assert(opt_parse(parser, &olen, &arg) == 0, "-q (added)");
	test_assert(quiet == 1, "quiet == 1 (set)");


	char *arg4[] = { program, "--long-option", "nowthis", NULL };
	arg = arg4;
	olen = len = (int) sizeof arg4 / sizeof arg4[0] - 1;
	char slongopt_default[] = "default";
	char *slongopt = slongopt_default;
	test_assert(opt_parse(parser, &len, &arg) == -1, "--long-option (not added)");
	opt_t olongopt = { .olong = "long-option", .var = &slongopt, .f=&opt_set_str };
	test_assert(opt_new(parser, &olongopt) == 0, "opt_new() --long-option");
	arg = arg4;
	test_assert(opt_parse(parser, &olen, &arg) == 0, "--long-option (added)");
	test_assert(!strcmp(slongopt, "nowthis"), "--long-option (set with custom f())");

	opt_free(parser);

	return fails;
}
