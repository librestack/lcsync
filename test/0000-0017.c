/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/opt.h"
#include <errno.h>

int main()
{
	opt_parser_t *parser;
	char program[] = "lcsync";
	char *arg0[] = { program, "--long-option", "nowthis", NULL };
	char **arg = arg0;
	int len = (int) sizeof arg0 / sizeof arg0[0] - 1;
	int olen = len;
	char slongopt_default[] = "default";
	char *slongopt = slongopt_default;

	test_name("opt_set_str()");

	test_assert((parser = opt_init(1)) != NULL, "opt_init(1)");
	test_assert(opt_parse(parser, &len, &arg) == -1, "--long-option (not added)");
	opt_t olongopt = { .olong = "long-option", .var = &slongopt, .type=OTYPE_STR };
	test_assert(opt_new(parser, &olongopt) == 0, "opt_new() --long-option");
	test_assert(!strcmp(slongopt, "default"), "--long-option (default)");
	arg = arg0;
	test_assert(opt_parse(parser, &olen, &arg) == 0, "--long-option (added)");
	test_assert(!strcmp(slongopt, "nowthis"), "--long-option (set with type handler)");
	opt_free(parser);

	return fails;
}
