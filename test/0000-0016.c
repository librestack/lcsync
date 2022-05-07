/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/opt.h"
#include <errno.h>

int main()
{
	char program[] = "lcsync";
	char **arg;
	opt_parser_t *parser;

	test_name("opt_set_int()");

	test_assert((parser = opt_init(1)) != NULL, "opt_init(1)");

	char *arg0[] = { program, "-i", "42", NULL };
	int len = (int) sizeof arg0 / sizeof arg0[0] - 1;
	int i = 13;
	opt_t o = { .oshort = 'i', .var = &i, .type = OTYPE_INT };
	test_assert(opt_new(parser, &o) == 0, "opt_new() -i");
	arg = arg0;
	test_assert(opt_parse(parser, &len, &arg) == 0, "-i");
	test_assert(i == 42, "integer option is set = %i", i);

	char *arg1[] = { program, "-i", "0xf", NULL };
	len = (int) sizeof arg1 / sizeof arg1[0] - 1;
	arg = arg1;
	test_assert(opt_parse(parser, &len, &arg) == 0, "-i");
	test_assert(i == 15, "integer option is set = %i", i);

	opt_free(parser);

	return fails;
}
