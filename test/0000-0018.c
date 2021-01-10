/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/file.h"
#include "../src/globals.h"
#include "../src/arg.h"
#include <errno.h>

int main()
{
	char program[] = "lcsync";
	char *arg0[] = { program, "--invalid", NULL };
	char *arg1[] = { program, "--hex", "./filename", NULL };
	char **arg = arg0;
	int len = (int) sizeof arg0 / sizeof arg0[0] - 1;

	test_name("arg_parse() --hex");

	test_assert(arg_parse(&len, &arg) == -1, "arg_parse() - invalid option");
	len = (int) sizeof arg1 / sizeof arg1[0] - 1;
	arg = arg1;
	test_assert(arg_parse(&len, &arg) == 0, "arg_parse() - --hex (valid)");
	test_assert(len == 1, "%i args left after parsing opts", len);
	test_assert(hex == 1, "hex (set) = %i", hex);
	test_assert(action == file_dump, "function ptr set to file_dump()");

	return fails;
}
