/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/lcsync.h"
#include "../src/file.h"
#include "../src/arg.h"
#include <errno.h>

int main()
{
	char program[] = "lcsync";
	char src[] = "./src";
	char dst[] = "./dst";
	char *arg0[] = { program, src, dst, NULL };
	char **arg = arg0;
	int len = (int) sizeof arg0 / sizeof arg0[0] - 1;

	test_name("arg_parse() - file_sync commandline args");
	test_assert(arg_parse(&len, &arg) == 0, "arg_parse() - src & dst(valid)");
	test_assert(len == 2, "%i args left after parsing opts", len);
	test_assert(hex == 0, "hex (not set) = %i", hex);
	test_assert(action == file_sync, "function ptr set to file_sync()");

	test_assert(arg[0] == src, "src = '%s'", arg[0]);
	test_assert(arg[1] == dst, "dst = '%s'", arg[1]);

	return fails;
}
