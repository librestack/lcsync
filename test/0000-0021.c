/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/globals.h"
#include "../src/net.h"
#include "../src/arg.h"
#include <errno.h>

int main()
{
	char program[] = "lcsync";
	char src[] = "remotesrc";
	char dst[] = "./dst";
	char *arg0[] = { program, src, dst, NULL };
	char **arg = arg0;
	int argc = (int) sizeof arg0 / sizeof arg0[0] - 1;

	test_name("arg_parse() - net_sync");

	test_assert(arg_parse(&argc, &arg) == 0, "arg_parse()");
	test_assert(action == net_sync, "action == net_sync()");

	return fails;
}
