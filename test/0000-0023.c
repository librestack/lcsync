/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/globals.h"
#include "../src/net.h"
#include "../src/arg.h"
#include <errno.h>

int main()
{
	char program[] = "lcsync";
	char src[] = "netsrc";
	char *arg0[] = { program, src, NULL };
	char **arg = arg0;
	int argc = (int) sizeof arg0 / sizeof arg0[0] - 1;

	return test_skip("arg_parse() - net_recv");

	test_assert(arg_parse(&argc, &arg) == 0, "arg_parse()");
	test_assert(action == net_recv, "action == net_recv()");

	return fails;
}
