/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/lcsync.h"
#include "../src/net.h"
#include "../src/arg.h"
#include <errno.h>

int main()
{
	char program[] = "lcsync";
	char src[] = "./localsrc";
	char *arg0[] = { program, src, NULL };
	char **arg = arg0;
	int argc = (int) sizeof arg0 / sizeof arg0[0] - 1;

	test_name("arg_parse() - net_send");

	test_assert(arg_parse(&argc, &arg) == 0, "arg_parse()");
	test_assert(action == net_send, "action == net_send()");

	return fails;
}
