/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/net.h"
#include <errno.h>

int main()
{
	char invalid[] = "./src_does_not_exist";
	char valid[] = "./0000-0024.c";
	char *arg0[] = { invalid, NULL };
	char *arg1[] = { valid, NULL };
	char **argv = arg0;
	int argc = (int) sizeof arg0 / sizeof arg0[0] - 1;

	test_name("net_send()");

	test_assert(net_send(&argc, argv) == -1, "net_send() - invalid source file");
	argv = arg1;
	test_assert(net_send(&argc, argv) == 0, "net_send() - valid source file");

	return fails;
}
