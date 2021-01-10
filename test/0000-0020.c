/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/arg.h"
#include <errno.h>

int main()
{
	char remote[] = "remotesrc";
	char local[] = "./dst";

	test_name("arg_islocal() - parse args for remote file");

	test_assert(arg_islocal(remote) == 0, "arg_islocal() - remote");
	test_assert(arg_islocal(local) == 1, "arg_islocal() - local");

	return fails;
}
