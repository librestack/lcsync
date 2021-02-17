/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/globals.h"
#include "../src/log.h"
#include "../src/mld.h"

int main(void)
{
	loginit();
	test_name("more MLD wait functions...");

	return fails;
}
