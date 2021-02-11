/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld.h"

int main(void)
{
	mld_t *mld;
	test_name("mld_start() / mld_stop()");
	mld = mld_start(NULL);
	test_assert(mld != NULL, "mld_t allocated");
	mld_stop(mld);
	return fails;
}
