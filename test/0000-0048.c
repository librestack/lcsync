/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld.h"

int main(void)
{
	mld_t *mld;
	test_name("mld_init() / mld_free()");
	mld = mld_init(1);
	test_assert(mld != NULL, "mld_t allocated");
	mld_free(mld);
	return fails;
}
