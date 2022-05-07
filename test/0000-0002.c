/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

int main()
{
	test_name("mtree_levels()");
	test_assert(mtree_levels(1) == 1, "mtree_levels(1)");
	test_assert(mtree_levels(2) == 2, "mtree_levels(2)");
	test_assert(mtree_levels(3) == 3, "mtree_levels(3)");
	test_assert(mtree_levels(4) == 3, "mtree_levels(4)");
	test_assert(mtree_levels(5) == 4, "mtree_levels(5)");
	test_assert(mtree_levels(6) == 4, "mtree_levels(6)");
	test_assert(mtree_levels(7) == 4, "mtree_levels(7)");
	test_assert(mtree_levels(8) == 4, "mtree_levels(8)");
	test_assert(mtree_levels(9) == 5, "mtree_levels(9)");
	test_assert(mtree_levels(31) == 6, "mtree_levels(31)");
	test_assert(mtree_levels(32) == 6, "mtree_levels(32)");
	test_assert(mtree_levels(33) == 7, "mtree_levels(33)");
	test_assert(mtree_levels(63) == 7, "mtree_levels(63)");
	test_assert(mtree_levels(64) == 7, "mtree_levels(64)");
	test_assert(mtree_levels(65) == 8, "mtree_levels(65)");
	test_assert(mtree_levels(100) == 8, "mtree_levels(100)");
	return fails;
}
