/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

int main()
{
	test_name("mtree_size()");
	test_assert(mtree_size(1) == 1, "mtree_size(1)");
	test_assert(mtree_size(2) == 3, "mtree_size(2)");
	test_assert(mtree_size(3) == 7, "mtree_size(3)");
	test_assert(mtree_size(4) == 7, "mtree_size(4)");
	test_assert(mtree_size(5) == 15, "mtree_size(5)");
	test_assert(mtree_size(6) == 15, "mtree_size(6)");
	test_assert(mtree_size(7) == 15, "mtree_size(7)");
	test_assert(mtree_size(8) == 15, "mtree_size(8)");
	test_assert(mtree_size(32) == 32 + 16 + 8 + 4 + 2 + 1, "mtree_size(32)");
	return fails;
}
