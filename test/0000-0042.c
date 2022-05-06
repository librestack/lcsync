/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

void test_f(size_t (*f)(size_t, size_t), size_t base, size_t root, size_t n)
{
	test_log("***\n");
	test_log("base = %zu, root = %zu, expected = %zu\n", base, root, n);
	size_t got = f(base, root);
	test_assert(got == n, "base=%zu, root=%zu, expected %zu, got %zu",
			base, root, n, got);
}

int main()
{
	test_name("mtree_subtree_data_min() / mtree_subtree_data_max()");

	test_f(&mtree_subtree_data_min, 1, 0, 0);
	test_f(&mtree_subtree_data_min, 2, 0, 1);
	test_f(&mtree_subtree_data_min, 4, 0, 3);
	test_f(&mtree_subtree_data_min, 4, 2, 5);

	test_f(&mtree_subtree_data_max, 1, 0, 0);
	test_f(&mtree_subtree_data_max, 2, 0, 2);
	test_f(&mtree_subtree_data_max, 4, 0, 6);
	test_f(&mtree_subtree_data_max, 4, 1, 4);
	test_f(&mtree_subtree_data_max, 4, 2, 6);
	test_f(&mtree_subtree_data_max, 8, 1, 10);
	test_f(&mtree_subtree_data_max, 8, 3, 8);
	test_f(&mtree_subtree_data_max, 8, 5, 12);
	test_f(&mtree_subtree_data_max, 8, 6, 14);

	test_f(&mtree_subtree_data_min, 32, 0, 31);
	test_f(&mtree_subtree_data_max, 32, 0, 62);
	test_f(&mtree_subtree_data_min, 32, 5, 47);
	test_f(&mtree_subtree_data_max, 32, 5, 54);

	test_f(&mtree_subtree_data_min, 32, 11, 47);
	test_f(&mtree_subtree_data_max, 32, 11, 50);
	test_f(&mtree_subtree_data_min, 32, 25, 51);
	test_f(&mtree_subtree_data_max, 32, 25, 52);

	return fails;
}
