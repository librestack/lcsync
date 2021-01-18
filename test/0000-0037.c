/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>
void test_mtree_base_subtree(size_t base, size_t n, size_t subbase)
{
	mtree_tree *tree = mtree_create(4096 * base, 4096);
	size_t res = mtree_base_subtree(tree, n);
	test_assert(res == subbase, "mtree_base_subtree(%zu, %zu) == %zu", base, n, res);
	mtree_free(tree);
}

int main()
{
	test_name("mtree_base_subtree()");
	test_mtree_base_subtree(42, 0, 64);
	test_mtree_base_subtree(65, 0, 128);
	test_mtree_base_subtree(42, 1, 32);
	test_mtree_base_subtree(42, 2, 32);
	test_mtree_base_subtree(42, 3, 16);
	test_mtree_base_subtree(42, 4, 16);
	test_mtree_base_subtree(42, 5, 16);
	test_mtree_base_subtree(42, 6, 16);
	test_mtree_base_subtree(42, 7, 8);
	return fails;
}
