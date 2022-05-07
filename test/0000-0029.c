/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

void test_mtree_child(mtree_tree *tree, size_t n, size_t child)
{
	test_assert(mtree_child(tree, n) == child,
			"mtree_child(%zu, %zu) == %zu", mtree_base(tree), n, child);
}

void test_mtree_child_base(size_t base, size_t n, size_t child)
{
	test_assert(mtree_child_base(base, n) == child,
			"mtree_child_base(%zu, %zu) == %zu", base, n, child);
}

int main()
{
	test_name("mtree_child() / mtree_child_base()");
	test_mtree_child_base(1, 0, 0);
	test_mtree_child_base(2, 0, 1);
	test_mtree_child_base(2, 1, 0);
	test_mtree_child_base(2, 2, 0);
	test_mtree_child_base(4, 0, 1);
	test_mtree_child_base(4, 1, 3);
	test_mtree_child_base(4, 2, 5);
	test_mtree_child_base(4, 3, 0);
	test_mtree_child_base(4, 4, 0);
	test_mtree_child_base(4, 5, 0);
	test_mtree_child_base(4, 6, 0);

	mtree_tree *tree = mtree_create(1, 1);
	test_mtree_child(tree, 0, 0);
	mtree_free(tree);

	tree = mtree_create(2, 1);
	test_mtree_child(tree, 0, 1);
	test_mtree_child(tree, 1, 0);
	test_mtree_child(tree, 2, 0);
	mtree_free(tree);

	tree = mtree_create(4, 1);
	test_mtree_child(tree, 0, 1);
	test_mtree_child(tree, 1, 3);
	test_mtree_child(tree, 2, 5);
	test_mtree_child(tree, 3, 0);
	test_mtree_child(tree, 4, 0);
	test_mtree_child(tree, 5, 0);
	test_mtree_child(tree, 6, 0);
	mtree_free(tree);

	return fails;
}
