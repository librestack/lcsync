/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

int main()
{
	test_name("mtree_level_nodes()");
	mtree_tree *tree = mtree_create(4096 * 42, 4096);
	fprintf(stderr, "mtree_nodes() = %zu\n", mtree_nodes(tree));
	fprintf(stderr, "mtree_base() = %zu\n", mtree_base(tree));
	fprintf(stderr, "mtree_level_nodes() = %zu\n", mtree_level_nodes(tree, 0));
	test_assert(mtree_level_nodes(tree, 0) == 64, "mtree_level_nodes(1)");
	test_assert(mtree_level_nodes(tree, 1) == 32, "mtree_level_nodes(1)");
	test_assert(mtree_level_nodes(tree, 2) == 16, "mtree_level_nodes(1)");
	test_assert(mtree_level_nodes(tree, 3) == 8, "mtree_level_nodes(1)");
	test_assert(mtree_level_nodes(tree, 4) == 4, "mtree_level_nodes(1)");
	test_assert(mtree_level_nodes(tree, 5) == 2, "mtree_level_nodes(1)");
	test_assert(mtree_level_nodes(tree, 6) == 1, "mtree_level_nodes(1)");
	test_assert(mtree_level_nodes(tree, 7) == 0, "mtree_level_nodes(1)");
	test_assert(mtree_level_nodes(tree, 42) == 0, "mtree_level_nodes(1)");
	mtree_free(tree);
	return fails;
}
