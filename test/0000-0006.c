/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

int main()
{
	test_name("mtree_node()");
	mtree_tree *tree = mtree_create(4096 * 42, 4096);
	for (size_t i = 0; i < 42; i++) {
		test_assert(mtree_data(tree, i) == mtree_node(tree, 0, i),
				"mtree_node(0,%zu) = mtree_data(%zu)", i, i);
	}
	for (size_t i = 0; i < 42; i++) {
		test_assert(mtree_data(tree, next_pow2(42)) + HASHSIZE * i == mtree_node(tree, 1, i),
				"mtree_node(0,%zu) = mtree_data(%zu)", i, i);
	}
	mtree_free(tree);
	return fails;
}
