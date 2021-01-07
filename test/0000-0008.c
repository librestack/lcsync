/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

int main()
{
	mtree_tree *tree = NULL;
	test_name("mtree_verify()");

	test_assert(mtree_verify(tree) == -1, "mtree_verify(NULL) is not a valid tree");

	tree = mtree_create(1, 1);
	test_assert(!mtree_verify(tree), "tree of size 1 always valid");
	mtree_free(tree);

	tree = mtree_create(2, 1);
	test_assert(mtree_verify(tree) == -1, "invalid tree");
	mtree_free(tree);

	char *data = malloc(2);
	data[0] = '4';
	data[1] = '2';
	tree = mtree_create(2, 1);
	mtree_build(tree, data);
	test_assert(!mtree_verify(tree), "valid tree");
	mtree_node(tree, 1, 0)[31] = !(mtree_node(tree, 1, 0)[31]); /* damage tree */
	test_assert(mtree_verify(tree) == -1, "damaged tree");
	mtree_free(tree);
	free(data);

	size_t chunksz = 4096;
	data = calloc(17, chunksz);
	tree = mtree_create(17 * chunksz, chunksz);
	mtree_build(tree, data);
	test_assert(!mtree_verify(tree), "valid tree");
	mtree_node(tree, 4, 2)[31] = !(mtree_node(tree, 4, 2)[31]); /* damage tree */
	test_assert(mtree_verify(tree) == -1, "damaged tree");
	mtree_free(tree);
	free(data);

	return fails;
}
