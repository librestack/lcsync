/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/globals.h"
#include "../src/mtree.h"
#include <errno.h>

void test_mtree_base_subtree(size_t base, size_t n, size_t subbase, size_t extra)
{
	mtree_tree *tree = mtree_create(blocksize * base + extra, blocksize);
	size_t res = mtree_base_subtree(tree, n);
	test_assert(res == subbase, "mtree_base_subtree(%zu, %zu) == %zu", base, n, res);
	mtree_free(tree);
}

int main()
{
	test_name("mtree_base_subtree()");

	test_mtree_base_subtree(42, 0, 64, 0);
	test_mtree_base_subtree(65, 0, 128, 0);
	test_mtree_base_subtree(42, 1, 32, 0);
	test_mtree_base_subtree(42, 2, 32, 0);
	test_mtree_base_subtree(42, 3, 16, 0);
	test_mtree_base_subtree(42, 4, 16, 0);
	test_mtree_base_subtree(42, 5, 16, 0);
	test_mtree_base_subtree(42, 6, 16, 0);
	test_mtree_base_subtree(42, 7, 8, 0);

	/* 6 blocks, 5 full, one partial, base = 8 */
	mtree_tree *tree = mtree_create(blocksize * 5 + 1, blocksize);

	test_assert(mtree_base_subtree(tree, 0) == 8, "check base");

	size_t res = mtree_blocks_subtree(tree, 0);
	test_assert(res == 6, "mtree_blocks_subtree(), expected 6, res = %zu", res);
	res = mtree_blocks_subtree(tree, 1);
	test_assert(res == 4, "mtree_base_subtree(), expected 4, res = %zu", res);
	res = mtree_blocks_subtree(tree, 2);
	test_assert(res == 2, "mtree_base_subtree(), expected 2, res = %zu", res);
	mtree_free(tree);

	return fails;
}
