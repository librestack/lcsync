/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

void test_mtree_block_len(mtree_tree *tree, size_t node, size_t expected)
{
	size_t len = mtree_block_len(tree, node);
	test_assert(len == expected, "%02zu: expected %zu, got %zu", node, expected, len);
}

void test_mtree_blockn_len(mtree_tree *tree, size_t node, size_t expected)
{
	size_t len = mtree_blockn_len(tree, node);
	test_assert(len == expected, "%02zu: expected %zu, got %zu", node, expected, len);
}

int main()
{
	mtree_tree *tree;
	size_t blocksz = 4096;
	size_t blocks = 17;
	size_t extra = 1234; /* incomplete block */
	size_t sz = blocks * blocksz + extra;
	char *srcdata;
	test_name("mtree_block_len() / mtree_blockn_len()");
	srcdata = malloc(sz);
	tree = mtree_create(sz, blocksz);
	mtree_build(tree, srcdata, NULL);

	for (size_t i = 0; i < 17; i++) {
		test_mtree_block_len(tree, i, blocksz);
	}
	test_mtree_block_len(tree, 17, extra);
	test_mtree_block_len(tree, 18, 0);

	test_mtree_blockn_len(tree, 0, 0);
	test_mtree_blockn_len(tree, 30, 0);
	for (size_t i = 31; i < 31 + blocks; i++) {
		test_mtree_blockn_len(tree, i, blocksz);
	}
	test_mtree_blockn_len(tree, 31 + blocks, extra);
	test_mtree_blockn_len(tree, 63, 0);

	free(srcdata);
	mtree_free(tree);
	return fails;
}
