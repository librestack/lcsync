/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

void test_mtree_block(mtree_tree *tree, size_t node, char *blkptr)
{
	char *ptr;
	ptr = mtree_block(tree, node);
	test_assert(ptr == blkptr, "expected %p, got %p", blkptr, ptr);
}

void test_mtree_blockn(mtree_tree *tree, size_t node, char *blkptr)
{
	char *ptr;
	ptr = mtree_blockn(tree, node);
	test_assert(ptr == blkptr, "expected %p, got %p", blkptr, ptr);
}

int main()
{
	mtree_tree *tree;
	size_t blocksz = 4096;
	size_t blocks = 17;
	size_t sz = blocks * blocksz;
	char *srcdata;
	test_name("mtree_block() / mtree_blockn()");
	srcdata = calloc(blocks, blocksz);
	tree = mtree_create(sz, blocksz);
	mtree_build(tree, srcdata, NULL);

	test_assert(mtree_blocksz(tree) == blocksz, "blocksize set");

	test_mtree_block(tree, 0, srcdata);
	test_mtree_block(tree, 1, srcdata + blocksz);
	test_mtree_block(tree, 2, srcdata + blocksz * 2);
	test_mtree_block(tree, blocks, srcdata + blocksz * blocks);
	test_mtree_block(tree, blocks + 1, NULL); /* Madness: One Step Beyond */

	test_mtree_blockn(tree, 0, NULL);
	test_mtree_blockn(tree, 1, NULL);
	test_mtree_blockn(tree, 31, srcdata);
	test_mtree_blockn(tree, 32, srcdata + blocksz);
	test_mtree_blockn(tree, 62, srcdata + blocksz * (62 - 31));
	test_mtree_blockn(tree, 63, NULL);

	free(srcdata);
	mtree_free(tree);
	return fails;
}
