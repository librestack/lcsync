/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

void cmp_tree(size_t sz, size_t blk, size_t n, uint8_t bin)
{
	unsigned char *map;
	mtree_tree *t1 = NULL;
	mtree_tree *t2 = NULL;
	size_t off;
	const size_t blocksz = 4096;
	char *data = calloc(sz, blocksz);
	char *copy = calloc(sz, blocksz);
	t1 = mtree_create(sz * blocksz, blocksz);
	t2 = mtree_create(sz * blocksz, blocksz);
	for (size_t i = 0; i < sz; i++) {
		(data + i * blocksz)[0] = i;
	}
	mtree_build(t1, data, NULL);
	mtree_build(t2, data, NULL);
	test_assert(mtree_diff(t1, t2) == 0, "trees match");

	map = mtree_diff_subtree(t1, t2, n, 1);
	test_assert(map == NULL, "mtree_diff_subtree() - trees match");

	memcpy(copy, data, sz * blocksz);
	fprintf(stderr, "scribbling on chunk %zu\n", blk);
	off = blk * blocksz;
	(copy + off)[0] = !(data + off)[0];
	mtree_build(t2, copy, NULL);
	test_assert(mtree_diff(t1, t2) == blk + 1, "%02zu: trees differ (tree)", blk);

	map = mtree_diff_subtree(t1, t2, n, 1);
	if ((bin != 0x0 || map))
		test_assert(map[0] == bin, "check %02x == %02x", map[0], bin);

	free(map);
	mtree_free(t1);
	mtree_free(t2);
	free(data);
	free(copy);
}

int main()
{
	test_name("mtree_diff_subtree()");

	/* base, diffblock, nodeatsubtree, map */
	cmp_tree(1, 0, 0, 0x1);
	cmp_tree(2, 0, 0, 0x1);
	cmp_tree(2, 1, 0, 0x2);
	cmp_tree(4, 0, 0, 0x1);
	cmp_tree(4, 1, 0, 0x2);
	cmp_tree(4, 2, 0, 0x4);
	cmp_tree(4, 3, 0, 0x8);
	cmp_tree(4, 0, 1, 0x1);
	cmp_tree(4, 1, 1, 0x2);
	cmp_tree(8, 0, 0, 0x1);
	cmp_tree(8, 1, 0, 0x2);
	cmp_tree(8, 2, 0, 0x4);
	cmp_tree(8, 3, 0, 0x8);
	cmp_tree(8, 4, 0, 0x10);
	cmp_tree(8, 7, 0, 0x80);
	cmp_tree(8, 0, 1, 0x1);
	cmp_tree(8, 4, 1, 0x0);
	return fails;
}
