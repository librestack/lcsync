/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

void cmp_tree(size_t sz, size_t i)
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

	map = mtree_diff_map(t1, t2);
	test_assert(map == NULL, "mtree_diff_map() - trees match");

	memcpy(copy, data, sz * blocksz);
	fprintf(stderr, "scribbling on chunk %zu\n", i);
	off = i * blocksz;
	(copy + off)[0] = !(data + off)[0];
	mtree_build(t2, copy, NULL);
	test_assert(mtree_diff(t1, t2) == i + 1, "%02zu: trees differ (tree)", i);

	map = mtree_diff_map(t1, t2);
	test_assert(map != NULL, "mtree_diff_map() - trees differ");

	test_assert(mtree_bitcmp(map, i + 1) == 0, "mtree_bitcmp(%zu) (0)", i);
	test_assert(mtree_bitcmp(map, i + 0) == 1, "mtree_bitcmp(%zu) (1)", i + 0);
	free(map);

	mtree_free(t1);
	mtree_free(t2);
	free(data);
	free(copy);
}

int main()
{
	test_name("mtree_diff_map() / mtree_bitcmp()");
	cmp_tree(1, 0);
	cmp_tree(2, 0);
	cmp_tree(2, 1);
	cmp_tree(4, 0);
	cmp_tree(4, 1);
	cmp_tree(4, 2);
	return fails;
}
