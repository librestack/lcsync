/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

void cmp_tree(size_t sz, size_t n, size_t lvl)
{
	unsigned char *map;
	mtree_tree *t1 = NULL;
	mtree_tree *t2 = NULL;
	size_t off;
	const size_t chunksz = 4096;
	char *data = calloc(sz, chunksz);
	char *copy = calloc(sz, chunksz);
	t1 = mtree_create(sz * chunksz, chunksz);
	t2 = mtree_create(sz * chunksz, chunksz);
	for (size_t i = 0; i < sz; i++) {
		(data + i * chunksz)[0] = i;
	}
	mtree_build(t1, data, NULL);
	mtree_build(t2, data, NULL);
	test_assert(mtree_diff(t1, t2) == 0, "trees match");

	map = mtree_diff_subtree(t1, t2, lvl);
	test_assert(map == NULL, "mtree_diff_subtree() - trees match");

	memcpy(copy, data, sz * chunksz);
	fprintf(stderr, "scribbling on chunk %zu\n", n);
	off = n * chunksz;
	(copy + off)[0] = !(data + off)[0];
	mtree_build(t2, copy, NULL);
	test_assert(mtree_diff(t1, t2) == n + 1, "%02zu: trees differ (tree)", n);

	map = mtree_diff_subtree(t1, t2, 0);
	test_assert(map != NULL, "mtree_diff_subtree() - trees differ");

	// FIXME - working here
	test_assert(mtree_bitcmp(map, n + 1) == 0, "mtree_bitcmp(%zu) (0) - bit not set", n);
	test_assert(mtree_bitcmp(map, n + 0) == 1, "mtree_bitcmp(%zu) (1) - bit set", n);

	free(map);
	mtree_free(t1);
	mtree_free(t2);
	free(data);
	free(copy);
}

int main()
{
	test_name("mtree_diff_subtree() / mtree_bitcmp()");

	/* base, diffblock, subtreelvl */
	cmp_tree(1, 0, 0);
#if 0
	cmp_tree(2, 1);
	cmp_tree(4, 0);
	cmp_tree(4, 1);
	cmp_tree(4, 2);
#endif
	return fails;
}
