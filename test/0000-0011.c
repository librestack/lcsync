/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

int main()
{
	mtree_tree *t1 = NULL;
	mtree_tree *t2 = NULL;
	size_t off;
	const size_t sz = 17;
	const size_t blocksz = 4096;
	char *data = calloc(sz, blocksz);
	char *copy = calloc(sz, blocksz);

	test_name("mtree_update()");

	t1 = mtree_create(sz * blocksz, blocksz);
	t2 = mtree_create(sz * blocksz, blocksz);
	for (size_t i = 0; i < sz; i++) {
		(data + i * blocksz)[0] = i;
	}

	for (size_t i = 0; i < sz; i++) {
		mtree_build(t1, data, NULL);
		mtree_build(t2, data, NULL);
		test_assert(mtree_diff     (t1, t2) == 0, "trees match");
		memcpy(copy, data, sz * blocksz);
		fprintf(stderr, "scribbling on chunk %zu\n", i);
		off = i * blocksz;
		(copy + off)[0] = !(data + off)[0];
		mtree_build(t2, copy, NULL);
		test_assert(mtree_cmp(t1, t2) != 0, "mtree_cmp()");
		test_assert(mtree_diff_data(t1, t2) == i + 1, "%02zu: trees differ (data)", i);
		test_assert(mtree_diff(t1, t2) == i + 1, "%02zu: trees differ (tree)", i);
		mtree_update(t1, copy, mtree_diff(t1, t2) - 1);
		test_assert(mtree_diff     (t1, t2) == 0, "trees match");
	}

	mtree_free(t1);
	mtree_free(t2);
	free(data);
	free(copy);

	return fails;
}
