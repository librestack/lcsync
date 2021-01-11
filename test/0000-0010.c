/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

int main()
{
	mtree_tree *t1 = NULL;
	mtree_tree *t2 = NULL;
	const size_t sz = 17;
	const size_t chunksz = 4096;
	char *data = calloc(sz, chunksz);
	char *copy = calloc(sz, chunksz);

	test_name("mtree_diff()");
	t1 = mtree_create(sz * chunksz, chunksz);
	t2 = mtree_create(sz * chunksz, chunksz);
	for (size_t i = 0; i < sz; i++) {
		(data + i * chunksz)[0] = i;
	}
	mtree_build(t1, data, NULL);
	mtree_build(t2, data, NULL);

	test_assert(mtree_diff_data(t1, t2) == 0, "trees match");
	test_assert(mtree_diff     (t1, t2) == 0, "trees match");

	for (size_t i = 0; i < sz; i++) {
		memcpy(copy, data, sz * chunksz);
		(copy + i * chunksz)[0] = !(data + i * chunksz)[0];
		mtree_build(t2, copy, NULL);
		test_assert(mtree_cmp(t1, t2) != 0, "mtree_cmp()");
		test_assert(mtree_diff_data(t1, t2) == i + 1, "%02zu: trees differ (data)", i);
		test_assert(mtree_diff(t1, t2) == i + 1, "%02zu: trees differ (tree)", i);
	}

	mtree_free(t1);
	mtree_free(t2);
	free(data);
	free(copy);

	return fails;
}
