/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

int main()
{
	mtree_tree *t1 = NULL;
	mtree_tree *t2 = NULL;

	test_name("mtree_cmp()");

	test_assert(mtree_cmp(t1, t2) == 0, "mtree_cmp(NULL, NULL)");

	t1 = mtree_create(1, 1);
	test_assert(mtree_cmp(t1, t2) == 1, "mtree_cmp(t1, NULL) == 1");
	mtree_free(t1);
	t1 = NULL;

	t2 = mtree_create(1, 1);
	test_assert(mtree_cmp(t1, t2) == -1, "mtree_cmp(NULL, r2) == -1");
	mtree_free(t2);
	t2 = NULL;

	t1 = mtree_create(1, 1);
	t2 = mtree_create(1, 1);
	test_assert(mtree_cmp(t1, t2) == 0, "mtree_cmp() - two empty trees match");
	mtree_free(t1);
	mtree_free(t2);

	t1 = mtree_create(2, 1);
	t2 = mtree_create(1, 1);
	test_assert(mtree_cmp(t1, t2) == 1, "mtree_cmp() - t1 larger than t2");
	mtree_free(t1);
	mtree_free(t2);

	t1 = mtree_create(2, 1);
	t2 = mtree_create(3, 1);
	test_assert(mtree_cmp(t1, t2) == -1, "mtree_cmp() - t2 larger than t1");
	mtree_free(t1);
	mtree_free(t2);

	const size_t sz = 17;
	const size_t chunksz = 4096;
	char *data = calloc(sz, chunksz);
	t1 = mtree_create(sz * chunksz, chunksz);
	t2 = mtree_create(sz * chunksz, chunksz);
	for (size_t i = 0; i < sz; i++) {
		(data + i * chunksz)[0] = i;
	}
	mtree_build(t1, data, NULL);
	mtree_build(t2, data, NULL);
	test_assert(memcmp(mtree_data(t1, 0), mtree_data(t2, 0), mtree_nodes(t1) * HASHSIZE) == 0,
			"memcmp of tree");
	test_assert(mtree_cmp(t1, t2) == 0, "trees match");
	mtree_free(t1);
	mtree_free(t2);
	free(data);

	return fails;
}
