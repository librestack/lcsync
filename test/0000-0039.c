/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

int main()
{
	test_name("mtree_build() - pre-allocated job queue");
	const size_t nthreads = 3;
	const size_t blocks = 42;
	const size_t blksize = 4096;
	const size_t len = blocks * blksize;
	char *data = calloc(blocks, blksize);
	job_queue_t *q;
	mtree_tree *tree;
	q = job_queue_create(nthreads);
	tree = mtree_create(len, blksize);
	mtree_build(tree, data, q);
	mtree_free(tree);
	job_queue_destroy(q);
	free(data);
	return fails;
}
