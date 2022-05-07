/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

int main()
{
	size_t nchunks, nthreads, id, first, last, res;
	test_name("mtree_data_first()");

	// TODO: test out of range returns -1 (SIZE_MAX)

	nchunks = 16; nthreads = 0; id = 0; first = 0;
	res = mtree_data_first(nchunks, nthreads, id);
	test_assert(res == first,
			"mtree_data_first(%zu, %zu) => %zu (got %zu)",
			nthreads, id, first, res);

	nchunks = 16; nthreads = 1; id = 0; first = 0;
	res = mtree_data_first(nchunks, nthreads, id);
	test_assert(res == first,
			"mtree_data_first(%zu, %zu) => %zu (got %zu)",
			nthreads, id, first, res);

	nchunks = 16; nthreads = 2; id = 0; first = 0;
	res = mtree_data_first(nchunks, nthreads, id);
	test_assert(res == first,
			"mtree_data_first(%zu, %zu) => %zu (got %zu)",
			nthreads, id, first, res);

	nchunks = 16; nthreads = 2; id = 1; first = 8;
	res = mtree_data_first(nchunks, nthreads, id);
	test_assert(res == first,
			"mtree_data_first(%zu, %zu) => %zu (got %zu)",
			nthreads, id, first, res);

	nchunks = 16; nthreads = 4; id = 1; first = 4; last = 7;
	res = mtree_data_first(nchunks, nthreads, id);
	test_assert(res == first,
			"mtree_data_first(%zu, %zu) => %zu (got %zu)",
			nthreads, id, first, res);
	res = mtree_data_last(nchunks, nthreads, id);
	test_assert(res == last,
			"mtree_data_last(%zu, %zu) => %zu (got %zu)",
			nthreads, id, last, res);

	nchunks = 16; nthreads = 4; id = 2; first = 8; last = 11;
	res = mtree_data_first(nchunks, nthreads, id);
	test_assert(res == first,
			"mtree_data_first(%zu, %zu) => %zu (got %zu)",
			nthreads, id, first, res);
	res = mtree_data_last(nchunks, nthreads, id);
	test_assert(res == last,
			"mtree_data_last(%zu, %zu) => %zu (got %zu)",
			nthreads, id, last, res);

	nchunks = 16; nthreads = 4; id = 3; first = 12; last = 15;
	res = mtree_data_first(nchunks, nthreads, id);
	test_assert(res == first,
			"mtree_data_first(%zu, %zu) => %zu (got %zu)",
			nthreads, id, first, res);
	res = mtree_data_last(nchunks, nthreads, id);
	test_assert(res == last,
			"mtree_data_last(%zu, %zu) => %zu (got %zu)",
			nthreads, id, last, res);

	return fails;
}
