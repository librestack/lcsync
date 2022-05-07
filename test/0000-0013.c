/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

int main()
{
	size_t base, lvl, off, node, res;
	test_name("mtree_base_node_num()");

	// TODO: test out of range returns -1 (SIZE_MAX)

	base = 1; lvl = 0; off = 0; node = 0;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	base = 2; lvl = 0; off = 0; node = 1;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	base = 2; lvl = 1; off = 0; node = 0;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	base = 4; lvl = 2; off = 0; node = 0;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	base = 4; lvl = 1; off = 0; node = 1;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	base = 4; lvl = 1; off = 1; node = 2;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	base = 4; lvl = 0; off = 0; node = 3;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	base = 4; lvl = 0; off = 1; node = 4;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	base = 4; lvl = 0; off = 2; node = 5;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	base = 4; lvl = 0; off = 3; node = 6;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	base = 8; lvl = 3; off = 0; node = 0;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	base = 8; lvl = 2; off = 0; node = 1;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	base = 8; lvl = 2; off = 1; node = 2;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	base = 8; lvl = 1; off = 0; node = 3;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	base = 8; lvl = 1; off = 1; node = 4;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	base = 8; lvl = 1; off = 2; node = 5;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	base = 8; lvl = 1; off = 3; node = 6;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	base = 8; lvl = 0; off = 0; node = 7;
	res = mtree_base_node_num(base, lvl, off);
	test_assert(res == node,
			"mtree_base_node_num(%zu, %zu, %zu) => %zu (got %zu)",
			base, lvl, off, node, res);

	return fails;
}
