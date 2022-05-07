/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

void test_mtree_node_level_base(size_t base, size_t node, size_t level)
{
	size_t rc = mtree_node_level_base(base, node);
	test_assert(rc == level,
		"mtree_node_level_base(%zu, %zu) == %zu (expected %zu)", base, node, rc, level);
}

int main()
{
	test_name("mtree_node_level_base()");

	test_mtree_node_level_base(1, 0, 0);
	test_mtree_node_level_base(2, 0, 1);
	test_mtree_node_level_base(2, 1, 0);
	test_mtree_node_level_base(2, 2, 0);
	test_mtree_node_level_base(4, 0, 2);
	test_mtree_node_level_base(4, 1, 1);
	test_mtree_node_level_base(4, 3, 0);
	test_mtree_node_level_base(8, 0, 3);
	test_mtree_node_level_base(8, 1, 2);
	test_mtree_node_level_base(8, 3, 1);
	test_mtree_node_level_base(8, 7, 0);

	return fails;
}
