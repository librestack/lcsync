/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

void test_mtree_node_level(size_t node, size_t level)
{
	size_t rc = mtree_node_level(node);
	test_assert(rc == level,
		"mtree_node_level(%zu) == %zu (expected %zu)", node, rc, level);
}

int main()
{
	test_name("mtree_node_level()");

	test_mtree_node_level(0, 0);
	test_mtree_node_level(1, 1);
	test_mtree_node_level(2, 1);
	test_mtree_node_level(3, 2);
	test_mtree_node_level(4, 2);
	test_mtree_node_level(5, 2);
	test_mtree_node_level(6, 2);
	test_mtree_node_level(7, 3);
	test_mtree_node_level(8, 3);
	test_mtree_node_level(15, 4);

	return fails;
}
