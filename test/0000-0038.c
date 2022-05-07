/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

void test_mtree_node_offset(size_t root, size_t node, size_t offset)
{
	size_t rc = mtree_node_offset_subtree(node, root);
	test_assert(rc == offset,
		"mtree_node_offset_subtree(%zu, %zu) == %zu (expected %zu)",
		node, root, rc, offset);
}

int main()
{
	test_name("mtree_node_offset_subtree()");
	test_mtree_node_offset(0, 0, 0);
	test_mtree_node_offset(0, 1, 0);
	test_mtree_node_offset(0, 2, 1);
	test_mtree_node_offset(0, 3, 0);
	test_mtree_node_offset(0, 4, 1);
	test_mtree_node_offset(0, 5, 2);
	test_mtree_node_offset(0, 6, 3);
	test_mtree_node_offset(0, 7, 0);

	//test_mtree_node_offset(1, 0, 0); // invalid
	test_mtree_node_offset(1, 1, 0);
	//test_mtree_node_offset(1, 2, 0); // invalid
	test_mtree_node_offset(1, 3, 0);
	test_mtree_node_offset(1, 4, 1);
	test_mtree_node_offset(2, 5, 0);
	test_mtree_node_offset(2, 6, 1);

	test_mtree_node_offset(0, 14, 7);
	test_mtree_node_offset(2, 14, 3);
	test_mtree_node_offset(6, 14, 1);

	return fails;
}
