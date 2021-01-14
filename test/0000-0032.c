/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

void test_mtree_node_offset(size_t node, size_t offset)
{
	size_t rc = mtree_node_offset(node);
	test_assert(rc == offset,
		"mtree_node_offset(%zu) == %zu (expected %zu)", node, rc, offset);
}

int main()
{
	test_name("mtree_node_offset()");

	test_mtree_node_offset(0, 0);
	test_mtree_node_offset(1, 0);
	test_mtree_node_offset(2, 1);
	test_mtree_node_offset(3, 0);
	test_mtree_node_offset(4, 1);
	test_mtree_node_offset(5, 2);
	test_mtree_node_offset(6, 3);
	test_mtree_node_offset(7, 0);

	return fails;
}
