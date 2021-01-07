/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

int main()
{
	size_t node, parent;
	test_name("mtree_node_parent()");

	node = 1; parent = 0;
	test_assert(mtree_node_parent(node) == parent,
					"mtree_node_parent(%zu) => %zu", node, parent);
	node = 1; parent = 0;
	test_assert(mtree_node_parent(node) == parent,
					"mtree_node_parent(%zu) => %zu", node, parent);
	node = 2; parent = 1;
	test_assert(mtree_node_parent(node) == parent,
					"mtree_node_parent(%zu) => %zu", node, parent);
	node = 3; parent = 1;
	test_assert(mtree_node_parent(node) == parent,
					"mtree_node_parent(%zu) => %zu", node, parent);
	node = 4; parent = 2;
	test_assert(mtree_node_parent(node) == parent,
					"mtree_node_parent(%zu) => %zu", node, parent);
	node = 5; parent = 2;
	test_assert(mtree_node_parent(node) == parent,
					"mtree_node_parent(%zu) => %zu", node, parent);
	node = 6; parent = 3;
	test_assert(mtree_node_parent(node) == parent,
					"mtree_node_parent(%zu) => %zu", node, parent);
	node = 7; parent = 3;
	test_assert(mtree_node_parent(node) == parent,
					"mtree_node_parent(%zu) => %zu", node, parent);
	node = 16; parent = 8;
	test_assert(mtree_node_parent(node) == parent,
					"mtree_node_parent(%zu) => %zu", node, parent);
		return fails;
}
