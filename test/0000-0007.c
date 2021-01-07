/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

int main()
{
	size_t node, sibling;
	test_name("mtree_node_sibling()");

	node = 0; sibling = 1;
	test_assert(mtree_node_sibling(node) == sibling,
					"mtree_node_sibling(%zu) => %zu", node, sibling);
	node = 1; sibling = 0;
	test_assert(mtree_node_sibling(node) == sibling,
					"mtree_node_sibling(%zu) => %zu", node, sibling);
	node = 2; sibling = 3;
	test_assert(mtree_node_sibling(node) == sibling,
					"mtree_node_sibling(%zu) => %zu", node, sibling);
	node = 3; sibling = 2;
	test_assert(mtree_node_sibling(node) == sibling,
					"mtree_node_sibling(%zu) => %zu", node, sibling);

	return fails;
}
