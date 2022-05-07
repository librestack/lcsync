/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <errno.h>

void test_mtree_nnode(mtree_tree *tree, size_t node, unsigned char *ptr)
{
	unsigned char *ret = mtree_nnode(tree, node);
	test_assert(ret == ptr,
		"mtree_nnode(%zu) == %p (expected %p => %ld)", node, ret, ptr, ptr-ret);
}

int main()
{
	mtree_tree *tree;
	const size_t base = 8;
	const size_t sz = 1;
	test_name("mtree_nnode()");
	tree = mtree_create(base, sz);
	test_mtree_nnode(tree, 0, mtree_root(tree));
	test_mtree_nnode(tree, 2, mtree_root(tree) - HASHSIZE * 1);
	test_mtree_nnode(tree, 1, mtree_root(tree) - HASHSIZE * 2);
	test_mtree_nnode(tree, 6, mtree_root(tree) - HASHSIZE * 3);
	test_mtree_nnode(tree, 5, mtree_root(tree) - HASHSIZE * 4);
	test_mtree_nnode(tree, 4, mtree_root(tree) - HASHSIZE * 5);
	test_mtree_nnode(tree, 3, mtree_root(tree) - HASHSIZE * 6);
	mtree_free(tree);
	return fails;
}
