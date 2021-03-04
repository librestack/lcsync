/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <unistd.h>

int main()
{
	mtree_tree *tree = NULL;
	char *data;
	size_t len;
	size_t blocksz;
	unsigned char hash[HASHSIZE] = "";
	unsigned char *ptr;

	test_name("mtree_create() - single node");

	/* write data */
	blocksz = 4096;
	len = blocksz;
	data = calloc(1, len);
	snprintf(data, len, "%i", 1);

	fprintf(stderr, "'%s'\n", data);

	/* build tree */
	tree = mtree_create(len, blocksz);
	test_assert(tree != NULL, "tree alloc'd");
	test_assert(mtree_base(tree) == 1, "mtree_base()");
	test_assert(mtree_lvl(tree) == 1, "mtree_levels()");
	test_assert(mtree_nodes(tree) == 1, "mtree_nodes()");
	mtree_build(tree, data, NULL);

	/* check hashes */
	hash_generic(hash, HASHSIZE, (unsigned char *)data, len);
	ptr = mtree_root(tree);
	test_assert(memcmp(hash, ptr, HASHSIZE) == 0, "checking root hash");

	test_assert(mtree_node(tree, 0, 0) == ptr, "mtree_node(0,0) = mtree_root()");

	/* clean up */
	mtree_free(tree);
	free(data);

	return fails;
}
