/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <unistd.h>

size_t blocksz = 4096;

int main()
{
	mtree_tree *tree = NULL;
	char *data;
	size_t len;
	unsigned char hash[HASHSIZE] = "";
	unsigned char *rptr;

	test_name("mtree_create() - multi-node");

	for (size_t i = 2; i < 17; i++) {
		/* write data */
		len = blocksz * i;
		data = calloc(i, blocksz);
		for (size_t z = 0; z < i; z++)
			snprintf(data + z * blocksz, len, "%zu", z + 1);

		/* build tree */
		tree = mtree_create(len, blocksz);
		test_assert(tree != NULL, "tree alloc'd");
		test_assert(mtree_base(tree) == next_pow2(i), "mtree_base()");
		test_assert(mtree_lvl(tree) == mtree_levels(i), "mtree_levels()");
		test_assert(mtree_nodes(tree) == mtree_size(i), "mtree_nodes()");
		mtree_build(tree, data, NULL);

		/* check root address */
		test_assert(mtree_root(tree) == mtree_node(tree, mtree_lvl(tree) - 1, 0),
				"mtree_root()");
		test_assert(mtree_root(tree) == mtree_data(tree, mtree_nodes(tree) - 1),
				"mtree_root()");

		/* check data hashes */
		for (size_t z = 0; z < i; z++) {
			rptr = (unsigned char *)data + z * blocksz;
			hash_generic(hash, HASHSIZE, rptr, blocksz);
			test_assert(memcmp(hash, mtree_data(tree, z), HASHSIZE) == 0,
					"%zu: checking data hash %zu", i, z);
		}

		/* check the tree */
		hash_state state;
		unsigned char *parent = mtree_node(tree, 1, 0);
		for (size_t z = 0; z < mtree_nodes(tree) - 1; z += 2) {
			hash_init(&state, NULL, 0, HASHSIZE);
			hash_update(&state, mtree_data(tree, z+0), HASHSIZE);
			hash_update(&state, mtree_data(tree, z+1), HASHSIZE);
			hash_final(&state, hash, HASHSIZE);
			fprintf(stderr, "inspecting parent %p (%ld)\n", (void *)parent, parent - mtree_node(tree, 1, 0));
			test_assert(memcmp(hash, parent, HASHSIZE) == 0,
					"checking node %zu + %zu", z, z + 1);
			parent += HASHSIZE;
		}

		/* clean up */
		mtree_free(tree);
		free(data);
	}

	return fails;
}
