/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mtree.h"
#include <unistd.h>

size_t chunksz = 4096;

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
		len = chunksz * i;
		data = calloc(i, chunksz);
		for (size_t z = 0; z < i; z++)
			snprintf(data + z * chunksz, len, "%zu", z + 1);

		/* build tree */
		tree = mtree_create(len, chunksz);
		test_assert(tree != NULL, "tree alloc'd");
		test_assert(mtree_base(tree) == next_pow2(i), "mtree_base()");
		test_assert(mtree_lvl(tree) == mtree_levels(i), "mtree_levels()");
		test_assert(mtree_nodes(tree) == mtree_size(i), "mtree_nodes()");
		mtree_build(tree, data);

		/* check root address */
		test_assert(mtree_root(tree) == mtree_node(tree, mtree_lvl(tree) - 1, 0),
				"mtree_root()");
		test_assert(mtree_root(tree) == mtree_data(tree, mtree_nodes(tree) - 1),
				"mtree_root()");

		/* check data hashes */
		for (size_t z = 0; z < i; z++) {
			rptr = (unsigned char *)data + z * chunksz;
			crypto_generichash(hash, HASHSIZE, rptr, chunksz, NULL, 0);
			test_assert(memcmp(hash, mtree_data(tree, z), HASHSIZE) == 0,
					"%zu: checking data hash %zu", i, z);
		}

		/* check the tree */
		crypto_generichash_state state;
		unsigned char *parent = mtree_node(tree, 1, 0);
		for (size_t z = 0; z < mtree_nodes(tree) - 1; z += 2) {
			crypto_generichash_init(&state, NULL, 0, HASHSIZE);
			crypto_generichash_update(&state, mtree_data(tree, z+0), HASHSIZE);
			crypto_generichash_update(&state, mtree_data(tree, z+1), HASHSIZE);
			crypto_generichash_final(&state, hash, HASHSIZE);
			fprintf(stderr, "inspecting parent %p (%ld)\n", parent, parent - mtree_node(tree, 1, 0));
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
