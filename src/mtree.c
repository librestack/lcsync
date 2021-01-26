/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <semaphore.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>
#include "globals.h"
#include "hash.h"
#include "job.h"
#include "log.h"
#include "mtree.h"
#include "misc.h"

struct mtree_tree {
	size_t base;		/* size of base of tree (pow of 2) */
	size_t chunksz;		/* size of block */
	size_t nchunks;		/* number of blocks (<= base)) */
	size_t len;		/* total size of base (file) data */
	size_t lvls;		/* count of levels in tree */
	size_t nodes;		/* count of total nodes in tree */
	char  *data;		/* ptr to the base data */
	unsigned char *tree;	/* ptr to tree data == data(0) */
};

struct mtree_queue {
	mtree_tree	*tree;
	char		*data;
	sem_t		*done;
};

struct mtree_thread {
	size_t id;
	size_t nthreads;
	struct mtree_queue *q;
};

void mtree_hexdump(mtree_tree *tree, FILE *fd)
{
	char hex[HEXLEN];
	if (quiet) return;
	for (size_t i = 0; i < tree->nodes; i++) {
		sodium_bin2hex(hex, HEXLEN, tree->tree + i * HASHSIZE, HASHSIZE);
		fprintf(fd, "%08zu: %.*s\n", i, HEXLEN, hex);
	}
}

size_t mtree_level_base(mtree_tree *tree, size_t level)
{
	return mtree_lvl(tree) - level - 1;
}

/* node numbered from 0=root, levels numbered from 0=root */
size_t mtree_node_level(size_t node)
{
	return (size_t)log2(node + 1);
}

/* node numbered from 0=root, levels numbered from 0=base */
size_t mtree_node_level_base(size_t base, size_t node)
{
	size_t rootlvl = mtree_node_level(node);
	size_t treelvl = mtree_levels(base);
	return treelvl - rootlvl - 1;
}

size_t mtree_node_offset(size_t node)
{
	size_t npow = 1;
	size_t lvl = mtree_node_level(node);
	while (lvl--) npow *= 2;
	return node - npow + 1;
}

/* NB: we have no bounds checking or errors,
 * root MUST NOT be greater than node */
size_t mtree_node_offset_subtree(size_t node, size_t root)
{
	size_t off = mtree_node_offset(node);
	size_t a = mtree_node_level(node);
	size_t b = mtree_node_level(root);
	size_t d = (1U << a) / (1U << b);
	while (off > (d - 1)) off -= d;
	return off;
}

size_t mtree_node_parent(size_t node)
{
	return node / 2;
}

size_t mtree_child_base(size_t base, size_t node)
{
	node = (node + 1) * 2 - 1;
	return (node >= mtree_size(base)) ? 0 : node;
}

size_t mtree_child(mtree_tree *tree, size_t node)
{
	node = (node + 1) * 2 - 1;
	return (node >= mtree_nodes(tree)) ? 0 : node;
}

size_t mtree_node_sibling(size_t node)
{
	return (node % 2) ? node - 1 : node + 1;
}

/* return number of levels for tree with base number of data nodes */
size_t mtree_levels(size_t base)
{
	return (size_t)log2(next_pow2((uint32_t)base)) + 1;
}

/* return number of nodes in tree with base number of data nodes */
size_t mtree_size(size_t base)
{
	return (size_t)(next_pow2((uint32_t)base) << 1UL) - 1;
}

size_t mtree_blocksz(mtree_tree *tree)
{
	return tree->chunksz;
}

size_t mtree_len(mtree_tree *tree)
{
	return tree->len;
}

size_t mtree_treelen(mtree_tree *tree)
{
	return tree->nodes * HASHSIZE;
}

size_t mtree_base_level_nodes(size_t base, size_t level)
{
	while (level--) base /= 2;
	return base;
}

size_t mtree_level_nodes(mtree_tree *tree, size_t level)
{
	return mtree_base_level_nodes(tree->base, level);
}

// TODO: if offset > mtree_base_level_nodes(base) return -1 (SIZE_MAX)
// TODO: if level > mtree_levels(base) return -1 (SIZE_MAX)
size_t mtree_base_node_num(size_t base, size_t level, size_t offset)
{
	size_t n = 0;
	for (size_t z = mtree_levels(base); z > level; z--)
		n += mtree_base_level_nodes(base, z);
	n += offset;
	return n;
}

size_t mtree_node_num(mtree_tree *tree, size_t level, size_t offset)
{
	return mtree_base_node_num(tree->base, level, offset);
}

unsigned char *mtree_node(mtree_tree *tree, size_t level, size_t offset)
{
	unsigned char *ptr = tree->tree;
	while (level--)
		ptr += mtree_level_nodes(tree, level) * HASHSIZE;
	ptr += offset * HASHSIZE;
	return ptr;
}

unsigned char *mtree_nnode(mtree_tree *tree, size_t node)
{
	size_t base = mtree_base(tree);
	size_t lvl = mtree_node_level_base(base, node);
	size_t off = mtree_node_offset(node);
	return mtree_node(tree, lvl, off);
}

size_t mtree_blocks(mtree_tree *tree)
{
	return tree->nchunks;
}

size_t mtree_base(mtree_tree *tree)
{
	return tree->base;
}

size_t mtree_lvl(mtree_tree *tree)
{
	return tree->lvls;
}

size_t mtree_nodes(mtree_tree *tree)
{
	return tree->nodes;
}

unsigned char *mtree_root(mtree_tree *tree)
{
	return mtree_node(tree, mtree_lvl(tree) - 1, 0);
}

unsigned char *mtree_data(mtree_tree *tree, size_t n)
{
	return tree->tree + n * HASHSIZE;
}

size_t mtree_block_len(mtree_tree *tree, size_t n)
{
	size_t mod;
	if (n > tree->nchunks) return 0;
	mod = tree->len % tree->chunksz;
	return ((mod) && n == tree->nchunks) ? mod : tree->chunksz;
}

size_t mtree_blockn_len(mtree_tree *tree, size_t n)
{
	size_t mod;
	size_t min = mtree_subtree_data_min(mtree_base(tree), 0);
	size_t max = mtree_subtree_data_max(mtree_base(tree), 0);
	if (max > min + tree->nchunks) max = tree->nchunks + min;
	if (n < min || n > max || n > min + tree->nchunks) return 0;
	mod = tree->len % tree->chunksz;
	return ((mod) && (n == max)) ? mod : tree->chunksz;
}

char *mtree_block(mtree_tree *tree, size_t n)
{
	if (n > tree->nchunks) return NULL;
	return tree->data + tree->chunksz * n;
}

char *mtree_blockn(mtree_tree *tree, size_t n)
{
	size_t min = mtree_subtree_data_min(mtree_base(tree), 0);
	size_t max = mtree_subtree_data_max(mtree_base(tree), 0);
	if (n < min || n > max || n > min + tree->nchunks) return NULL;
	return tree->data + tree->chunksz * (n - min);
}

static int mtree_resize(mtree_tree *tree)
{
	/* FIXME: this only works for a fixed-size tree */
	tree->tree = calloc(tree->nodes, HASHSIZE);
	if (!tree->tree) {
		perror("calloc()");
		return -1;
	}
	return (tree->tree) ? 0 : -1;
}

size_t mtree_subtree_data_max(size_t base, size_t root)
{
	size_t n = root;
	while (mtree_node_level_base(base, n)) {
		n = mtree_child_base(base, n) + 1;
	}
	return n;
}

size_t mtree_subtree_data_min(size_t base, size_t root)
{
	size_t n = root;
	while (mtree_node_level_base(base, n)) {
		n = mtree_child_base(base, n);
	}
	return n;
}

size_t mtree_data_first(size_t nchunks, size_t nthreads, size_t id)
{
	if (nthreads == 0) nthreads++;
	return nchunks / nthreads * id;
}

size_t mtree_data_last(size_t nchunks, size_t nthreads, size_t id)
{
	if (nthreads == 0) nthreads++;
	if (id == nthreads - 1) return nchunks - 1;
	return nchunks / nthreads * (id + 1) - 1;
}

static void *mtree_hash_data(void *arg)
{
	struct mtree_thread *mt = (struct mtree_thread *)arg;
	struct mtree_queue *q = mt->q;
	size_t nthreads = (mt->nthreads > q->tree->base) ? q->tree->base : mt->nthreads;
	size_t child0, child1, parent, t, sz, first, last, len, level_nodes;
	unsigned char *wptr, *rptr;
	crypto_generichash_state state;

	/* hash data chunks */
	first = mtree_data_first(q->tree->base, nthreads, mt->id);
	last = mtree_data_last(q->tree->base, nthreads, mt->id);
	for (size_t z = first; z <= last; z++) {
		if (z < q->tree->nchunks) {
			len = q->tree->len - q->tree->chunksz * z;
			sz = (len < q->tree->chunksz) ? len : q->tree->chunksz;
			wptr = mtree_data(q->tree, z);
			rptr = (unsigned char *)q->data + z * q->tree->chunksz;
			crypto_generichash(wptr, HASHSIZE, rptr, sz, NULL, 0);
		}
		sem_post(&q->done[mtree_node_num(q->tree, 0, z)]);
	}

	/* write rest of tree */
	for (size_t lvl = 1; lvl < q->tree->lvls; lvl++) {
		level_nodes = mtree_level_nodes(q->tree, lvl);
		if (mt->id >= level_nodes) return NULL;
		t = (level_nodes < nthreads) ? level_nodes : nthreads;
		first = mtree_data_first(level_nodes, t, mt->id);
		last = mtree_data_last(level_nodes, t, mt->id);
		for (size_t z = first; z <= last; z++) {
			parent = mtree_node_num(q->tree, lvl, z);
			child0 = mtree_node_num(q->tree, lvl - 1, z * 2 + 0);
			child1 = mtree_node_num(q->tree, lvl - 1, z * 2 + 1);
			sem_wait(&q->done[child0]);
			sem_wait(&q->done[child1]);
			crypto_generichash_init(&state, NULL, 0, HASHSIZE);
			rptr = mtree_node(q->tree, lvl - 1, z * 2 + 0);
			crypto_generichash_update(&state, rptr, HASHSIZE);
			rptr = mtree_node(q->tree, lvl - 1, z * 2 + 1);
			crypto_generichash_update(&state, rptr, HASHSIZE);
			wptr = mtree_node(q->tree, lvl, z);
			crypto_generichash_final(&state, wptr, HASHSIZE);
			sem_post(&q->done[parent]);
		}
	}
	return NULL;
}

int mtree_build(mtree_tree *tree, char *data, job_queue_t *jq)
{
	job_queue_t *jobq = jq;
	size_t nthreads = MIN((jq) ? jq->nthreads : THREAD_MAX, tree->base);
	struct mtree_queue q = {0};
	struct mtree_thread *mt = NULL;
	tree->data = data;
	q.tree = tree;
	q.data = data; // FIXME: redundant - tree now has pointer to data
	q.done = calloc(tree->nodes, sizeof(sem_t));
	if (!q.done) return -1;
	for (size_t z = 0; z < tree->nodes; z++) sem_init(&q.done[z], 0, 0);
	if (!jq) jobq = job_queue_create(nthreads);
	if (nthreads) {
		mt = calloc(nthreads, sizeof(struct mtree_thread));
		if (!mt) goto err_nomem_0;
	}
	for (size_t z = 0; z < nthreads; z++) {
		mt[z].id = z;
		mt[z].q = &q;
		mt[z].nthreads = nthreads;
		job_push_new(jobq, &mtree_hash_data, &mt[z], sizeof mt[z], &free, 0);
	}
#if THREAD_MAX == 0
	mt = calloc(1, sizeof(struct mtree_thread));
	if (!mt) goto err_nomem_0;
	mt[0].q = &q;
	mt[0].nthreads = nthreads;
	mtree_hash_data(mt);
#else
	sem_wait(&q.done[0]); /* wait for root node */
#endif
	if (!jq) job_queue_destroy(jobq);
	free(mt);
	for (size_t z = 0; z < tree->nodes; z++) sem_destroy(&q.done[z]);
	free(q.done);
	return 0;
err_nomem_0:
	free(q.done);
	errno = ENOMEM;
	return -1;
}

// FIXME: badly named - we're setting the tree ptr, not the data
void mtree_setdata(mtree_tree *tree, unsigned char *data)
{
	free(tree->tree); // FIXME: caller should do this
	tree->tree = data;
}

mtree_tree *mtree_create(size_t len, size_t chunksz)
{
	mtree_tree *tree = calloc(1, sizeof(mtree_tree));
	if (!tree) {
		perror("calloc()");
		return NULL;
	}
	tree->chunksz = chunksz;
	tree->len = len;
	tree->nchunks = len / chunksz + !!(len % chunksz);
	tree->base = next_pow2(tree->nchunks);
	tree->lvls = mtree_levels(tree->base);
	tree->nodes = mtree_size(tree->base);
	if (len && mtree_resize(tree)) {
		mtree_free(tree);
		tree = NULL;
	}
	return tree;
}

void mtree_free(mtree_tree *tree)
{
	free(tree->tree);
	free(tree);
}

int mtree_verify(mtree_tree *tree, size_t len)
{
	unsigned char hash[HASHSIZE];
	unsigned char *parent;
	crypto_generichash_state state;
	if (tree == NULL || !len) return -1;
	if (tree->tree == NULL || !len) return -1;
	if (len % HASHSIZE) return -1;
	parent = mtree_node(tree, 1, 0);
	for (size_t i = 0; i < tree->nodes - 1; i += 2) {
		if (mtree_data(tree, i+1) + HASHSIZE > tree->tree + len) return -1;
		crypto_generichash_init(&state, NULL, 0, HASHSIZE);
		crypto_generichash_update(&state, mtree_data(tree, i+0), HASHSIZE);
		crypto_generichash_update(&state, mtree_data(tree, i+1), HASHSIZE);
		crypto_generichash_final(&state, hash, HASHSIZE);
		if (memcmp(hash, parent, HASHSIZE) != 0) return -1;
		parent += HASHSIZE;
	}
	return 0;
}

int mtree_cmp(mtree_tree *t1, mtree_tree *t2)
{
	if (t1 == NULL && t2 == NULL) return 0;
	if (!t1) return -1;
	if (!t2) return 1;
	if (t1->len < t2->len) return -1;
	if (t1->len > t2->len) return 1;
	return memcmp(t1->tree, t2->tree, mtree_nodes(t1) * HASHSIZE);
}

size_t mtree_diff_data(mtree_tree *t1, mtree_tree *t2)
{
	for (size_t i = 0; i < mtree_base(t1); i++) {
		if (memcmp(mtree_data(t1, i), mtree_data(t2, i), HASHSIZE))
			return i + 1;
	}
	return 0;
}

size_t mtree_diff(mtree_tree *t1, mtree_tree *t2)
{
	size_t off = 0;
	size_t lvl = mtree_lvl(t1) - 1;
	if (memcmp(mtree_root(t1), mtree_root(t2), HASHSIZE) == 0) return 0;
	while (lvl) {
		while (!memcmp(mtree_node(t1, lvl, off), mtree_node(t2, lvl, off), HASHSIZE))
			off++;
		off *= 2;
		lvl--;
	}
	if (!memcmp(mtree_data(t1, off), mtree_data(t2, off), HASHSIZE)) off++;
	return off + 1;
}

int mtree_bitcmp(unsigned char *map, size_t block)
{
	if (!map) return -1;
	return !!(map[block >> CHAR_BIT] & 1UL << block);
}

unsigned char *mtree_diff_map(mtree_tree *t1, mtree_tree *t2)
{
	return mtree_diff_subtree(t1, t2, 0, 1);
}

size_t mtree_base_subtree(mtree_tree *tree, size_t n)
{
	return mtree_base(tree) / (1U << mtree_node_level(n));
}

/* perform bredth-first search of subtree, return bitmap */
unsigned char *mtree_diff_subtree(mtree_tree *t1, mtree_tree *t2, size_t root, unsigned bits)
{
	size_t base, child, n;
	job_queue_t *q;
	job_t *job;
	unsigned char *map = NULL;
	if (!memcmp(mtree_nnode(t1, root), mtree_nnode(t2, root), HASHSIZE))
		return NULL; /* subtree root matches, stop now */
	base = mtree_base_subtree(t1, root);
	n = (base + (CHAR_BIT - 1)) / CHAR_BIT;
	map = calloc(bits, n);
	child = mtree_child(t1, root);
	if (!child) { /* leaf node */
		map[0] |= 1U;
		return map;
	}
	q = job_queue_create(0);
	job_push_new(q, NULL, &child, sizeof child, NULL, JOB_COPY);
	child++;
	job_push_new(q, NULL, &child, sizeof child, NULL, JOB_COPY);
	while ((job = job_shift(q))) {
		n = *(size_t *)job->arg;
		if (memcmp(mtree_nnode(t1, n), mtree_nnode(t2, n), HASHSIZE)) {
			child = mtree_child(t1, n);
			if (child) {
				job_push_new(q, NULL, &child, sizeof child, NULL, JOB_COPY);
				child++;
				job_push_new(q, NULL, &child, sizeof child, NULL, JOB_COPY);
			}
			else { /* leaf node, update bitmap */
				n = mtree_node_offset_subtree(n, root);
				for (unsigned i = 0; i < bits; i++) {
					map[(n + i) / CHAR_BIT] |= 1U << ((n + i) % CHAR_BIT);
				}
			}
		}
		free(job->arg);
		free(job);
	}
	job_queue_destroy(q);
	return map;
}

void mtree_update(mtree_tree *tree, char *data, size_t n)
{
	unsigned char *parent, *child1, *child2;
	size_t sz = ((n + 1) * tree->chunksz > tree->len) ? tree->len % tree->chunksz : tree->chunksz;
	crypto_generichash_state state;

	/* rehash changed data chunk */
	child1 = (unsigned char *)data + tree->chunksz * n;
	crypto_generichash(mtree_data(tree, n), HASHSIZE, child1, sz, NULL, 0);

	/* update parent nodes */
	for (size_t lvl = 1; lvl < mtree_lvl(tree); lvl++) {
		n /= 2;
		parent = mtree_node(tree, lvl, n);
		child1 = mtree_node(tree, lvl - 1, n * 2);
		child2 = child1 + HASHSIZE;
		crypto_generichash_init(&state, NULL, 0, HASHSIZE);
		crypto_generichash_update(&state, child1, HASHSIZE);
		crypto_generichash_update(&state, child2, HASHSIZE);
		crypto_generichash_final(&state, parent, HASHSIZE);
	}
}
