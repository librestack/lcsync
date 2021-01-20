/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _MTREE_H
#define _MTREE_H 1

#include <stddef.h>
#include "hash.h"
#include "job.h"

/* NB: except where stated otherwise, nodes are numbered from 0=root
 * levels are in reverse from 0=base=data to mtree_levels() - 1 */

typedef struct mtree_tree mtree_tree;

typedef struct mtree_subtree_s mtree_subtree_t;
struct mtree_subtree_s {
	mtree_tree *    tree;           /* main tree */
	size_t          root;           /* root node of subtree */
};

/* hexdump tree to fd */
void mtree_hexdump(mtree_tree *tree, FILE *fd);

/* return level numbered from base, given level numbered from root */
size_t mtree_level_base(mtree_tree *tree, size_t level);

/* return tree level of node, numbered from 0=root, levels from 0=root */
size_t mtree_node_level(size_t node);

/* return tree level of node, numbered from 0=root, levels from 0=base */
size_t mtree_node_level_base(size_t base, size_t node);

/* return offset of node from first node in level */
size_t mtree_node_offset(size_t node);

/* return offset of node from first node in subtree level */
size_t mtree_node_offset_subtree(size_t node, size_t root);

/* return number of parent node, or 0 if none */
size_t mtree_node_parent(size_t node);

/* return number of first child node, or 0 if none */
size_t mtree_child_base(size_t base, size_t node);
size_t mtree_child(mtree_tree *tree, size_t node);

/* return number of sibling node, or 0 if none */
size_t mtree_node_sibling(size_t node);

/* return number of levels for tree with base number of data nodes */
size_t mtree_levels(size_t base);

/* return number of nodes in tree with base number of data nodes */
size_t mtree_size(size_t base);

/* return blocksize (FIXME: this is called chunksz in struct) for tree */
size_t mtree_blocksz(mtree_tree *tree);

/* return size of base (file) data from which tree is built */
size_t mtree_len(mtree_tree *tree);

/* return size of tree data */
size_t mtree_treelen(mtree_tree *tree);

/* return base (# of data chunks) in tree */
size_t mtree_base(mtree_tree *tree);

/* return base size of subtree */
size_t mtree_base_subtree(mtree_tree *tree, size_t n);

/* return number of levels in tree */
size_t mtree_lvl(mtree_tree *tree);

/* return node number for level and offset, nodes are numbered from 0=root and
 * levels are in reverse from 0=base=data to mtree_levels() - 1 */
size_t mtree_base_node_num(size_t base, size_t level, size_t offset);
size_t mtree_node_num(mtree_tree *tree, size_t level, size_t offset);

/* return number of nodes in tree */
size_t mtree_nodes(mtree_tree *tree);

/* return number of nodes on specified level. Levels are number up from the
 * base. base == 0 == data hashes */
size_t mtree_base_level_nodes(size_t base, size_t level);
size_t mtree_level_nodes(mtree_tree *tree, size_t level);

/* return pointer to specific node, where level is the number of levels above
 * 0=data hashes, and offset is the number of hashes from the start of that
 * level */
unsigned char *mtree_node(mtree_tree *tree, size_t level, size_t offset);

/* return pointer to numbered node (0=root) */
unsigned char *mtree_nnode(mtree_tree *tree, size_t node);

/* return pointer to root hash of tree */
unsigned char *mtree_root(mtree_tree *tree);

/* return pointer to specific data node */
unsigned char *mtree_data(mtree_tree *tree, size_t n);

/* return pointer to data block for node n */
char *mtree_block(mtree_tree *tree, size_t n);

/* build/update tree */
int mtree_build(mtree_tree *tree, char *data, job_queue_t *jobq);

/* set tree data pointer */
void mtree_setdata(mtree_tree *tree, unsigned char *data);

/* create merkle tree from data, hashing chunks of size chunksz
 * free tree when done */
mtree_tree *mtree_create(size_t len, size_t chunksz);

void mtree_free(mtree_tree *tree);

/* return 0 if tree is a valid tree, -1 if not, len = size of tree in bytes */
int mtree_verify(mtree_tree *tree, size_t len);

/* compare whole trees */
int mtree_cmp(mtree_tree *tree1, mtree_tree *tree2);

/* return first differing data node (by count, not index - first data node is 1)
 * return 0 if trees match */
size_t mtree_diff_data(mtree_tree *tree1, mtree_tree *tree2);

/* same as mtree_data_diff, but using the tree */
size_t mtree_diff(mtree_tree *tree1, mtree_tree *tree2);

/* return 1 if bit corresponding to block is set in bitmap, 0 if not */
int mtree_bitcmp(unsigned char *map, size_t block);

/* return bitmap of block differences, NULL if no difference
 * size is set to length of map returned */
unsigned char *mtree_diff_map(mtree_tree *t1, mtree_tree *t2);

/* return bitmap of block differences for the subtree below root
 * return NULL if trees match */
unsigned char *mtree_diff_subtree(mtree_tree *t1, mtree_tree *t2, size_t root);

/* update tree after data node n changed */
void mtree_update(mtree_tree *tree, char *data, size_t n);

/* return starting chunk based on number of threads */
size_t mtree_data_first(size_t nchunks, size_t nthreads, size_t id);
size_t mtree_data_last(size_t nchunks, size_t nthreads, size_t id);
size_t mtree_tree_first(size_t nchunks, size_t nthreads, size_t id);

#endif /* _MTREE_H */
