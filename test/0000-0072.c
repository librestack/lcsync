/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2022 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/globals.h"
#include "../src/mtree.h"
#include "../src/net.h"
#include <assert.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

char * get_random_data(size_t sz)
{
	char *data;
	ssize_t byt;
	int fdr;
	data = malloc(sz);
	assert(data);
	fdr = open("/dev/random", O_RDONLY, 0);
	assert(fdr != -1);
	byt = read(fdr, data, sz);
	test_assert(byt == (ssize_t)sz, "read random bytes");
	return data;
}

int main()
{
	job_queue_t *q;
	mtree_tree *t1, *t2;
	size_t blocksz, len;
	size_t maplen;
	size_t bits;
	char *d1, *d2;
	unsigned char *bitmap;
	const int wholeblks = 20;
	size_t extrabytes;

	test_name("mtree_diff_subtree()");

	q = job_queue_create(8);

	blocksz = 16384;

	/* ensure length of data isn't an exact multiple of block size */
	extrabytes = 503;
	len = blocksz * wholeblks + extrabytes;

	/* create two trees with same random data */
	bits = blocksz / DATA_FIXED;
	t1 = mtree_create(len, blocksz);
	d1 = get_random_data(len);
	mtree_build(t1, d1, q);

	t2 = mtree_create(len, blocksz);
	d2 = malloc(len);
	memcpy(d2, d1, len);
	mtree_build(t2, d2, q);

	/* compare the trees, ensure they match */
	test_assert(mtree_diff_data(t1, t2) == 0, "trees match");

	/* create diffmap, ensure all bits zero */
	unsigned e = bits * wholeblks + howmany(extrabytes, DATA_FIXED);
	bitmap = mtree_diff_subtree(t1, t2, 0, bits);
	size_t base = mtree_blocks_subtree(t1, 0);
	maplen = base * bits;
	test_log("e = %u\n", e);
	test_log("maplen = %zu\n", maplen);
	test_assert(!hamm(bitmap, maplen), "zeroed bitmap");

	/* change some data */
	char *ptr;
	ptr = d2; //+ blocksz * wholeblks;
	memset(ptr, ~ptr[0], 1);

	ptr += blocksz * wholeblks;
	memset(ptr, ~ptr[0], 1);

	/* rebuild changed tree */
	mtree_build(t2, d2, q);
	test_assert(mtree_diff_data(t1, t2) != 0, "trees no longer match");

	/* recheck bitmap */
	bitmap = mtree_diff_subtree(t1, t2, 0, bits);
	unsigned hw = hamm(bitmap, maplen);
	test_assert(hw == 17, "bitmap registered the change, hw = %u/%u", hw, 17);
	free(bitmap);

	/* get bitmap for last block */
	size_t root = 12;
	base = mtree_blocks_subtree(t1, root);
	maplen = base * bits;
	bitmap = mtree_diff_subtree(t1, t2, root, bits);
	hw = hamm(bitmap, maplen);
	test_assert(hw == 1, "bitmap registered the change, hw = %u/%u", hw, 1);

	/* clean up */
	free(bitmap);
	free(d1);
	free(d2);
	mtree_free(t1);
	mtree_free(t2);

	job_queue_destroy(q);

	return fails;
}
