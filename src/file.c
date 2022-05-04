/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2022 Brett Sheffield <bacs@librecast.net> */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "globals.h"
#include "file.h"
#include "job.h"
#include "log.h"
#include "mtree.h"

long file_chunksize(void)
{
	return blocksize;
}

ssize_t file_map(char *filename, int *fd, char **map, off_t sz, int prot, struct stat *sb)
{
	size_t st_size;
	int oflag = O_RDONLY;
	int flags = MAP_PRIVATE;
	mode_t mode = 0;
	if (((prot & PROT_WRITE) == PROT_WRITE)) {
		oflag = O_RDWR;
		flags = MAP_SHARED;
	}
	if (sz) {
		oflag |= O_CREAT;
		mode = sb->st_mode;
	}
	if ((*fd = open(filename, oflag, mode)) == -1) {
		if (errno != EISDIR) perror("open");
		return -1;
	}
	if (!sb->st_ino && fstat(*fd, sb) == -1) {
		perror("fstat");
		return -1;
	}
	st_size = (sz) ? sz : sb->st_size;
	if (sz) {
		if (ftruncate(*fd, sz) == -1) {
			perror("ftruncate");
			return -1;
		}
	}
	*map = mmap(NULL, st_size, prot, flags, *fd, 0);
	if (*map == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	return st_size;
}

void file_unmap(char *map, size_t st_size, int fd)
{
	munmap(map, st_size);
	close(fd);
}

int file_dump(int *argc, char *argv[])
{
	(void) argc; /* unused */
	int fds;
	char *src = argv[0];
	char *smap = NULL;
	ssize_t sz_s;
	struct stat sbs;
	mtree_tree *stree;
	if ((sz_s = file_map(src, &fds, &smap, 0, PROT_READ, &sbs)) == -1)
		return -1;
	stree = mtree_create(sz_s, blocksize);
	mtree_build(stree, smap, NULL);
	mtree_hexdump(stree, stderr);
	mtree_free(stree);
	file_unmap(smap, sz_s, fds);
	return 0;
}

int file_sync(int *argc, char *argv[])
{
	(void) argc; /* unused */
	char *src = argv[0];
	char *dst = argv[1];
	int c = 0;
	int fds, fdd;
	char *smap = NULL, *dmap = NULL;
	size_t base, blocksz, n, nthreads, off, sz;
	ssize_t sz_s, sz_d;
	struct stat sbs = {0};
	struct stat sbd = {0};
	job_queue_t *jobq;
	mtree_tree *stree, *dtree;
	DEBUG("mapping src: %s", src);
	if ((sz_s = file_map(src, &fds, &smap, 0, PROT_READ, &sbs)) == -1)
		return -1;
	DEBUG("mapping dst: %s", dst);
	sbd.st_mode = sbs.st_mode;
	if ((sz_d = file_map(dst, &fdd, &dmap, sz_s, PROT_READ|PROT_WRITE, &sbd)) == -1)
		return -1;
	fchmod(fdd, sbs.st_mode);
	blocksz = (size_t)file_chunksize();
	if (sbs.st_size > sbd.st_size) {
		sz = sbs.st_size - sbd.st_size;
		memcpy(dmap + sbs.st_size - sz, smap + sbs.st_size - sz, sz);
	}
	if (sbd.st_size) {
		stree = mtree_create(sz_s, blocksz);
		dtree = mtree_create(sz_s, blocksz);
		base = mtree_base(stree);
		DEBUG("source tree with %zu nodes (base = %zu, levels = %zu)",
				mtree_nodes(stree), base, mtree_lvl(stree));
		nthreads = (base < THREAD_MAX) ? base : THREAD_MAX;
		jobq = job_queue_create(nthreads);
		mtree_build(stree, smap, jobq);
		mtree_build(dtree, dmap, jobq);
		while ((n = mtree_diff(stree, dtree))) {
			n--;
			sz = ((n + 1) * blocksz > (size_t)sz_s) ? sz_s % blocksz : blocksz;
			off = n * blocksz;
			DEBUG("syncing chunk %zu (offset=%zu)", n, off);
			memcpy(dmap + off, smap + off, sz);
			mtree_update(dtree, dmap, n);
			c++;
		}
		mtree_free(stree);
		mtree_free(dtree);
		job_queue_destroy(jobq);
	}
	file_unmap(smap, sz_s, fds);
	file_unmap(smap, sz_d, fdd);
	DEBUG("syncing took %i rounds", c);
	return c;
}
