/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _FILE_H
#define _FILE_H 1

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

/* return size in bytes of data chunks 
 * for network, a chunk should be less than MTU (TODO) 
 * otherwise, we use the kernel page size */
long file_chunksize(void);

/* map local file into memory */
ssize_t file_map(char *filename, int *fd, char **map, off_t sz, int prot, struct stat *sb);

/* unmap memory-mapped file */
void file_unmap(char *map, size_t st_size, int fd);

/* hexdump merkle tree for local file */
int file_dump(int *argc, char *argv[]);

/* sync file src to dst, return number of chunks synced */
int file_sync(int *argc, char *argv[]);

#endif /* _FILE_H */
