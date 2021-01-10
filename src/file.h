/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _FILE_H
#define _FILE_H 1

/* return size in bytes of data chunks 
 * for network, a chunk should be less than MTU (TODO) 
 * otherwise, we use the kernel page size */
long file_chunksize(void);

int file_dump(int *argc, char *argv[]);

/* sync file src to dst, return number of chunks synced */
int file_sync(int *argc, char *argv[]);

#endif /* _FILE_H */
