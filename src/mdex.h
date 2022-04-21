/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _MDEX_H
#define _MDEX_H 1

#include <netinet/in.h>
#include <stdint.h>

/* when we see a channel join, which type of object is it for? */
typedef enum {
	MDEX_SHARE,      /* share details, same as directory? */
	MDEX_DIR,        /* a directory of files -> send fpaths? */
	MDEX_FILE,       /* file on disk => send mtree */
	MDEX_MEM,        /* maps to pointer to data in memory, send mtree */
	MDEX_SUBTREE,    /* subtree of blocks, send blocks */
	MDEX_BLOCK       /* single block. A subtree, but with special handling */
} mdex_type;

typedef struct mdex_s mdex_t;

int mdex_get(struct in6_addr *addr, void **data, size_t *size, char *type);
int mdex_put(struct in6_addr *addr, void  *data, size_t  size, char  type);
int mdex_del(struct in6_addr *addr);

void mdex_dump(mdex_t *mdex);
uint64_t mdex_filecount(mdex_t *mdex);
uint64_t mdex_filebytes(mdex_t *mdex);

/* index files and directories. Return 0 on success, -1 on error */
int mdex_files(mdex_t *mdex, int argc, char *argv[]);

mdex_t *mdex_init();
void mdex_free(mdex_t *mdex);

#endif /* _MDEX_H */
