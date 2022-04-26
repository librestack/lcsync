/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _MDEX_H
#define _MDEX_H 1

#include "job.h"
#include "mtree.h"
#include <librecast/types.h>
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

typedef struct mdex_file_s mdex_file_t;
typedef struct mdex_grp_s mdex_grp_t;
typedef struct mdex_s mdex_t;

int mdex_get(mdex_t *mdex, struct in6_addr *addr, void **data, char *type);

void mdex_dump(mdex_t *mdex);
uint64_t mdex_filecount(mdex_t *mdex);
uint64_t mdex_filebytes(mdex_t *mdex);
char *mdex_file_alias(mdex_file_t *f);
char *mdex_file_fpath(mdex_file_t *f);
lc_channel_t *mdex_file_chan(mdex_file_t *f);
mtree_tree *mdex_file_tree(mdex_file_t *f);
job_queue_t *mdex_q(mdex_t *mdex);
struct stat * mdex_file_sb(mdex_file_t *file);

/* index files and directories. Return 0 on success, -1 on error */
int mdex_files(mdex_t *mdex, int argc, char *argv[]);

mdex_t *mdex_init();
void mdex_reinit(mdex_t *mdex);
void mdex_free(mdex_t *mdex);

#endif /* _MDEX_H */
