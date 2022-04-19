/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2022 Brett Sheffield <bacs@librecast.net> */

#define _XOPEN_SOURCE 500 /* required for nftw() */
#include "log.h"
#include "mdex.h"
#include <assert.h>
#include <ftw.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>

struct bnode {
	struct bnode *l;
	struct bnode *r;
	size_t klen;
	size_t vlen;
	void *key;
	void *val;
};

struct mdex_s {
	uint64_t files;
	uint64_t bytes;
};

static mdex_t *g_mdex;

int mdex_del(struct in6_addr *addr)
{
	(void)addr;
	return 0;
}

uint64_t mdex_filecount(mdex_t *mdex)
{
	return mdex->files;
}

uint64_t mdex_filebytes(mdex_t *mdex)
{
	return mdex->bytes;
}

static int mdex_file(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	(void)fpath; (void)sb; (void)typeflag; (void)ftwbuf;
	DEBUG("%s(%s)", __func__, fpath);

	// TODO - count files
	// TODO - count bytes
	// TODO - index file / directory
	// TODO - create mtree
	// TODO - index blocks
	//
	// TODO - mtree for directory? What about metadata?
	g_mdex->files++;
	g_mdex->bytes += sb->st_size;

	return 0;
}

int mdex_files(mdex_t *mdex, int argc, char *argv[])
{
	char *cwd[] = { ".", NULL };
	char *alias, *p;
	char *hostptr = NULL;
	char hostname[HOST_NAME_MAX];
	int flags = FTW_MOUNT | FTW_DEPTH;
	int err = 0;

	g_mdex = mdex;

	/* default to serving current working directory */
	if (!argc) {
		argc++;
		argv = cwd;
	}

	// TODO TODO TODO

	for (int i = 0; i < argc && !err; i++) {
		/* split off colon-delimited alias, if present */
		if ((p = strchr(argv[i], ':'))) {
			p[0] = '\0';
			alias = argv[i];
			argv[i] = p + 1;
		}
		else {
			/* no alias, use hostname */
			if (!hostptr) {
				gethostname(hostname, HOST_NAME_MAX);
				hostptr = hostname;
			}
			alias = hostptr;
		}
		err = nftw(argv[i], &mdex_file, 20, flags);
	}
	(void)alias;
	return err;
}

void mdex_free(mdex_t *mdex)
{
	free(mdex);
}

mdex_t *mdex_init()
{
	return calloc(1, sizeof(mdex_t));
}
