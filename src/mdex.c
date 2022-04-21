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

static volatile int mdex_status;

struct bnode {
	struct bnode *l;
	struct bnode *r;
	size_t klen;
	size_t vlen;
	void *key;
	void *val;
};

struct mdex_file {
	struct mdex_file *next;
	struct stat sb;
	char fpath[PATH_MAX];
	int typeflag;
};

struct mdex_s {
	uint64_t files;
	uint64_t bytes;
	struct mdex_file *head;
};

static mdex_t *g_mdex;

int mdex_del(struct in6_addr *addr)
{
	(void)addr;
	return 0;
}

void mdex_dump(mdex_t *mdex)
{
	DEBUG("dumping mdex");
	for (struct mdex_file *f = mdex->head; f; f = f->next) {
		DEBUG("%s", f->fpath);
	}
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
	(void)ftwbuf;

	if (typeflag == FTW_F) {

		g_mdex->files++;
		g_mdex->bytes += sb->st_size;

		struct mdex_file *file = calloc(1, sizeof(struct mdex_file));
		if (!file) return -1;
		file->next = g_mdex->head;
		file->typeflag = typeflag;
		strcpy(file->fpath, fpath);
		memcpy(&file->sb, sb, sizeof(*sb));
		g_mdex->head = file;

		// TODO mtree for directory? What about metadata?

		// TODO check if mtree exists - compare mtime of file and mtree

		// TODO create mtree

		// TODO index blocks

	}
	return mdex_status;
}

void mdex_stop(int signo)
{
	mdex_status = signo;
}

int mdex_files(mdex_t *mdex, int argc, char *argv[])
{
	struct sigaction sa_int = { .sa_handler = &mdex_stop };
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

	sigaction(SIGINT, &sa_int, NULL);

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
	struct mdex_file *f = mdex->head, *tmp;
	while (f) {
		tmp = f;
		f = f->next;
		free(tmp);
	}
	free(mdex);
}

mdex_t *mdex_init()
{
	return calloc(1, sizeof(mdex_t));
}
