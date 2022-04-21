/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2022 Brett Sheffield <bacs@librecast.net> */

#define _XOPEN_SOURCE 500 /* required for nftw() */
#include "log.h"
#include "mdex.h"
#include <assert.h>
#include <ftw.h>
#include <libgen.h>
#include <semaphore.h>
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

struct mdex_file_s {
	mdex_file_t *next;
	struct stat sb;
	char fpath[PATH_MAX];
	int typeflag;
};

struct mdex_s {
	sem_t lock;
	uint64_t files;
	uint64_t bytes;
	char *share;
	mdex_file_t *head;
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
	for (mdex_file_t *f = mdex->head; f; f = f->next) {
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

static void mdex_fpath_set(mdex_t *mdex, mdex_file_t *file, const char *fpath)
{
	char *ptr = file->fpath;
	char *btmp = strdup(fpath);
	char *dtmp = strdup(fpath);
	char *dir, *base;
	size_t z;

	assert(btmp); assert(dtmp);

	dir = dirname(dtmp);
	base = basename(btmp);

	/* strip leading ./ if present */
	if (!strncmp(dir, "./", 2)) dir += 2;

	/* prepend share name */
	if (mdex->share) {
		z = strlen(mdex->share);
		memcpy(ptr, mdex->share, z);
		ptr += z;
	}

	/* dirname + / + basename */
	z = strlen(dir);
	memcpy(ptr, dir, z);
	ptr += z;
	*ptr = '/';
	ptr++;
	z = strlen(base);
	memcpy(ptr, base, z);

	free(btmp);
	free(dtmp);
}

static int mdex_file(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	(void)ftwbuf;

	if (typeflag == FTW_F) {
		mdex_file_t *file = calloc(1, sizeof(mdex_file_t));
		if (!file) return -1;
		file->typeflag = typeflag;

		memcpy(&file->sb, sb, sizeof(*sb));
		mdex_fpath_set(g_mdex, file, fpath);

		// TODO hash the resulting mess
		// TODO index hash of file - multicast group
		// unsigned char hash[HASHSIZE];
		// eg. hash_generic(hash, HASHSIZE, (unsigned char *)alias, strlen(alias));

		// TODO mtree for directory? What about metadata?

		// TODO check if mtree exists - compare mtime of file and mtree

		// TODO create mtree

		// TODO index blocks

		sem_wait(&g_mdex->lock);
		g_mdex->files++;
		g_mdex->bytes += sb->st_size;
		file->next = g_mdex->head;
		g_mdex->head = file;
		sem_post(&g_mdex->lock);
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
	mdex_file_t *f, *tmp;

	sem_wait(&mdex->lock);
	f = mdex->head;
	while (f) {
		tmp = f;
		f = f->next;
		free(tmp);
	}
	sem_destroy(&mdex->lock);
	free(mdex);
}

mdex_t *mdex_init(char *share)
{
	mdex_t *mdex = calloc(1, sizeof(mdex_t));
	sem_init(&mdex->lock, 0, 1);
	if (mdex && share) mdex->share = share;
	return mdex;
}
