/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2022 Brett Sheffield <bacs@librecast.net> */

#define _XOPEN_SOURCE 500 /* required for nftw() */
#include "log.h"
#include "mdex.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ftw.h>
#include <libgen.h>
#include <librecast.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>

#define DEBUG_MDEX 1
#ifdef DEBUG_MDEX
#undef DEBUG
#define DEBUG(...) do { if (DEBUG_ON) LOG(LOG_DEBUG, __VA_ARGS__); } while(0)
#else
#undef DEBUG
#define DEBUG(...) while(0)
#endif

static volatile int mdex_status;

struct mdex_file_s {
	mdex_file_t *next;
	struct stat sb;
	char fpath[PATH_MAX];
	unsigned char hash[HASHSIZE];
	lc_channel_t *chan;
	int typeflag;
};

struct mdex_grp_s {
	mdex_grp_t *next;
	struct in6_addr grp;
	char type;
	void *entry;
};

struct mdex_s {
	sem_t lock;
	uint64_t files;
	uint64_t bytes;
	lc_ctx_t *lctx;
	char *share;
	mdex_grp_t *grp;
	mdex_file_t *file;
};

static mdex_t *g_mdex;

/* find grp, return object and type */
int mdex_get(mdex_t *mdex, struct in6_addr *addr, void **data, char *type)
{
	char strgrp[INET6_ADDRSTRLEN];
	int ret = 0;
	DEBUG("%s", __func__);
	sem_wait(&mdex->lock);
	for (mdex_grp_t *grp = mdex->grp; grp; grp = grp->next) {
		inet_ntop(AF_INET6, &grp->grp, strgrp, INET6_ADDRSTRLEN);
		if (!memcmp(&grp->grp, addr, sizeof(struct in6_addr))) {
			*data = grp->entry;
			*type = grp->type;
			switch (grp->type) {
			case MDEX_SHARE:
				DEBUG("MDEX_SHARE");
				break;
			case MDEX_DIR:
				DEBUG("MDEX_DIR");
				break;
			case MDEX_FILE:
				DEBUG("MDEX_FILE");
				break;
			case MDEX_MEM:
				DEBUG("MDEX_MEM");
				break;
			case MDEX_SUBTREE:
				DEBUG("MDEX_SUBTREE");
				break;
			case MDEX_BLOCK:
				DEBUG("MDEX_BLOCK");
				break;
			};
			ret = 1;
			break;
		}
	}
	sem_post(&mdex->lock);
	return ret;
}

void mdex_dump(mdex_t *mdex)
{
	DEBUG("dumping mdex");
	for (mdex_file_t *f = mdex->file; f; f = f->next) {
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

char *mdex_file_fpath(mdex_file_t *f)
{
	return f->fpath;
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
		mdex_grp_t *grp = calloc(1, sizeof(mdex_grp_t));
		if (!grp) return -1;
		file->typeflag = typeflag;

		memcpy(&file->sb, sb, sizeof(*sb));
		mdex_fpath_set(g_mdex, file, fpath);
		hash_generic(file->hash, HASHSIZE, (unsigned char *)file->fpath, strlen(file->fpath));
		file->chan = lc_channel_nnew(g_mdex->lctx, file->hash, HASHSIZE);

		/* index multicast grp addr -> file */
		memcpy(&grp->grp, lc_channel_in6addr(file->chan), sizeof(struct in6_addr));
		grp->type = MDEX_FILE;
		grp->entry = file;

		// TODO mtree for directory? What about metadata?

		// TODO check if mtree exists - compare mtime of file and mtree

		// TODO create mtree

		// TODO index blocks

		sem_wait(&g_mdex->lock);
		g_mdex->files++;
		g_mdex->bytes += sb->st_size;
		file->next = g_mdex->file;
		g_mdex->file = file;
		grp->next = g_mdex->grp;
		g_mdex->grp = grp;
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

void mdex_reinit(mdex_t *mdex)
{
	void *tmp;
	sem_wait(&mdex->lock);
	for (mdex_file_t *f = mdex->file; f;) {
		tmp = f;
		lc_channel_free(f->chan);
		f = f->next;
		free(tmp);
	}
	mdex->file = NULL;
	for (mdex_grp_t *g = mdex->grp; g;) {
		tmp = g;
		g = g->next;
		free(tmp);
	}
	mdex->grp = NULL;
	sem_post(&mdex->lock);
}

void mdex_free(mdex_t *mdex)
{
	void *tmp;
	sem_wait(&mdex->lock);
	for (mdex_file_t *f = mdex->file; f;) {
		tmp = f;
		lc_channel_free(f->chan);
		f = f->next;
		free(tmp);
	}
	for (mdex_grp_t *g = mdex->grp; g;) {
		tmp = g;
		g = g->next;
		free(tmp);
	}
	sem_destroy(&mdex->lock);
	free(mdex);
}

mdex_t *mdex_init(lc_ctx_t *lctx, char *share)
{
	mdex_t *mdex = calloc(1, sizeof(mdex_t));
	mdex->lctx = lctx;
	sem_init(&mdex->lock, 0, 1);
	if (mdex && share) mdex->share = share;
	return mdex;
}
