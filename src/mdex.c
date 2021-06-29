/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#define _XOPEN_SOURCE 500
#define _DEFAULT_SOURCE 1
#include "log.h"
#include "mdex.h"
#include <assert.h>
#include <ftw.h>
#include <lmdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>

#define MAXDBS 4
#define MAPSIZE 10485760000

struct bnode {
	struct bnode *l;
	struct bnode *r;
	size_t klen;
	size_t vlen;
	void *key;
	void *val;
};

struct mdex_s {
	MDB_env *env;
	MDB_dbi *dbi;
	MDB_txn *txn;
};

char blah[1024];
struct bnode *last = (struct bnode *)blah;

//static int mdex_put_type_file(struct in6_addr *addr, char *fpath ... );

int mdex_del(struct in6_addr *addr)
{
	(void)addr;
	return 0;
}

int mdex_get(struct in6_addr *addr, void **data, size_t *size, char *type)
{
	(void)addr; (void)data; (void)size; (void)type;
	return 0;
}

/* for MDEX_FILE, mmap the file, store the mtree and fstat 
 * for MDEX_MEM, store mtree and ptr + size
 * for MDEX_SUBTREE, point to the mtree + node */
int mdex_put(struct in6_addr *addr, void *data, size_t size, char type)
{
	(void)addr; (void)data; (void)size; (void)type;
	/* MDEX_FILE
	 *
	 * key = addr
	 * val = fpath
	 *
	 *  +++
	 *
	 *  key = fpath
	 *  val = mtree, fstat
	 *
	 *  -------------
	 *  MDEX_MEM
	 *
	 *  key = addr
	 *  val = ptr, size, mtree
	 *
	 *  no additional data needed
	 *  -------------
	 *  MDEX_SUBTREE
	 *
	 *  key = addr
	 *  val = fpath, node
	 *
	 *  +++
	 *
	 *  key = fpath
	 *  val = mtree, fstat
	 */

	struct s_s {
		char   type;
		void * data;
		size_t size;
	} s;

	s.type = type;
	s.size = size;
	memcpy(&s.data, data, size);

	return 0;
}

static int mdex_file(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	DEBUG("%s(%s)", __func__, fpath);
	return 0;
}

int mdex_files(int argc, char *argv[])
{
	char *cwd[] = { ".", NULL };
	char *alias, *p;
	char *hostptr = NULL;
	char hostname[HOST_NAME_MAX];
	int flags = FTW_MOUNT | FTW_DEPTH;
	int err = 0;
	//ctx = lc_ctx_new();
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
		//chanmain = lc_channel_new(ctx, alias);
		err = nftw(argv[i], &mdex_file, 20, flags);
		//lc_channel_free(chanmain);
	}
	//lc_ctx_free(ctx);
	return err;
}

#if 0
int mdex_db_open(void)
{
	char template[] = "/tmp/mdex-XXXXXX";
	char *dbpath = mkdtemp(template);
	if (!dbpath) return EXIT_FAILURE;
	mdb_env_create(&env);
	mdb_env_set_mapsize(env, 10485760000);
	mdb_env_set_maxdbs(env, MAXDBS);
	mdb_env_open(env, dbpath, 0, 0600);
	mdb_txn_begin(env, NULL, 0, &txn);
	mdb_dbi_open(txn, "file", MDB_CREATE, &dbi_file);
	mdb_dbi_open(txn, "chan", MDB_CREATE, &dbi_chan);
}
#endif

void mdex_free(mdex_t *mdex)
{
	if (!mdex) return;
	if (mdex->env) mdb_env_close(mdex->env);
	free(mdex);
}

mdex_t *mdex_init()
{
	mdex_t *mdex;
	char template[] = "/tmp/mdex-XXXXXX";
	char *dbpath = mkdtemp(template);

	if (!dbpath) return NULL;
	mdex = calloc(1, sizeof(mdex_t));
	mdb_env_create(&mdex->env);
	mdb_env_set_mapsize(mdex->env, MAPSIZE);
	mdb_env_set_maxdbs(mdex->env, MAXDBS);
	mdb_env_open(mdex->env, dbpath, 0, 0600);

	return mdex;
}
