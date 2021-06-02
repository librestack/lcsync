#define _XOPEN_SOURCE 500
#define _DEFAULT_SOURCE 1
#include <arpa/inet.h>
#include <assert.h>
#include <ftw.h>
#include <libgen.h>
#include <librecast/crypto.h>
#include <librecast/net.h>
#include <limits.h>
#include <lmdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>
#include "file.h"
#include "globals.h"
#include "mld.h"
#include "mtree.h"
#include "net.h"

#define THREADS 1
#define MAXDBS 4

typedef enum {
	MDEX_TREE,
	MDEX_SUBTREE,
	MDEX_BLOCK
} mdex_type;

MDB_env *env;
MDB_txn *txn;
MDB_dbi dbi_file, dbi_chan;
//job_queue_t *jobq;
const size_t blocksz = 1024;

static size_t blockcnt;
static size_t dups;
static size_t files;
static size_t bytes;
static char *alias;
static lc_ctx_t *ctx;
static lc_channel_t *chanmain;
static volatile int running = 1;
static sem_t stop;

static void send_tree(struct in6_addr *addr, char *data, size_t len)
{
	lc_socket_t *sock = NULL;
	enum { vlen = 2 };
	struct iovec iov[vlen];
	const int on = 1;
	int s;
	struct stat *sb = (struct stat *)data;
	//mtree_tree *tree = (mtree_tree *)(data + sizeof(struct stat));

	printf("size of file to send is %zu\n", sb->st_size);

	if (!(sock = lc_socket_new(ctx))) return;
	if (lc_socket_loop(sock, on)) goto err_0;
	s = lc_socket_raw(sock);

	net_treehead_t hdr = {
		.data = htobe64((uint64_t)sb->st_size),
		.size = htobe64((uint64_t)len),
		.blocksz = htobe32(blocksz),
		.chan = net_send_channels,
		.pkts = htobe32(howmany(len, DATA_FIXED))
	};

	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof hdr;
	iov[1].iov_len = len;
	iov[1].iov_base = data + sizeof(struct stat);

	struct sockaddr_in6 sa = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(LC_DEFAULT_PORT),
	};
	memcpy(&sa.sin6_addr, addr, 16);

	mtree_tree *testtree;
	testtree = mtree_create(len, blocksz);
	mtree_build(testtree, data, NULL);
	assert(!mtree_verify(testtree, mtree_treelen(testtree)));

	net_send_tree(s, &sa, vlen, iov);
err_0:
	lc_socket_close(sock);
}

static void handle_join(mld_watch_t *event, mld_watch_t *watch)
{
	(void)watch; /* unused */
	char strgrp[INET6_ADDRSTRLEN];
	char hex[HEXLEN];
	unsigned char *hash;
	size_t node, flen;
	char *fpath;
	MDB_val k, v;
	int ret;

	inet_ntop(AF_INET6, event->grp, strgrp, INET6_ADDRSTRLEN);
	printf("%s() received request for grp %s on if=%u", __func__, strgrp, event->ifx);

	/* lookup address in index */
	mdb_txn_begin(env, NULL, 0, &txn);
	mdb_dbi_open(txn, "chan", MDB_RDONLY, &dbi_chan);

	k.mv_data = event->grp;
	k.mv_size = sizeof(struct in6_addr);
	ret = mdb_get(txn, dbi_chan, &k, &v);
	if (!ret) {
		mdex_type mtyp = *(char *)v.mv_data;
		char *p = (char *)v.mv_data + 1;
		switch (mtyp) {
		case MDEX_TREE:
			puts(" (match tree)");
			flen = v.mv_size - 1;
			fpath = p;
			printf("matched mtree for file '%.*s'\n", (int)flen, fpath);
			mdb_dbi_open(txn, "file", MDB_RDONLY, &dbi_file);
			k.mv_size = flen;
			k.mv_data = fpath;
			ret = mdb_get(txn, dbi_file, &k, &v);
			if (ret) fprintf(stderr, "%s\n", mdb_strerror(ret));
			else send_tree(event->grp, (char *)v.mv_data, v.mv_size);
			break;
		case MDEX_SUBTREE:
			puts(" (match subtree)");
			/* extract hash */
			/* [node][flen][HASH][fpath] => [size_t][size_t][HASHSIZE][flen] */
			node = *(size_t *)p;
			p += sizeof node;
			flen = *(size_t *)p;
			p += sizeof flen;
			hash = (unsigned char *)p;
			p += HASHSIZE;
			fpath = p;
			printf("matched subtree (%zu) of file '%.*s'\n", node, (int)flen, fpath);
			break;
		case MDEX_BLOCK:
			puts(" (match block)");
			// TODO: basically the same as MDEX_SUBTREE
			break;
		}
	}
#if 0
	else if (ret == MDB_NOTFOUND) {
		mdb_dbi_open(txn, "chan_block", MDB_RDONLY, &dbi_chanblock);
		ret = mdb_get(txn, dbi_chanblock, &k, &v);
		if (!ret) {
			printf(" (channel matches block)");
			// TODO find block & send
		}
#endif
	else if (ret == MDB_NOTFOUND) {
		puts(" (ignored)");
	}
	mdb_txn_abort(txn);
}

static void do_mld()
{
	mld_t *mld;
	mld_watch_t *watch;

	puts("starting MLD listener");
	mld = mld_start(&running);
	watch = mld_watch_init(mld, 0, NULL, MLD_EVENT_JOIN, &handle_join, NULL, 0);
	mld_watch_start(watch);
	sem_wait(&stop);
	mld_watch_cancel(watch);
	mld_stop(mld);
}

static int indextree(mtree_tree *tree, const char *fpath, const size_t flen, const struct stat *sb, int typeflag)
{
	// TODO: index subtree hashes and blocks
	//
	// TODO channel -> type|hash|node|file
	lc_channel_t *chanside;
	MDB_val k, v;
	unsigned char *ptr;
	char hex[HEXLEN];
	char straddr[INET6_ADDRSTRLEN];
	int ret = 0;
	size_t blocks = mtree_blocks(tree);
	for (size_t i = 0; i < mtree_nodes(tree); i++) {
		ptr = mtree_data(tree, i);

		/* channel -> hash(block) */
		chanside = lc_channel_nnew(ctx, ptr, HASHSIZE);
		k.mv_data = lc_channel_in6addr(chanside);
		inet_ntop(AF_INET6, k.mv_data, straddr, INET6_ADDRSTRLEN);
		k.mv_size = sizeof(struct in6_addr);
		v.mv_size = sizeof i + sizeof flen + HASHSIZE + flen + 1;
		ret = mdb_put(txn, dbi_chan, &k, &v, MDB_NOOVERWRITE | MDB_RESERVE);
		if (ret && ret != MDB_KEYEXIST) {
			fprintf(stderr, "%s\n", mdb_strerror(ret));
			break;
		}
		if (i < blocks) {
			*(char *)v.mv_data = MDEX_BLOCK;
			blockcnt++;
		}
		else {
			*(char *)v.mv_data = MDEX_SUBTREE;
		}
		/* store filename, node number etc. */
		/* [node][flen][HASH][fpath] => [size_t][size_t][HASHSIZE][flen] */
		char *p = (char *)v.mv_data + 1;
		*(size_t *)p = i;
		printf("this is node %zu\n", *(size_t *)p);
		p += sizeof i;
		*(size_t *)p = flen;
		p += sizeof flen;
		memcpy(p, ptr, HASHSIZE);
		p += HASHSIZE;
		memcpy(p, fpath, flen);

		sodium_bin2hex(hex, HEXLEN, ptr, HASHSIZE);
		fprintf(stderr, "%08zu: %.*s %s\n", i, HEXLEN, hex, straddr);
	}
	lc_channel_free(chanside);
	return ret;
}


static int indexfile(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	(void)ftwbuf;
	int ret = 0;
	int fds;
	char *smap = NULL;
	char straddr[INET6_ADDRSTRLEN];
	ssize_t sz_s;
	struct stat sbs;
	mtree_tree *stree;
	lc_channel_t *chanside;
	MDB_val k, v;

	if (typeflag != FTW_F) return 0;
	files++;

	/* TODO: record all metadata, even for 0 byte files */
	if (!sb->st_size) return 0;

	/* TODO: if alias, check for matching key */

	if ((sz_s = file_map((char *)fpath, &fds, &smap, 0, PROT_READ, &sbs)) == -1)
		return -1;
	stree = mtree_create(sz_s, blocksz);
	mtree_build(stree, smap, NULL);
	//mtree_hexdump(stree, stderr);

	//blocks += mtree_blocks(stree);

	bytes += sb->st_size;

	// TODO: store metadata

	/* channel -> filename */
	unsigned char hash[HASHSIZE];
	char *fcopy = strdup(fpath);
	char *base  = basename(fcopy);
	size_t flen = strlen(fpath);
	hash_generic(hash, HASHSIZE, (unsigned char *)base, strlen(base));
	chanside = lc_channel_nnew(ctx, hash, HASHSIZE);
	//chanside = lc_channel_new(ctx, (char *)fpath); // FIXME (temp) - ignore alias
	//chanside = lc_channel_sidehash(chanmain, (unsigned char *)fpath, strlen(fpath)); // FIXME - duplicate
	k.mv_data = lc_channel_in6addr(chanside);
	inet_ntop(AF_INET6, k.mv_data, straddr, INET6_ADDRSTRLEN);
	k.mv_size = sizeof(struct in6_addr);
	//v.mv_data = (char *)fpath;
	v.mv_size = flen + 1;
	if (alias) printf("[%s] alias=%s, (%zu) ", straddr, alias, v.mv_size);
	puts(fpath);
	ret = mdb_put(txn, dbi_chan, &k, &v, MDB_NOOVERWRITE | MDB_RESERVE);
	if (ret && ret != MDB_KEYEXIST) {
		fprintf(stderr, "%s\n", mdb_strerror(ret));
		goto err_0;
	}
	*(char *)v.mv_data = MDEX_TREE;
	memcpy((char *)v.mv_data + 1, fpath, flen);
	lc_channel_free(chanside);

	/* filename -> mtree */
	k.mv_data = (char *)fpath;
	k.mv_size = strlen(fpath);
	size_t treelen = mtree_treelen(stree);
	v.mv_size = treelen + sizeof(struct stat);
	//ret = mdb_put(txn, dbi_file, &k, &v, MDB_NOOVERWRITE);
	ret = mdb_put(txn, dbi_file, &k, &v, MDB_NOOVERWRITE | MDB_RESERVE);
	//v.mv_data = mtree_data(stree, 0);
	if (ret == MDB_KEYEXIST) {
		//dups++;
		ret = 0;
	}
	else if (ret) {
		fprintf(stderr, "%s\n", mdb_strerror(ret));
	}
	else {
		/* store stat buffer and mtree data */
		memcpy(v.mv_data, sb, sizeof(struct stat));
		memcpy((char *)v.mv_data + sizeof(struct stat), mtree_data(stree, 0), treelen);
	}

	ret = indextree(stree, fpath, flen, sb, typeflag);
err_0:
	mtree_free(stree);
	file_unmap(smap, sz_s, fds);
	return ret;
}

int main(int argc, char *argv[])
{
	int flags = FTW_MOUNT | FTW_DEPTH;
	char hostname[HOST_NAME_MAX];
	char *hostptr = NULL;
	char template[] = "/tmp/mdex-XXXXXX";
	char *dbpath = mkdtemp(template);
	char *p;

	if (!dbpath) return EXIT_FAILURE;

	//blocksz = (size_t)file_chunksize();

	//jobq = job_queue_create(THREADS);

	ctx = lc_ctx_new();

	mdb_env_create(&env);
	mdb_env_set_mapsize(env, 10485760000);
	mdb_env_set_maxdbs(env, MAXDBS);
	mdb_env_open(env, dbpath, 0, 0600);
	mdb_txn_begin(env, NULL, 0, &txn);
	mdb_dbi_open(txn, "file", MDB_CREATE, &dbi_file);
	mdb_dbi_open(txn, "chan", MDB_CREATE, &dbi_chan);

	argv[0] = ".";
	for (int i = (argc < 2) ? 0 : 1; i < argc; i++) {
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
		chanmain = lc_channel_new(ctx, alias);
		nftw(argv[i], &indexfile, 20, flags);
		lc_channel_free(chanmain);
	}
	mdb_txn_commit(txn);

	//job_queue_destroy(jobq);

	printf("%zu blocks indexed in %zu files. %zu duplicate blocks skipped. %zu bytes total\n", blockcnt, files, dups, bytes);

	// TODO: fire up mld listener
	do_mld();

	mdb_env_close(env);

	// TODO delete tempdir

	lc_ctx_free(ctx);

	return 0;
}
