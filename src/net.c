/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include <assert.h>
#include <endian.h>
#include <libgen.h>
#include <netdb.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include "net.h"
#include "globals.h"
#include "mtree.h"
#include "file.h"

static int running = 1;

/* return number of bits set in bitmap */
static unsigned int countmap(unsigned char *map, size_t len)
{
	unsigned int c = 0;
	while (len--) {
		for (char v = map[len]; v; c++) {
			v &= v - 1;
		}
	}
	return c;
}

static void printmap(unsigned char *map, size_t len)
{
	for (size_t i = 0; i < len * CHAR_BIT; i++) {
		fprintf(stderr, "%d", !!isset(map, i));
	}
	fputc('\n', stderr);
}


void net_stop(int signo)
{
	(void) signo;
	running = 0;
	fprintf(stderr, "\nstopping on signal\n");
}

static size_t net_chunksize(void)
{
	return DATA_FIXED;
}

static unsigned char *net_hash_flag(unsigned char *hash, int flags)
{
	unsigned char *new = malloc(HASHSIZE);
	crypto_generichash_state state;
	crypto_generichash_init(&state, NULL, 0, HASHSIZE);
	crypto_generichash_update(&state, hash, HASHSIZE);
	crypto_generichash_update(&state, (unsigned char *)&flags, sizeof flags);
	crypto_generichash_final(&state, new, HASHSIZE);
	return new;
}

net_treehead_t *net_hdr_tree(net_treehead_t *hdr, mtree_tree *tree)
{
	memset(hdr, 0, sizeof *hdr);
	hdr->pkts = mtree_len(tree) / DATA_FIXED;
	if (mtree_len(tree) % DATA_FIXED) hdr->pkts++;
	hdr->chan = net_send_channels;
	memcpy(hdr->hash, mtree_root(tree), HASHSIZE);
	return hdr;
}

ssize_t net_recv_tree(int sock, struct iovec *iov)
{
	fprintf(stderr, "%s()\n", __func__);
	size_t idx, off, len, maplen, pkts;
	ssize_t byt = 0, msglen;
	uint64_t sz = iov->iov_len;
	net_treehead_t *hdr;
	char buf[MTU_FIXED];
	unsigned char *bitmap = NULL;
	do {
		if ((msglen = recv(sock, buf, MTU_FIXED, 0)) == -1) {
			perror("recv()");
			byt = -1;
			break;
		}
		fprintf(stderr, "%s(): recv %zi bytes\n", __func__, msglen);
		hdr = (net_treehead_t *)buf;
		if (!bitmap) {
			pkts = be32toh(hdr->pkts);
			maplen = pkts / CHAR_BIT + !!(pkts % CHAR_BIT);
			if (!(bitmap = malloc(maplen))) {
				perror("malloc()");
				return -1;
			}
			memset(bitmap, ~0, maplen - 1);
			bitmap[maplen - 1] = (1UL << (pkts % CHAR_BIT)) - 1;
		}
		sz = be64toh(hdr->size);
		if (!iov->iov_base) {
			if (!(iov->iov_base = malloc(sz))) {
				perror("malloc()");
				byt = -1;
				break;
			}
			//iov->iov_len = sz;
			iov->iov_len = (size_t)be64toh(hdr->data);
			fprintf(stderr, "got me %zu bytes !!!!!!!!!!!!!!!!!\n", iov->iov_len);
		}
		idx = (size_t)be32toh(hdr->idx);
		off = be32toh(hdr->idx) * DATA_FIXED;
		len = (size_t)be32toh(hdr->len);
		if (!!(bitmap[idx >> CHAR_BIT] & 1UL << idx)) {
			memcpy((char *)iov->iov_base + off, buf + sizeof (net_treehead_t), len);
			bitmap[idx >> CHAR_BIT] &= ~(1UL << (idx % CHAR_BIT));
		}
		byt += be32toh(hdr->len);
	}
	while (countmap(bitmap, maplen));
	// TODO verify tree (check hashes, mark bitmap with any that don't
	// match, go again
	free(bitmap);
	return byt;
}

void *net_job_recv_tree(void *arg)
{
	fprintf(stderr, "%s()\n", __func__);
	int s;
	ssize_t byt;
	net_data_t *data = (net_data_t *)arg;
	struct iovec *iov = calloc(1, sizeof(struct iovec));
	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_channel_t *chan = lc_channel_nnew(lctx, data->alias, HASHSIZE);
	lc_channel_bind(sock, chan);
	lc_channel_join(chan);
	s = lc_socket_raw(sock);
	byt = net_recv_tree(s, iov);
	fprintf(stderr, "%s(): tree received (%zi bytes)\n", __func__, byt);
	lc_channel_part(chan);
	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);
	return iov;
}

ssize_t net_send_tree(int sock, struct addrinfo *addr, size_t vlen, struct iovec *iov)
{
	ssize_t byt = 0;
	size_t sz, off = 0;
	size_t len = iov[1].iov_len;
	size_t idx = 0;
	net_treehead_t *hdr = iov[0].iov_base;
	struct msghdr msgh = {0};
	hdr->pkts = htobe32(iov[1].iov_len / DATA_FIXED + !!(iov[1].iov_len % DATA_FIXED));
	while (len) {
		sz = (len > DATA_FIXED) ? DATA_FIXED : len;
		msgh.msg_name = addr->ai_addr;
		msgh.msg_namelen = addr->ai_addrlen;
		msgh.msg_iov = iov;
		msgh.msg_iovlen = vlen;
		iov[1].iov_len = sz;
		iov[1].iov_base = (char *)iov[1].iov_base + off;
		hdr->idx = htobe32(idx++);
		hdr->len = htobe32(sz);
		off = sz;
		len -= sz;
		if ((byt = sendmsg(sock, &msgh, 0)) == -1) {
			perror("sendmsg()");
			break;
		}
	}
	return byt;
}

void *net_job_send_tree(void *arg)
{
	fprintf(stderr, "%s()\n", __func__);
	const int on = 1;
	net_data_t *data = (net_data_t *)arg;
	void *base = data->iov[0].iov_base;
	size_t len = data->iov[0].iov_len;
	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &on, sizeof(on));
	lc_channel_t *chan = lc_channel_nnew(lctx, data->alias, HASHSIZE);
	lc_channel_bind(sock, chan);
	int s = lc_channel_socket_raw(chan);
	struct addrinfo *addr = lc_channel_addrinfo(chan);
	struct iovec iov[2] = {0};
	net_treehead_t hdr = {
		.data = htobe64((uint64_t)data->byt),
		.size = htobe64(data->iov[0].iov_len),
		.chan = net_send_channels,
		.pkts = data->iov[0].iov_len / DATA_FIXED + !!(data->iov[0].iov_len % DATA_FIXED)
	};
	memcpy(&hdr.hash, data->hash, HASHSIZE);
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof hdr;
	while (running) {
		iov[1].iov_len = len;
		iov[1].iov_base = base;
		net_send_tree(s, addr, 2, iov);
	}
	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);
	return NULL;
}

ssize_t net_recv_subtree(int sock, mtree_tree *stree, mtree_tree *dtree, size_t root)
{
	fprintf(stderr, "%s()\n", __func__);
	ssize_t byt = 0, msglen;
	unsigned char *bitmap = NULL;
	char buf[MTU_FIXED];
	struct iovec iov[2] = {0};
	net_blockhead_t *hdr;
	uint32_t idx;
	size_t len, off;
	size_t maplen = howmany(mtree_base(stree), CHAR_BIT);
	bitmap = mtree_diff_subtree(stree, dtree, 0);
	printmap(bitmap, maplen);
	do {
		if ((msglen = recv(sock, buf, MTU_FIXED, 0)) == -1) {
			perror("recv()");
			byt = -1;
			break;
		}
		fprintf(stderr, "%s(): recv %zi bytes\n", __func__, msglen);
		hdr = (net_blockhead_t *)buf;
		//sz = be64toh(hdr->size);
		idx = be32toh(hdr->idx);
		off = (size_t)be32toh(hdr->idx) * DATA_FIXED;
		len = (size_t)be32toh(hdr->len);
		if (isset(bitmap, idx)) {
			fprintf(stderr, "recv'd a block I wanted idx=%u\n", idx);
			memcpy(mtree_block(dtree, idx), buf + sizeof (net_blockhead_t), len);
			clrbit(bitmap, idx);
		}
		else {
			fprintf(stderr, "recv'd a block I didn't want idx=%u\n", idx);
		}
		byt += be32toh(hdr->len);
	}
	while (countmap(bitmap, maplen));
	fprintf(stderr, "receiver - all blocks received\n");
	printmap(bitmap, maplen);
	free(bitmap);
	return byt;
}

ssize_t net_sync_subtree(mtree_tree *stree, mtree_tree *dtree, size_t root)
{
	int s;
	ssize_t byt = 0;
	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_channel_t *chan = lc_channel_nnew(lctx, mtree_nnode(stree, root), HASHSIZE);
	lc_channel_bind(sock, chan);
	lc_channel_join(chan);
	s = lc_socket_raw(sock);

	/* TODO: first, ensure destination is big enough */
	/* TODO: malloc, remap, update *len etc */

	fprintf(stderr, "%s(): receiving subtree at root %zu\n", __func__, root);

	byt = net_recv_subtree(s, stree, dtree, root);

	lc_channel_part(chan);
	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);
	return byt;
}

// TODO: write test for this function
// pass in arg with appropriate data and map
// check map is updated
// check jobs are queued
// data syncing?
//
// what does this job do?
// check a node, if different, queue it up
// if (and only if) we're at the channel level,
//	call mtree_diff_subtree() to build channel map
//	sync data on that channel
//	(this will be a separate function)
static void *net_job_diff_tree(void *arg)
{
	net_data_t *data = (net_data_t *)arg;
	size_t sz = sizeof(net_data_t) + sizeof(struct iovec) * data->len;
	job_queue_t *q = (job_queue_t *)data->iov[0].iov_base;
	mtree_tree *t1 = (mtree_tree *)data->iov[1].iov_base;
	mtree_tree *t2 = (mtree_tree *)data->iov[2].iov_base;
	char *dstdata = (char *)data->iov[3].iov_base;
	size_t len = data->iov[3].iov_len;
	size_t n = data->n;
	size_t child;

	fprintf(stderr, "sz %zu\n", sz);
	fprintf(stderr, "checking node %zu\n", n);
	if (memcmp(mtree_nnode(t1, n), mtree_nnode(t2, n), HASHSIZE)) {
		fprintf(stderr, "node %zu is different, but that's not its fault\n", n);
		if ((child = mtree_child(t1, n))) {
			// FIXME: if level == channel, call net_sync_subtree()
#if 0
			data->n = child;
			fprintf(stderr, "child of %zu is %zu\n", n, child);
			job_push_new(q, &net_job_diff_tree, data, sz, &free, JOB_COPY|JOB_FREE);
			data->n = child + 1;
			fprintf(stderr, "child of %zu is %zu\n", n, child + 1);
			job_push_new(q, &net_job_diff_tree, data, sz, &free, JOB_COPY|JOB_FREE);
#endif
		}
	}
	clrbit(data->map, n - 1);
	printmap(data->map, howmany(data->chan, CHAR_BIT));
	if (!countmap(data->map, data->chan - 1)) {
		fprintf(stderr, "map is clear - all done\n");
		sem_post(&q->done);
	}
	else {
		fprintf(stderr, "we have more work to do\n");
	}
	return NULL;
}

ssize_t net_recv_data(unsigned char *hash, char *dstdata, size_t *len)
{
	fprintf(stderr, "%s()\n", __func__);

	mtree_tree *stree, *dtree;
	net_data_t *data;
	job_t *job;
	job_queue_t *q;
	size_t vlen = 4;
	size_t sz = sizeof(net_data_t) + sizeof(struct iovec) * vlen;

	data = calloc(1, sz);
	data->len = vlen;
	data->alias = hash;
	data->hash = hash;
	q = job_queue_create(1);

	/* fetch source tree */
	job = job_push_new(q, &net_job_recv_tree, data, sizeof data, NULL, 0);
	sem_wait(&job->done);
	stree = mtree_create(*len, blocksize); // FIXME: get len from job
	mtree_setdata(stree, ((struct iovec *)job->ret)[0].iov_base);
	free(job);
	fprintf(stderr, "%s(): tree with %zu nodes received\n", __func__, mtree_nodes(stree));

	/* build destination tree */
	dtree = mtree_create(*len, blocksize); // FIXME: get len from job
	mtree_build(dtree, dstdata, q);
#if 0
	/* if root nodes differ, perform bredth-first search */
	if (memcmp(mtree_root(stree), mtree_root(dtree), HASHSIZE)) {
		data->chan = 1; // FIXME - temp
		if (data->chan == 1) {
			net_sync_subtree(stree, dtree, 0);
		}
		else {
			data->map = calloc(1, howmany(data->chan, CHAR_BIT));
			for (size_t i = 0; i < data->chan; i++) setbit(data->map, i);
			fprintf(stderr, "starting map: \n");
			printmap(data->map, howmany(data->chan, CHAR_BIT));

			// TODO: diff trees, build maps
			// TODO: bredth search of tree, then mtree_diff_subtree() once at channel level

			data->iov[0].iov_base = q;
			data->iov[0].iov_len = sz;
			data->iov[1].iov_base = stree;
			data->iov[2].iov_base = dtree;
			data->iov[3].iov_len = *len;
			data->iov[3].iov_base = dstdata;

			/* push on first two children */
			data->n = 1;
			job_push_new(q, &net_job_diff_tree, data, sz, &free, JOB_COPY|JOB_FREE);
			data->n = 2;
			job_push_new(q, &net_job_diff_tree, data, sz, &free, JOB_COPY|JOB_FREE);
			sem_wait(&q->done);
		}
		// TODO: recv data blocks - this will happen in net_job_diff_tree()
	}
#endif

	/* clean up */
	job_queue_destroy(q);
	free(data->map);
	free(data);
	mtree_free(stree);
	mtree_free(dtree);
	return 0;
}


/* break a block into DATA_FIXED size pieces and send with header
 * header is in iov[0], data in iov[1] 
 * idx and len need updating */
ssize_t net_send_block(int sock, struct addrinfo *addr, size_t vlen, struct iovec *iov)
{
	ssize_t byt = 0;
	size_t sz, off = 0;
	size_t len = iov[1].iov_len;
	size_t idx = 0;
	net_blockhead_t *hdr = iov[0].iov_base;
	struct msghdr msgh = {0};
	fprintf(stderr, "iov[1] = %p\n", (void *)iov[1].iov_base);
	while (len) {
		sz = (len > DATA_FIXED) ? DATA_FIXED : len;
		msgh.msg_name = addr->ai_addr;
		msgh.msg_namelen = addr->ai_addrlen;
		msgh.msg_iov = iov;
		msgh.msg_iovlen = vlen;
		iov[1].iov_len = sz;
		//iov[1].iov_base = (char *)iov[1].iov_base + off;
		//hdr->idx = htobe32(idx++);
		hdr->len = htobe32(sz);
		off = sz;
		len -= sz;
		// FIXME: Syscall param sendmsg(msg.msg_iov[1]) points to unaddressable byte(s)
		if ((byt = sendmsg(sock, &msgh, 0)) == -1) {
			perror("sendmsg()");
			//_exit(EXIT_FAILURE);
			break;
		}
	}
	return byt;
}

ssize_t net_send_subtree(mtree_tree *stree, size_t root)
{
	fprintf(stderr, "%s()\n", __func__);
	const int on = 1;
	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &on, sizeof(on));
	lc_channel_t *chan = lc_channel_nnew(lctx, mtree_nnode(stree, root), HASHSIZE);
	lc_channel_bind(sock, chan);
	int s = lc_channel_socket_raw(chan);
	struct addrinfo *addr = lc_channel_addrinfo(chan);
	struct iovec iov[2] = {0};
	net_blockhead_t hdr = {
		.len = htobe32(mtree_len(stree)),
	};
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof hdr;

	size_t base = mtree_base(stree);
	size_t min = mtree_subtree_data_min(base, root);
	size_t max = mtree_subtree_data_max(base, root);
	//size_t max = MIN(mtree_subtree_data_max(base, root), mtree_blocks(stree));
	fprintf(stderr, "base: %zu, min: %zu, max: %zu\n", base, min, max);
	//size_t sz;
	while (running) {
		uint32_t idx = 0;
		for (size_t blk = min; blk <= max; blk++, idx++) {
			fprintf(stderr, "sending block %zu with idx=%u\n", blk, idx);
			hdr.idx = htobe32(idx);
			iov[1].iov_len = mtree_blockn_len(stree, blk);
			fprintf(stderr, "blockn(%zu)=%p, data(%zu)=%p\n",
					blk, mtree_blockn(stree, blk), 
					blk-min, mtree_block(stree, blk-min));
			char *ptr = mtree_blockn(stree, blk);
			if (!ptr) {
				fprintf(stderr, "no data for this block\n");
				break;
			}
			iov[1].iov_base = ptr; // FIXME
			hdr.len = htobe32((uint32_t)iov[1].iov_len);
			net_send_block(s, addr, 2, iov);
			usleep(100); // FIXME
		}
	}
	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);
	return 0;
}

void *net_job_sync_subtree(void *arg)
{
	net_data_t *data = (net_data_t *)arg;
	mtree_tree *stree = data->iov[0].iov_base;
	mtree_tree *dtree = data->iov[1].iov_base;
	size_t root = data->n;
	net_sync_subtree(stree, dtree, root);
	return arg;
}

void *net_job_send_subtree(void *arg)
{
	net_data_t *data = (net_data_t *)arg;
	mtree_tree *stree = data->iov[0].iov_base;
	size_t root = data->n;
	net_send_subtree(stree, root);
	return arg;
}

ssize_t net_send_data(char *srcdata, size_t len)
{
	fprintf(stderr, "%s()\n", __func__);
	size_t channels = 1U << net_send_channels; // FIXME
	net_data_t *data;
	job_t *job_tree, *job_data;
	mtree_tree *tree = mtree_create(len, blocksize);
	job_queue_t *q = job_queue_create(channels);
	mtree_build(tree, srcdata, q);
	fprintf(stderr, "%s(): source tree built\n", __func__);

	data = calloc(1, sizeof(net_data_t) + sizeof(struct iovec));
	data->hash = mtree_root(tree);
	data->alias = data->hash;
	data->iov[0].iov_len = mtree_treelen(tree);
	data->iov[0].iov_base = mtree_data(tree, 0);
	job_tree = job_push_new(q, &net_job_send_tree, data, sizeof data, NULL, 0);
	fprintf(stderr, "%s(): job pushed\n", __func__);
	
#if 0
	// TODO: send data blocks
	// TODO: work out channels
	// TODO: call net_send_subtree() for each
	//net_send_subtree(tree, 0);
#endif
	data->n = 0;
	job_data = job_push_new(q, &net_job_send_subtree, data, sizeof data, NULL, 0);

	sem_wait(&job_tree->done);
	sem_wait(&job_data->done);
	free(job_tree);
	free(job_data);
	mtree_free(tree);
	job_queue_destroy(q);
	free(data);
	return 0;
}

int net_recv(int *argc, char *argv[])
{
	(void) argc;
	fprintf(stderr, "%s('%s', '%s')\n", __func__, argv[0], argv[1]);
	// TODO: fetch tree
	// TODO: verify tree
	// TODO: build channel maps
	// TODO: join required channels
	// TODO: receive blocks
	// TODO: verify blocks / check hashes
	// TODO: part / cleanup
	return 0;
}

int net_send(int *argc, char *argv[])
{
	(void) argc;
	char *src = argv[0];
	int fds;
	char *smap = NULL;
	job_queue_t *jobq;
	job_t *job_tree, *job_data;
	mtree_tree *stree;
	size_t chunksz;
	ssize_t sz_s;
	struct stat sbs;
	struct sigaction sa_int = { .sa_handler = net_stop };

	fprintf(stderr, "%s('%s')\n", __func__, argv[0]); // FIXME - delete

	fprintf(stderr, "mapping src: %s\n", src);
	if ((sz_s = file_map(src, &fds, &smap, 0, PROT_READ, &sbs)) == -1)
		return -1;

	// TODO: print hash
	// TODO: allow inputing hash/alias for send/recv
	//
	// TODO: default to using hash(basename) as tree channel

	sigaction(SIGINT, &sa_int, NULL);

	chunksz = (size_t)net_chunksize();
	stree = mtree_create(sz_s, chunksz);
	fprintf(stderr, "source tree with %zu nodes (base = %zu, levels = %zu)\n",
		mtree_nodes(stree), mtree_base(stree), mtree_lvl(stree));

	// TODO: choose number of channels to use - global var

	net_data_t *odata = calloc(1, sizeof(net_data_t) + sizeof(struct iovec));
	odata->alias = malloc(HASHSIZE);
	odata->hash = mtree_root(stree);
	odata->byt = mtree_len(stree);
	odata->iov[0].iov_len = mtree_treelen(stree);
	odata->iov[0].iov_base = mtree_data(stree, 0);
	char *alias = basename(src);
	crypto_generichash(odata->alias, HASHSIZE, (unsigned char *)alias, strlen(alias), NULL, 0);
	fprintf(stderr, "sending file as '%s'\n", alias);

	net_data_t *data = calloc(1, sizeof(net_data_t) + sizeof(struct iovec) * 2);
	data->n = 0;
	data->iov[0].iov_base = stree;

	// TODO: spin up a thread for each subtree + one for tree itself

	jobq = job_queue_create(2);
	mtree_build(stree, smap, NULL);
	job_tree = job_push_new(jobq, &net_job_send_tree, odata, sizeof odata, NULL, 0);
	job_data = job_push_new(jobq, &net_job_send_subtree, data, sizeof data, NULL, 0);
	sem_wait(&job_tree->done);
	sem_wait(&job_data->done);
	free(job_tree);
	free(job_data);
	free(odata->alias);
	free(odata);
	free(data);
	job_queue_destroy(jobq);
	mtree_free(stree);
	file_unmap(smap, sz_s, fds);
	return 0;
}

int net_sync(int *argc, char *argv[])
{
	(void) argc;
	char *dst = argv[1];
	int fdd;
	char *dmap = NULL;
	mtree_tree *dtree;
	size_t chunksz;
	ssize_t sz_d;
	struct stat sbd;
	struct sigaction sa_int = { .sa_handler = net_stop };
	job_queue_t *jobq;
	job_t *job_tree, *job_data;
	net_data_t *idata;

	fprintf(stderr, "%s('%s', '%s')\n", __func__, argv[0], argv[1]);

	sigaction(SIGINT, &sa_int, NULL);
	idata = calloc(1, sizeof(net_data_t) + sizeof(struct iovec) * 2);
	idata->alias = malloc(HASHSIZE);
	crypto_generichash(idata->alias, HASHSIZE, (unsigned char *)argv[0], strlen(argv[0]), NULL, 0);

	fprintf(stderr, "lets sync '%s'\n", argv[0]);

	jobq = job_queue_create(1);
	job_tree = job_push_new(jobq, &net_job_recv_tree, idata, sizeof idata, NULL, 0);
	sem_wait(&job_tree->done);

	// TODO: sync everything else
	
	fprintf(stderr, "got tree\n");
	struct iovec *iov = (struct iovec *)job_tree->ret;
	chunksz = (size_t)net_chunksize();
	size_t len = iov->iov_len;
	fprintf(stderr, "length of tree is %zu\n", len);
	mtree_tree *stree = mtree_create(len, chunksz);
	mtree_setdata(stree, iov->iov_base);
	fprintf(stderr, "source tree with %zu nodes (base = %zu, levels = %zu)\n",
		mtree_nodes(stree), mtree_base(stree), mtree_lvl(stree));

	// TODO: check if file exists
	// TODO: set permissions
	fprintf(stderr, "mapping dst: %s\n", dst);
	sbd.st_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH; // FIXME
	if ((sz_d = file_map(dst, &fdd, &dmap, len, PROT_READ|PROT_WRITE, &sbd)) == -1)
		return -1; // FIXME - clean up here

	size_t filesz = mtree_len(stree);
	fprintf(stderr, "sz_d=%zu, len=%zu, filesz=%zu\n", sz_d, len, filesz);
	dtree = mtree_create(sz_d, chunksz);
	mtree_build(dtree, dmap, NULL);
	fprintf(stderr, "destination tree with %zu nodes (base = %zu, levels = %zu)\n",
		mtree_nodes(dtree), mtree_base(dtree), mtree_lvl(dtree));

	/* sync the file */
	idata->n = 0;
	idata->iov[0].iov_base = stree;
	idata->iov[1].iov_base = dtree;
	job_data = job_push_new(jobq, &net_job_sync_subtree, idata, 0, NULL, 0);
	sem_wait(&job_data->done);
	free(job_data);

	mtree_free(dtree);
	mtree_free(stree);
	free(job_tree->ret);
	free(job_tree);
	job_queue_destroy(jobq);
	free(idata->alias);
	free(idata);
	file_unmap(dmap, sz_d, fdd);
	return 0;
}
