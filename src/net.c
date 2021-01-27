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
#include "log.h"
#include "globals.h"
#include "mtree.h"
#include "file.h"

static int running = 1;

/* return number of bits set in bitmap */
unsigned int countmap(unsigned char *map, size_t len)
{
	unsigned int c = 0;
	while (len--) {
		for (char v = map[len]; v; c++) {
			v &= v - 1;
		}
	}
	return c;
}

void printmap(unsigned char *map, size_t len)
{
	if (quiet) return;
	logwait(); /* stop logger from scribbling until we're done */
	for (size_t i = 0; i < len; i++) {
		fprintf(stderr, "%d", !!isset(map, i));
	}
	fputc('\n', stderr);
	logdone(); /* release lock */
}


void net_stop(int signo)
{
	(void) signo;
	running = 0;
	DEBUG("stopping on signal");
}
#if 0
static size_t net_chunksize(void)
{
	return DATA_FIXED;
}
#endif
#if 0
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
#endif

net_treehead_t *net_hdr_tree(net_treehead_t *hdr, mtree_tree *tree)
{
	memset(hdr, 0, sizeof *hdr);
	hdr->pkts = htobe32(howmany(mtree_len(tree), DATA_FIXED));
	hdr->chan = net_send_channels;
	memcpy(hdr->hash, mtree_root(tree), HASHSIZE);
	return hdr;
}

ssize_t net_recv_tree(int sock, struct iovec *iov, size_t *blocksz)
{
	TRACE("%s()", __func__);
	size_t idx, off, len, maplen, pkts;
	ssize_t byt = 0, msglen;
	uint64_t sz;
	net_treehead_t *hdr;
	char buf[MTU_FIXED];
	unsigned char *bitmap = NULL;
	do {
		if ((msglen = recv(sock, buf, MTU_FIXED, 0)) == -1) {
			perror("recv()");
			byt = -1;
			break;
		}
		DEBUG("%s(): recv %zi bytes", __func__, msglen);
		hdr = (net_treehead_t *)buf;
		if (!bitmap) {
			pkts = be32toh(hdr->pkts);
			if (!pkts) {
				DEBUG("invalid packet header");
				return -1;
			}
			DEBUG("packets = %lu", pkts);
			maplen = howmany(pkts, CHAR_BIT);
			if (!(bitmap = malloc(maplen))) {
				perror("malloc()");
				return -1;
			}
			memset(bitmap, 0, maplen);
			for (uint32_t i=0; i < pkts; i++) setbit(bitmap, i);
			// FIXME
#if 0
			printmap(bitmap, pkts);
			memset(bitmap, ~0, maplen - 1);
			printmap(bitmap, pkts);
			bitmap[maplen - 1] = (1UL << (pkts % CHAR_BIT)) - 1;
#endif
			printmap(bitmap, pkts);
		}
		sz = (size_t)be64toh(hdr->size);
		*blocksz = be32toh(hdr->blocksz);
		if (!iov->iov_base) {
			if (!(iov->iov_base = malloc(sz))) {
				perror("malloc()");
				byt = -1;
				break;
			}
			iov[0].iov_len = sz;
			iov[1].iov_len = (size_t)be64toh(hdr->data);
		}
		idx = (size_t)be32toh(hdr->idx);
		off = be32toh(hdr->idx) * DATA_FIXED;
		len = (size_t)be32toh(hdr->len);
		if (isset(bitmap, idx)) {
			memcpy((char *)iov->iov_base + off, buf + sizeof (net_treehead_t), len);
			clrbit(bitmap, idx);
		}
		byt += be32toh(hdr->len);
		printmap(bitmap, pkts);
		DEBUG("packets still required=%u", countmap(bitmap, maplen));
	}
	while (countmap(bitmap, maplen));
	// TODO verify tree (check hashes, mark bitmap with any that don't
	// match, go again
	free(bitmap);
	return byt;
}

ssize_t net_fetch_tree(unsigned char *hash, mtree_tree **tree)
{
	TRACE("%s()", __func__);
	int s;
	size_t blocksz;
	ssize_t byt;
	struct iovec *iov = calloc(1, sizeof(struct iovec) * 2);
	if (!iov) return -1;
	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_channel_t *chan = lc_channel_nnew(lctx, hash, HASHSIZE);
	lc_channel_bind(sock, chan);
	lc_channel_join(chan);
	s = lc_socket_raw(sock);
	byt = net_recv_tree(s, iov, &blocksz);
	if (byt > 0) {
		DEBUG("%s(): tree received (%zi bytes)", __func__, byt);
		*tree = mtree_create(iov[1].iov_len, blocksz);
		mtree_setdata(*tree, iov[0].iov_base);
	}
	lc_channel_part(chan);
	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);
	free(iov);
	return byt;
}

void *net_job_recv_tree(void *arg)
{
	TRACE("%s()", __func__);
	int s;
	size_t blocksz;
	ssize_t byt;
	net_data_t *data = (net_data_t *)arg;
	struct iovec *iov = calloc(1, sizeof(struct iovec) * 2);
	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_channel_t *chan = lc_channel_nnew(lctx, data->alias, HASHSIZE);
	lc_channel_bind(sock, chan);
	lc_channel_join(chan);
	s = lc_socket_raw(sock);
	byt = net_recv_tree(s, iov, &blocksz);
	DEBUG("%s(): tree received (%zi bytes)", __func__, byt);
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
	size_t filesz = len;
	size_t idx = 0;
	net_treehead_t *hdr = iov[0].iov_base;
	struct msghdr msgh = {0};
	hdr->pkts = htobe32(howmany(iov[1].iov_len, DATA_FIXED));
	char *temp = calloc(1, len);
	memcpy(temp, iov[1].iov_base, len);
	while (running && len) {
		sz = (len > DATA_FIXED) ? DATA_FIXED : len;
		DEBUG("len = %zu, sz=%zu, off = %zu", len, sz, off);
		iov[1].iov_len = sz;
		//iov[1].iov_base = (char *)iov[1].iov_base + off;
		iov[1].iov_base = temp + off;
		msgh.msg_name = addr->ai_addr;
		msgh.msg_namelen = addr->ai_addrlen;
		msgh.msg_iov = iov;
		msgh.msg_iovlen = vlen;
		assert(off + sz <= filesz);
		hdr->idx = htobe32(idx++);
		hdr->len = htobe32(sz);
		size_t hdrsz = iov[0].iov_len;
		DEBUG("%zu + %zu = %zu bytes", sz, hdrsz, sz + hdrsz); 
		off += sz;
		len -= sz;
		if ((byt = sendmsg(sock, &msgh, 0)) == -1) {
			perror("sendmsg()");
			//break;
		}
		DEBUG("%zi bytes sent", byt); 
		if (DELAY) usleep(DELAY);
	}
	free(temp);
	return byt;
}

void *net_job_send_tree(void *arg)
{
	TRACE("%s()", __func__);
	const int on = 1;
	net_data_t *data = (net_data_t *)arg;
	mtree_tree *tree = (mtree_tree *)data->iov[0].iov_base;
	void * base = mtree_data(tree, 0);
	size_t len = mtree_treelen(tree);
	assert(!mtree_verify(tree, len));
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
		.blocksz = htobe32(mtree_blocksz(tree)),
		.chan = net_send_channels,
		.pkts = htobe32(howmany(data->iov[0].iov_len, DATA_FIXED))
	};
	DEBUG("idx=%u", be32toh(hdr.idx));
	DEBUG("len=%u", be32toh(hdr.len));
	DEBUG("data=%lu", be64toh(hdr.data));
	DEBUG("size=%lu", be64toh(hdr.size));
	DEBUG("blocksz=%u", be32toh(hdr.blocksz));
	DEBUG("pkts=%u", be32toh(hdr.pkts));
	DEBUG("chan=%u", hdr.chan);
	DEBUG("sizeof hdr=%zu", sizeof hdr);
	assert(data->byt > 0);
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
	TRACE("%s()", __func__);
	char buf[DATA_FIXED];
	unsigned char *bitmap = NULL;
	uint32_t idx;
	size_t blk, len, off;
	size_t blocksz = mtree_blocksz(stree);
	unsigned bits = howmany(blocksz, DATA_FIXED);
	size_t maplen = howmany(mtree_base_subtree(stree, root) * bits, CHAR_BIT);
	size_t min = mtree_subtree_data_min(mtree_base(stree), root);
	ssize_t byt = 0, msglen;
	net_blockhead_t hdr = {0};
	struct iovec iov[2];
	struct msghdr msgh = { .msg_iov = iov, .msg_iovlen = 2 };
	DEBUG("%s(): blocks  = %zu", __func__, mtree_blocks(stree));
	DEBUG("%s(): base    = %zu", __func__, mtree_base_subtree(stree, root));
	DEBUG("%s(): blocksz = %zu", __func__, blocksz);
	DEBUG("%s(): bits    = %u", __func__, bits);
	DEBUG("%s(): maplen  = %zu", __func__, maplen);
	bitmap = mtree_diff_subtree(stree, dtree, root, bits);
	if (bitmap) {
		DEBUG("packets required=%u", countmap(bitmap, maplen));
		printmap(bitmap, mtree_base_subtree(stree, root) * bits);
	}
	DEBUG("dryrun=%i", dryrun);
	DEBUG("bitmap=%p", bitmap);
	DEBUG("PKTS=%zu", PKTS);
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof hdr;
	iov[1].iov_base = buf;
	iov[1].iov_len = DATA_FIXED;
	while (!dryrun && bitmap && countmap(bitmap, maplen) && PKTS) {
		if ((msglen = recvmsg(sock, &msgh, 0)) == -1) {
			perror("recv()");
			byt = -1;
			break;
		}
		DEBUG("%s(): recv %zi bytes", __func__, msglen);
		idx = be32toh(hdr.idx);
		len = (size_t)be32toh(hdr.len);
		blk = idx / bits;
		if (isset(bitmap, idx)) {
			off = (idx % bits) * DATA_FIXED;
			DEBUG("recv'd a block I wanted idx=%u, blk=%zu", idx, blk);
			memcpy(mtree_blockn(dtree, blk + min) + off, buf, len);
			clrbit(bitmap, idx);
			PKTS--;
		}
		else {
			DEBUG("recv'd a block I didn't want idx=%u, blk=%zu", idx, blk);
		}
		byt += be32toh(hdr.len);
		DEBUG("packets still required=%u", countmap(bitmap, maplen));
		printmap(bitmap, mtree_base_subtree(stree, root) * bits);
	}
	DEBUG("receiver - all blocks received");
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

	DEBUG("%s(): receiving subtree at root %zu", __func__, root);

	mtree_hexdump(stree, stderr);
	DEBUG("recving subtree with root %zu", root);
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
	//char *dstdata = (char *)data->iov[3].iov_base;
	//size_t len = data->iov[3].iov_len;
	size_t n = data->n;
	size_t child;

	DEBUG("sz %zu", sz);
	DEBUG("checking node %zu", n);
	if (memcmp(mtree_nnode(t1, n), mtree_nnode(t2, n), HASHSIZE)) {
		DEBUG("node %zu is different, but that's not its fault", n);
		if ((child = mtree_child(t1, n))) {
			// FIXME: if level == channel, call net_sync_subtree()
#if 0
			data->n = child;
			DEBUG("child of %zu is %zu\n", n, child);
			job_push_new(q, &net_job_diff_tree, data, sz, &free, JOB_COPY|JOB_FREE);
			data->n = child + 1;
			DEBUG("child of %zu is %zu\n", n, child + 1);
			job_push_new(q, &net_job_diff_tree, data, sz, &free, JOB_COPY|JOB_FREE);
#endif
		}
	}
	clrbit(data->map, n - 1);
	printmap(data->map, howmany(data->chan, CHAR_BIT));
	if (!countmap(data->map, data->chan - 1)) {
		DEBUG("map is clear - all done");
		sem_post(&q->done);
	}
	return NULL;
}

ssize_t net_recv_data(unsigned char *hash, char *dstdata, size_t *len)
{
	unsigned channels = 1U << net_send_channels;
	mtree_tree *stree = NULL, *dtree = NULL;
	net_data_t *data;
	job_t *job[channels];
	job_queue_t *q;
	size_t blocksz;
	size_t vlen = 2;
	size_t sz = sizeof(net_data_t) + sizeof(struct iovec) * vlen;
	TRACE("%s()", __func__);
	data = calloc(1, sz);
	data->len = vlen;
	data->alias = hash;
	data->hash = hash;
	q = job_queue_create(1);

	if (net_fetch_tree(hash, &stree) == -1) return -1;
	blocksz = mtree_blocksz(stree);
	*len = mtree_len(stree);
	dtree = mtree_create(*len, blocksz);
	mtree_build(dtree, dstdata, q);

	/* if root nodes differ, perform bredth-first search */
	if (memcmp(mtree_root(stree), mtree_root(dtree), HASHSIZE)) {
		DEBUG("root hashes differ:");
		hash_hex_debug(mtree_root(stree), HASHSIZE);
		hash_hex_debug(mtree_root(dtree), HASHSIZE);
		channels = 1; // FIXME - temp
		data->byt = len;
		data->iov[0].iov_len = mtree_treelen(stree);
		data->iov[0].iov_base = stree;
		data->iov[1].iov_len = mtree_treelen(dtree);
		data->iov[1].iov_base = dtree;
		for (unsigned chan = 0; chan < channels; chan++) {
			data->n = channels - 1;
			job[chan] = job_push_new(q, &net_job_sync_subtree, data, sz, NULL, JOB_COPY|JOB_FREE);
		}
		for (unsigned chan = 0; chan < channels; chan++) {
			sem_wait(&job[chan]->done);
			free(job[chan]);
		}
		// TODO: split this out into a function
#if 0
		else {
			data->map = calloc(1, howmany(data->chan, CHAR_BIT));
			for (size_t i = 0; i < data->chan; i++) setbit(data->map, i);
			DEBUG("starting map: ");
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
#endif
	}
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
ssize_t net_send_block(int sock, struct addrinfo *addr, size_t vlen, struct iovec *iov, size_t blk)
{
	ssize_t byt = 0;
	size_t sz;
	size_t len = iov[1].iov_len;
	char * ptr = iov[1].iov_base;
	net_blockhead_t *hdr = iov[0].iov_base;
	unsigned bits = howmany(len, DATA_FIXED);
	struct msghdr msgh = {0};
	for (size_t idx = blk * bits; running && len; idx++) {
		sz = (len > DATA_FIXED) ? DATA_FIXED : len;
		msgh.msg_name = addr->ai_addr;
		msgh.msg_namelen = addr->ai_addrlen;
		msgh.msg_iov = iov;
		msgh.msg_iovlen = vlen;
		iov[1].iov_len = sz;
		iov[1].iov_base = ptr;
		hdr->len = htobe32(sz);
		hdr->idx = htobe32(idx);
		if ((byt = sendmsg(sock, &msgh, 0)) == -1) {
			perror("sendmsg()");
			//break;
		}
		len -= sz;
		ptr += sz;
		DEBUG("%zi bytes sent (blk=%zu, idx = %zu)", byt, blk, idx);
	}
	return byt;
}

ssize_t net_send_subtree(mtree_tree *stree, size_t root)
{
	TRACE("%s()", __func__);
	const int on = 1;
	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &on, sizeof(on));
	lc_channel_t *chan = lc_channel_nnew(lctx, mtree_nnode(stree, root), HASHSIZE);
	lc_channel_bind(sock, chan);
	int s = lc_channel_socket_raw(chan);
	struct addrinfo *addr = lc_channel_addrinfo(chan);
	struct iovec iov[2] = {0};
	net_blockhead_t hdr = { .len = htobe32(mtree_len(stree)) };
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof hdr;
	size_t base = mtree_base(stree);
	size_t min = mtree_subtree_data_min(base, root);
	size_t max = MIN(mtree_subtree_data_max(base, root), mtree_blocks(stree) + min - 1);
	DEBUG("base: %zu, min: %zu, max: %zu", base, min, max);
	running = 1;
	while (running) {
		uint32_t idx = 0;
		for (size_t blk = min; running && blk <= max; blk++, idx++) {
			DEBUG("sending block %zu with idx=%u", blk, idx);
			iov[1].iov_len = mtree_blockn_len(stree, blk);
			char *ptr = mtree_blockn(stree, blk);
			if (!ptr) continue;
			iov[1].iov_base = ptr; // FIXME
			hdr.len = htobe32((uint32_t)iov[1].iov_len);
			net_send_block(s, addr, 2, iov, idx);
			if (DELAY) {
				DEBUG("delay %i", DELAY);
				usleep(DELAY);
			}
		}
	}
	mtree_hexdump(stree, stderr);
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
	DEBUG("sending subtree with root %zu", root);
	net_send_subtree(stree, root);
	return arg;
}

ssize_t net_send_data(unsigned char *hash, char *srcdata, size_t len)
{
	TRACE("%s()", __func__);
	unsigned channels = 1U << net_send_channels;
	size_t sz = sizeof(net_data_t) + sizeof(struct iovec);
	net_data_t *data;
	job_t *job_tree, *job_data[channels];
	mtree_tree *tree = mtree_create(len, blocksize);
	job_queue_t *q = job_queue_create(channels);
	mtree_build(tree, srcdata, q);
	DEBUG("%s(): source tree built", __func__);
	assert(!mtree_verify(tree, mtree_treelen(tree)));
	data = calloc(1, sz);
	data->hash = mtree_root(tree);
	data->alias = (hash) ? hash : data->hash;
	data->byt = len;
	data->iov[0].iov_len = mtree_treelen(tree);
	data->iov[0].iov_base = tree;
	job_tree = job_push_new(q, &net_job_send_tree, data, sz, NULL, 0);
	channels = 1; // FIXME - temp
	for (unsigned chan = 0; chan < channels; chan++) {
		data->n = channels - 1;
		job_data[chan] = job_push_new(q, &net_job_send_subtree, data, sz, NULL, JOB_COPY|JOB_FREE);
	}
	sem_wait(&job_tree->done);
	for (unsigned chan = 0; chan < channels; chan++) {
		sem_wait(&job_data[chan]->done);
		free(job_data[chan]);
	}
	free(job_tree);
	mtree_free(tree);
	job_queue_destroy(q);
	free(data);
	return 0;
}

int net_recv(int *argc, char *argv[])
{
	(void) argc;
	TRACE("%s('%s', '%s')", __func__, argv[0], argv[1]);
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
	int fds;
	ssize_t sz_s;
	struct stat sbs;
	struct sigaction sa_int = { .sa_handler = net_stop };
	char *src = argv[0];
	char *alias = basename(src);
	char *smap = NULL;
	unsigned char hash[HASHSIZE];
	TRACE("%s('%s')", __func__, argv[0]);
	DEBUG("mapping src: %s", src);
	if ((sz_s = file_map(src, &fds, &smap, 0, PROT_READ, &sbs)) == -1)
		return -1;
	sigaction(SIGINT, &sa_int, NULL);
	crypto_generichash(hash, HASHSIZE, (unsigned char *)alias, strlen(alias), NULL, 0);
	net_send_data(hash, smap, sz_s);
	DEBUG("unmapping src: %s", src);
	file_unmap(smap, sz_s, fds);
	return 0;
}

int net_sync(int *argc, char *argv[])
{
	(void) argc; /* unused */
	int fdd;
	size_t blocksz, len;
	ssize_t sz_d;
	struct stat sbd;
	char *src = argv[0];
	char *dst = argv[1];
	char *dmap = NULL;
	struct sigaction sa_int = { .sa_handler = net_stop };
	unsigned char hash[HASHSIZE];
	mtree_tree *stree = NULL;
	mtree_tree *dtree;
	TRACE("%s('%s')", __func__, argv[0]);
	sigaction(SIGINT, &sa_int, NULL);

	/* fetch source tree */
	crypto_generichash(hash, HASHSIZE, (unsigned char *)src, strlen(src), NULL, 0);
	if (net_fetch_tree(hash, &stree) == -1) return -1;

	/* create & map destination file */
	DEBUG("mapping dst: %s", dst);
	len = mtree_len(stree);
	sbd.st_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH; // TODO - set from packet data
	if ((sz_d = file_map(dst, &fdd, &dmap, len, PROT_READ|PROT_WRITE, &sbd)) == -1)
		return -1; // FIXME - clean up here
	
	blocksz = mtree_blocksz(stree);
	len = mtree_len(stree);
	dtree = mtree_create(len, blocksz);
	mtree_build(dtree, dmap, NULL);
	assert(!mtree_verify(stree, mtree_treelen(stree)));
	assert(!mtree_verify(dtree, mtree_treelen(dtree)));

	/* sync data */
	if (memcmp(mtree_root(stree), mtree_root(dtree), HASHSIZE)) {
		DEBUG("root hashes differ:");
		hash_hex_debug(mtree_root(stree), HASHSIZE);
		hash_hex_debug(mtree_root(dtree), HASHSIZE);
		net_sync_subtree(stree, dtree, 0);
	}
	mtree_free(stree);
	mtree_free(dtree);
	return 0;
}
