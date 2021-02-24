/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include <arpa/inet.h>
#include <assert.h>
#include <endian.h>
#include <libgen.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include "net_pvt.h"
#include "log.h"
#include "macro.h"
#include "globals.h"
#include "file.h"

static volatile int running = 1;
static sem_t stop;

/* return number of bits set in bitmap (Hamming Weight) */
static unsigned int hamm(unsigned char *map, size_t len)
{
	unsigned int c = 0;
	while (len--) for (char v = map[len]; v; c++) v &= v - 1;
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

void net_reset(void)
{
	running = 1;
}

void net_stop(int signo)
{
	(void) signo;
	running = 0;
	sem_post(&stop);
	DEBUG("stopping on signal");
}

ssize_t net_recv_tree(int sock, struct iovec *iov, size_t *blocksz)
{
	TRACE("%s()", __func__);
	struct pollfd fds = { .fd = sock, .events = POLL_IN };
	size_t idx, off, len, maplen, pkts;
	ssize_t byt = 0, msglen;
	net_treehead_t *hdr;
	char buf[MTU_FIXED];
	unsigned char *bitmap = NULL;
	uint64_t sz;
	uint8_t mod;
	const int timeout = 100;
	int rc;
	do {
		while (!(rc = poll(&fds, 1, timeout)) && running);
		if (!running) {
			byt = -1;
			break;
		}
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
			memset(bitmap, ~0, maplen);
			mod = pkts % CHAR_BIT;
			if (mod) bitmap[maplen - 1] = (1U << (mod)) - 1;
			printmap(bitmap, pkts);
		}
		sz = (size_t)be64toh(hdr->size);
		*blocksz = be32toh(hdr->blocksz);
		if (!iov->iov_base) {
			if (!(iov->iov_base = calloc(1, sz))) {
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
		DEBUG("packets still required=%u", hamm(bitmap, maplen));
	}
	while (running && hamm(bitmap, maplen));
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
	ssize_t byt = -1;
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;
	struct iovec *iov = calloc(1, sizeof(struct iovec) * 2);
	if (!iov) return -1;
	if (!(lctx = lc_ctx_new())) goto err_0;
	if (!(sock = lc_socket_new(lctx))) goto err_1;
	if (!(chan = lc_channel_nnew(lctx, hash, HASHSIZE))) goto err_2;
	if (lc_channel_bind(sock, chan) || lc_channel_join(chan)) goto err_3;
	s = lc_socket_raw(sock);
	byt = net_recv_tree(s, iov, &blocksz);
	if (byt > 0) {
		DEBUG("%s(): tree received (%zi bytes)", __func__, byt);
		*tree = mtree_create(iov[1].iov_len, blocksz);
		mtree_setdata(*tree, iov[0].iov_base);
	}
	lc_channel_part(chan);
err_3:
	lc_channel_free(chan);
err_2:
	lc_socket_close(sock);
err_1:
	lc_ctx_free(lctx);
err_0:
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
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;
	struct iovec *iov = NULL;
	if (!(lctx = lc_ctx_new())) return NULL;
	if (!(sock = lc_socket_new(lctx))) goto err_0;
	if (!(chan = lc_channel_nnew(lctx, data->alias, HASHSIZE))) goto err_1;
	if (!(iov = calloc(1, sizeof(struct iovec) * 2))) goto err_2;
	if (lc_channel_bind(sock, chan) || lc_channel_join(chan)) goto err_2;
	s = lc_socket_raw(sock);
	byt = net_recv_tree(s, iov, &blocksz);
	DEBUG("%s(): tree received (%zi bytes)", __func__, byt);
	lc_channel_part(chan);
err_2:
	lc_channel_free(chan);
err_1:
	lc_socket_close(sock);
err_0:
	lc_ctx_free(lctx);
	return iov;
}

ssize_t net_send_tree(int sock, struct addrinfo *addr, size_t vlen, struct iovec *iov)
{
	TRACE("%s()", __func__);
	ssize_t byt = 0, rc;
	size_t sz, off = 0;
	size_t len = iov[1].iov_len;
	size_t idx = 0;
	net_treehead_t *hdr = iov[0].iov_base;
	struct msghdr msgh = {0};
	hdr->pkts = htobe32(howmany(iov[1].iov_len, DATA_FIXED));
	char *data = calloc(1, len);
	if (!data) {
		perror("calloc");
		return -1;
	}
	memcpy(data, iov[1].iov_base, len);
	while (running && len) {
		sz = (len > DATA_FIXED) ? DATA_FIXED : len;
		iov[1].iov_len = sz;
		iov[1].iov_base = data + off;
		msgh.msg_name = addr->ai_addr;
		msgh.msg_namelen = addr->ai_addrlen;
		msgh.msg_iov = iov;
		msgh.msg_iovlen = vlen;
		hdr->idx = htobe32(idx++);
		hdr->len = htobe32(sz);
		off += sz;
		len -= sz;
		// FIXME: Cannot assign requested address - test 0034
		int on = 1;
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
		if ((rc = sendmsg(sock, &msgh, 0)) == -1) {
			perror("sendmsg()");
			byt = -1; break;
		}
		DEBUG("%zi bytes sent", rc); 
		byt += rc;
		if (DELAY) usleep(DELAY);
	}
	free(data);
	return byt;
}

void *net_job_send_tree(void *arg)
{
	TRACE("%s()", __func__);
	const int on = 1;
	int s;
	enum { vlen = 2 };
	struct iovec iov[vlen];
	struct addrinfo *addr;
	struct in6_addr *grp;
	net_data_t *data = (net_data_t *)arg;
	mtree_tree *tree = (mtree_tree *)data->iov[0].iov_base;
	unsigned char * base = mtree_data(tree, 0);
	size_t len = mtree_treelen(tree);
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;
	assert(!mtree_verify(tree, len));
	if (!(lctx = lc_ctx_new()))
		return NULL;
	if (!(sock = lc_socket_new(lctx)))
		goto err_0;
	if (lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &on, sizeof on))
		goto err_1;
	if (!(chan = lc_channel_nnew(lctx, data->alias, HASHSIZE)))
		goto err_1;
	if (lc_channel_bind(sock, chan))
		goto err_2;
	s = lc_channel_socket_raw(chan);
	addr = lc_channel_addrinfo(chan);
	grp = aitoin6(addr);
	net_treehead_t hdr = {
		.data = htobe64((uint64_t)data->byt),
		.size = htobe64(data->iov[0].iov_len),
		.blocksz = htobe32(mtree_blocksz(tree)),
		.chan = net_send_channels,
		.pkts = htobe32(howmany(data->iov[0].iov_len, DATA_FIXED))
	};
#ifdef NET_DEBUG
	char straddr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, grp, straddr, INET6_ADDRSTRLEN);
	DEBUG("sending tree on channel addr: %s", straddr);
	DEBUG("idx=%u", be32toh(hdr.idx));
	DEBUG("len=%u", be32toh(hdr.len));
	DEBUG("data=%lu", be64toh(hdr.data));
	DEBUG("size=%lu", be64toh(hdr.size));
	DEBUG("blocksz=%u", be32toh(hdr.blocksz));
	DEBUG("pkts=%u", be32toh(hdr.pkts));
	DEBUG("chan=%u", hdr.chan);
	DEBUG("sizeof hdr=%zu", sizeof hdr);
#endif
	memcpy(&hdr.hash, data->hash, HASHSIZE);
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof hdr;
	while (running) {
		// FIXME - sending needs to be triggered by a join on a specific
		// interface.  We don't want to block for a join on each
		// interface, but only fire up our threads when there is a join
		if (mld_enabled && data->mld) mld_wait(data->mld, 0, grp);
		iov[1].iov_len = len;
		iov[1].iov_base = base;
		if (net_send_tree(s, addr, vlen, iov) == -1) {
			ERROR("error sending tree - aborting");
			break;
		}
	}
err_2:
	lc_channel_free(chan);
err_1:
	lc_socket_close(sock);
err_0:
	lc_ctx_free(lctx);
	return NULL;
}

static ssize_t net_recv_subtree(int sock, mtree_tree *stree, mtree_tree *dtree, size_t root)
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
	ssize_t byt = 0, msglen = 0;
	net_blockhead_t hdr = {0};
	struct iovec iov[2] = {0};
	struct msghdr msgh = { .msg_iov = iov, .msg_iovlen = 2 };
	struct pollfd fds = {
		.fd = sock,
		.events = POLL_IN
	};
	int rc = 0;
	DEBUG("%s(): blocks  = %zu", __func__, mtree_blocks(stree));
	DEBUG("%s(): base    = %zu", __func__, mtree_base_subtree(stree, root));
	DEBUG("%s(): blocksz = %zu", __func__, blocksz);
	DEBUG("%s(): bits    = %u", __func__, bits);
	DEBUG("%s(): maplen  = %zu", __func__, maplen);
	bitmap = mtree_diff_subtree(stree, dtree, root, bits);
	if (!bitmap) return -1;
	DEBUG("packets required=%u", hamm(bitmap, maplen));
	printmap(bitmap, mtree_base_subtree(stree, root) * bits);
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof hdr;
	iov[1].iov_base = buf;
	iov[1].iov_len = DATA_FIXED;
	if (!dryrun) while (running && hamm(bitmap, maplen) && PKTS) {
		DEBUG("%s() recvmsg", __func__);
		while (running && !(rc = poll(&fds, 1, 100)));
		if (rc > 0 && (msglen = recvmsg(sock, &msgh, 0)) == -1) {
			perror("recv()");
			byt = -1; break;
		}
		else if (rc == -1) {
			perror("poll()");
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
		DEBUG("packets still required=%u", hamm(bitmap, maplen));
		printmap(bitmap, mtree_base_subtree(stree, root) * bits);
	}
	DEBUG("receiver - all blocks received");
	free(bitmap);
	return byt;
}

ssize_t net_sync_subtree(mtree_tree *stree, mtree_tree *dtree, size_t root)
{
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;
	ssize_t byt = -1;
	int s;
	if (!(lctx = lc_ctx_new()))
		goto err_0;
	if (!(sock = lc_socket_new(lctx)))
		goto err_1;
	if (!(chan = lc_channel_nnew(lctx, mtree_nnode(stree, root), HASHSIZE)))
		goto err_2;
	if (lc_channel_bind(sock, chan) || lc_channel_join(chan))
		goto err_3;
	s = lc_socket_raw(sock);
	if (hex) mtree_hexdump(stree, stderr);
	DEBUG("recving subtree with root %zu", root);
	byt = net_recv_subtree(s, stree, dtree, root);
	lc_channel_part(chan);
err_3:
	lc_channel_free(chan);
err_2:
	lc_socket_close(sock);
err_1:
	lc_ctx_free(lctx);
err_0:
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
#if 0
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
	if (!hamm(data->map, data->chan - 1)) {
		DEBUG("map is clear - all done");
		sem_post(&q->done);
	}
	return NULL;
}
#endif
#if 0
		// TODO: split this out into a function
	/* if root nodes differ, perform bredth-first search */
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

static int net_sync_trees(mtree_tree *stree, mtree_tree *dtree, job_queue_t *q)
{
	TRACE("%s()", __func__);
	unsigned channels = 1U << net_send_channels; // FIXME - get this from tree
	job_t *job[channels];
	const size_t vlen = 2;
	size_t sz = sizeof(net_data_t) + sizeof(struct iovec) * vlen;
	net_data_t *data;
	if (!(data = calloc(1, sz))) return -1;
	data->len = vlen;
#ifdef NET_DEBUG
	DEBUG("root hashes differ:");
	hash_hex_debug(mtree_root(stree), HASHSIZE);
	hash_hex_debug(mtree_root(dtree), HASHSIZE);
#endif
	data->byt = mtree_len(stree);
	data->iov[0].iov_len = mtree_treelen(stree);
	data->iov[0].iov_base = stree;
	data->iov[1].iov_len = mtree_treelen(dtree);
	data->iov[1].iov_base = dtree;
	for (unsigned chan = 0; chan < channels; chan++) {
		data->n = channels - 1 + chan;
		job[chan] = job_push_new(q, &net_job_sync_subtree, data, sz, NULL, JOB_COPY|JOB_FREE);
	}
	for (unsigned chan = 0; chan < channels; chan++) {
		struct timespec ts = { .tv_nsec = 100 };
		while (sem_timedwait(&job[chan]->done, &ts) == -1 && errno == ETIMEDOUT && running);
		free(job[chan]);
	}
	free(data);
	return 0;
}

ssize_t net_recv_data(unsigned char *hash, char *dstdata, size_t *len)
{
	int rc = -1;
	mtree_tree *stree = NULL, *dtree = NULL;
	job_queue_t *q;
	size_t blocksz;
	TRACE("%s()", __func__);
	if (!(q = job_queue_create(1U << net_send_channels))) return -1;
	if (net_fetch_tree(hash, &stree) == -1) goto err_0;
	blocksz = mtree_blocksz(stree);
	assert(len);
	*len = mtree_len(stree);
	dtree = mtree_create(*len, blocksz);
	if (!dtree) goto err_1;
	mtree_build(dtree, dstdata, q);
	if (memcmp(mtree_root(stree), mtree_root(dtree), HASHSIZE)) {
		rc = net_sync_trees(stree, dtree, q);
	}
	else rc = 0;
	mtree_free(dtree);
err_1:
	mtree_free(stree);
err_0:
	job_queue_destroy(q);
	return rc;
}

/* break a block into DATA_FIXED size pieces and send with header
 * header is in iov[0], data in iov[1] 
 * idx and len need updating */
static void net_send_block(int sock, struct addrinfo *addr, size_t vlen, struct iovec *iov, size_t blk)
{
	ssize_t byt;
	size_t len = iov[1].iov_len;
	char * ptr = iov[1].iov_base;
	net_blockhead_t *hdr = iov[0].iov_base;
	unsigned bits = howmany(len, DATA_FIXED);
	for (size_t idx = blk * bits; running && len; idx++) {
		size_t sz = MIN(len, DATA_FIXED);
		struct msghdr msgh = {
			.msg_name = addr->ai_addr,
			.msg_namelen = addr->ai_addrlen,
			.msg_iov = iov,
			.msg_iovlen = vlen,
		};
		iov[1].iov_len = sz;
		iov[1].iov_base = ptr;
		hdr->len = htobe32(sz);
		hdr->idx = htobe32(idx);
		// FIXME - Syscall param sendmsg(msg.msg_iov[1]) points to unaddressable byte(s)
		if ((byt = sendmsg(sock, &msgh, 0)) == -1) {
			perror("sendmsg()");
			break;
		}
		len -= sz;
		ptr += sz;
		DEBUG("%zi bytes sent (blk=%zu, idx = %zu)", byt, blk, idx);
	}
}

ssize_t net_send_subtree(mld_t *mld, mtree_tree *stree, size_t root)
{
	TRACE("%s()", __func__);
	const int on = 1;
	int s;
	ssize_t rc = -1;
	size_t base, min, max;
	enum { vlen = 2 };
	struct iovec iov[vlen];
	struct addrinfo *addr;
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;
	if (!(lctx = lc_ctx_new()))
		return -1;
	if (!(sock = lc_socket_new(lctx)))
		goto err_0;
	if (lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &on, sizeof(on)))
		goto err_1;
	if (!(chan = lc_channel_nnew(lctx, mtree_nnode(stree, root), HASHSIZE)))
		goto err_1;
	if (lc_channel_bind(sock, chan))
		goto err_1;
	s = lc_channel_socket_raw(chan);
	addr = lc_channel_addrinfo(chan);
	net_blockhead_t hdr = { .len = htobe32(mtree_len(stree)) };
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof hdr;
	base = mtree_base(stree);
	min = mtree_subtree_data_min(base, root);
	max = MIN(mtree_subtree_data_max(base, root), mtree_blocks(stree) + min - 1);
	while (running) {
		for (size_t blk = min, idx = 0; running && blk <= max; blk++, idx++) {
			/* FIXME - we don't want to block here in MLD mode - we
			 * should subscribe for notifications on all addresses
			 * on all interfaces and wait to be told what blocks to
			 * send, firing up a thread only when required */
			if (mld_enabled && mld) mld_wait(mld, 0, aitoin6(addr));
			DEBUG("sending block %zu with idx=%zu", blk, idx);
			iov[1].iov_base = mtree_blockn(stree, blk);
			if (!iov[1].iov_base) continue;
			iov[1].iov_len = mtree_blockn_len(stree, blk);
			hdr.len = htobe32((uint32_t)iov[1].iov_len);
			net_send_block(s, addr, vlen, iov, idx);
			if (DELAY) usleep(DELAY);
		}
	}
	if (hex) mtree_hexdump(stree, stderr);
	rc = 0;
	lc_channel_free(chan);
err_1:
	lc_socket_close(sock);
err_0:
	lc_ctx_free(lctx);
	return rc;
}

void *net_job_sync_subtree(void *arg)
{
	net_data_t *data = (net_data_t *)arg;
	mtree_tree *stree = data->iov[0].iov_base;
	mtree_tree *dtree = data->iov[1].iov_base;
	net_sync_subtree(stree, dtree, data->n);
	DEBUG("%s() done", __func__);
	return arg;
}

void *net_job_send_subtree(void *arg)
{
	net_data_t *data = (net_data_t *)arg;
	mtree_tree *stree = data->iov[0].iov_base;
	net_send_subtree(data->mld, stree, data->n);
	return arg;
}

static void net_send_queue_jobs(net_data_t *data, size_t sz, size_t blocks, unsigned channels)
{
	TRACE("%s()", __func__);
	job_t *job_tree, *job_data[channels];
	job_tree = job_push_new(data->q, &net_job_send_tree, data, sz, NULL, 0);
	for (unsigned chan = 0; chan < MIN(channels, blocks); chan++) {
		data->n = channels - 1 + chan;
		job_data[chan] = job_push_new(data->q, &net_job_send_subtree, data, sz, NULL, JOB_COPY|JOB_FREE);
	}
	sem_wait(&job_tree->done);
	for (unsigned chan = 0; chan < MIN(channels, blocks); chan++) {
		sem_wait(&job_data[chan]->done);
		free(job_data[chan]);
	}
	free(job_tree);
}

/* Search lvl of tree for node whose hash corresponds to grp.  Return node
 * number, -2 if mtree requested  or -1 if not found */
static ssize_t net_tree_level_search(lc_ctx_t *lctx, mtree_tree *tree, size_t lvl, struct in6_addr *grp,
		unsigned char *alias, lc_channel_t *chan)
{
	size_t n;
	size_t first = (1 << lvl) - 1;
	size_t last = (first + 1) * 2 - 1;
	struct addrinfo *ai;
#ifdef NET_DEBUG
	char strgrp[INET6_ADDRSTRLEN];
#endif

	/* first check alias (mtree) hash */
	chan = lc_channel_nnew(lctx, alias, HASHSIZE);
	ai = lc_channel_addrinfo(chan);
	inet_ntop(AF_INET6, aitoin6(ai), strgrp, INET6_ADDRSTRLEN);
	if (!memcmp(grp, aitoin6(ai), IPV6_BYTES)) {
			return -2;
		}
	lc_channel_free(chan);

	for (n = first; n <= last; n++) {
		chan = lc_channel_nnew(lctx, mtree_nnode(tree, n), HASHSIZE);
		ai = lc_channel_addrinfo(chan);
#ifdef NET_DEBUG
		inet_ntop(AF_INET6, aitoin6(ai), strgrp, INET6_ADDRSTRLEN);
		DEBUG("checking %s", strgrp);
#endif
		if (!memcmp(grp, aitoin6(ai), IPV6_BYTES)) {
			return (ssize_t)n;
		}
		lc_channel_free(chan);
	}
	return -1;
}

/* this is a callback from within a watch loop
 * it does not need to be reentrant, but we want to keep it tight
 * just push a job and exit so the watch loop can proceed */
static void net_send_event(mld_watch_t *event, mld_watch_t *watch)
{
	net_data_t *data = (net_data_t *)watch->arg;
	mtree_tree *stree = data->iov[0].iov_base;
	mld_t *mld = data->mld;
	lc_ctx_t *lctx = mld_lctx(mld);
	lc_channel_t *chan = NULL;

#ifdef NET_DEBUG
	assert(event); assert(mld); assert(stree); assert(lctx);
	char strgrp[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, event->grp, strgrp, INET6_ADDRSTRLEN);
	DEBUG("received request for grp %s on if=%u", strgrp, event->ifx);
#endif

	ssize_t n;
	size_t lvl = net_send_channels; //FIXME - are you sure?
	size_t sz = sizeof(net_data_t) + sizeof(struct iovec);
	n = net_tree_level_search(lctx, stree, lvl, event->grp, data->alias, chan);
	if (n == -2) {		/* send mtree */
		//unsigned int iface = mld_idx_iface(mld, event->ifx); // FIXME - use iface
		DEBUG("------------------ MTREE REQUESTED MON COLONEL ------------------------------");
		job_push_new(data->q, &net_job_send_tree, data, sz, NULL, 0); // FIXME
	}
	else if (n >= 0) {	/* send subtree */
		DEBUG("------------------ BLOCK %zi REQUESTED MON COLONEL --------------------------", n);
		data->n = (size_t)n;
		job_push_new(data->q, &net_job_send_subtree, data, sz, &free, JOB_COPY|JOB_FREE);
	}
	else {
		DEBUG("------------------ I HAVE NOT THE THING THAT YOU ARE LOOKING FOR ------------");
	}
}

ssize_t net_send_data(unsigned char *hash, char *srcdata, size_t len)
{
	unsigned channels = 1U << net_send_channels;
	ssize_t rc = -1;
	size_t blocks;
	size_t sz = sizeof(net_data_t) + sizeof(struct iovec);
	mtree_tree *tree;
	job_queue_t *q;
	net_data_t *data;

	TRACE("%s()", __func__);
	if (!(tree = mtree_create(len, blocksize))) goto err_0;
	if (!(q = job_queue_create(channels + 1))) goto err_1;
	assert(srcdata);
	mtree_build(tree, srcdata, q);
	DEBUG("%s(): source tree built", __func__);
	if (mtree_verify(tree, mtree_treelen(tree))) goto err_2;
	blocks = mtree_blocks(tree);
	if (!(data = calloc(1, sz))) {
		perror("calloc");
		goto err_2;
	}
	data->q = q;
	data->chan = channels;
	data->hash = mtree_root(tree);
	data->alias = (hash) ? hash : data->hash;
	data->byt = len;
	data->iov[0].iov_len = mtree_treelen(tree);
	data->iov[0].iov_base = tree;
	if (mld_enabled) {
		mld_watch_t *watch;
		data->mld = mld_start(&running);
		if (!data->mld) goto err_3;
		watch = mld_watch_init(data->mld, 0, NULL, MLD_EVENT_JOIN, &net_send_event, data, 0);
		mld_watch_start(watch);
		sem_wait(&stop);
		mld_watch_cancel(watch);
		mld_stop(data->mld);
	}
	else net_send_queue_jobs(data, sz, blocks, channels);
	rc = 0;
err_3:
	free(data);
err_2:
	job_queue_destroy(q);
err_1:
	mtree_free(tree);
err_0:
	return rc;
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
	if ((sz_s = file_map(src, &fds, &smap, 0, PROT_READ, &sbs)) == -1) return -1;
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
	int rc = -1;
	int fdd;
	size_t blocksz, len;
	ssize_t sz_d;
	struct stat sbd = {0};
	char *src = argv[0];
	char *dst = argv[1];
	char *dmap = NULL;
	struct sigaction sa_int = { .sa_handler = net_stop };
	unsigned char hash[HASHSIZE];
	job_queue_t *q = job_queue_create(1U << net_send_channels);
	mtree_tree *stree = NULL, *dtree = NULL;
	TRACE("%s('%s')", __func__, argv[0]);
	sigaction(SIGINT, &sa_int, NULL);
	crypto_generichash(hash, HASHSIZE, (unsigned char *)src, strlen(src), NULL, 0);
	if (net_fetch_tree(hash, &stree) == -1) goto err_0;
	if (mtree_verify(stree, mtree_treelen(stree))) goto err_0;
	DEBUG("mapping dst: %s", dst);
	len = mtree_len(stree);
	sbd.st_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH; // TODO - set from packet data
	if ((sz_d = file_map(dst, &fdd, &dmap, len, PROT_READ|PROT_WRITE, &sbd)) == -1) {
		goto err_0;
	}
	blocksz = mtree_blocksz(stree);
	len = mtree_len(stree);
	dtree = mtree_create(len, blocksz);
	mtree_build(dtree, dmap, NULL);
	if (mtree_verify(dtree, mtree_treelen(dtree))) goto err_1;
	if (memcmp(mtree_root(stree), mtree_root(dtree), HASHSIZE)) {
		net_sync_trees(stree, dtree, q);
	}
	rc = 0;
err_1:
	mtree_free(dtree);
err_0:
	mtree_free(stree);
	job_queue_destroy(q);
	return rc;
}
