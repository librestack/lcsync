/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/globals.h"
#include "../src/job.h"
#include "../src/net.h"
#include "../src/mtree.h"
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

static int keep_sending = 1;
mtree_tree *stree;
const size_t blocks = 42;
const size_t blocksz = 4096;
const size_t sz = blocks * blocksz;

void *do_recv(void *arg)
{
	net_data_t *data = (net_data_t *)arg;
	unsigned char *map = NULL;
	mtree_tree *stree = (mtree_tree *)data->iov[0].iov_base;
	mtree_tree *dtree = mtree_create(sz, blocksz);
	char *dstdata = (char *)data->iov[1].iov_base;
	dtree = mtree_create(sz, blocksz);
	mtree_build(dtree, dstdata, NULL);
	map = mtree_diff_map(stree, dtree);
	test_assert(map != 0, "differences found");

#define ROUNDUP(x, y) (x + y - 1) / y
#define MIN(x, y) ((x) < (y)) ? (x) : (y)
#define POWEROF2(x) ((((x) - 1) & (x)) == 0)

	size_t channels = MIN(blocks, (1UL << net_send_channels));
	size_t chanblks = ROUNDUP(blocks, (1UL << net_send_channels));
	size_t maxlvl = (POWEROF2(channels)) ? channels : next_pow2(channels);
	size_t lvl = (size_t)log2(maxlvl);        /* level numbered from root */
	size_t ulvl = mtree_lvl(stree) - lvl - 1; /* level numbered from base */
	test_log("sz: %zu bytes\n", sz);
	test_log("blocks: %zu\n", blocks);
	test_log("base: %zu\n", mtree_base(stree));
	test_log("channels available: %zu\n", 1UL << net_send_channels);
	test_log("channels to use: %zu\n", channels);
	test_log("blocks / channel: %zu\n", chanblks);
	test_log("tree level: %zu (from root)\n", lvl);
	test_log("tree level: %zu (from base)\n", ulvl);

	if (POWEROF2(channels)) fprintf(stderr, "channels=%zu is power of 2\n", channels);
	else fprintf(stderr, "channels=%zu is not a power of 2\n", channels);
	fprintf(stderr, "nextpow2(%zu) = %zu\n", channels, (size_t)next_pow2(channels));



	// TODO: find subtree hashes for each channel
	/* loop through hashes on appropriate tree level */
	for (size_t n = 0; n < channels; n++) {
		unsigned char *hash = mtree_node(stree, ulvl, n);
		fprintf(stderr, "%zu: got me a hash\n", n);
	}

	// TODO: break bitmap into channel sized pieces
	// TODO: receive subtrees

#if 0
	int s;
	ssize_t byt;
	struct iovec iov = {0};
#endif


	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
#if 0
	lc_channel_t *chan = lc_channel_nnew(lctx, data->hash, HASHSIZE);
	lc_channel_bind(sock, chan);
	lc_channel_join(chan);
	s = lc_socket_raw(sock);
	byt = net_recv_tree(s, &iov);
	mtree_tree *dtree = mtree_create(blocks, blocksz);
	mtree_setdata(dtree, iov.iov_base);
	test_assert((size_t)byt == mtree_treelen(stree), "%zu bytes received", byt);
	test_assert(iov.iov_len == mtree_treelen(stree), "iov_len=%zu", iov.iov_len);
	test_assert(iov.iov_base != NULL, "recv buffer allocated");
	test_assert(!mtree_verify(dtree, iov.iov_len), "validate tree");
	for (size_t z = 0; z < mtree_nodes(stree); z++) {
		test_assert(!memcmp(mtree_data(stree, z), mtree_data(dtree, z), HASHSIZE), "check hash %zu", z);
	}
	lc_channel_free(chan);
	mtree_free(dtree);
#endif
	lc_socket_close(sock);
	lc_ctx_free(lctx);
	free(map);
	return NULL;
}

void *do_send(void *arg)
{
	const int on = 1;
	net_data_t *data = (net_data_t *)arg;
#if 0
	void *base = data->iov[0].iov_base;
	size_t len = data->iov[0].iov_len;
#endif
	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &on, sizeof(on));

	// TODO: work out channels to send on
	// send subtree
#if 0
	lc_channel_t *chan = lc_channel_nnew(lctx, data->hash, HASHSIZE);
	lc_channel_bind(sock, chan);
	int s = lc_channel_socket_raw(chan);
	struct addrinfo *addr = lc_channel_addrinfo(chan);
	struct iovec iov[2] = {0};
	net_treehead_t hdr = {
		.size = htobe64(data->iov[0].iov_len),
		.chan = net_send_channels,
		.pkts = data->iov[0].iov_len / DATA_FIXED + !!(data->iov[0].iov_len % DATA_FIXED)
	};
	memcpy(&hdr.hash, data->hash, HASHSIZE);
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof hdr;
	while (keep_sending) {
		iov[1].iov_len = len;
		iov[1].iov_base = base;
		net_send_tree(s, addr, 2, iov);
	}
	lc_channel_free(chan);
#endif
	lc_socket_close(sock);
	lc_ctx_free(lctx);
	return NULL;
}

int main(void)
{
	const int waits = 1; /* test timeout in s */
	struct timespec timeout;
	job_queue_t *jobq;
	job_t *job_send, *job_recv;
	unsigned char *hash = malloc(HASHSIZE);
	net_data_t *odata = calloc(1, sizeof(net_data_t) + sizeof(struct iovec) * 2);
	net_data_t *idata = calloc(1, sizeof(net_data_t) + sizeof(struct iovec) * 2);
	char *srcdata = calloc(blocks, blocksz);
	char *dstdata = calloc(blocks, blocksz);

	test_name("net_send_data() / net_recv_data()");
	
	/* build source data, make each block different */
	for (size_t i = 0; i < blocks; i++) {
		(srcdata + i * blocksz)[0] = i + 1;
	}

	/* build source tree */
	stree = mtree_create(sz, blocksz);
	mtree_build(stree, srcdata, NULL);
	fprintf(stderr, "node= %zu, treelen=%zu\n", mtree_nodes(stree), mtree_treelen(stree));

	/* sender needs tree and data */
	odata->iov[0].iov_len = sizeof stree;
	odata->iov[0].iov_base = stree;
	odata->iov[1].iov_len = sz;
	odata->iov[1].iov_base = srcdata;

	/* start from when receiver already has source tree */
	idata->iov[0].iov_len = sizeof stree;
	idata->iov[0].iov_base = stree;
	idata->iov[1].iov_len = sz;
	idata->iov[1].iov_base = dstdata;

	test_assert(memcmp(srcdata, dstdata, sz), "src and dst data differ before syncing");

	/* queue up send / recv jobs */
	jobq = job_queue_create(2);
	job_send = job_push_new(jobq, &do_send, odata, NULL);
	job_recv = job_push_new(jobq, &do_recv, idata, NULL);

	/* wait for recv job to finish, check for timeout */
	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec += waits;
	test_assert(!sem_timedwait(&job_recv->done, &timeout), "timeout - recv");
	free(job_recv);

	keep_sending = 0; /* stop send job */

	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec++;
	test_assert(!sem_timedwait(&job_send->done, &timeout), "timeout - send");
	free(job_send);

	test_assert(!memcmp(srcdata, dstdata, sz), "src and dst data match after syncing");

	job_queue_destroy(jobq);
	free(srcdata);
	free(dstdata);
	free(odata);
	free(idata);
	free(hash);
	mtree_free(stree);

	return fails;
}
