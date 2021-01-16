/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/job.h"
#include "../src/net.h"
#include "../src/mtree.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

static int keep_sending = 1;

void *do_recv(void *arg)
{
	net_data_t *data = (net_data_t *)arg;
	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_channel_t *chan = lc_channel_nnew(lctx, data->hash, HASHSIZE);
	lc_channel_bind(sock, chan);
	lc_channel_join(chan);
	int s = lc_socket_raw(sock);
#if 0
	net_recv_data(s, data);
	unsigned char *roothash = data->iov[1].iov_base + data->iov[1].iov_len - HASHSIZE;
	test_assert(!memcmp(roothash, data->hash, HASHSIZE),
			"root hash at end of tree matches");
	// TODO: validate tree
#endif
	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);
	return NULL;
}

void *do_send(void *arg)
{
	const int on = 1;
	net_data_t *data = (net_data_t *)arg;
	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &on, sizeof(on));
	lc_channel_t *chan = lc_channel_nnew(lctx, data->hash, HASHSIZE);
	lc_channel_bind(sock, chan);
	int s = lc_channel_socket_raw(chan);
	struct addrinfo *addr = lc_channel_addrinfo(chan);
	while (keep_sending) {
		//net_send_data(s, addr, data);
		usleep(100);
	}
	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);

	return NULL;
}

int main(void)
{
	const int waits = 5; /* test timeout in s */
	struct timespec timeout;
	job_queue_t *jobq;
	job_t *job_send, *job_recv;
	const size_t blocks = 42;
	const size_t blocksz = 4096;
	const size_t sz = blocks * blocksz;
	unsigned char hash[HASHSIZE];
	net_data_t *odata = calloc(1, sizeof(net_data_t) + sizeof(struct iovec));
	net_data_t *idata = calloc(1, sizeof(net_data_t) + sizeof(struct iovec));
	char *srcdata = calloc(blocks, blocksz);
	char *dstdata = calloc(blocks, blocksz);

	test_name("net_send_data() / net_recv_data() - send tree");
	
	/* build source data, make each block different */
	for (size_t i = 0; i < blocks; i++) {
		(srcdata + i * blocksz)[0] = i + 1;
	}

	/* build source tree */
	mtree_tree *stree;
	stree = mtree_create(sz, blocksz);
	mtree_build(stree, srcdata, NULL);

	/* create channel hash */
	crypto_generichash(hash, HASHSIZE, (unsigned char *)srcdata, sz, NULL, 0);

	/* queue up send / recv jobs */
	fprintf(stderr, "node= %zu, treelen=%zu\n", mtree_nodes(stree), mtree_treelen(stree));

	//net_treehead_t hdr_tree = {0};
	//net_hdr_tree(hdr_tree, stree);

	// FIXME: working here
	
	/* we are sending the source tree */
	memcpy(odata->hash, hash, HASHSIZE);
	odata->iov[0].iov_len = mtree_treelen(stree);
	odata->iov[0].iov_base = mtree_data(stree, 0);

	/* receiver is recving source tree of unknown size
	 * all receiver knows is hash of data to join channel */
	memcpy(idata->hash, hash, HASHSIZE);

	jobq = job_queue_create(2);
	job_send = job_push_new(jobq, &do_send, &odata, NULL);
	job_recv = job_push_new(jobq, &do_recv, &idata, NULL);

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

	job_queue_destroy(jobq);
	free(srcdata);
	free(dstdata);
	free(odata);
	free(idata);
	mtree_free(stree);

	return fails;
}
