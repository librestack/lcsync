/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/globals.h"
#include "../src/job.h"
#include "../src/net.h"
#include "../src/mtree.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

mtree_tree *stree;
const size_t blocks = 42;
const size_t blocksz = 4096;

void *do_recv(void *arg)
{
	int s;
	ssize_t byt;
	net_data_t *data = (net_data_t *)arg;
	struct iovec iov = {0};
	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
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
	lc_socket_close(sock);
	lc_ctx_free(lctx);
	mtree_free(dtree);
	return NULL;
}

int main(void)
{
	const int waits = 1; /* test timeout in s */
	struct timespec timeout;
	job_queue_t *jobq;
	job_t *job_send, *job_recv;
	const size_t sz = blocks * blocksz;
	unsigned char *hash = malloc(HASHSIZE);
	net_data_t *odata = calloc(1, sizeof(net_data_t) + sizeof(struct iovec));
	net_data_t *idata = calloc(1, sizeof(net_data_t) + sizeof(struct iovec));
	char *srcdata = calloc(blocks, blocksz);

	test_name("net_send_tree() / net_recv_tree()");
	
	/* build source data, make each block different */
	for (size_t i = 0; i < blocks; i++) {
		(srcdata + i * blocksz)[0] = i + 1;
	}

	/* build source tree */
	stree = mtree_create(sz, blocksz);
	mtree_build(stree, srcdata, NULL);
	fprintf(stderr, "node= %zu, treelen=%zu\n", mtree_nodes(stree), mtree_treelen(stree));

	/* we are sending the source tree */
	odata->hash = mtree_root(stree);
	odata->iov[0].iov_len = mtree_treelen(stree);
	odata->iov[0].iov_base = mtree_data(stree, 0);

	/* receiver is recving source tree of unknown size
	 * all receiver knows is hash of data to join channel */
	idata->hash = odata->hash;

	/* queue up send / recv jobs */
	jobq = job_queue_create(2);
	job_send = job_push_new(jobq, &net_job_send_tree, odata, sizeof odata, NULL, 0);
	job_recv = job_push_new(jobq, &do_recv, idata, sizeof idata, NULL, 0);

	/* wait for recv job to finish, check for timeout */
	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec += waits;
	test_assert(!sem_timedwait(&job_recv->done, &timeout), "timeout - recv");
	free(job_recv);

	net_stop(SIGINT);

	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec++;
	test_assert(!sem_timedwait(&job_send->done, &timeout), "timeout - send");
	free(job_send);

	job_queue_destroy(jobq);
	free(srcdata);
	free(odata);
	free(idata);
	free(hash);
	mtree_free(stree);

	return fails;
}
