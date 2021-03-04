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
const char *alias = "My Preciousssss";

int main(void)
{
	const int waits = 1; /* test timeout in s */
	struct timespec timeout;
	job_queue_t *jobq;
	job_t *job_send, *job_recv = NULL;
	const size_t sz = blocks * blocksize;
	unsigned char *hash = malloc(HASHSIZE);
	size_t odatasz = sizeof(net_data_t) + sizeof(struct iovec);
	net_data_t *odata = calloc(1, odatasz);
	net_data_t *idata = calloc(1, sizeof(net_data_t) + sizeof(struct iovec));
	char *srcdata = calloc(blocks, blocksize);

	test_name("net_send_tree() / net_recv_tree()");
	
	/* build source data, make each block different */
	for (size_t i = 0; i < blocks; i++) {
		(srcdata + i * blocksize)[0] = i + 1;
	}

	/* build source tree */
	stree = mtree_create(sz, blocksize);
	fprintf(stderr, "mtree_create(%zu, %zu)\n", sz, blocksize);
	mtree_build(stree, srcdata, NULL);
	fprintf(stderr, "node= %zu, treelen=%zu\n", mtree_nodes(stree), mtree_treelen(stree));

	/* we are sending the source tree */
#ifdef sodium_init
	test_assert(sodium_init() != -1, "sodium_init()");
#endif
	odata->alias = malloc(HASHSIZE);
	hash_generic(odata->alias, HASHSIZE, (unsigned char *)alias, strlen(alias));
	odata->hash = mtree_root(stree);
	odata->byt = sz;
	odata->iov[0].iov_len = mtree_treelen(stree);
	odata->iov[0].iov_base = stree;

	test_assert(!mtree_verify(stree, odata->iov[0].iov_len), "source tree validates");

	/* receiver is recving source tree of unknown size
	 * all receiver knows is alias of channel to join */
	idata->alias = odata->alias;

	/* queue up send / recv jobs */
	jobq = job_queue_create(2);
	job_send = job_push_new(jobq, &net_job_send_tree, odata, sizeof odata, NULL, 0);
	job_recv = job_push_new(jobq, &net_job_recv_tree, idata, sizeof idata, NULL, 0);

	/* wait for recv job to finish, check for timeout */
	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec += waits;
	test_assert(!sem_timedwait(&job_recv->done, &timeout), "timeout - recv");

	struct iovec *iov = (struct iovec *)job_recv->ret;
	assert(job_recv->ret);
	// FIXME - Invalid read of size 8
	// at 0x10AA17: main (0000-0034.c:71)
	// Address 0x0 is not stack'd, malloc'd or (recently) free'd
	test_assert(iov->iov_base != NULL, "recv buffer allocated");
	mtree_tree *dtree = mtree_create(blocks, blocksize);
	mtree_setdata(dtree, iov->iov_base);
	test_assert(!mtree_verify(dtree, iov[0].iov_len), "validate tree");
	free(job_recv->ret);
	mtree_free(dtree);

	net_stop(SIGINT);

	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec++;
	test_assert(!sem_timedwait(&job_send->done, &timeout), "timeout - send");
	free(job_recv);
	free(job_send);
	job_queue_destroy(jobq);
	free(srcdata);
	free(odata->alias);
	free(odata);
	free(idata);
	free(hash);
	mtree_free(stree);
	return fails;
}
