/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/globals.h"
#include "../src/job.h"
#include "../src/net.h"
#include "../src/mtree.h"
#include "../src/log.h"
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>

const int waits = 1; /* test timeout in s */
const size_t blocks = 42;
const size_t blocksz = 1024;
const size_t extra = 123; /* some extra bytes */
const size_t sz = blocks * blocksz + extra;
unsigned char hash[HASHSIZE];
mtree_tree *stree, *dtree;

void do_sync(void)
{
	struct timespec timeout;
	job_queue_t *jobq;
	job_t *job_send, *job_recv;
	net_data_t *data = calloc(1, sizeof(net_data_t) + sizeof(struct iovec) * 2);
	data->n = 0;
	data->iov[0].iov_base = stree;
	data->iov[1].iov_base = dtree;

	/* queue up send / recv jobs */
	jobq = job_queue_create(2);
	job_send = job_push_new(jobq, &net_job_send_subtree, data, 0, NULL, 0);
	job_recv = job_push_new(jobq, &net_job_sync_subtree, data, 0, NULL, 0);

	/* wait for recv job to finish, check for timeout */
	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec += waits;
	test_assert(!sem_timedwait(&job_recv->done, &timeout), "timeout - recv");
	free(job_recv);

	/* stop send job */
	net_stop(SIGINT);
	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec += waits;
	test_assert(!sem_timedwait(&job_send->done, &timeout), "timeout - send");
	free(job_send);
	job_queue_destroy(jobq);
	free(data);
}

void gentestdata(char *srcdata, char *dstdata)
{
	/* build source data, make each block different */
	for (size_t i = 0; i < blocks; i++) {
		size_t off = i * blocksz;
		memset(srcdata + off, i + 1, blocksz); /* set whole block */
		/* copy a selection of blocks to destination, leaving some holes */
		if ((i % 7) && (i % 9)) {
			memcpy(dstdata + off, srcdata + off, blocksz);
		}
	}
	memset(srcdata + blocks * blocksz, ~0, extra);
}

int main(void)
{
	loginit();
	test_name("net_send_subtree() / net_sync_subtree() - %zu byte blocks", blocksz);
	char *srcdata = calloc(blocks, blocksz + extra);
	char *dstdata = calloc(blocks, blocksz + extra);
	gentestdata(srcdata, dstdata);
	/* start where receiver already has the source tree */
	stree = mtree_create(sz, blocksz);
	dtree = mtree_create(sz, blocksz);
	mtree_build(stree, srcdata, NULL);
	mtree_build(dtree, dstdata, NULL);
	test_assert(memcmp(srcdata, dstdata, sz), "src and dst data differ before syncing");
	do_sync();
	test_assert(!memcmp(srcdata, dstdata, sz),
			"src and dst data match after syncing (blocksz=%zu)", blocksz);

	/* rebuild dsttree, diff, and check bitmap is zero */
	mtree_free(dtree);
	dtree = mtree_create(sz, blocksz);
	mtree_build(dtree, dstdata, NULL);
	unsigned char *bitmap;
	unsigned bits = howmany(blocksz, DATA_FIXED);
	bitmap = mtree_diff_subtree(stree, dtree, 0, bits);
	test_assert(bitmap == NULL, "bitmap - no differences");
	free(bitmap);

	free(srcdata);
	free(dstdata);
	mtree_free(stree);
	mtree_free(dtree);
	return fails;
}
