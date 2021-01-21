/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/globals.h"
#include "../src/job.h"
#include "../src/net.h"
#include "../src/mtree.h"
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

const int waits = 1; /* test timeout in s */
const size_t blocks = 42;
const size_t blocksz = 1024;
const size_t sz = blocks * blocksz;
unsigned char hash[HASHSIZE];

void *do_recv(void *arg)
{
	size_t len = sz;
	net_recv_data(hash, (char *)arg, &len);
	return arg;
}

void *do_send(void *arg)
{
	net_send_data((char *)arg, sz);
	return arg;
}

void do_sync(char *srcdata, char *dstdata)
{
	struct timespec timeout;
	job_queue_t *jobq;
	job_t *job_send, *job_recv;

	/* queue up send / recv jobs */
	jobq = job_queue_create(2);
	job_send = job_push_new(jobq, &do_send, srcdata, sizeof srcdata, NULL, 0);
	job_recv = job_push_new(jobq, &do_recv, dstdata, sizeof dstdata, NULL, 0);

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
}

/* work out root hash so recv thread knows what channel to join */
void saveroothash(char *srcdata)
{
	mtree_tree *tree = mtree_create(sz, blocksz);
	mtree_build(tree, srcdata, NULL);
	memcpy(hash, mtree_root(tree), HASHSIZE);
	mtree_free(tree);
}

void gentestdata(char *srcdata, char *dstdata)
{
	/* build source data, make each block different */
	for (size_t i = 0; i < blocks; i++) {
		(srcdata + i * blocksz)[0] = i + 1;
		/* copy a selection of blocks to destination, leaving some holes */
		if ((i % 7) && (i % 9)) (dstdata + i * blocksz)[0] = i + 1;
	}
}

int main(void)
{
	char *srcdata = calloc(blocks, blocksz);
	char *dstdata = calloc(blocks, blocksz);
	test_name("net_send() / net_recv()");
	gentestdata(srcdata, dstdata);
	saveroothash(srcdata);
	test_assert(memcmp(srcdata, dstdata, sz), "src and dst data differ before syncing");
	do_sync(srcdata, dstdata);
	test_assert(!memcmp(srcdata, dstdata, sz), "src and dst data match after syncing");
	free(srcdata);
	free(dstdata);
	return fails;
}
