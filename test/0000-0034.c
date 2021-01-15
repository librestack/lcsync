/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/job.h"
#include "../src/net.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

static int keep_sending = 1;

void *do_recv(void *arg)
{
	net_data_t *data = (net_data_t *)arg;
	usleep(100);
	return NULL;
}

void *do_send(void *arg)
{
	net_data_t *data = (net_data_t *)arg;
	// - generate tree
	// - send tree (what header information do we send?)
	// - send blocks
	usleep(100);

	return NULL;
}

int main(void)
{
	struct timespec timeout;
	job_queue_t *jobq;
	job_t *job_send, *job_recv;
	net_data_t *odat, *idat;
	const size_t blocks = 42;
	const size_t blocksz = 4096;
	const size_t sz = blocks * blocksz;
	unsigned char hash[HASHSIZE];
	char *srcdata = calloc(blocks, blocksz);
	char *dstdata = calloc(blocks, blocksz);

	test_name("net_send_data() / net_recv_data() - send tree");
	
	/* build source data, make each block different */
	for (size_t i = 0; i < blocks; i++) {
		(srcdata + i * blocksz)[0] = i + 1;
	}

	/* create channel hash */
	crypto_generichash(hash, HASHSIZE, (unsigned char *)srcdata, sz, NULL, 0);

	/* queue up send / recv jobs */
	odat = net_chunk(hash, sz, srcdata, sz);
	idat = net_chunk(hash, sz, dstdata, sz);
	jobq = job_queue_create(2);
	job_send = job_push_new(jobq, &do_send, odat, NULL);
	job_recv = job_push_new(jobq, &do_recv, idat, NULL);

	/* wait for recv job to finish, check for timeout */
	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec++;
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
	free(odat);
	free(idat);

	return fails;
}
