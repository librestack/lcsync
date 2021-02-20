/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/globals.h"
#include "../src/log.h"
#include "../src/net.h"
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

const int waits = 1; /* test timeout in s */
const size_t blocks = 42;
size_t blocksz;
size_t sz;
const char *alias = "alias";
unsigned char hash[HASHSIZE];
sem_t send_done, recv_done;

void *do_recv(void *arg)
{
	mtree_tree *dtree = NULL;
	net_fetch_tree(hash, &dtree);
	// TODO check stree & dtree match
	sem_post(&recv_done);
	return arg;
}

void *do_send(void *arg)
{
	net_send_data(hash, (char *)arg, sz);
	sem_post(&send_done);
	return arg;
}

void do_sync(char *srcdata, char *dstdata)
{
	struct timespec timeout;
	pthread_t tsend, trecv;
	pthread_attr_t attr = {0};

	sem_init(&send_done, 0, 0);
	sem_init(&recv_done, 0, 0);

	/* queue up send / recv jobs */
	pthread_attr_init(&attr);
	pthread_create(&trecv, &attr, &do_recv, dstdata);
	pthread_create(&tsend, &attr, &do_send, srcdata);
	pthread_attr_destroy(&attr);

	/* wait for recv job to finish, check for timeout */
	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec += waits;
	test_assert(!sem_timedwait(&recv_done, &timeout), "timeout - recv");
	net_stop(SIGINT);
	pthread_join(trecv, NULL);

	/* stop sender */
	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec += waits;
	test_assert(!sem_timedwait(&send_done, &timeout), "timeout - send");
	pthread_join(tsend, NULL);

	sem_destroy(&recv_done);
	sem_destroy(&send_done);
}

void gentestdata(char *srcdata, char *dstdata)
{
	/* build source data, make each block different */
	for (size_t i = 0; i < blocks; i++) {
		(srcdata + i * blocksz)[0] = i + 1;
		/* copy a selection of blocks to destination, leaving some holes */
		if ((i % 7) && (i % 9)) (dstdata + i * blocksz)[0] = i + 1;
	}

	hash_generic(hash, HASHSIZE, (unsigned char *)alias, strlen(alias));
}

int main(void)
{
	char *srcdata, *dstdata;

	loginit();

	test_name("MLD sync (tree only)"); // TODO

	blocksz = blocksize;
	sz = blocks * blocksz;
	srcdata = calloc(blocks, blocksz);
	dstdata = calloc(blocks, blocksz);
	assert(srcdata); assert(dstdata);

	gentestdata(srcdata, dstdata);

	test_assert(memcmp(srcdata, dstdata, sz), "src and dst data differ before syncing");
	
	mld_enabled = 1;
	do_sync(srcdata, dstdata);

	free(dstdata);
	free(srcdata);

	return fails;
}
