/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/globals.h"
#include "../src/job.h"
#include "../src/log.h"
#include "../src/macro.h"
#include "../src/mld.h"
#include "../src/net.h"
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <semaphore.h>
#include <time.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

static const time_t waits = 1;
static int events;
static mld_t *mld;
static sem_t sem;

/* mld_wait(), increment events counter, return */
void *do_mld_watch(void *arg)
{
	struct in6_addr *addr = (struct in6_addr *)arg;
	char straddr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, addr, straddr, INET6_ADDRSTRLEN);
	test_log("watching %s\n", straddr);
	sem_post(&sem);
	if (!mld_wait(mld, 0, addr)) events++;
	test_log("notify received for %s\n", straddr);
	return arg;
}

/* convert channel address and queue mld_wait() job */
job_t *push_job(job_queue_t *q, lc_channel_t *chan)
{
	return job_push_new(q, &do_mld_watch, lc_channel_in6addr(chan), sizeof(struct in6_addr), NULL, JOB_COPY|JOB_FREE);
}

int main(void)
{
	struct timespec timeout;
	job_queue_t *q;
	job_t *job[2] = {0};
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan[2];

	loginit();
	test_name("mld_wait()");

	/* This test is simple. We create two channels, and mld_wait() on both
	 * of them.  We join the first, but not the second and ensure only one
	 * of the calls returns.  Repeat. */

	mld = mld_start(NULL);
	test_assert(mld != NULL, "mld_start()");
	if (!mld) return fails;
	test_log("%s() mld has address %p\n", "main", (void*)mld);
	lctx = lc_ctx_new();
	assert(lctx);
	q = job_queue_create(2);
	assert(q);

	events = 0;
	sock = lc_socket_new(lctx);
	assert(sock);
	chan[0] = lc_channel_new(lctx, "we will join this channel");
	chan[1] = lc_channel_new(lctx, "but not this one");
	assert(chan[0]);
	assert(chan[1]);

	sem_init(&sem, 0, 0);

	job[0] = push_job(q, chan[0]);
	job[1] = push_job(q, chan[1]);

	sem_wait(&sem); sem_wait(&sem);
	sem_destroy(&sem);

	usleep(5000);

	test_assert(!lc_channel_bind(sock, chan[0]), "lc_channel_bind()");
	test_assert(!lc_channel_join(chan[0]), "lc_channel_join()");

	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec += waits;

	/* first job should return, we joined its channel */
	test_assert(!sem_timedwait(&job[0]->done, &timeout), "timeout - mld_wait() channel 0");
	free(job[0]);

	/* second channel will timeout, we ignored it */
	test_assert(sem_timedwait(&job[1]->done, &timeout), "timeout - mld_wait() channel 1");
	free(job[1]->arg);
	free(job[1]);

	lc_channel_part(chan[0]);
	lc_channel_free(chan[1]);
	lc_channel_free(chan[0]);
	lc_socket_close(sock);

	test_assert(events == 1, "received %i/1 event notifications", events);

	lc_ctx_free(lctx);
	job_queue_destroy(q);
	mld_stop(mld);
	return fails;
}
