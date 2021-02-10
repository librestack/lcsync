/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/globals.h"
#include "../src/job.h"
#include "../src/log.h"
#include "../src/mld.h"
#include "../src/net.h"
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
static int iface;

/* mld_wait(), increment events counter, return */
void *do_mld_watch(void *arg)
{
	struct in6_addr *addr = (struct in6_addr *)arg;
	char straddr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, addr, straddr, INET6_ADDRSTRLEN);
	test_log("watching %s\n", straddr);
	if (!mld_wait(mld, iface, addr)) events++;
	test_log("notify received for %s\n", straddr);
	return arg;
}

/* convert channel address and queue mld_wait() job */
job_t *push_job(job_queue_t *q, lc_channel_t *chan)
{
	struct in6_addr *addr;
	struct sockaddr_in6 *sad;
	struct addrinfo *p;
	p = lc_channel_addrinfo(chan);
	sad = (struct sockaddr_in6 *)p->ai_addr;
	addr = &(sad->sin6_addr);
	return job_push_new(q, &do_mld_watch, addr, sizeof(struct in6_addr), NULL, JOB_COPY|JOB_FREE);
}

int main(void)
{
	const int limit = 1;
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

	mld = mld_start();
	test_assert(mld != NULL, "mld_start()");
	if (!mld) return fails;
	test_log("%s() mld has address %p\n", "main", (void*)mld);
	lctx = lc_ctx_new();
	q = job_queue_create(2);

	for (int i = 0; i < limit; i++) {
		events = 0;
		sock = lc_socket_new(lctx);
		chan[0] = lc_channel_new(lctx, "we will join this channel");
		chan[1] = lc_channel_new(lctx, "but not this one");

		job[0] = push_job(q, chan[0]);
		job[1] = push_job(q, chan[1]);
		usleep(1000);

		lc_channel_bind(sock, chan[0]);
		lc_channel_join(chan[0]);
		usleep(10000);

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
	}
	lc_ctx_free(lctx);
	job_queue_destroy(q);
	mld_stop(mld);
	return fails;
}
