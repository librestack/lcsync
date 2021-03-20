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

static const int waits = 1;
static int events;
static sem_t sem;
static mld_t *mld;

void *do_join(void *arg)
{
	lc_channel_join((lc_channel_t *)arg);
	return arg;
}

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

job_t *push_job(job_queue_t *q, lc_channel_t *chan)
{
	struct in6_addr *addr = lc_channel_in6addr(chan);
	return job_push_new(q, &do_mld_watch, addr, sizeof(struct in6_addr), NULL, JOB_COPY|JOB_FREE);
}

int main(void)
{
	struct timespec timeout;
	struct in6_addr *addr;
	job_queue_t *q;
	job_t *job;
	lc_ctx_t *lctx;
	lc_channel_t *chan;

	loginit();
	test_name("mld_wait() - address already in filter");

	q = job_queue_create(1);
	mld = mld_init(1);
	lctx = lc_ctx_new();
	chan = lc_channel_new(lctx, "manually put this in filter");

	/* we manually put this in the filter, so it must return immediately */
	addr = lc_channel_in6addr(chan);
	mld_filter_grp_add(mld, 0, addr);
	job = push_job(q, chan);

	/* set test timeout */
	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec += waits;
	test_assert(!sem_timedwait(&job->done, &timeout), "timeout - mld_wait()");
	free(job);

	test_assert(events == 1, "received %i/1 event notifications", events);

	lc_ctx_free(lctx);
	mld_free(mld);
	job_queue_destroy(q);
	return fails;
}
