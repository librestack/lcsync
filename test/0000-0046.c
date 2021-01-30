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
#include <time.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

static const time_t waits = 1;
static int events;

void *do_mld_watch(void *arg)
{
	struct in6_addr *addr = (struct in6_addr *)arg;
	char straddr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, addr, straddr, INET6_ADDRSTRLEN);
	test_log("watching %s\n", straddr);
	if (!mld_wait(addr)) events++;
	return arg;
}

int main(void)
{
	struct timespec timeout;
	struct in6_addr *addr[2];
	struct sockaddr_in6 *sad[2];
	struct addrinfo *p[2];
	job_queue_t *q;
	job_t *job[2] = {0};
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan[2];

	loginit();
	test_name("mld_wait()");

	/* TODO spawn child in new network namespace */

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	chan[0] = lc_channel_new(lctx, "we will join this channel");
	chan[1] = lc_channel_new(lctx, "but not this one");
	for (int i = 0; i < 2; i++) {
		p[i] = lc_channel_addrinfo(chan[i]);
		sad[i] = (struct sockaddr_in6 *)p[i]->ai_addr;
		addr[i] = &(sad[i]->sin6_addr);
	}

	/* wait on two channels, one we'll join, and one we won't */
	q = job_queue_create(2);
	job[0] = job_push_new(q, &do_mld_watch, addr[0], sizeof(struct in6_addr), NULL, JOB_COPY|JOB_FREE);
	job[1] = job_push_new(q, &do_mld_watch, addr[1], sizeof(struct in6_addr), NULL, JOB_COPY|JOB_FREE);

	lc_channel_bind(sock, chan[0]);
	lc_channel_join(chan[0]);

	/* set test timeout */
	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec += waits;
	/* first job should return, we joined its channel */
	test_assert(!sem_timedwait(&job[0]->done, &timeout), "timeout - mld_watch() channel 0");
	/* second channel will timeout, we ignored it */
	test_assert(sem_timedwait(&job[1]->done, &timeout), "timeout - mld_watch() channel 1");
	free(job[0]);
	free(job[1]);

	test_assert(events == 1, "received %i/1 event notifications", events);

	lc_channel_part(chan[0]);
	lc_channel_free(chan[0]);
	lc_socket_close(sock);
	lc_ctx_free(lctx);
	job_queue_destroy(q);
	return fails;
}
