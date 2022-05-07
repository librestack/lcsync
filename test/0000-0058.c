/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#define _GNU_SOURCE /* required for struct in6_pktinfo */
#include "test.h"
#include "../src/mld.h"
#include <librecast.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>

enum {
	CHANMAIN,
	CHANSIDE,
};

int msgs = 0;
struct in6_addr *addr;
sem_t sem_notify;
const int waits = 2; /* test timeout in s */

void *socket_listen(void *arg)
{
	lc_socket_t *sock = (lc_socket_t *)arg;
	struct in6_pktinfo pi = {0};
	sem_post(&sem_notify);
	lc_socket_recv(sock, &pi, sizeof(struct in6_pktinfo), 0);

	/* check address matches */
	char straddr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &pi.ipi6_addr, straddr, INET6_ADDRSTRLEN);
	test_log("got a notification for %s\n", straddr);
	if (memcmp(addr, &pi.ipi6_addr, sizeof(struct in6_addr))) {
		test_log("notification address not matched\n");
	}
	else {
		test_log("notification address matches\n");
		msgs++;
	}
	sem_post(&sem_notify);
	return arg;
}

int main(void)
{
	lc_ctx_t *lctx;
	lc_socket_t *sock[2];
	lc_channel_t *chan[2];
	mld_t *mld;
	pthread_attr_t attr = {0};
	pthread_t tnotify = {0};
	struct timespec timeout;

	test_name("mld_notify()");
	lctx = lc_ctx_new();
	chan[CHANMAIN] = lc_channel_random(lctx);
	addr = lc_channel_in6addr(chan[CHANMAIN]);
	mld = mld_start(NULL);
	test_assert(mld != NULL, "mld_start()");

	/* join side channel for MLD events */
	chan[CHANSIDE] = mld_notification_channel(mld, addr, MLD_EVENT_JOIN);

	/* join notification channel and wait for notify msg */
	test_assert((sock[CHANMAIN] = lc_socket_new(lctx)) != NULL, "lc_socket_new()");
	test_assert((sock[CHANSIDE] = lc_socket_new(lctx)) != NULL, "lc_socket_new()");
	test_assert(!lc_channel_bind(sock[CHANSIDE], chan[CHANSIDE]), "lc_channel_bind() SIDE");
	test_assert(!lc_channel_join(chan[CHANSIDE]), "join notification channel");

	sem_init(&sem_notify, 0, 0);

	pthread_attr_init(&attr);
	pthread_create(&tnotify, &attr, &socket_listen, sock[CHANSIDE]);
	pthread_attr_destroy(&attr);

	/* wait for notify thread to be ready */
	sem_wait(&sem_notify); usleep(50000);

	/* trigger join notification */
	test_assert(!lc_channel_bind(sock[CHANMAIN], chan[CHANMAIN]), "lc_channel_bind() MAIN");
	test_assert(!lc_channel_join(chan[CHANMAIN]), "join main channel");

	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec += waits;
	test_assert(!sem_timedwait(&sem_notify, &timeout), "timeout - waiting for notifications");
	pthread_cancel(tnotify);
	pthread_join(tnotify, NULL);

	sem_destroy(&sem_notify);

	test_assert(msgs == 1, "got %i msgs", msgs);

	mld_stop(mld);
	lc_ctx_free(lctx);
	return fails;
}
