/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld.h"
#include <librecast.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

enum {
	CHANMAIN,
	CHANSIDE,
};

int msgs = 0;

void gotmsg(lc_message_t *msg)
{
	(void)msg;
	test_log("got a message\n");
	msgs++;
}

int main(void)
{
	lc_ctx_t *lctx;
	lc_socket_t *sock[2];
	lc_channel_t *chan[2];
	struct in6_addr *addr;
	mld_t *mld;

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
	lc_socket_listen(sock[CHANSIDE], &gotmsg, NULL);

	/* give MLD listener a few cycles to wake up */
	usleep(5000);

	/* trigger join notification */
	test_assert(!lc_channel_bind(sock[CHANMAIN], chan[CHANMAIN]), "lc_channel_bind() MAIN");
	test_assert(!lc_channel_join(chan[CHANMAIN]), "join main channel");

	/* wait a moment, and check for messages */
	usleep(5000);
	test_assert(msgs == 1, "got %i msgs", msgs);

	mld_stop(mld);
	lc_ctx_free(lctx);
	return fails;
}
