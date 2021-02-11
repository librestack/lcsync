/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld.h"
#include <librecast.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

// FIXME - temp
lc_channel_t * lc_channel_sidehash(lc_ctx_t *lctx, struct in6_addr *addr, int band);

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
	struct addrinfo *ai;
	struct sockaddr_in6 *sad;
	struct in6_addr *addr;
	mld_t *mld;

	test_name("mld_notify()");
	lctx = lc_ctx_new();
	chan[CHANMAIN] = lc_channel_new(lctx, "Is it lunchtime yet?");
	ai = lc_channel_addrinfo(chan[CHANMAIN]);
	sad = (struct sockaddr_in6 *)ai->ai_addr;
	addr = &(sad->sin6_addr);
	mld = mld_start(NULL);
	test_assert(mld != NULL, "mld_start()");
	
	/* join side channel for MLD events */
	/* TODO an API call for side channels would be nice */
	chan[CHANSIDE] = lc_channel_sidehash(lctx, addr, MLD_EVENT_ALL);

	/* join notification channel and wait for notify msg */
	test_assert((sock[0] = lc_socket_new(lctx)) != NULL, "lc_socket_new()");
	test_assert((sock[1] = lc_socket_new(lctx)) != NULL, "lc_socket_new()");
	test_assert(!lc_channel_bind(sock[0], chan[CHANSIDE]), "lc_channel_bind() SIDE");
	test_assert(!lc_channel_join(chan[CHANSIDE]), "join notification channel");
	lc_socket_listen(sock[0], &gotmsg, NULL);

	/* give MLD listener a few cycles to wake up */
	usleep(5000);

	/* trigger join notification */
	test_assert(!lc_channel_bind(sock[1], chan[CHANMAIN]), "lc_channel_bind() MAIN");
	test_assert(!lc_channel_join(chan[CHANMAIN]), "join main channel");

	/* wait a moment, and check for messages */
	usleep(5000);
	test_assert(msgs == 1, "got %i msgs", msgs);

	mld_stop(mld);
	lc_ctx_free(lctx);
	return fails;
}
