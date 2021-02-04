/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld.h"
#include <librecast.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int main(void)
{
	const int limit = 32;
	mld_t *mld;
	struct in6_addr *addr[limit];
	struct sockaddr_in6 *sad;
	struct addrinfo *ai;
	char channame[16] = "";
	lc_ctx_t *lctx;
	lc_channel_t *chan;
	test_name("mld_filter_grp_add() / mld_filter_grp_cmp()");
	lctx = lc_ctx_new();

	mld = mld_init(1);
	// FIXME - multiple channels not working
	for (int i = 0; i < limit; i++) {
		snprintf(channame, 16, "channel %i", i);
		chan = lc_channel_new(lctx, channame);
		ai = lc_channel_addrinfo(chan);
		sad = (struct sockaddr_in6 *)ai->ai_addr;
		addr[i] = &(sad->sin6_addr);
		/* test false before adding */
		test_log("testing '%s' (false)\n", channame);
		test_assert(!mld_filter_grp_cmp(mld, 0, addr[i]), "mld_filter_grp_cmp() - false (%i)", i);
		test_log("adding '%s'\n", channame);
		mld_filter_grp_add(mld, 0, addr[i]);
		/* test positive after adding */
		test_log("testing '%s' (true)\n", channame);
		test_assert(mld_filter_grp_cmp(mld, 0, addr[i]), "mld_filter_grp_cmp() - true (%i)", i);
	}

	/* TODO test timer */

	/* TODO timer tick with SIGTIMER ? */

	// TODO work through state machine
	//
	// TODO test cmp with source address

	mld_free(mld);
	lc_ctx_free(lctx);
	return fails;
}
