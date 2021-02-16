/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld.h"
#include <librecast.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

int main(void)
{
	const int limit = 1; /* a modest number for normal test runs */
	mld_t *mld;
	struct in6_addr *addr[limit];
	struct sockaddr_in6 *sad;
	struct addrinfo *ai;
	char channame[16] = "";
	int t;
	unsigned int iface = 0;
	lc_ctx_t *lctx;
	lc_channel_t *chan;
	test_name("mld_filter_grp_add() / mld_filter_grp_cmp()");
	lctx = lc_ctx_new();

	mld = mld_start(NULL);
	for (int i = 0; i < limit; i++) {
		snprintf(channame, 16, "channel %i", i);
		chan = lc_channel_new(lctx, channame);
		ai = lc_channel_addrinfo(chan);
		sad = (struct sockaddr_in6 *)ai->ai_addr;
		addr[i] = &(sad->sin6_addr);
		/* test false before adding */
		test_log("testing '%s' (false)\n", channame);
		test_assert(!mld_filter_grp_cmp(mld, iface, addr[i]),
				"mld_filter_grp_cmp() - before adding (%i)", i);
		test_log("adding '%s'\n", channame);
		mld_filter_grp_add(mld, iface, addr[i]);
		/* test positive after adding */
		test_log("testing '%s' (true)\n", channame);
		test_assert(mld_filter_grp_cmp(mld, iface, addr[i]),
				"mld_filter_grp_cmp() - added (%i)", i);
	}

	/* timer ticks down */
	t = mld_filter_timer_get(mld, iface, addr[0]);
	test_assert(t > MLD_TIMEOUT - 1, "timer set %i", t);
	usleep(1500000);
	t = mld_filter_timer_get(mld, iface, addr[0]);
	test_assert(t < MLD_TIMEOUT, "timer ticking %i", t);

	mld_stop(mld);
	lc_ctx_free(lctx);
	return fails;
}
