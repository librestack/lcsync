/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld_pvt.h"
#include <librecast.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>


int main(void)
{
	mld_t *mld;
	struct in6_addr *addr[2];
	char channame[][16] = { "#librecast", "#multicast" };
	lc_ctx_t *lctx;
	lc_channel_t *chan[2];
	int t;

	test_name("MLD - test timer expiry");

	lctx = lc_ctx_new();
	mld = mld_start(NULL);
	chan[0] = lc_channel_new(lctx, channame[0]);
	chan[1] = lc_channel_new(lctx, channame[1]);
	addr[0] = aitoin6(lc_channel_addrinfo(chan[0]));
	addr[1] = aitoin6(lc_channel_addrinfo(chan[1]));

	test_log("adding '%s'\n", channame[0]);
	mld_filter_grp_add(mld, 0, addr[0]);
	mld_filter_grp_add(mld, 0, addr[1]);

	/* test positive after adding */
	test_log("testing '%s' (true)\n", channame[0]);
	test_assert(mld_filter_grp_cmp(mld, 0, addr[0]), "mld_filter_grp_cmp(0) - added");
	test_assert(mld_filter_grp_cmp(mld, 0, addr[1]), "mld_filter_grp_cmp(1) - added");

	/* set timer to expire in 1s */
	mld_filter_timer_set(mld, 0, addr[0], 1);
	usleep(100);
	t = mld_filter_timer_get(mld, 0, addr[0]);
	test_assert(t == 1, "timer set to %i == 1", t);

	/* ensure timer expires */
	usleep(1200000);
	t = mld_filter_timer_get(mld, 0, addr[0]);
	test_assert(t == 0, "timer expired %i == 0", t);

	/* ensure address check fails post-expiry */
	usleep(100);
	test_assert(!mld_filter_grp_cmp(mld, 0, addr[0]), "mld_filter_grp_cmp(0) - expired");
	test_assert(mld_filter_grp_cmp(mld, 0, addr[1]), "mld_filter_grp_cmp(1) - 2nd address ok");
	t = mld_filter_timer_get(mld, 0, addr[1]);
	test_assert(t > 1, "timer set to %i", t);

	mld_stop(mld);
	lc_ctx_free(lctx);
	return fails;
}
