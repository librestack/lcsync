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
	struct in6_addr *addr;
	char channame[] = "#librecast";
	lc_ctx_t *lctx;
	lc_channel_t *chan;
	int t;

	test_name("mld_timer_set()");

	lctx = lc_ctx_new();
	mld = mld_init(1);
	chan = lc_channel_new(lctx, channame);
	addr = lc_channel_in6addr(chan);

	/* test false before adding */
	test_assert(!mld_filter_grp_cmp(mld, 0, addr),
			"mld_filter_grp_cmp() - before adding)");

	test_log("adding '%s'\n", channame);
	mld_filter_grp_add(mld, 0, addr);

	/* test positive after adding */
	test_log("testing '%s' (true)\n", channame);
	test_assert(mld_filter_grp_cmp(mld, 0, addr),
			"mld_filter_grp_cmp() - added");

	/* ensure timer set */
	usleep(100);
	t = mld_filter_timer_get(mld, 0, addr);
	test_assert(t == MLD_TIMEOUT, "timer set to %i", t);

	/* set timer to something else */
	mld_filter_timer_set(mld, 0, addr, 42);
	usleep(100);
	t = mld_filter_timer_get(mld, 0, addr);
	test_assert(t == 42, "timer set to %i", t);

	mld_free(mld);
	lc_ctx_free(lctx);
	return fails;
}
