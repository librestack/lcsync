/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld.h"
#include <librecast.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

int main(void)
{
	/* we can add 65535 hashes to our filter of size 16.7 million
	 * with only two false positives using 2 hashes
	 * with 3 hashes we get no false positives
	 * log2(16777216/65535) suggests 8 hashes is optimal
	 * There's no extra cost to this, as we generate enough bits in a single
	 * pass of blake2b => 256 bits / 32 bits = 8 hashes
	 * with this many hashes we no longer get collisions, even with 131072
	 * entries */
	//const int limit = 65535;
	const int limit = 4096; /* a modest number for normal test runs */
	mld_t *mld;
	struct in6_addr *addr[limit];
	char channame[16] = "";
	lc_ctx_t *lctx;
	lc_channel_t *chan;
	test_name("mld_filter_grp_add() / mld_filter_grp_cmp()");
	lctx = lc_ctx_new();
	mld = mld_init(1);
	for (int i = 0; i < limit; i++) {
		snprintf(channame, 16, "channel %i", i);
		chan = lc_channel_new(lctx, channame);
		addr[i] = lc_channel_in6addr(chan);
		/* test false before adding */
		test_log("testing '%s' (false)\n", channame);
		test_assert(!mld_filter_grp_cmp(mld, 0, addr[i]),
				"mld_filter_grp_cmp() - before adding (%i)", i);
		test_log("adding '%s'\n", channame);
		mld_filter_grp_add(mld, 0, addr[i]);
		/* test positive after adding */
		test_log("testing '%s' (true)\n", channame);
		test_assert(mld_filter_grp_cmp(mld, 0, addr[i]),
				"mld_filter_grp_cmp() - added (%i)", i);
		/* ensure timer set */
		usleep(100);
		int t = mld_filter_timer_get(mld, 0, addr[i]);
		test_assert(t == MLD_TIMEOUT, "timer set to %i", t);
	}
	/* test we can remove groups too */
	for (int i = 0; i < limit; i++) {
		test_assert(mld_filter_grp_cmp(mld, 0, addr[i]), "mld_filter_grp_cmp() - true (%i)", i);
		/* remove group and check again */
		mld_filter_grp_del(mld, 0, addr[i]);
		test_assert(!mld_filter_grp_cmp(mld, 0, addr[i]), "mld_filter_grp_cmp() - false (%i)", i);
	}
	/* add same group twice and remove - should have only been added once */
	mld_filter_grp_add(mld, 0, addr[17]);
	test_assert(mld_filter_grp_cmp(mld, 0, addr[17]), "mld_filter_grp_cmp() - add twice");
	mld_filter_grp_add(mld, 0, addr[17]);
	test_assert(mld_filter_grp_cmp(mld, 0, addr[17]), "mld_filter_grp_cmp() - add twice");
	mld_filter_grp_del(mld, 0, addr[17]);
	test_assert(!mld_filter_grp_cmp(mld, 0, addr[17]), "mld_filter_grp_cmp() - remove once");

	mld_free(mld);
	lc_ctx_free(lctx);
	return fails;
}
