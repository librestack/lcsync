/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/macro.h"
#include "../src/log.h"
#include "../src/mld.h"
#include <assert.h>
#include <librecast.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

static void channel_part(lc_channel_t *chan)
{
	test_assert(!lc_channel_part(chan), "lc_channel_part()");
	usleep(10000);
}

static void channel_join(lc_channel_t *chan)
{
	test_assert(!lc_channel_join(chan), "lc_channel_join()");
	usleep(10000);
}

int main(void)
{
	//const int limit = 64; /* a modest number for normal test runs */
	const int limit = 1; // FIXME
	mld_t *mld;
	struct in6_addr *addr[limit];
	char channame[16] = "";
	lc_ctx_t *lctx;
	lc_socket_t *sock[limit];
	lc_channel_t *chan[limit];
	int t = 0;

	loginit();

	test_name("MLD filter testing - joining via multicast");
	test_assert((lctx = lc_ctx_new()) != NULL, "lc_ctx_new()");
	test_assert((mld = mld_start(NULL)) != NULL, "mld_start()");
	for (int i = 0; i < limit; i++) {
		snprintf(channame, 16, "channel %i", i);
		sock[i] = lc_socket_new(lctx);
		chan[i] = lc_channel_new(lctx, channame);
		addr[i] = aitoin6(lc_channel_addrinfo(chan[i]));
		assert(sock[i]); assert(chan[i]); assert(addr[i]);

		/* test false before adding */
		test_log("testing '%s' (false)\n", channame);
		test_assert(!mld_filter_grp_cmp(mld, 1, addr[i]),
				"mld_filter_grp_cmp() - before adding (%i)", i);

		/* now join the channel */
		test_log("adding '%s'\n", channame);
		test_assert(!lc_channel_bind(sock[i], chan[i]), "lc_channel_bind()");
		channel_join(chan[i]);

		usleep(10000);

		/* test positive after adding */
		test_log("testing '%s' (true)\n", channame);
		test_assert(mld_filter_grp_cmp(mld, 1, addr[i]),
				"mld_filter_grp_cmp() - added (%i)", i);

		/* and check the timer is set */
		t = mld_filter_timer_get(mld, 1, addr[i]);
		test_assert(t == MLD_TIMEOUT, "%i: timer set to %i", i, t);
	}
	/* test we can remove groups too */
	for (int i = 0; i < limit; i++) {
		test_assert(mld_filter_grp_cmp(mld, 1, addr[i]), "mld_filter_grp_cmp() - before part (%i)", i);
		/* remove group and check again */
		channel_part(chan[i]);
		usleep(1000000);
		test_assert(!mld_filter_grp_cmp(mld, 1, addr[i]), "mld_filter_grp_cmp() - parted (%i)", i);
	}

	mld_stop(mld);
	lc_ctx_free(lctx);
	return fails;
}
