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
	mld_t *mld;
	struct in6_addr *addr;
	struct sockaddr_in6 *sad;
	struct addrinfo *ai;
	lc_ctx_t *lctx;
	lc_channel_t *chan;
	test_name("mld_filter_grp_add()");
	lctx = lc_ctx_new();
	chan = lc_channel_new(lctx, "black");
	ai = lc_channel_addrinfo(chan);
	sad = (struct sockaddr_in6 *)ai->ai_addr;
	addr = &(sad->sin6_addr);
	mld = mld_init(1);
	mld_filter_grp_add(mld, 0, addr);

	/* read back from filter */
	test_log("testing true\n");
	test_assert(mld_filter_grp_cmp(mld, 0, addr), "mld_filter_grp_cmp() - true");

	/* now try reading false address */
	test_log("testing false\n");
	addr->s6_addr[0] = 0;
	test_assert(!mld_filter_grp_cmp(mld, 0, addr), "mld_filter_grp_cmp() - false");

	mld_free(mld);
	lc_ctx_free(lctx);
	return fails;
}
