/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/log.h"
#include "../src/mdex.h"
#include <arpa/inet.h>
#include <librecast/net.h>
#include <string.h>

#define CHANNELS 2

int main(void)
{
	mdex_t *mdex;
	//lc_ctx_t *lctx;
#if 0
	lc_channel_t *chan[CHANNELS];
	struct in6_addr *addr;
	char straddr[INET6_ADDRSTRLEN];
	void *data;
	char testdata[BUFSIZ][CHANNELS];
	size_t testsize[CHANNELS];
	size_t sz;
	char type = 0;
#endif

	loginit();

	test_name("TODO: mdex_put() / mdex_get() / mdex_del()");

	//lctx = lc_ctx_new();

	// TODO all we're doing here is outlining the API at first
	// don't worry about actually storing or retrieving things, just make
	// the calls as though they would work, then we'll add tests and fill in
	// the rest later.
	//
	// What data do we have to pass in?
	// What do we have when we want to retrieve (key = chan)
	// What data do we want back?
	// Does this all fit nicely in some structs?

	// TODO store channel -> file (fpath)
	// TODO store fpath -> mtree, fstat

#if 0
	/* store some channel keys */
	for (int i = 0; i < CHANNELS; i++) {
		/* create channel to use as key */
		chan[i] = lc_channel_random(lctx);
		addr = lc_channel_in6addr(chan[i]);
		inet_ntop(AF_INET6, addr, straddr, INET6_ADDRSTRLEN);
		test_log("created channel %s\n", straddr);

		testsize[i] = snprintf(testdata[i], BUFSIZ, "Librecast %i", i);

		/* store key + value */
		test_assert(mdex_put(addr, testdata[i], strlen(testdata[i]), MDEX_MEM) == 0,
				"return value == 0");
	}

	/* read back channel data */
	for (int i = 0; i < CHANNELS; i++) {
		/* fetch what we just stored */
		addr = lc_channel_in6addr(chan[i]);
		mdex_get(addr, &data, &sz, &type);

		/* check length and data matches */
		test_assert(sz == testsize[i], "sz = %zu, expected %zu", sz, testsize[i]);
		test_assert(!memcmp(testdata[i], data, sz), "%i: check data matches", i);
		test_assert(type == MDEX_MEM, "type MDEX_MEM");
	}
#endif

	//lc_ctx_free(lctx);
	mdex = mdex_init();
	mdex_free(mdex);

	return fails;
}
