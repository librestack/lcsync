/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/log.h"
#include "../src/mdex.h"
#include <librecast/net.h>

int main(void)
{
	lc_ctx_t *lctx;
	lc_channel_t *chan;
	struct in6_addr *addr;
	void *data = NULL;
	size_t sz = 0;
	int type = 0;

	loginit();

	test_name("mdex_put() / mdex_get() / mdex_del()");

	lctx = lc_ctx_new();
	chan = lc_channel_random(lctx);
	addr = lc_channel_in6addr(chan);

	mdex_put(addr, data, sz, type);

	lc_ctx_free(lctx);

	return fails;
}
