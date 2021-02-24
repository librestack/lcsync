/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld_pvt.h"
#include <librecast.h>
#include <netdb.h>

lc_ctx_t *lctx;

void create_channel(struct in6_addr *addr, char *name)
{
	snprintf(name, 16, "channel 0");
	lc_channel_t *chan = lc_channel_new(lctx, name);
	memcpy(addr, lc_channel_in6addr(chan), sizeof (struct in6_addr));
}

int main(void)
{
	const int interfaces = 1;
	char channame[16] = "";
	lctx = lc_ctx_new();
	mld_t *mld;
	mld_addr_rec_t rec = {0};

	test_name("mld_address_record() - ASM");

	create_channel(&rec.addr, channame);
	mld = mld_init(interfaces);

	test_assert(!mld_filter_grp_cmp(mld, 0, &rec.addr), "test filter before adding any records");

	rec.type = MODE_IS_EXCLUDE;
	mld_address_record(mld, 0, &rec); /* EXCLUDE(NULL) => ASM join */
	test_assert(mld_filter_grp_cmp(mld, 0, &rec.addr), "test filter after EXCLUDE(NULL) => join");

	rec.type = MODE_IS_INCLUDE;
	mld_address_record(mld, 0, &rec); /* INCLUDE(NULL) => ASM leave */
	test_assert(!mld_filter_grp_cmp(mld, 0, &rec.addr), "test filter after INCLUDE(NULL) => leave");

	mld_free(mld);
	lc_ctx_free(lctx);
	return fails;
}
