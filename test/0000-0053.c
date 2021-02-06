/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld.h"
#include <librecast.h>
#include <netdb.h>

lc_ctx_t *lctx;

/* Multicast Address Record */
struct mld_addr_rec_s {
	uint8_t         type;   /* Record Type */
	uint8_t         auxl;   /* Aux Data Len */
	uint16_t        srcs;   /* Number of Sources */
	struct in6_addr addr;	/* Multicast Address */
} __attribute__((__packed__));

void create_channel(struct in6_addr *addr, char *name)
{
	struct sockaddr_in6 *sad;
	struct addrinfo *ai;
	snprintf(name, 16, "channel 0");
	lc_channel_t *chan = lc_channel_new(lctx, name);
	ai = lc_channel_addrinfo(chan);
	sad = (struct sockaddr_in6 *)ai->ai_addr;
	memcpy(&addr, &(sad->sin6_addr), sizeof (struct in6_addr));
}

int main(void)
{
	const int interfaces = 1;
	char channame[16] = "";
	lctx = lc_ctx_new();
	mld_t *mld;
	mld_addr_rec_t rec = { .type = MODE_IS_EXCLUDE };
	struct in6_addr addr = {0};

	test_name("mld_address_record() - MODE_IS_EXCLUDE");

	create_channel(&addr, channame);
	mld = mld_init(interfaces);

	test_assert(!mld_filter_grp_cmp(mld, 1, &addr), "test filter before adding any records");
	mld_address_record(mld, 0, &rec);
	test_assert(mld_filter_grp_cmp(mld, 0, &addr), "test filter after adding record");

	mld_free(mld);
	lc_ctx_free(lctx);
	return fails;
}
