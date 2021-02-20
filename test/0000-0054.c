/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld.h"
#include <assert.h>
#include <arpa/inet.h>
#include <librecast.h>
#include <netdb.h>
#include <sys/types.h>
#include <ifaddrs.h>

#define sz_sa6 sizeof(struct sockaddr_in6)

lc_ctx_t *lctx;

/* Multicast Address Record */
struct mld_addr_rec_s {
	uint8_t         type;   /* Record Type */
	uint8_t         auxl;   /* Aux Data Len */
	uint16_t        srcs;   /* Number of Sources */
	struct in6_addr addr;	/* Multicast Address */
	struct in6_addr src[];	/* Source Addresses */
} __attribute__((__packed__));

void create_channel(struct in6_addr *addr, char *name)
{
	struct sockaddr_in6 *sad;
	struct addrinfo *ai;
	snprintf(name, 16, "channel 0");
	lc_channel_t *chan = lc_channel_new(lctx, name);
	ai = lc_channel_addrinfo(chan);
	sad = (struct sockaddr_in6 *)ai->ai_addr;
	memcpy(addr, &(sad->sin6_addr), sizeof (struct in6_addr));
}

int main(void)
{
	const int interfaces = 1;
	char channame[16] = "";
	lctx = lc_ctx_new();
	mld_t *mld;
	mld_addr_rec_t *rec = calloc(1, sizeof(mld_addr_rec_t) + sizeof(struct in6_addr));
	struct in6_addr addr = {0};

	test_name("mld_address_record() - SSM");

	create_channel(&addr, channame);
	mld = mld_init(interfaces);

	test_assert(!mld_filter_grp_cmp(mld, 0, &addr), "test filter before adding any records");

	/* join non-local source (not added) */
	rec->type = MODE_IS_INCLUDE;
	rec->srcs = 1;
	rec->addr.s6_addr[0] = 42;   // not a real address
	rec->addr.s6_addr[1] = 133;  // not a real address
	mld_address_record(mld, 0, rec);
	test_assert(!mld_filter_grp_cmp(mld, 0, &addr), "join non-local source (not added)");

	/* find a local source address to use for SSM */
	struct ifaddrs *ifaddr, *ifa;
	getifaddrs(&ifaddr);
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) continue;
		if (ifa->ifa_addr->sa_family != AF_INET6) continue;
		memcpy(rec->src, ifa->ifa_addr, sizeof(struct in6_addr));
		break;
	}
	memcpy(&rec->addr, &addr, sizeof(struct in6_addr));
	mld_address_record(mld, 0, rec);
	test_assert(mld_filter_grp_cmp(mld, 0, &addr), "join local source (added)");
	freeifaddrs(ifaddr);

	/* join ASM (still valid) */
	memset(rec, 0, sizeof(mld_addr_rec_t) + sizeof(struct in6_addr));
	rec->type = MODE_IS_EXCLUDE;
	mld_address_record(mld, 0, rec); /* EXCLUDE(NULL) => ASM join */
	test_assert(mld_filter_grp_cmp(mld, 0, &addr), "test filter after EXCLUDE(NULL) => join");

	// TODO leave ASM (SSM source still valid)
	// TODO leave SSM (not subscribed)

	free(rec);
	mld_free(mld);
	lc_ctx_free(lctx);
	return fails;
}
