/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/globals.h"
#include "../src/log.h"
#include "../src/mld_pvt.h"
#include <net/if.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <librecast.h>

static int calls;

void watch_callback(mld_watch_t *event, mld_watch_t *orig)
{
	(void)event; (void)orig;
	calls++;
}

// FIXME - split this out into test_misc.c
/* find an interface that supports multicast */
static unsigned get_multicast_if(void)
{
	unsigned ifidx = 0;
	struct ifaddrs *ifa, *ifap;
	test_assert(getifaddrs(&ifa) != -1, "getifaddrs(): %s", strerror(errno));
	for (ifap = ifa; ifap; ifap = ifap->ifa_next) {
		if (!(ifap->ifa_flags & IFF_MULTICAST)) continue;
		if (ifap->ifa_addr == NULL) continue;
		if (ifap->ifa_addr->sa_family != AF_INET6) continue;
		ifidx = if_nametoindex(ifap->ifa_name);
		test_log("found multicast interface %s\n", ifap->ifa_name);
		break;
	}
	freeifaddrs(ifa);
	return ifidx;
}

void do_join(void)
{
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;

	lctx = lc_ctx_new();
	assert(lctx);
	sock = lc_socket_new(lctx);
	assert(sock);
	chan = lc_channel_init(lctx, "ff1e:3:1415:9265:3589:7932:3846:2643", "3832");
	assert(chan);
	test_assert(!lc_channel_bind(sock, chan), "bind channel");
	test_assert(!lc_channel_join(chan), "join channel");
	test_assert(!lc_channel_part(chan), "part channel");
	lc_ctx_free(lctx);
}

int main(void)
{
	mld_t *mld;
	mld_watch_t *watch;
	// FIXME - this needs to be defined somewhere
	struct in6_addr any = IN6ADDR_ANY_INIT;
	any.s6_addr[0] = 0xff;
	any.s6_addr[1] = 0x1e;
	int events = MLD_EVENT_JOIN | MLD_EVENT_PART;
	int flags = 42;
	unsigned int ifx;

	loginit();

	test_name("mld_watch_init() / mld_watch_free()");

	mld = mld_init(1);
	assert(mld);

	ifx = get_multicast_if();
	test_assert(ifx, "get_multicast_if() returned interface idx=%u", ifx);
	
	watch = mld_watch_init(mld, ifx, &any, events, &watch_callback, flags);

	test_assert(watch != NULL, "mld_watch_init() - watch allocated");
	test_assert(watch->mld == mld, "mld ptr set");
	test_assert(watch->grp == &any, "group set");
	test_assert(watch->ifx == ifx, "ifx set");
	test_assert(watch->events == events, "events set");
	test_assert(watch->flags == flags, "flags set");
	test_assert(watch->f == &watch_callback, "callback set");

	// TODO mld_watch_arg - get/set arg in struct

	test_assert(!mld_watch_start(watch), "watch started");

	do_join();

	/* we joined and left a channel - check callback counter */
	test_assert(calls == 1, "callbacks=%i\n", calls);

	test_assert(!mld_watch_stop(watch), "watch stopped");
	// TODO test mld_watch_stop()

	mld_watch_free(watch);

	watch = mld_watch(mld, ifx, &any, events, &watch_callback, flags);
	mld_watch_cancel(watch);

	mld_free(mld);

	return fails;
}
