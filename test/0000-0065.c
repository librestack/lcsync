/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/globals.h"
#include "../src/log.h"
#include "../src/mld_pvt.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <librecast.h>
#include <unistd.h>

static int calls;

void watch_callback(mld_watch_t *event, mld_watch_t *orig)
{
	calls++;
	test_assert(event != NULL, "event allocated");
	test_assert(event != orig, "event new");
	test_assert(event->ifx > 0, "event ifx set=%u", event->ifx);
	test_assert(event->grp != NULL, "event grp set");
}

// FIXME - split this out into test_misc.c
/* find an interface that supports multicast */
static unsigned get_multicast_ifx(void)
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

void do_join()
{
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;

	lctx = lc_ctx_new();
	assert(lctx);
	sock = lc_socket_new(lctx);
	assert(sock);
	struct sockaddr_in6 sa = {
		.sin6_port = htons(3279),
	};
	sa.sin6_addr.s6_addr[0] = 0xff;
	sa.sin6_addr.s6_addr[1] = 0x1e;
	sa.sin6_addr.s6_addr[2] = 0x03;
	sa.sin6_addr.s6_addr[3] = 0x14;
	sa.sin6_addr.s6_addr[4] = 0x15;
	sa.sin6_addr.s6_addr[5] = 0x92;
	sa.sin6_addr.s6_addr[6] = 0x65;
	sa.sin6_addr.s6_addr[7] = 0x35;
	sa.sin6_addr.s6_addr[8] = 0x89;
	sa.sin6_addr.s6_addr[9] = 0x79;
	sa.sin6_addr.s6_addr[10] = 0x32;
	sa.sin6_addr.s6_addr[11] = 0x38;
	sa.sin6_addr.s6_addr[12] = 0x46;
	sa.sin6_addr.s6_addr[13] = 0x26;
	sa.sin6_addr.s6_addr[14] = 0x43;
	sa.sin6_addr.s6_addr[15] = 0x38;
	chan = lc_channel_init(lctx, &sa);
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
	int events = MLD_EVENT_JOIN | MLD_EVENT_PART;
	int flags = 42;
	unsigned int ifx;

	loginit();

	test_name("mld_watch_init() / mld_watch_free()");

	mld = mld_start(NULL);
	assert(mld);

	ifx = get_multicast_ifx();
	test_assert(ifx, "get_multicast_if() returned interface idx=%u", ifx);
	
	char *arg = malloc(1024);
	watch = mld_watch_init(mld, ifx, NULL, events, &watch_callback, arg, flags);

	test_assert(watch != NULL, "mld_watch_init() - watch allocated");
	test_assert(watch->mld == mld, "mld ptr set");
	test_assert(watch->grp == NULL, "group set");
	test_assert(watch->ifx == ifx, "ifx set");
	test_assert(watch->events == events, "events set");
	test_assert(watch->flags == flags, "flags set");
	test_assert(watch->f == &watch_callback, "callback set");
	test_assert(watch->arg == arg, "arg set");

	test_assert(!mld_watch_start(watch), "watch started");

	usleep(10000);

	do_join();

	usleep(10000);

	/* we joined and left a channel - check callback counter */
	test_assert(calls > 0, "callbacks=%i", calls);

	test_assert(!mld_watch_stop(watch), "watch stopped");

	mld_watch_free(watch);
	free(arg);

	watch = mld_watch(mld, ifx, NULL, events, &watch_callback, NULL, flags);
	mld_watch_cancel(watch);

	mld_stop(mld);

	return fails;
}
