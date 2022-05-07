/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netdb.h>

#define sz_sa6 sizeof(struct sockaddr_in6)

int main(void)
{
	struct in6_addr addr = {0};
	struct ifaddrs *ifaddr, *ifa;
	char host[INET6_ADDRSTRLEN];
	test_name("mld_thatsme()");
	test_assert(!mld_thatsme(&addr), "mld_thatsme() - NULL");

	getifaddrs(&ifaddr);
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) continue;
		if (ifa->ifa_addr->sa_family != AF_INET6) continue;
		getnameinfo(ifa->ifa_addr, sz_sa6, host, INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST);
		memcpy(&addr, ifa->ifa_addr, sizeof(struct in6_addr));
		test_assert(mld_thatsme(&addr) == -1, "mld_thatsme() - %s", host);
	}
	freeifaddrs(ifaddr);

	return fails;
}
