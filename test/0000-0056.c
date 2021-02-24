/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld_pvt.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netdb.h>
#include <librecast.h>

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
	struct in6_addr addr = {0};
	lctx = lc_ctx_new();
	mld_t *mld;
	mld_addr_rec_t *mrec = calloc(1, sizeof(mld_addr_rec_t) + sizeof(struct in6_addr));
	struct iovec iov[2] = {0};
	struct icmp6_hdr icmpv6 = {0};
	struct msghdr msg = {0};
	unsigned int iface = if_nametoindex("lo");
	const unsigned ifidx = 0;

	test_name("mld_listen_report() / mld_msg_handle()");

	create_channel(&addr, channame);

	char straddr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &addr, straddr, INET6_ADDRSTRLEN);
	test_log("addr = %s\n", straddr);

	/* pack the ancillary data with interface index */
	struct in6_pktinfo pi = { .ipi6_ifindex = htonl(iface) };
	socklen_t cmsg_len = sizeof(struct cmsghdr) + sizeof(struct in6_pktinfo);
	struct cmsghdr *cmsgh = calloc(1, cmsg_len);
	cmsgh->cmsg_len = cmsg_len;
	cmsgh->cmsg_level = IPPROTO_IPV6;
	cmsgh->cmsg_type = IPV6_PKTINFO;
	memcpy(CMSG_DATA(cmsgh), &pi, sizeof(struct in6_pktinfo));

	mld = mld_init(interfaces);
	mld->ifx[ifidx] = iface; /* this normally happens in mld_start() */

	test_assert(!mld_filter_grp_cmp(mld, iface, &addr), "test filter before adding any records");

	/* create MLD2_LISTEN_REPORT */
	mrec->type = MODE_IS_EXCLUDE;
	icmpv6.icmp6_data16[1] = htons(1);
	memcpy(&mrec->addr, &addr, sizeof(struct in6_addr));
	icmpv6.icmp6_type = MLD2_LISTEN_REPORT;
	iov[0].iov_base = &icmpv6;
	iov[0].iov_len = sizeof icmpv6;
	iov[1].iov_base = mrec;
	iov[1].iov_len = sizeof mrec;
	msg.msg_control = cmsgh;
	msg.msg_controllen = cmsg_len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	mld_listen_report(mld, &msg);
	test_assert(mld_filter_grp_cmp(mld, ifidx, &addr), "test filter after EXCLUDE(NULL) => join");

	mrec->type = MODE_IS_INCLUDE;
	mld_msg_handle(mld, &msg);
	test_assert(!mld_filter_grp_cmp(mld, ifidx, &addr), "test filter after INCLUDE(NULL) => leave");

	// TODO some more tests here - multiple records etc.

	free(cmsgh);
	free(mrec);
	mld_free(mld);
	lc_ctx_free(lctx);
	return fails;
}
