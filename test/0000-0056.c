/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld_pvt.h"
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netdb.h>
#include <librecast.h>

lc_ctx_t *lctx;

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
	struct in6_addr addr = {0};
	lctx = lc_ctx_new();
	mld_t *mld;
	mld_addr_rec_t *mrec = calloc(1, sizeof(mld_addr_rec_t) + sizeof(struct in6_addr));
	struct iovec iov[2] = {0};
	struct icmp6_hdr icmpv6 = {0};
	struct msghdr msg = {0};
	unsigned int iface = if_nametoindex("lo");

	test_name("mld_listen_report() / mld_msg_handle()");

	// FIXME - calling mld_listen_report() without iface hits assert() in
	// interface_index()


	create_channel(&addr, channame);
	mld = mld_init(interfaces);

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
	//msg.msg_name = buf_name;
	//msg.msg_namelen = IPV6_BYTES;
	//msg.msg_control = buf_ctrl;
	//msg.msg_controllen = BUFSIZE;
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	//msg.msg_flags = 0;

	mld_listen_report(mld, &msg);
	test_assert(mld_filter_grp_cmp(mld, iface, &addr), "test filter after EXCLUDE(NULL) => join");

	mrec->type = MODE_IS_INCLUDE;
	mld_msg_handle(mld, &msg);
	test_assert(!mld_filter_grp_cmp(mld, iface, &addr), "test filter after INCLUDE(NULL) => leave");

	// TODO some more tests here - multiple records etc.
	
	free(mrec);
	mld_free(mld);
	lc_ctx_free(lctx);
	return fails;
}
