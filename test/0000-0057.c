/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld_pvt.h"
#include "../src/job.h"
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <librecast.h>
#include <unistd.h>

lc_ctx_t *lctx;

void create_channel(struct in6_addr *addr, char *name)
{
	snprintf(name, 16, "channel 0");
	lc_channel_t *chan = lc_channel_new(lctx, name);
	memcpy(addr, lc_channel_in6addr(chan), sizeof (struct in6_addr));
}

void *listen_thread(void *arg)
{
	test_log("%()\n", __func__);
	mld_t *mld = (mld_t *)arg;
	test_assert(mld_listen(mld) == 0, "mld_listen() - have socket");
	return arg;
}

int main(void)
{
	char channame[16] = "";
	struct in6_addr addr = {0};
	mld_addr_rec_t *mrec;
	struct iovec iov[2] = {0};
	struct icmp6_hdr icmpv6 = {0};
	struct msghdr msg = {0};
	const int interfaces = 1;
	int rc;
	int sock[2];
	mld_t *mld;
	pthread_t thread;
	pthread_attr_t attr;
	const unsigned ifidx = 0;

	return test_skip("mld_listen()");

	lctx = lc_ctx_new();
	mrec = calloc(1, sizeof(mld_addr_rec_t) + sizeof(struct in6_addr));

	//iface = if_nametoindex("lo");
	//test_assert(iface, "iface = %u: %s", iface, strerror(errno));

	rc =socketpair(AF_UNIX, SOCK_RAW, 0, sock);
	if (rc) {
		perror("socketpair()");
	}
	test_assert(rc == 0, "socketpair()");
	mld = mld_init(interfaces);
	mld->ifx[ifidx] = sock[1]; /* this normally happens in mld_start() */

	test_log("iface == %u\n", sock[1]);

	test_assert(mld_listen(mld) == -1, "mld_listen() - return -1 when socket not initialized");

	mld->sock = sock[1];

	pthread_attr_init(&attr);
	pthread_attr_destroy(&attr);
	pthread_create(&thread, &attr, &listen_thread, mld);

	create_channel(&addr, channame);
	test_assert(!mld_filter_grp_cmp(mld, ifidx, &addr), "test filter before adding any records");

	/* create MLD2_LISTEN_REPORT */
	mrec->type = MODE_IS_EXCLUDE;
	icmpv6.icmp6_data16[1] = htons(1);
	memcpy(&mrec->addr, &addr, sizeof(struct in6_addr));
	icmpv6.icmp6_type = MLD2_LISTEN_REPORT;
	iov[0].iov_base = &icmpv6;
	iov[0].iov_len = sizeof icmpv6;
	iov[1].iov_base = mrec;
	iov[1].iov_len = sizeof mrec;
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	rc = sendmsg(sock[0], &msg, 0);
	if (rc == -1) perror("sendmsg()");
	// FIXME this works with mld_listen_report, but AF_UNIX sockets don't
	// support ancillary data, so we have no way to recover the interface
	//mld_listen_report(mld, &msg);
	usleep(1000);
	test_assert(mld_filter_grp_cmp(mld, ifidx, &addr), "test filter after EXCLUDE(NULL) => join");

	mrec->type = MODE_IS_INCLUDE;
	rc = sendmsg(sock[0], &msg, 0);
	if (rc == -1) perror("sendmsg()");
	// FIXME - see above
	//mld_listen_report(mld, &msg);
	usleep(1000);
	test_assert(!mld_filter_grp_cmp(mld, ifidx, &addr), "test filter after INCLUDE(NULL) => leave");

	pthread_cancel(thread);
	pthread_join(thread, NULL);
	close(sock[0]);
	close(sock[1]);
	free(mrec);
	lc_ctx_free(lctx);
	mld_free(mld);
	return fails;
}
