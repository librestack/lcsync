/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld.h"
#include "../src/job.h"
#include <netinet/icmp6.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <librecast.h>
#include <unistd.h>

lc_ctx_t *lctx;

/* Multicast Address Record */
struct mld_addr_rec_s {
	uint8_t         type;   /* Record Type */
	uint8_t         auxl;   /* Aux Data Len */
	uint16_t        srcs;   /* Number of Sources */
	struct in6_addr addr;   /* Multicast Address */
	struct in6_addr src[];  /* Source Addresses */
} __attribute__((__packed__));

struct mld_filter_s {
	vec_t   grp[BLOOM_VECTORS];
	vec_t   t[BLOOM_VECTORS];
};

struct mld_s {
	int sock;
	job_queue_t *timerq;
	int len;
	mld_filter_t filter[];
};

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

void *listen_thread(void *arg)
{
	mld_t *mld = (mld_t *)arg;
	test_assert(mld_listen(mld) == 0, "mld_listen() - have socket");
	return arg;
}

int main(void)
{
	char channame[16] = "";
	struct in6_addr addr = {0};
	lctx = lc_ctx_new();
	mld_addr_rec_t *mrec = calloc(1, sizeof(mld_addr_rec_t) + sizeof(struct in6_addr));
	struct iovec iov[2] = {0};
	struct icmp6_hdr icmpv6 = {0};
	struct msghdr msg = {0};
	const int interfaces = 1;
	int rc;
	int socks[2];
	mld_t *mld;
	pthread_t thread;
	pthread_attr_t attr;

	test_name("mld_listen()");

	mld = mld_init(interfaces);
	test_assert(mld_listen(mld) == -1, "mld_listen() - return -1 when socket not initialized");

	rc =socketpair(AF_UNIX, SOCK_RAW, 0, socks);
	if (rc) {
		perror("socketpair()");
	}
	test_assert(rc == 0, "socketpair()");
	mld->sock = socks[1];

	pthread_attr_init(&attr);
	pthread_attr_destroy(&attr);
	pthread_create(&thread, &attr, &listen_thread, mld);

	create_channel(&addr, channame);
	test_assert(!mld_filter_grp_cmp(mld, 0, &addr), "test filter before adding any records");

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

	rc = sendmsg(socks[0], &msg, 0);
	if (rc == -1) perror("sendmsg()");
	usleep(1000);
	test_assert(mld_filter_grp_cmp(mld, 0, &addr), "test filter after EXCLUDE(NULL) => join");

	mrec->type = MODE_IS_INCLUDE;
	rc = sendmsg(socks[0], &msg, 0);
	if (rc == -1) perror("sendmsg()");
	usleep(1000);
	test_assert(!mld_filter_grp_cmp(mld, 0, &addr), "test filter after INCLUDE(NULL) => leave");

	pthread_cancel(thread);
	pthread_join(thread, NULL);
	free(mrec);
	lc_ctx_free(lctx);
	mld_free(mld);
	return fails;
}
