/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

/* watch multicast traffic to ensure no packets sent *until* MLD join */

#include "test.h"
#include "../src/globals.h"
#include "../src/log.h"
#include "../src/mld.h"
#include "../src/job.h"
#include "../src/mtree.h"
#include "../src/net.h"
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

static int pkts = 0; /* data packets to multicast group */
static int tots = 0; /* data packets intercepted */
static int running = 1;

/* sniff multicast packets for grp, without joining group */
void *packet_sniff(void *arg)
{
	char msg_name[16];
	char strsrc[INET6_ADDRSTRLEN];
	char strdst[INET6_ADDRSTRLEN];
	struct hdr_v6 {
		uint64_t ignore;
		struct in6_addr src;
		struct in6_addr dst;
	} hdr;
	struct iovec iov = { .iov_len = sizeof hdr, .iov_base = &hdr };
	struct msghdr msgh = {
		.msg_name = msg_name,
		.msg_namelen = 16,
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	ssize_t byt;
	struct in6_addr *grp = (struct in6_addr *)arg;
	//int sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IPV6));
	int sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	test_assert(sock != -1, "socket(): %s", strerror(errno));

	inet_ntop(AF_INET6, grp, strsrc, INET6_ADDRSTRLEN);
	test_log("snoop group: %s\n", strsrc);
	running = sock;
	while (running) {
		test_log("I will wait here until the good packets come to me\n");
		byt = recvmsg(sock, &msgh, 0);
		test_assert(byt != -1, "recvmsg(): %s", strerror(errno));
		test_log("%zi bytes received\n", byt);
		inet_ntop(AF_INET6, &hdr.src, strsrc, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &hdr.dst, strdst, INET6_ADDRSTRLEN);
		test_log("src: %s\n", strsrc);
		test_log("dst: %s\n", strdst);
		if (!memcmp(grp, &hdr.dst, sizeof (struct in6_addr))) pkts++;
		tots++;
	}
	pthread_exit(arg);
	return arg;
}

int main(void)
{
	const size_t sz = 4242;
	const size_t blocksz = 512;
	unsigned char hash[HASHSIZE];
	char channame[] = "somechan";
	hash_generic(hash, HASHSIZE, (unsigned char *)channame, strlen(channame));
	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_channel_t *chan = lc_channel_nnew(lctx, hash, HASHSIZE);
	pthread_t thread_count, thread_serv;
	pthread_attr_t attr = {0};
	struct addrinfo *p;
	struct sockaddr_in6 *sad;
	struct in6_addr *grp;
	net_data_t *data = calloc(1, sizeof(net_data_t) + sizeof(struct iovec));
	char *srcdata = calloc(1, sz);
	mtree_tree *stree = mtree_create(sz, blocksz);
	mtree_build(stree, srcdata, NULL);

	p = lc_channel_addrinfo(chan);
	sad = (struct sockaddr_in6 *)p->ai_addr;
	grp = &(sad->sin6_addr);

	data->alias = hash;
	data->hash = hash;
	data->iov[0].iov_base = stree;
	data->iov[0].iov_len = sz;
	data->byt = sz;
	data->mld = mld_start();

	loginit();
	test_name("net_job_send_tree() - MLD trigger");

	mld_enabled = 1;

	/* start thread to count packets to dst grp */
	pthread_attr_init(&attr);
	pthread_create(&thread_count, &attr, &packet_sniff, grp);
	pthread_create(&thread_serv, &attr, &net_job_send_tree, data);
	pthread_attr_destroy(&attr);

	/* wait a moment, ensure no packets received */
	usleep(10000);
	test_assert(pkts == 0, "pkts received=%i", pkts);

	lc_channel_bind(sock, chan);
	for (int i = 0; i < 8; i++) {
		/* join grp, wait, ensure packets received */
		pkts = 0;
		lc_channel_join(chan);
		usleep(100000);
		test_assert(pkts > 0, "%i:pkts received=%i", i, pkts);
		test_log("pkts received (total) = %i\n", tots);

		/* leave group, reset counters, make sure sending has stopped */
		lc_channel_part(chan);
		usleep(100000);
		pkts = 0;
		usleep(100000);
		test_assert(pkts == 0, "%i: pkts received=%i", i, pkts);
	}

	running = 0;
	net_stop(SIGINT);
	pthread_cancel(thread_count); pthread_cancel(thread_serv);
	pthread_join(thread_count, NULL); pthread_join(thread_serv, NULL);
	free(data->iov[0].iov_base);
	mld_stop(data->mld);
	free(data);
	lc_channel_part(chan);
	lc_ctx_free(lctx);
	return fails;
}
