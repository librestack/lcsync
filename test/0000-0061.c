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
const char *alias = "alias";
unsigned char hash[HASHSIZE];
const size_t blocksz = 512;
const size_t blocks = 13;
const size_t sz = blocksz * blocks;

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

void *thread_send_data(void *arg)
{
	net_send_data(hash, (char *)arg, sz);
	return arg;
}

void saveroothash()
{
	crypto_generichash(hash, HASHSIZE, (unsigned char *)alias, strlen(alias), NULL, 0);
}

void gentestdata(char *srcdata)
{
	/* build source data, make each block different */
	for (size_t i = 0; i < blocks; i++) {
		(srcdata + i * blocksz)[0] = i + 1;
	}
}

int main(void)
{
	loginit();
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
	char *srcdata = calloc(blocks, blocksz);
	gentestdata(srcdata);
	mtree_tree *stree = mtree_create(sz, blocksz);
	mtree_build(stree, srcdata, NULL);

	p = lc_channel_addrinfo(chan);
	sad = (struct sockaddr_in6 *)p->ai_addr;
	grp = &(sad->sin6_addr);

	test_name("net_send_data() - MLD trigger");

	mld_enabled = 1;

	/* start thread to count packets to dst grp */
	pthread_attr_init(&attr);
	pthread_create(&thread_count, &attr, &packet_sniff, grp);
	pthread_create(&thread_serv, &attr, &thread_send_data, srcdata);
	pthread_attr_destroy(&attr);

	// FIXME - mld_notify thinks no one is listening to side channel for grp
	// is this a timing issue, or is something broken?
	// mld_filter_grp_add(): ff3e:ba5b:2812:9174:980b:632b:8f5c:9d81
	// no one listening to ff3e:5513:4ada:6a77:84de:ed91:b4d4:b808 - skipping notification for ff3e:ba5b:2812:9174:980b:632b:8f5c:9d81
	// FIXME join from mld_wait() never gets into filter

	/* wait a moment, ensure no packets received */
	usleep(10000);
	test_assert(pkts == 0, "pkts received=%i", pkts);

	lc_channel_bind(sock, chan);
	for (int i = 0; i < 1; i++) {
		/* join grp, wait, ensure packets received */
		pkts = 0;
		lc_channel_join(chan);
		usleep(10000);
		test_assert(pkts > 0, "%i:pkts received=%i", i, pkts);
		test_log("pkts received (total) = %i\n", tots);

		/* leave group, reset counters, make sure sending has stopped */
		lc_channel_part(chan);
		usleep(100);
		pkts = 0;
		usleep(100);
		test_assert(pkts == 0, "%i: pkts received=%i", i, pkts);
	}

	running = 0;
	net_stop(SIGINT);
	pthread_cancel(thread_count); pthread_cancel(thread_serv);
	pthread_join(thread_count, NULL); pthread_join(thread_serv, NULL);
	free(srcdata);
	lc_channel_part(chan);
	lc_ctx_free(lctx);
	return fails;
}
