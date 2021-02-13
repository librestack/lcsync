/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

/* watch multicast traffic to ensure no packets sent *until* MLD join */

#include "test.h"
#include "../src/globals.h"
#include "../src/log.h"
#include "../src/mld.h"
#include "../src/job.h"
#include "../src/macro.h"
#include "../src/mtree.h"
#include "../src/net.h"
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <librecast.h>
#include <netdb.h>
#include <unistd.h>

// FIXME - temp
lc_channel_t * lc_channel_sidehash(lc_ctx_t *lctx, struct in6_addr *addr, int band);

static const size_t sz = 4242;
static const size_t blocksz = 512;
static int pkts = 0; /* data packets to multicast group */
static int tots = 0; /* data packets intercepted */
static int running = 1;
static lc_ctx_t *lctx;
static lc_socket_t *sock;
static lc_channel_t *chan, *chanside;

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

void pack_payload(net_data_t *data, unsigned char *hash, mtree_tree *stree)
{
	data->alias = hash;
	data->hash = hash;
	data->iov[0].iov_base = stree;
	data->iov[0].iov_len = sz;
	data->byt = sz;
	data->mld = mld_start(NULL);
}

struct in6_addr * prepare_multicast_channel(unsigned char *hash, unsigned char *channame, size_t len)
{
	hash_generic(hash, HASHSIZE, channame, len);
	lctx = lc_ctx_new();
	test_assert(lctx != NULL, "lc_ctx_new()");
	sock = lc_socket_new(lctx);
	test_assert(sock != NULL, "lc_socket_new()");
	chan = lc_channel_nnew(lctx, hash, HASHSIZE);
	test_assert(chan != NULL, "lc_channel_nnew()");
	return aitoin6(lc_channel_addrinfo(chan));
}

void build_src_and_tree(net_data_t **data, mtree_tree **stree)
{
	char *srcdata;
	*data = calloc(1, sizeof(net_data_t) + sizeof(struct iovec));
	test_assert(*data != NULL, "calloc(data)");
	srcdata = calloc(1, sz);
	test_assert(srcdata != NULL, "calloc(srcdata)");
	*stree = mtree_create(sz, blocksz);
	mtree_build(*stree, srcdata, NULL);
}

void do_test_init(void)
{
	loginit();
	test_name("net_job_send_tree() - MLD trigger");
	mld_enabled = 1;
}

int main(void)
{
	unsigned char hash[HASHSIZE];
	char channame[] = "somechan";
	pthread_t thread_count, thread_serv;
	pthread_attr_t attr = {0};
	struct in6_addr *grp, *grpn;
	mtree_tree *stree;
	net_data_t *data;

	do_test_init();
	build_src_and_tree(&data, &stree);
	grp = prepare_multicast_channel(hash, (unsigned char *)channame, strlen(channame));
	pack_payload(data, hash, stree);

	/* get side channel for grp to monitor join events */
	chanside = lc_channel_sidehash(lctx, grp, MLD_EVENT_ALL);
	grpn = aitoin6(lc_channel_addrinfo(chanside));

	test_assert(!mld_filter_grp_cmp(data->mld, 0, grpn), "filter doesn't contain notify group (0)");

	/* start thread to count packets to dst grp */
	pthread_attr_init(&attr);
	pthread_create(&thread_count, &attr, &packet_sniff, grp);
	pthread_create(&thread_serv, &attr, &net_job_send_tree, data);
	pthread_attr_destroy(&attr);

	/* wait a moment, ensure no packets received before join */
	usleep(10000);
	test_assert(pkts == 0, "pkts received=%i (before join)", pkts);

	/* check filter for notification side-channel */
	test_assert(mld_filter_grp_cmp(data->mld, 0, grpn), "filter contains notify group (1)");

	/* join grp, wait, ensure packets received */
	lc_channel_bind(sock, chan);
	test_assert(mld_filter_grp_cmp(data->mld, 0, grpn), "filter contains notify group (2)");
	lc_channel_join(chan);
	test_assert(mld_filter_grp_cmp(data->mld, 0, grpn), "filter contains notify group (2b)");
	usleep(10000);
	test_assert(pkts > 0, "pkts received=%i (joined)", pkts);
	test_log("pkts received (total) = %i\n", tots);

	//test_assert(mld_filter_grp_cmp(data->mld, 0, grpn), "filter contains notify group (3)");

	/* leave group, reset counters, make sure sending has stopped */
	test_assert(!lc_channel_part(chan), "lc_channel_part()");

	usleep(100000);
	pkts = 0;
	usleep(100000);
	test_assert(pkts == 0, "pkts received=%i (parted)", pkts);

	running = 0;
	net_stop(SIGINT);
	pthread_cancel(thread_count); pthread_cancel(thread_serv);
	pthread_join(thread_count, NULL); pthread_join(thread_serv, NULL);
	free(data->iov[0].iov_base);
	mld_stop(data->mld);
	free(data);
	lc_ctx_free(lctx);
	return fails;
}
