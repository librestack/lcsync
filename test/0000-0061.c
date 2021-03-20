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
#include <semaphore.h>

static sem_t sem;
static volatile int pkts = 0; /* data packets to multicast group */
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
	sem_post(&sem);
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
	sem_post(&sem);
	net_send_data(hash, (char *)arg, sz);
	return arg;
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
	char channame[] = "and now for something completely different...";
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;
	pthread_t thread_count, thread_serv;
	pthread_attr_t attr = {0};
	char *srcdata = calloc(blocks, blocksz);

	loginit();
	test_name("net_send_data() - MLD trigger");

	/* MLD trigger testing with net_send_data()
	 *
	 * Create two threads:
	 * 1) one which listens on a raw socket and counts multicast packets WITHOUT
	 *    joining that channel
	 * 2) a net_send_data() thread, which only sends data when channel is
	 *    JOINed.
	 *
	 * Once threads are ready, we wait a bit and check that no packets have been
	 * received prematurely. Data MUST NOT be sent until we do a PIM join.
	 *
	 * Then, perform a join, wait a bit, and check that data packets were
	 * received.
	 *
	 * Leave the channel, wait, reset the packet counter, wait some more,
	 * and ensure data packets have stopped being sent.
	 */

	hash_generic(hash, HASHSIZE, (unsigned char *)channame, strlen(channame));

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	chan = lc_channel_nnew(lctx, hash, HASHSIZE);

	gentestdata(srcdata);
	mtree_tree *stree = mtree_create(sz, blocksz);
	mtree_build(stree, srcdata, NULL);

	sem_init(&sem, 0, 0);
	mld_enabled = 1;

	/* start thread to count packets to dst grp */
	pthread_attr_init(&attr);
	pthread_create(&thread_count, &attr, &packet_sniff, lc_channel_in6addr(chan));
	pthread_create(&thread_serv, &attr, &thread_send_data, srcdata);
	pthread_attr_destroy(&attr);

	/* make sure threads are ready */
	sem_wait(&sem); sem_wait(&sem); sem_destroy(&sem);

	/* wait a moment, ensure no packets received before MLD join */
	sleep(1);
	test_assert(pkts == 0, "pkts received=%i (before join)", pkts);

	lc_channel_bind(sock, chan);

	for (int i = 0; i < 2; i++) {
		//usleep(10000);

		/* join grp, wait, ensure packets received */

		DEBUG("JOINING");
		lc_channel_join(chan);

		DEBUG("WAITING");
		usleep(1000000);

		DEBUG("TESTING");

		// FIXME - sometimes fails, sometimes (rarely) test segfaults
		test_assert(pkts > 0, "%i:pkts received=%i (joined)", i, pkts); // FIXME
		test_log("pkts received (total) = %i\n", tots);

		/* leave group, reset counters, make sure sending has stopped */
		DEBUG("PARTING");
		lc_channel_part(chan);

		DEBUG("WAITING");
		usleep(10000); /* wait before resetting counter after parting channel */

		DEBUG("RESET COUNTER");
		pkts = 0;

		usleep(10000); /* counter reset, wait to see what arrives */

		DEBUG("TESTING");
		test_assert(pkts == 0, "%i: pkts received=%i (parted)", i, pkts);
	}

	running = 0;
	net_stop(SIGINT);
	pthread_cancel(thread_count);
	pthread_cancel(thread_serv);
	pthread_join(thread_count, NULL);
	pthread_join(thread_serv, NULL);
	free(srcdata);
	lc_ctx_free(lctx);
	return fails;
}
