/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include "mld.h"
#include "hash.h"
#include "log.h"
#include "job.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFSIZE 1500

/* we assume BLOOM_HASHES is not larger than the maximum hash generated by
 * our hash function - 64 bytes for blake2b.  Make sure. */
static_assert(BLOOM_HASHES <= HASHMAXBYTES, "BLOOM_HASHES cannot be larger than hash");

#if !__USE_KERNEL_IPV6_DEFS
/* IPv6 packet information.  */
struct in6_pktinfo
{
	struct in6_addr ipi6_addr;  /* src/dst IPv6 address */
	unsigned int ipi6_ifindex;  /* send/recv interface index */
};
#endif

typedef enum {
	FILTER_MODE_INCLUDE = 1,
	FILTER_MODE_EXCLUDE,
} mld_mode_t;

struct mld_timerjob_s {
	mld_t *mld;
	void (*f)(mld_t *, int iface, size_t idx);
	size_t idx;
	int iface;
};

struct mld_filter_s {
	/* counted bloom filter for multicast group addresses */
	vec_t	grp[BLOOM_VECTORS];
	/* bloom timer with 8 bit timer values */
	vec_t	t[BLOOM_VECTORS];
};

struct mld_s {
	/* raw socket for MLD snooping */
	int sock;
	job_queue_t *timerq;
	/* number of interfaces allocated */
	int len;
	/* counted bloom filter for groups gives us O(1) for insert/query/delete 
	 * combined with a bloom timer (is that a thing, or did I just make it
	 * up?) - basically a counted bloom filter where the max is set to the
	 * time in seconds, and we count it down using SIMD instructions
	 */
	/* variable-length array of filters */
	mld_filter_t filter[];
};

/* Multicast Address Record */
struct mld_addr_rec_s {
	uint8_t         type;    /* Record Type */
	uint8_t         auxl;    /* Aux Data Len */
	uint16_t        srcs;    /* Number of Sources */
	struct in6_addr addr;    /* Multicast Address */
	struct in6_addr src[];   /* Source Address */
};
static_assert(sizeof(struct mld_addr_rec_s) == 20); /* ensure struct doesn't need packing */

/* Version 2 Multicast Listener Report Message */
#if 0
struct mld_lrm_t {
	uint8_t         type;	/* type field */
	uint8_t         res1;   /* reserved */
	uint16_t        cksm;   /* checksum field */
	uint16_t        res2;   /* reserved */
	uint16_t        recs;   /* Nr of Mcast Address Records */
	char *		mrec;   /* First MCast Address Record */
} __attribute__((__packed__));
#endif

/* extract interface number from ancillary control data */
static int interface_index(struct msghdr *msg)
{
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pi;
	int ifidx = 0;
	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IPV6 || cmsg->cmsg_type != IPV6_PKTINFO)
			continue;
		pi = (struct in6_pktinfo *) CMSG_DATA(cmsg);
		ifidx = pi->ipi6_ifindex;
	}
	return ifidx;
}

void mld_free(mld_t *mld)
{
	job_queue_destroy(mld->timerq);
	free(mld);
}

void mld_stop(mld_t *mld)
{
	struct ipv6_mreq req;
	setsockopt(mld->sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &req, sizeof(req));
	close(mld->sock);
	mld_free(mld);
}

/* 
 * This whole thing needs re-writing so that it is simply an enquiry as to
 * current state. The state machine for updating that state is a separate
 * concern.
 */
int mld_wait(struct in6_addr *addr)
{
	(void)addr;
	return 0;
}

void vec_dump(vec_t *vec, int idx)
{
	for (int j = 0; j < 16; j++) {
		fprintf(stderr, "%u ", (uint8_t)vec[idx / VECTOR_BITS].u8[j]);
	}
	putc('\n', stderr);
}

/* decrement all the counters. There are 16.7 million of them, use SIMD */
void mld_timer_tick(mld_t *mld, int iface, size_t idx)
{
	(void)iface; (void)idx;
	vec_t *t;
	vec_t mask = {0};
	for (int i = 0; i < mld->len; i++) {
		t = mld->filter[i].t;
		for (size_t z = 0; z < BLOOM_VECTORS; z++) {
			mask.u8 = t[z].u8 > 0;
			t[z].u8 += mask.u8;
		}
	}
	DEBUG("%s() - update complete", __func__);
}

void mld_timer_refresh(mld_t *mld, int iface, size_t idx)
{
	vec_t *t = mld->filter[iface].t;
	vec_set_epi8(t, idx, MLD_TIMEOUT);
	DEBUG("timer refreshed (%zu)", idx);
}

void *mld_timer_job(void *arg)
{
	mld_timerjob_t *tj = (mld_timerjob_t *)arg;
	tj->f(tj->mld, tj->iface, tj->idx);
	return arg;
}

/* this thread handles the clock ticks, creating a job for the timer thread */
void mld_timer_ticker(mld_t *mld, int iface, size_t idx)
{
	struct timespec ts;
	sem_t sem;
	mld_timerjob_t tj = { .mld = mld, .iface = iface, .idx = idx, .f = &mld_timer_tick };
	sem_init(&sem, 0, 0);
	clock_gettime(CLOCK_REALTIME, &ts);
	for (;;) {
		ts.tv_sec += MLD_TIMER_INTERVAL;
		sem_timedwait(&sem, &ts);
		job_push_new(mld->timerq, &mld_timer_job, &tj, sizeof tj, &free, JOB_COPY|JOB_FREE);
	}
}
// FIXME some refactoring to do here - these functions are all similar
int mld_filter_timer_get(mld_t *mld, int iface, struct in6_addr *saddr)
{
	uint32_t hash[BLOOM_HASHES];
	if (iface >= mld->len) {
		errno = EINVAL;
		return -1;
	}
	vec_t *t = mld->filter[iface].t;
	hash_generic((unsigned char *)hash, sizeof hash, saddr->s6_addr, IPV6_BYTES);
	size_t idx = hash[0] % BLOOM_SZ;
	return vec_get_epi8(t, idx);
}

int mld_filter_grp_cmp(mld_t *mld, int iface, struct in6_addr *saddr)
{
	uint32_t hash[BLOOM_HASHES];
	vec_t *grp = mld->filter[iface].grp;
	if (iface >= mld->len) {
		errno = EINVAL;
		return 0;
	}
	hash_generic((unsigned char *)hash, sizeof hash, saddr->s6_addr, IPV6_BYTES);
	for (int i = 0; i < BLOOM_HASHES; i++) {
		size_t idx = hash[i] % BLOOM_SZ;
		if (!vec_get_epi8(grp, idx)) return 0;
	}
	return 1;
}

int mld_filter_grp_del(mld_t *mld, int iface, struct in6_addr *saddr)
{
	uint32_t hash[BLOOM_HASHES];
	if (iface >= mld->len) {
		errno = EINVAL;
		return -1;
	}
	vec_t *grp = mld->filter[iface].grp;
	hash_generic((unsigned char *)hash, sizeof hash, saddr->s6_addr, IPV6_BYTES);
	for (int i = 0; i < BLOOM_HASHES; i++) {
		size_t idx = hash[i] % BLOOM_SZ;
		if (vec_get_epi8(grp, idx)) vec_dec_epi8(grp, idx);
	}
	return 0;
}

int mld_filter_grp_add(mld_t *mld, int iface, struct in6_addr *saddr)
{
	uint32_t hash[BLOOM_HASHES];
	if (iface >= mld->len) {
		errno = EINVAL;
		return -1;
	}
	if (mld_filter_grp_cmp(mld, iface, saddr)) return 0; /* exists */
	mld_timerjob_t tj = { .mld = mld, .iface = iface, .f = &mld_timer_refresh };
	vec_t *grp = mld->filter[iface].grp;
	hash_generic((unsigned char *)hash, sizeof hash, saddr->s6_addr, IPV6_BYTES);
	for (int i = 0; i < BLOOM_HASHES; i++) {
		size_t idx = hash[i] % BLOOM_SZ;
		if (vec_get_epi8(grp, idx) != CHAR_MAX)
			vec_inc_epi8(grp, idx);
		tj.idx = idx;
		job_push_new(mld->timerq, &mld_timer_job, &tj, sizeof tj, &free, JOB_COPY|JOB_FREE);
	}
	return 0;
}

// FIXME: cache this in another bloom filter
int mld_thatsme(struct in6_addr *addr)
{
	int ret = 1;
	struct ifaddrs *ifaddr, *ifa;
	getifaddrs(&ifaddr);
	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr) continue;
		if (ifa->ifa_addr->sa_family != AF_INET6) continue;
		if (!memcmp(ifa->ifa_addr, addr, sizeof (struct in6_addr))) {
			ret = 0; break;
		}
	}
	freeifaddrs(ifaddr);
	return ret;
}

void mld_address_record(mld_t *mld, int iface, mld_addr_rec_t *rec)
{
	struct in6_addr grp = rec->addr;
	struct in6_addr *src = rec->src;
	int idx = -1;
	switch (rec->type) {
		case MODE_IS_INCLUDE:
			if (!rec->srcs) {
				mld_filter_grp_del(mld, iface, &grp);
				break;
			}
			for (int i = 0; i < rec->srcs; i++) {
				if (!mld_thatsme(&src[i])) {
					idx = i;
					break;
				}
			}
			if (idx < 0) break;
			/* fallthru */
		case MODE_IS_EXCLUDE:
			mld_filter_grp_add(mld, iface, &grp);
			break;
	}
}

void mld_listen_report(mld_t *mld, struct msghdr *msg)
{
	int iface = interface_index(msg);
	struct icmp6_hdr *icmpv6 = msg->msg_iov[0].iov_base;
	mld_addr_rec_t *mrec = msg->msg_iov[1].iov_base;
	uint16_t recs = ntohs(icmpv6->icmp6_data16[1]);
	for (int i = 0; i < recs; i++) {
		mld_address_record(mld, iface, &mrec[i]);
	}
}

void mld_msg_handle(mld_t *mld, struct msghdr *msg)
{
	struct icmp6_hdr *icmpv6 = msg->msg_iov[0].iov_base;
	if (icmpv6->icmp6_type == MLD2_LISTEN_REPORT) {
		mld_listen_report(mld, msg);
	}
}

int mld_listen(mld_t *mld)
{
	ssize_t byt = 0;
	char buf_ctrl[BUFSIZE];
	char buf_name[IPV6_BYTES];
	struct iovec iov[2] = {0};
	struct icmp6_hdr icmpv6 = {0};
	mld_addr_rec_t mrec = {0};
	struct msghdr msg;
	iov[0].iov_base = &icmpv6;
	iov[0].iov_len = sizeof icmpv6;
	iov[1].iov_base = &mrec;
	iov[1].iov_len = sizeof mrec;
	msg.msg_name = buf_name;
	msg.msg_namelen = IPV6_BYTES;
	msg.msg_control = buf_ctrl;
	msg.msg_controllen = BUFSIZE;
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	msg.msg_flags = 0;
	for (;;) {
		if ((byt = recvmsg(mld->sock, &msg, 0)) == -1) {
			perror("recvmsg()");
			return -1;
		}
		DEBUG("%s(): msg received", __func__);
		mld_msg_handle(mld, &msg);
	}
	return 0;
}

mld_t *mld_init(int ifaces)
{
	mld_t *mld = calloc(1, sizeof(mld_t) + ifaces * sizeof(mld_filter_t));
	if (!mld) return NULL;
	mld->len = ifaces;
	/* create FIFO queue with timer writer thread + ticker */
	mld->timerq = job_queue_create(2);
	return mld;
}

mld_t *mld_start(void)
{
	mld_t *mld = NULL;
	int ret = 0;
	int sock;
	int opt = 1;
	int joins = 0;
	struct ifaddrs *ifaddr, *ifa;
	struct ipv6_mreq req;
	sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (sock == -1) {
		perror("socket()");
		return NULL;
	}
	setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt, sizeof(opt));
	getifaddrs(&ifaddr);
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family !=AF_INET6) continue; /* ipv6 only */
		inet_pton(AF_INET6, MLD2_CAPABLE_ROUTERS, &(req.ipv6mr_multiaddr));
		req.ipv6mr_interface = if_nametoindex(ifa->ifa_name);
		ret = setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &req, sizeof(req));
		if (ret != -1) {
			DEBUG("listening on interface %s", ifa->ifa_name);
			joins++;
		}
	}
	freeifaddrs(ifaddr);
	if (!joins) {
		ERROR("Unable to join on any interfaces");
		return NULL;
	}
	mld = mld_init(joins);
	if (!mld) return NULL;
	mld->sock = sock;
	mld_timerjob_t tj = { .mld = mld, .f = &mld_timer_ticker };
	job_push_new(mld->timerq, &mld_timer_job, &tj, sizeof tj, &free, JOB_COPY|JOB_FREE);
	return mld;
}
