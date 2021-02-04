/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include "mld.h"
#include "hash.h"
#include "log.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

/* See RFC 3810 */

/* MALI = Multicast Address Listening Interval */
/* LLQT = Last Listener Query Time */

#define MLD2_ROBUSTNESS 2		/* 9.14.1.  Robustness Variable */
#define MLD2_CAPABLE_ROUTERS "ff02::16" /* all MLDv2-capable routers */
#define MLD2_LISTEN_REPORT 143		/* Multicast Listener Report messages */
#define BUFSIZE 1500

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

struct mld_filter_s {
	/* counted bloom filter for multicast group addresses */
	vec_t	grp[BLOOM_VECTORS];
	/* bloom timer with 8 bit timer values */
	vec_t	t[BLOOM_VECTORS];
};

struct mld_s {
	/* raw socket for MLD snooping */
	int sock;
	/* number of interfaces allocated */
	int len;
	/* counted bloom filter for groups gives us O(1) for insert/query/delete 
	 * combied with a bloom timer (is that a thing, or did I just make it
	 * up?) - basically a counted bloom filter where the max is set to the
	 * time in seconds, and we count it down using SIMD instructions
	 */
	/* variable-length array of filters */
	mld_filter_t filter[];
};

/* Multicast Address Record */
struct mar {
	uint8_t         mar_type;       /* Record Type */
	uint8_t         mar_auxlen;     /* Aux Data Len */
	uint16_t        mar_sources;    /* Number of Sources */
	struct in6_addr mar_address;    /* Multicast Address */
} __attribute__((__packed__));

/* Version 2 Multicast Listener Report Message */
struct mld2 {
	uint8_t         mld2_type;      /* type field */
	uint8_t         mld2_res1;      /* reserved */
	uint16_t        mld2_cksum;     /* checksum field */
	uint16_t        mld2_res2;      /* reserved */
	uint16_t        mld2_rec;       /* Nr of Mcast Address Records */
	struct mar      mld2_mar;       /* First MCast Address Record */
} __attribute__((__packed__));

/* extract interface number from ancillary control data */
int interface_index(struct msghdr msg)
{
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pi;
	int ifidx = 0;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IPV6 || cmsg->cmsg_type != IPV6_PKTINFO)
			continue;
		pi = (struct in6_pktinfo *) CMSG_DATA(cmsg);
		ifidx = pi->ipi6_ifindex;
	}
	return ifidx;
}

/* 
 * This whole thing needs re-writing so that it is simply an enquiry as to
 * current state. The state machine for updating that state is a separate
 * concern.
 */
int mld_wait(struct in6_addr *addr)
{
	int ret = 0;
	int opt = 1;
	int joins = 0;
	int sock;
	//int ifidx;
	ssize_t byt;
	struct ipv6_mreq req;
	struct ifaddrs *ifaddr, *ifa;
	struct iovec iov[2] = {0};
	struct icmp6_hdr icmpv6 = {0};
	struct mar mrec = {0};
	struct msghdr msg;
	char buf_ctrl[BUFSIZE];
	char buf_name[BUFSIZE];
	char straddr[INET6_ADDRSTRLEN];
	sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	assert(sock);
	if (sock == -1) {
		perror("socket()");
		return -1;
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
		return -1;
	}
	iov[0].iov_base = &icmpv6;
	iov[0].iov_len = sizeof icmpv6;
	iov[1].iov_base = &mrec;
	iov[1].iov_len = sizeof mrec;
	msg.msg_control = buf_ctrl;
	msg.msg_controllen = BUFSIZE;
	msg.msg_name = buf_name;
	msg.msg_namelen = BUFSIZE;
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	msg.msg_flags = 0;
	for (;;) {
		if ((byt = recvmsg(sock, &msg, 0)) == -1) {
			perror("recvmsg()");
			return -1;
		}
		//ifidx = interface_index(msg);
		if (icmpv6.icmp6_type == MLD2_LISTEN_REPORT) {
			uint16_t rec = ntohs(icmpv6.icmp6_data16[1]);
			DEBUG("got a MLD2_LISTEN_REPORT with %u records", rec);
			for (int i = 0; i < rec; i++) {
				if (!memcmp(addr, &mrec.mar_address, sizeof(struct in6_addr))) {
					inet_ntop(AF_INET6, (&mrec.mar_address)->s6_addr, straddr, INET6_ADDRSTRLEN);
					DEBUG("MATCH FOUND: %s", straddr);
					return 0;
				}
			}
		}
	}
	close(sock);
	return 0;
}

#if 0
static void vec_dump(vec_t v, char *label)
{
	fprintf(stderr, "%s:\t", label);
	for (int j = 0; j < VECTOR_SZ; j++) {
		fprintf(stderr, "%03u ", (uint8_t)v.u8[j]);
	}
	putc('\n', stderr);
}

static void vec_load_8(vec_t *v, unsigned char *p, int len)
{
	//unsigned char u[VECTOR_SZ * BLOOM_SZ] = {0};
	unsigned char *u = calloc(VECTOR_SZ, BLOOM_SZ);
	for (int i = 0; i < BLOOM_HASHES; i++) {
		//fprintf(stderr, "considering %03u\n", p[i] & 0x7f);
		//u[p[i] & 0x7f] = 1;
		fprintf(stderr, "considering %03u\n", p[i]);
		u[p[i]] = 1;
	}
	for (int i = 0; i < len; i++) {
		v[i].v = _mm_set_epi8 (
			u[0xf + i * 16],
			u[0xe + i * 16],
			u[0xd + i * 16],
			u[0xc + i * 16],
			u[0xb + i * 16],
			u[0xa + i * 16],
			u[0x9 + i * 16],
			u[0x8 + i * 16],
			u[0x7 + i * 16],
			u[0x6 + i * 16],
			u[0x5 + i * 16],
			u[0x4 + i * 16],
			u[0x3 + i * 16],
			u[0x2 + i * 16],
			u[0x1 + i * 16],
			u[0x0 + i * 16]
		);
	}
	free(u);
}

// TODO need to compare source address too for SSM
int mld_filter_grp_cmp(mld_t *mld, int iface, struct in6_addr *saddr)
{
	unsigned char *addr = saddr->s6_addr;
	unsigned char hash[HASHSIZE];
	vec_t *grp = mld->filter[iface].grp;
	vec_t vgrp[BLOOM_SZ], mask[BLOOM_SZ], cmp;
	
	// TODO addr[0] => EXCLUDE/INCLUDE mode + router id
	// TODO test EXCLUDE/INCLUDE modes
	
	/* hash address */
	hash_generic(hash, HASHSIZE, addr, IPV6_BYTES);

	/* load hashed address into vector registers */
	vec_load_8(vgrp, hash, BLOOM_SZ);

	// FIXME temp debug
	for (unsigned i = 0; i < HASHSIZE; i++) {
		fprintf(stderr, "%u\n", hash[i] & 0x7f);
		vec_dump(vgrp[i], "vgrp");
	}

	for (int i = 0; i < BLOOM_SZ; i++) {
		/* create a mask of bloom counters > 0 */
		mask[i].u8 = grp[i].u8 > 0;
		/* add counters (0/-1) to mask (0/1) */
		cmp.u8 = mask[i].u8 + vgrp[i].u8;

		/* FIXME temp debug */
		vec_dump(vgrp[i], "vgrp");
		vec_dump(mask[i], "mask");
		vec_dump(cmp, "cmp");
		fputc('\n', stderr);

		/* test each element of the vector */
		for (int j = 0; j < VECTOR_SZ; j++) {
			/* filter not set (0) + hash is (1) => 1 => not matched
			 * ignore -1's - that means the filter is set but we
			 * don't care */
			if (cmp.u8[j] == 1) return 0;
		}
	}
	return -1;
}

void mld_filter_grp_add(mld_t *mld, int iface, struct in6_addr *saddr)
{
	unsigned char *addr = saddr->s6_addr;
	unsigned char hash[HASHSIZE];
	vec_t *grp = mld->filter[iface].grp;
	vec_t mask[BLOOM_SZ];

	/* hash address */
	hash_generic(hash, HASHSIZE, addr, IPV6_BYTES);

	// FIXME temp debug
	for (unsigned i = 0; i < HASHSIZE; i++) {
		fprintf(stderr, "%u\n", hash[i] & 0x7f);
	}

	/* load addr into vector registers */
	vec_load_8(mask, hash, BLOOM_SZ);

	for (int i = 0; i < BLOOM_SZ; i++) {
		// TODO check if group already in filter
		// TODO check for overflow
		//grp[i].v = _mm_add_epi8(grp[i].v, mask[i].v);

		/* increment bloom counter */
		grp[i].u8 += mask[i].u8;
	}
	// TODO addr[0] => EXCLUDE/INCLUDE mode + router id
	// TODO timer
	// TODO source addresses
}
#endif

/* set one element of a vector to value */
void vec_inc_epi8(vec_t *v, size_t idx)
{
	v[idx / VECTOR_BITS].u8[idx % VECTOR_BITS]++;
}

void vec_dec_epi8(vec_t *v, size_t idx)
{
	v[idx / VECTOR_BITS].u8[idx % VECTOR_BITS]--;
}

uint8_t vec_get_epi8(vec_t *v, size_t idx)
{
	return v[idx / VECTOR_BITS].u8[idx % VECTOR_BITS];
}

void vec_set_epi8(vec_t *v, size_t idx, uint8_t val)
{
	v[idx / VECTOR_BITS].u8[idx % VECTOR_BITS] = val;
}

int mld_filter_grp_cmp(mld_t *mld, int iface, struct in6_addr *saddr)
{
	uint64_t hash[BLOOM_HASHES];
	vec_t *grp = mld->filter[iface].grp;
	hash_generic((unsigned char *)hash, sizeof hash, saddr->s6_addr, IPV6_BYTES);
	for (int i = 0; i < BLOOM_HASHES; i++) {
		size_t idx = hash[i] % BLOOM_SZ;
		if (!vec_get_epi8(grp, idx)) return 0;
	}
	return 1;
}

void mld_filter_grp_add(mld_t *mld, int iface, struct in6_addr *saddr)
{
	uint64_t hash[BLOOM_HASHES];
	vec_t *grp = mld->filter[iface].grp;
	hash_generic((unsigned char *)hash, sizeof hash, saddr->s6_addr, IPV6_BYTES);
	for (int i = 0; i < BLOOM_HASHES; i++) {
		size_t idx = hash[i] % BLOOM_SZ;
		vec_inc_epi8(grp, idx);
		vec_set_epi8(grp, idx, MLD_TIMEOUT);
	}
}

mld_t *mld_init(int ifaces)
{
	return calloc(1, sizeof(mld_t) + ifaces * sizeof(mld_filter_t));
}

void mld_free(mld_t *mld)
{
	free(mld);
}

void mld_stop(mld_t *mld)
{
	struct ipv6_mreq req;
	setsockopt(mld->sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &req, sizeof(req));
	close(mld->sock);
	mld_free(mld);
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
	if (mld) mld->sock = sock;
	return mld;
}
