/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef MLD_PVT_H
#define MLD_PVT_H 1

#include "mld.h"
#include "macro.h"
#include "job.h"
#include <assert.h>

#define MLD_DEBUG 1
#define BUFSIZE 1500
#define IFACE_MAX UCHAR_MAX

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
	void (*f)(mld_t *, unsigned int, size_t, uint8_t);
	size_t idx;
	unsigned int iface;
	uint8_t val;
};

struct mld_filter_s {
	/* counted bloom filter for multicast group addresses */
	vec_t	grp[BLOOM_VECTORS];
	/* bloom timer with 8 bit timer values */
	vec_t	t[BLOOM_VECTORS];
};

struct mld_s {
	lc_ctx_t *lctx;
	/* stop if cont points to zero value */
	volatile int *cont;
	job_queue_t *timerq;
	/* raw socket for MLD snooping */
	int sock;
	/* number of interfaces allocated */
	int len;
	/* iface -> interface_idx mapping */
	unsigned int ifx[IFACE_MAX];
	/* counted bloom filter for groups gives us O(1) for insert/query/delete 
	 * combined with a bloom timer (is that a thing, or did I just make it
	 * up?) - basically a counted bloom filter where the max is set to the
	 * time in seconds, and we count it down using SIMD instructions
	 */
	/* variable-length array of filters */
	mld_filter_t filter[];
};

struct mld_watch_s {
	mld_t *mld;
	pthread_t thread;
	lc_socket_t *sock;
	lc_channel_t *chan;
	void (*f)(mld_watch_t *, mld_watch_t *);
	struct in6_addr *grp;
	unsigned int ifx;
	int events;
	int flags;
};

/* Multicast Address Record */
struct mld_addr_rec_s {
	uint8_t         type;    /* Record Type */
	uint8_t         auxl;    /* Aux Data Len */
	uint16_t        srcs;    /* Number of Sources */
	struct in6_addr addr;    /* Multicast Address */
	struct in6_addr src[];   /* Source Address */
};
#ifdef static_assert
static_assert(sizeof(struct mld_addr_rec_s) == 20, "ensure struct doesn't need packing");
#endif

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

/* convert network index to mld filter array index */
unsigned int mld_idx_iface(mld_t *mld, unsigned int idx);

#endif /* MLD_PVT_H */
