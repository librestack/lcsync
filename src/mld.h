/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _MLD_H
#define _MLD_H 1

#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <immintrin.h>
#include "vec.h"

#define BLOOM_SZ 16777216
#define BLOOM_VECTORS BLOOM_SZ / VECTOR_BITS
#define BLOOM_HASHES 8 /* optimal = LOG2(BLOOM_SZ / ENTRIES) */
#define MLD_TIMEOUT 120 /* seconds before MLD record expires */
#define MLD_TIMER_INTERVAL 1 /* length of timer tick in seconds */
#define IPV6_BYTES 16

/* See RFC 3810 */

/* MALI = Multicast Address Listening Interval */
/* LLQT = Last Listener Query Time */

#define MLD2_ROBUSTNESS 2               /* 9.14.1.  Robustness Variable */
#define MLD2_CAPABLE_ROUTERS "ff02::16" /* all MLDv2-capable routers */
#define MLD2_LISTEN_REPORT 143          /* Multicast Listener Report messages */

/* Current State Record */
#define MODE_IS_INCLUDE 1
#define MODE_IS_EXCLUDE 2

/* Filter Mode Change Record */
#define CHANGE_TO_INCLUDE_MODE 3
#define CHANGE_TO_EXCLUDE_MODE 4

/* Source List Change Record */
#define ALLOW_NEW_SOURCES 5
#define BLOCK_OLD_SOURCES 6

/* 9.14.1.  Robustness Variable */
#define MLD2_ROBUSTNESS 2

/* Event Types */
typedef enum {
	MLD_EVENT_JOIN = 1,
	MLD_EVENT_PART = 2,
	MLD_EVENT_MAX
} mld_event_type_t;
#define MLD_EVENT_ALL ((MLD_EVENT_MAX - 1) << 1) - 1

/* port (or service) to use for MLD event notifications */
#define MLD_EVENT_SERV "4242"

typedef struct mld_s mld_t;
typedef struct mld_filter_s mld_filter_t;
typedef struct mld_timerjob_s mld_timerjob_t;
typedef struct mld_addr_rec_s mld_addr_rec_t;

/* initialize / free state machine */
mld_t *mld_init(int ifaces);

/* free MLD objects */
void mld_free(mld_t *mld);

/* start MLD snooping */
mld_t *mld_start(volatile int *cont);

/* stop MLD snooping */
void mld_stop(mld_t *mld);

/* decrement all the counters. */
void mld_timer_tick(mld_t *mld, unsigned int iface, size_t idx);

/* reset specific timer to MLD_TIMEOUT */
void mld_timer_refresh(mld_t *mld, unsigned int iface, size_t idx);

/* inspect timer for group address */
int mld_filter_timer_get(mld_t *mld, unsigned int iface, struct in6_addr *saddr);

/* add group address to interface bloom filter */
int mld_filter_grp_add(mld_t *mld, unsigned int iface, struct in6_addr *addr);
int mld_filter_grp_add_ai(mld_t *mld, unsigned int iface, struct addrinfo *ai);

/* return true (-1) if filter contains addr, false (0) if not */
int mld_filter_grp_cmp(mld_t *mld, unsigned int iface, struct in6_addr *addr);

/* remove group address from interface bloom filter */
int mld_filter_grp_del(mld_t *mld, unsigned int iface, struct in6_addr *addr);
int mld_filter_grp_del_ai(mld_t *mld, unsigned int iface, struct addrinfo *ai);

/* return 0 if addr is assigned to a local interface, 1 if not, -1 on error */
int mld_thatsme(struct in6_addr *addr);

/* handle MLD2 router msgs */
void mld_address_record(mld_t *mld, unsigned int iface, mld_addr_rec_t *rec);
void mld_listen_report(mld_t *mld, struct msghdr *msg);
void mld_msg_handle(mld_t *mld, struct msghdr *msg);

/* start mld listener. return -1 on error, 0 success */
int mld_listen(mld_t *mld);

/* query state */

/* block until notification received for addr */
int mld_wait(mld_t *mld, unsigned int iface, struct in6_addr *addr);

#endif /* _MLD_H */
