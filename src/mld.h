/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _MLD_H
#define _MLD_H 1

#include <netinet/in.h>
#include <emmintrin.h>

typedef struct mld_s mld_t;
typedef struct mld_filter_s mld_filter_t;

/* initialize / free state machine */
mld_t *mld_init(void);
void mld_free(mld_t *mld);

/* manage state */
void mld_is_in(unsigned int ifidx, struct in6_addr *addr); /* MODE_IS_INCLUDE */
void mld_is_ex(unsigned int ifidx, struct in6_addr *addr); /* MODE_IS_EXCLUDE */
void mld_to_in(unsigned int ifidx, struct in6_addr *addr); /* CHANGE_TO_INCLUDE_MODE */
void mld_to_ex(unsigned int ifidx, struct in6_addr *addr); /* CHANGE_TO_EXCLUDE_MODE */
void mld_allow(unsigned int ifidx, struct in6_addr *addr); /* ALLOW_NEW_SOURCES */
void mld_block(unsigned int ifidx, struct in6_addr *addr); /* BLOCK_OLD_SOURCES */

/* query state */
int mld_wait(struct in6_addr *addr);
//int mld_wait(unsigned int ifidx, struct in6_addr *addr);

#endif /* _MLD_H */
