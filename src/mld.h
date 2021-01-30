/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _MLD_H
#define _MLD_H 1

#include <netinet/in.h>

int mld_wait(struct in6_addr *addr);

#endif /* _MLD_H */
