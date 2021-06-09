/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _MDEX_H
#define _MDEX_H 1

#include <netinet/in.h>

int mdex_put(struct in6_addr *addr, void *data, size_t size, int type);

#endif /* _MDEX_H */
