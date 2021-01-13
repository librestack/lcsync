/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _NET_H
#define _NET_H 1

#include <librecast/net.h>
#include "hash.h"

/* IPv6 path discovery isn't much use for multicast and
 * we don't want to receive a bunch of Packet Too Big messages
 * so we'll use a fixed MTU of 1280 - headers + extensions => ~1200
 * Essentially we can send about 1024 bytes + some headers */
#define MTU_FIXED 1194
#define DATA_FIXED 1024

#if 0
typedef struct net_head_s {
	/* packet index, 0 to packets for this channel - 1 */
	u_int64_t       idx;
} __attribute__((__packed__)) net_head_t;
#endif

typedef struct net_data_s net_data_t;
struct net_data_s {
	uint64_t idx;
	unsigned char *hash;		/* hash of data chunk */
	size_t len;			/* total length of chunk */
	struct iovec iov[];		/* scatter-gather array */
};

/* convenience function to pack a single data chunk into net_data_t */
net_data_t *net_chunk(unsigned char *hash, size_t len, char *base, uint64_t block);

/* blocking receive of data chunk from a librecast socket 
 * return bytes received or -1 on error */
ssize_t net_recv_data(int sock, net_data_t *data);

/* send a data chunk to a librecast channel
 * return bytes sent or -1 on error */
ssize_t net_send_data(int sock, struct addrinfo *addr, net_data_t *data);

int net_recv(int *argc, char *argv[]);
int net_send(int *argc, char *argv[]);
int net_sync(int *argc, char *argv[]);

#endif /* _NET_H */
