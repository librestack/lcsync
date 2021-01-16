/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _NET_H
#define _NET_H 1

#include <librecast/net.h>
#include "hash.h"
#include "mtree.h"

/* IPv6 path discovery isn't much use for multicast and
 * we don't want to receive a bunch of Packet Too Big messages
 * so we'll use a fixed MTU of 1280 - headers + extensions => ~1200
 * Essentially we can send about 1024 bytes + some headers */
#define MTU_FIXED 1194
#define DATA_FIXED 1024

typedef struct net_treehead_s {
	/* packet index 0 to n-1 of tree */
	uint32_t	idx;
	/* no. of packets in tree */
	uint32_t	pkts;
	/* length in bytes of data in this packet */
	uint32_t	len;
	/* channels used to send file (as power of 2) */
	uint8_t		chan;
	/* root hash of file */
	unsigned char hash[HASHSIZE];
} __attribute__((__packed__)) net_treehead_t;

typedef struct net_blockhead_s net_blockhead_t;
struct net_blockhead_s {
	/* packet index 0 to n-1 of block */
	uint32_t	idx;
	/* receiver knows the hash, block len etc. already from tree */
} __attribute__((__packed__));

typedef union {
	net_treehead_t hdr_tree;
	net_blockhead_t hdr_block;
} net_head_t;

#if 0
typedef struct net_rdata_s net_rdata_t;
struct net_rdata_s {
	/* total length of data expected - work this out from iovec */

	/* do we need to knwo what kind of data this is? */

	/* just blindly receive data - caller can check if it is what was
	 * expected */

	/* scatter array to store recv'd data */
	size_t		len;		/* len of scatter-gather array */
	struct iovec	iov[];		/* scatter-gather array */
};
#endif

/* struct for send/recving tree/data block */
typedef struct net_data_s net_data_t;
struct net_data_s {
	unsigned char hash[HASHSIZE];	/* hash of file/data */
	size_t		len;		/* len of scatter-gather array */
	struct iovec	iov[];		/* scatter-gather array */
};

/* pack tree header */
net_treehead_t *net_hdr_tree(net_treehead_t *hdr, mtree_tree *tree);

/* blocking receive of chunk from a librecast socket 
 * return bytes received or -1 on error
	size_t		len;		len of scatter-gather array
	struct iovec	iov[];		scatter-gather array
*/
ssize_t net_recv_data(int sock, size_t vlen, struct iovec *iov);

/* send a data block or tree to a librecast channel
 * return bytes sent or -1 on error
	int		sock		datagram socket
	struct addrinfo *addr		addr to send to
	size_t		len;		len of scatter-gather array
	struct iovec	iov[];		scatter-gather array
First iovec is assumed to be the header and will be sent with every packet.
*/
ssize_t net_send_data(int sock, struct addrinfo *addr, size_t vlen, struct iovec *iov);

int net_recv(int *argc, char *argv[]);
int net_send(int *argc, char *argv[]);
int net_sync(int *argc, char *argv[]);

#endif /* _NET_H */
