/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _NET_H
#define _NET_H 1

#include <librecast/crypto.h>
#include <librecast/net.h>
#include <signal.h>
#include "mtree.h"
#include "mld.h"

/* IPv6 path discovery isn't much use for multicast and
 * we don't want to receive a bunch of Packet Too Big messages
 * so we'll use a fixed MTU of 1280 - headers + extensions => ~1200
 * Essentially we can send about 1024 bytes + some headers */
#define MTU_FIXED 1194
#define DATA_FIXED 1024

#if 0
enum net_channel_flags {
	NET_TREE = 1,
};
#endif

/* packet header for tree data */
typedef struct net_treehead_s {
	/* packet index 0 to n-1 of tree */
	uint32_t	idx;
	/* length in bytes of data in this packet */
	uint32_t	len;
	/* size of whole data in bytes */
	uint64_t	data;
	/* size of whole tree in bytes */
	uint64_t	size;
	/* size of data blocks */
	uint32_t        blocksz;
	/* no. of packets in tree */
	uint32_t	pkts;
	/* channels used to send file (as power of 2) */
	uint8_t		chan;
	/* root hash of file */
	unsigned char hash[HASHSIZE];
} __attribute__((__packed__)) net_treehead_t;

/* packet header for block data */
typedef struct net_blockhead_s net_blockhead_t;
struct net_blockhead_s {
	/* packet index 0 to n-1 of block */
	uint32_t	idx;
	/* length in bytes of data in this packet */
	uint32_t	len;
} __attribute__((__packed__));

typedef union {
	net_treehead_t hdr_tree;
	net_blockhead_t hdr_block;
} net_head_t;

/* struct for send/recving tree/data block */
typedef struct net_data_s net_data_t;
struct net_data_s {
	unsigned char * alias;		/* hash of file alias */
	unsigned char * hash;		/* hash of file/data */
	unsigned char * map;		/* channel bitmap */
	mld_t         * mld;		/* MLD handle */
	job_queue_t   * q;		/* job queue */
	size_t		byt;		/* data bytes */
	size_t		chan;		/* channels */
	size_t		n;		/* node */
	size_t		len;		/* len of scatter-gather array */
	struct iovec	iov[];		/* scatter-gather array */
};

unsigned int countmap(unsigned char *map, size_t len);
void printmap(unsigned char *map, size_t len);

/* signal server threads to stop work/exit */
void net_stop(int signo);

/* reset running flag after net_stop() */
void net_reset();

/* blocking receive of tree from a librecast socket
 * return bytes received or -1 on error
If iov is NULL, allocate the receive buffer. */
ssize_t net_recv_tree(int sock, struct iovec *iov, size_t *blocksz);

/* fetch tree on channel hash. Returns number of bytes received or -1 on error.
 * mtree_free(*tree) when done */
ssize_t net_fetch_tree(unsigned char *hash, mtree_tree **tree);

/* send a data block or tree to a librecast channel
 * return bytes sent or -1 on error
	
	lc_channel_t *  chan		Librecast channel to send to
	size_t		len;		len of scatter-gather array
	struct iovec	iov[];		scatter-gather array
First iovec is assumed to be the header and will be sent with every packet.
*/
ssize_t net_send_tree(lc_channel_t *chan, size_t vlen, struct iovec *iov, mld_grp_t *check);

ssize_t net_sync_subtree(mtree_tree *stree, mtree_tree *dtree, size_t root);
ssize_t net_send_subtree(mld_t *mld, mtree_tree *stree, size_t root);

/* thread job functions for above */
void *net_job_recv_tree(void *arg);
void *net_job_send_tree(void *arg);
void *net_job_sync_subtree(void *arg);
void *net_job_send_subtree(void *arg);

/* recv data with root hash (or alias) into memory at dstdata which has size len
 * if dstdata is NULL, memory will be allocated. If len is too small, dstdata
 * will be reallocated */
ssize_t net_recv_data(unsigned char *hash, char *dstdata, size_t *len);

/* send data at srcdata with size len if hash is NULL, tree data will be sent on
 * the channel formed from the root hash actual data will be split across
 * (2 ** net_send_channels) formed from the hash of the subtree root */
ssize_t net_send_data(unsigned char *hash, char *srcdata, size_t len);

int net_recv(int *argc, char *argv[]);
int net_send(int *argc, char *argv[]);
int net_send_mdex(int *argc, char *argv[]);
int net_sync(int *argc, char *argv[]);

#endif /* _NET_H */
