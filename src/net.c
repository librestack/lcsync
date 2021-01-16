/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include <endian.h>
#include <netdb.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include "net.h"
#include "globals.h"
#include "mtree.h"
#include "file.h"

static int running = 1;

void net_stop(int signo)
{
	(void) signo;
	running = 0;
	fprintf(stderr, "\nstopping on signal\n");
}

static size_t net_chunksize(void)
{
	return DATA_FIXED;
}

net_treehead_t *net_hdr_tree(net_treehead_t *hdr, mtree_tree *tree)
{
	memset(hdr, 0, sizeof hdr);
	hdr->pkts = mtree_len(tree) / DATA_FIXED;
	if (mtree_len(tree) % DATA_FIXED) hdr->pkts++;
	hdr->chan = net_send_channels;
	memcpy(hdr->hash, mtree_root(tree), HASHSIZE);
	return hdr;
}

ssize_t net_recv_data(int sock, net_data_t *data)
{
	ssize_t byt = 0;
	unsigned char hash[HASHSIZE];
	fprintf(stderr, "%s() waiting for %zu bytes\n", __func__, data->len);
	while (byt < (ssize_t)data->len) {
		byt += readv(sock, data->iov, 2);
		// TODO: ensure we read correct number of bytes
		// TODO: check idx against our bitmap to see if we need this block -  mtree_bitcmp()
		// TODO: check the hash
		// TODO: write the block in the correct place
		fprintf(stderr, "got %zu bytes\n", byt);
	}
	uint64_t idx = be64toh(*(uint64_t *)data->iov[0].iov_base);
	fprintf(stderr, "idx = %zu\n", idx);
	crypto_generichash(hash, HASHSIZE, data->iov[1].iov_base, data->iov[1].iov_len, NULL, 0);
	if (!memcmp(hash, data->hash, HASHSIZE))
		fprintf(stderr, "hash matches\n");
	else
		fprintf(stderr, "hash wrong\n");
	return byt;
}

/* FIXME: send header struct with updatable index + data chunks
 * we're either sending a block or a tree, each of which will be broken into
 * separate datagrams with an idx at the start of the header + other header info
 * first struct iovec is header (idx at start of this struct), data is in second
 * and subsequent iovecs */
ssize_t net_send_data(int sock, struct addrinfo *addr, net_data_t *data)
{
	size_t sz, off = 0;
	ssize_t byt = 0;
	struct msghdr msgh = {0};
	size_t len = data->len;
	fprintf(stderr, "sending data of %zu bytes\n", len);
	while (len) {
		sz = (len > DATA_FIXED) ? DATA_FIXED : len;
		fprintf(stderr, "queuing msg of %zu bytes\n", sz);
		msgh.msg_name = addr->ai_addr;
		msgh.msg_namelen = addr->ai_addrlen;
		msgh.msg_iov = data->iov;
		msgh.msg_iovlen = 2;
		data->iov[1].iov_len = sz;
		data->iov[1].iov_base += off;
		off = sz;
		len -= sz;
		// TODO: consider sendmmsg()
		if ((byt = sendmsg(sock, &msgh, 0)) == -1) {
			perror("sendmsg()");
			break;
		}
		else
			fprintf(stderr, "sendmsg wrote %zi bytes\n", byt);
		fprintf(stderr, "%zu bytes remaining\n", len);
	}
	return byt;
}

int net_recv(int *argc, char *argv[])
{
	(void) argc;
	fprintf(stderr, "%s('%s', '%s')\n", __func__, argv[0], argv[1]);
	// TODO: fetch tree
	// TODO: verify tree
	// TODO: build channel maps
	// TODO: join required channels
	// TODO: receive blocks
	// TODO: verify blocks / check hashes
	// TODO: part / cleanup
	return 0;
}

// TODO: send subtree - blocks below a specific node
//static void *net_send_subtree();

int net_send(int *argc, char *argv[])
{
	(void) argc;
	char *src = argv[0];
	int fds;
	char *smap = NULL;
	job_queue_t *jobq;
	mtree_tree *stree;
	size_t chunksz, nthreads;
	ssize_t sz_s;
	struct stat sbs;
	struct sigaction sa_int = { .sa_handler = net_stop };

	fprintf(stderr, "%s('%s')\n", __func__, argv[0]); // FIXME - delete

	fprintf(stderr, "mapping src: %s\n", src);
	if ((sz_s = file_map(src, &fds, &smap, 0, PROT_READ, &sbs)) == -1)
		return -1;

	sigaction(SIGINT, &sa_int, NULL);

	chunksz = (size_t)net_chunksize();
	stree = mtree_create(sz_s, chunksz);
	fprintf(stderr, "source tree with %zu nodes (base = %zu, levels = %zu)\n",
		mtree_nodes(stree), mtree_base(stree), mtree_lvl(stree));

	// TODO: choose number of channels to use - global var

	// TODO: spin up a thread for each subtree + one for tree itself
	nthreads = 8;
	jobq = job_queue_create(nthreads);
	mtree_build(stree, smap, jobq);

	// TODO: mldspy?
	//
	// TODO: set up librecast channel for sending
#if 0
	ctx = lc_ctx_new();
	sock = lc_socket_new(ctx);
	chan = lc_channel_new(ctx, MY_HARDCODED_CHANNEL);
	lc_channel_bind(sock, chan);
#endif
	// TODO: network data frame structure
#if 0
	memset(&f, 0, sizeof(iot_frame_t));
#endif

	// TODO: send blocks on a loop

	// TODO: move loop to job thread
	while (running) {
		// TODO: blast the file into cyberspace
#if 0
		memcpy(f.data, map + i, f.len);
		lc_msg_init_data(&msg, &f, sizeof(f), NULL, NULL);
		lc_msg_send(chan, &msg);
#endif
		pause();
	}

	job_queue_destroy(jobq);
	mtree_free(stree);
	file_unmap(smap, sz_s, fds);

	// TODO - librecast cleanup
#if 0
	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(ctx);
#endif
	return 0;
}

int net_sync(int *argc, char *argv[])
{
	(void) argc;
	fprintf(stderr, "%s('%s', '%s')\n", __func__, argv[0], argv[1]);
	return 0;
}
