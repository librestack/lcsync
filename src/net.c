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
	memset(hdr, 0, sizeof *hdr);
	hdr->pkts = mtree_len(tree) / DATA_FIXED;
	if (mtree_len(tree) % DATA_FIXED) hdr->pkts++;
	hdr->chan = net_send_channels;
	memcpy(hdr->hash, mtree_root(tree), HASHSIZE);
	return hdr;
}

ssize_t net_recv_data(int sock, size_t vlen, struct iovec *iov)
{
	size_t idx, off, len, pkts;
	ssize_t byt = 0, msglen;
	uint64_t sz = iov->iov_len;
	net_treehead_t *hdr;
	char *buf = malloc(MTU_FIXED);
	char *bitmap = NULL;
	if (!buf) return -1;
	do {
		if ((msglen = recv(sock, buf, MTU_FIXED, 0)) == -1) {
			perror("recv()");
			free(buf);
			return -1;
		}
		hdr = (net_treehead_t *)buf;
		sz = be64toh(hdr->size);
		if (!bitmap) {
			pkts = be32toh(hdr->pkts);
			bitmap = calloc(1, pkts / CHAR_BIT + !!(pkts / CHAR_BIT));
			for (size_t z = 0; z < pkts; z++) {
				bitmap[z >> CHAR_BIT] |= 1UL << (z % CHAR_BIT);
			}
		}
		if (!iov->iov_base) {
			iov->iov_base = calloc(1, sz);
			if (!iov->iov_base) {
				perror("calloc()");
				return -1;
			}
			iov->iov_len = sz;
			vlen = 1;
		}
		idx = (size_t)be32toh(hdr->idx);
		off = be32toh(hdr->idx) * DATA_FIXED;
		len = (size_t)be32toh(hdr->len);
		if (!!(bitmap[idx >> CHAR_BIT] & 1UL << idx)) {
			memcpy((char *)iov->iov_base + off, buf + sizeof (net_treehead_t), len);
			bitmap[idx >> CHAR_BIT] &= ~(1UL << (idx % CHAR_BIT));
		}
		byt += be32toh(hdr->len);
	}
	while (*bitmap);
	free(buf);
	free(bitmap);
	return byt;
}

ssize_t net_send_tree(int sock, struct addrinfo *addr, size_t vlen, struct iovec *iov)
{
	ssize_t byt = 0;
	size_t sz, off = 0;
	size_t len = iov[1].iov_len;
	size_t idx = 0;
	net_treehead_t *hdr = iov[0].iov_base;
	struct msghdr msgh = {0};
	hdr->pkts = htobe32(iov[1].iov_len / DATA_FIXED + !!(iov[1].iov_len % DATA_FIXED));
	while (len) {
		sz = (len > DATA_FIXED) ? DATA_FIXED : len;
		msgh.msg_name = addr->ai_addr;
		msgh.msg_namelen = addr->ai_addrlen;
		msgh.msg_iov = iov;
		msgh.msg_iovlen = vlen;
		iov[1].iov_len = sz;
		iov[1].iov_base = (char *)iov[1].iov_base + off;
		hdr->idx = htobe32(idx++);
		hdr->len = htobe32(sz);
		off = sz;
		len -= sz;
		if ((byt = sendmsg(sock, &msgh, 0)) == -1) {
			perror("sendmsg()");
			break;
		}
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
