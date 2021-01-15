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

net_data_t *net_chunk(unsigned char *hash, size_t len, char *base, uint64_t block)
{
	net_data_t *data = calloc(1, sizeof(net_data_t) + sizeof(struct iovec) * 2);
	data->idx = htobe64(block);
	data->hash = hash;
	data->len = len + sizeof data->idx;
	data->iov[0].iov_len = sizeof data->idx;
	data->iov[0].iov_base = &data->idx;
	data->iov[1].iov_len = len;
	data->iov[1].iov_base = base;
	return data;
}

ssize_t net_recv_data(int sock, net_data_t *data)
{
	ssize_t byt = 0;
	unsigned char hash[HASHSIZE];
	while (byt < (ssize_t)data->len) {
		byt += readv(sock, data->iov, 2);
		// TODO: ensure we read correct number of bytes
		// TODO: check idx against our bitmap to see if we need this block -  mtree_bitcmp()
		// TODO: check the hash
		// TODO: write the block
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

ssize_t net_send_data(int sock, struct addrinfo *addr, net_data_t *data)
{
	ssize_t byt = 0;
	struct msghdr msgh = {0};
	msgh.msg_name = addr->ai_addr;
	msgh.msg_namelen = addr->ai_addrlen;
	msgh.msg_iov = data->iov;
	msgh.msg_iovlen = 2;
	fprintf(stderr, "sendmsg wants to write %zu bytes\n", data->iov[0].iov_len + data->iov[1].iov_len);
	if ((byt = sendmsg(sock, &msgh, 0) == -1))
		perror("sendmsg()");
	else
		fprintf(stderr, "sendmsg wrote %zi bytes\n", byt);
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
