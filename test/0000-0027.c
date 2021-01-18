/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/job.h"
#include "../src/net.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#if 0
static int keep_sending = 1;
void *do_recv(void *arg)
{
	net_data_t *data = (net_data_t *)arg;
	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_channel_t *chan = lc_channel_nnew(lctx, data->hash, HASHSIZE);
	lc_channel_bind(sock, chan);
	lc_channel_join(chan);
	int s = lc_socket_raw(sock);
	net_recv_data(s, data);
	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);
	return NULL;
}

void *do_send(void *arg)
{
	const int on = 1;
	net_data_t *data = (net_data_t *)arg;
	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &on, sizeof(on));
	lc_channel_t *chan = lc_channel_nnew(lctx, data->hash, HASHSIZE);
	lc_channel_bind(sock, chan);
	int s = lc_channel_socket_raw(chan);
	struct addrinfo *addr = lc_channel_addrinfo(chan);
	while (keep_sending) {
		net_send_data(s, addr, data);
		usleep(100);
	}
	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);
	return NULL;
}
#endif

int main(void)
{
#if 0
	struct timespec timeout;
	job_queue_t *jobq;
	job_t *job_send, *job_recv;
	net_data_t *odat;
	net_data_t *idat;
	char question[] = "Life, the Universe and Everything";
	char answer[42] = "42";
	char *ptr = answer;
	size_t sz = strlen(question);
	unsigned char hash[HASHSIZE];
#endif
	return test_skip("net_send_data() / net_recv_data()");
#if 0
	// TODO: write librecast function to use supplied hash
	crypto_generichash(hash, HASHSIZE, (unsigned char *)question, sz, NULL, 0);

	/* set up send / recv data structures */
	odat = net_chunk(hash, sz, question, 42);
	idat = net_chunk(hash, sz, ptr, 1);

	/* queue up send / recv jobs */
	jobq = job_queue_create(2);
	job_send = job_push_new(jobq, &do_send, odat, NULL, 0);
	job_recv = job_push_new(jobq, &do_recv, idat, NULL, 0);

	/* wait for recv job to finish, check for timeout */
	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec++;
	test_assert(!sem_timedwait(&job_recv->done, &timeout), "timeout - recv");
	free(job_recv);

	keep_sending = 0; /* stop send job */

	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec++;
	test_assert(!sem_timedwait(&job_send->done, &timeout), "timeout - send");
	free(job_send);

	test_expect(question, answer);

	/* check block index */
	uint64_t idx = be64toh(idat->idx);
	test_assert(idx == 42, "answer to the ultimate question: %zu", idx);

	job_queue_destroy(jobq);
	free(odat);
	free(idat);
#endif
	return fails;
}
