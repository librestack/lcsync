/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/globals.h"
#include "../src/log.h"
#include "../src/job.h"
#include "../src/net.h"
#include <errno.h>
#include <bsd/md5.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "valgrind.h"

const int waits = 1;
const int waits_valgrind = 25; // high for valgrind

typedef struct arg_s {
	int argc;
	char **argv;
} arg_t;

static void do_verify(char *src, char *dst)
{
	char *sbuf = NULL;
	char *dbuf = NULL;
	char *shash, *dhash;
	test_assert((shash = MD5File(src, sbuf)) != NULL, "MD5File(%s) - src file exists", src);
	test_assert((dhash = MD5File(dst, dbuf)) != NULL, "MD5File(%s) - dst file exists", dst);
	if (shash && dhash)
		test_assert(!memcmp(shash, dhash, MD5_DIGEST_STRING_LENGTH), "source and destination match");
	free(shash);
	free(dhash);
}

static void absname(char *file, char *buf, size_t buflen)
{
	size_t len;
	test_assert(getcwd(buf, buflen) != NULL, "getcwd()");
	len = strlen(buf);
	buf[len] = '/';
	strcpy(buf + len + 1, file);
}

static void *do_recv(void *arg)
{
	int argc = 2;
	char *src = ((char **)arg)[0];
	char dst[PATH_MAX];
	char *argv[] = { src, dst, NULL };
	absname(((char **)arg)[1], dst, PATH_MAX);
	net_sync(&argc, argv);
	return NULL;
}

static void *do_send(void *arg)
{
	int argc = 1;
	char src[PATH_MAX];
	char *argv[] = { src, NULL };
	absname((char *)arg, src, PATH_MAX);
	net_send(&argc, argv);
	return NULL;
}

static void do_sync(char *src, char *dst)
{
	char *arg[2] = { src, dst };
	struct timespec timeout;
	job_queue_t *q = job_queue_create(2);

	/* queue up send/recv jobs */
	job_t *job_send = job_push_new(q, &do_send, src, sizeof src, NULL, 0);
	job_t *job_recv = job_push_new(q, &do_recv, arg, sizeof arg, NULL, 0);

	/* wait for recv job to finish, check for timeout */
	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	if (RUNNING_ON_VALGRIND)
		timeout.tv_sec += waits_valgrind;
	else
		timeout.tv_sec += waits;
	test_assert(!sem_timedwait(&job_recv->done, &timeout), "timeout - recv");
	free(job_recv);

	/* stop send job */
	net_stop(SIGINT);
	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	timeout.tv_sec++;
	test_assert(!sem_timedwait(&job_send->done, &timeout), "timeout - send");
	free(job_send);
	job_queue_destroy(q);
}

static void gentestfiles(char *src, char *dst)
{
	const size_t nchunks = 127;
	const size_t blocksz = blocksize;
	FILE *fds;
	test_assert(mkstemp(src) != -1, "mkstemp()");
	size_t off = strlen(src) - 6;
	memcpy(dst + off, src + off, 6);
	fds = fopen(src, "w");
	char *data = calloc(1, blocksz);
	for (size_t i = 1; i <= nchunks; i++) {
		data[0] = (char)i;
		fwrite(data, 1, blocksz, fds);
	}
	fwrite(data, 1, 17, fds); /* write a few extra bytes */
	fclose(fds);
	free(data);
}

int main(void)
{
	loginit();
	char src[] = "0000-0027.src.tmp.XXXXXX";
	char dst[] = "0000-0027.dst.tmp.XXXXXX";
	test_name("net_send() / net_sync()");
	gentestfiles(src, dst);
	do_sync(src, dst);
	do_verify(src, dst);
	return fails;
}
