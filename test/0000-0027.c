/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/globals.h"
#include "../src/log.h"
#include "../src/job.h"
#include "../src/net.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "valgrind.h"

static off_t filesize = 4194304; /* 4KiB */
const int waits = 3;
const int waits_valgrind = 25; // high for valgrind

typedef struct arg_s {
	int argc;
	char **argv;
} arg_t;

static void verify_test_files(char *src, char *dst)
{
	struct stat ssb = {0};
	struct stat dsb = {0};
	char *smap, *dmap;
	int fds, fdd;

	/* open src */
	fds = open(src, O_RDONLY, 0);
	test_assert(fds != -1, "open() src '%s'", src);
	if (fds == -1) return;

	/* open dst */
	fdd = open(dst, O_RDONLY, 0);
	if (fdd == -1) perror("open");
	test_assert(fdd != -1, "open() dst '%s'", dst);
	if (fdd == -1) return;

	/* map src */
	fstat(fds, &ssb);
	smap = mmap(NULL, ssb.st_size, PROT_READ, MAP_SHARED, fds, 0);
	if (smap == MAP_FAILED) perror("mmap");
	test_assert(smap != MAP_FAILED, "mmap() src");

	/* map dst */
	fstat(fdd, &dsb);
	dmap = mmap(NULL, dsb.st_size, PROT_READ, MAP_SHARED, fdd, 0);
	if (dmap == MAP_FAILED) perror("mmap");
	test_assert(dmap != MAP_FAILED, "mmap() dst");

	/* verify src and dst match */
	test_assert(ssb.st_size == dsb.st_size, "src and dst sizes match");
	if (ssb.st_size != dsb.st_size) return;
	test_assert(!memcmp(smap, dmap, ssb.st_size), "source and destination match");

	/* clean up */
	munmap(dmap, dsb.st_size);
	munmap(smap, ssb.st_size);
	close(fdd);
	close(fds);
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
	char src[PATH_MAX];
	char dst[PATH_MAX];
	char *argv[] = { src, dst, NULL };
	size_t len;
	absname(((char **)arg)[0], src, PATH_MAX);
	absname(((char **)arg)[1], dst, PATH_MAX);
	len = strlen(src) - 1;
	memmove(src, src + 1, len);
	src[len] = 0;
	sleep(1);
	test_log("requesting '%s'\n", src);
	test_log("writing to '%s'\n", dst);
	net_sync(&argc, argv);
	test_log("receive job exiting\n");
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

static void sync_files(char *src, char *dst)
{
	char *arg[2] = { src, dst };
	struct timespec timeout;
	job_queue_t *q = job_queue_create(2);

	/* queue up send/recv jobs */
	job_t *job_recv = job_push_new(q, &do_recv, arg, sizeof arg, NULL, 0);
	job_t *job_send = job_push_new(q, &do_send, src, sizeof src, NULL, 0);

	/* wait for recv job to finish, check for timeout */
	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	if (RUNNING_ON_VALGRIND)
		timeout.tv_sec += waits_valgrind;
	else
		timeout.tv_sec += waits;
	test_assert(!sem_timedwait(&job_recv->done, &timeout), "timeout - recv");

	/* stop send job */
	net_stop(SIGINT);
	test_assert(!clock_gettime(CLOCK_REALTIME, &timeout), "clock_gettime()");
	free(job_send);
	job_queue_destroy(q);
}

static int generate_test_files(char *src, char *dst)
{
	ssize_t byt, tot = 0;
	off_t off;
	char buf[blocksize];
	int fds, fdr;

	/* create and map src file */
	fds = mkstemp(src);
	test_assert(fds != -1, "mkstemp()");

	/* copy random bytes to src */
	if ((fdr = open("/dev/random", O_RDONLY, 0)) == -1) {
		perror("open /dev/random");
		return -1;
	}
	while (tot < filesize) {
		size_t len = filesize - tot;
		if (len > sizeof buf) len = sizeof buf;
		byt = read(fdr, buf, len);
		if (byt == -1) {
			perror("read random bytes");
			return -1;
		}
		tot += byt;
		if (write(fds, buf, len) != (ssize_t)len) {
			perror("write");
			return -1;
		}
	}
	close(fdr);

	/* set dst filename */
	off = strlen(src) - 6;
	memcpy(dst + off, src + off, 6);

	return 0;
}

int main(void)
{
	char src[] = "0000-0027.src.tmp.XXXXXX";
	char dst[] = "0000-0027.dst.tmp.XXXXXX";
	int rc = 0;

	loginit();
	test_name("net_send() / net_sync()");

	rc = generate_test_files(src, dst);
	test_assert(rc != -1, "generate_test_files()");
	if (rc == -1) return fails;

	sync_files(src, dst);

	verify_test_files(src, dst);

	test_rusage();

	return fails;
}
