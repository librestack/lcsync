/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/log.h"
#include <semaphore.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>

int fails = 0;
sem_t log_lock;

void vfail_msg(char *msg, va_list argp)
{
	char *b;
	b = malloc(_vscprintf(msg, argp) + 1);
	vsprintf(b, msg, argp);
	printf("\n            %-70s", b);
	free(b);
	fails++;
}

void fail_msg(char *msg, ...)
{
	va_list argp;
	va_start(argp, msg);
	vfail_msg(msg, argp);
	va_end(argp);
}

void test_assert(int condition, char *msg, ...)
{
	char *b;
	va_list argp;
	va_start(argp, msg);
	b = malloc(_vscprintf(msg, argp) + 1);
	vsprintf(b, msg, argp);
	va_end(argp);
	test_log("%s(): %s\n", __func__, b);
	va_start(argp, msg);
	if (!condition) {
		vfail_msg(msg, argp);
	}
	va_end(argp);
	free(b);
}

void test_sleep(time_t tv_sec, long tv_nsec)
{
	struct timespec ts = { tv_sec, tv_nsec };
	test_log("test thread sleeping");
	nanosleep(&ts, NULL);
	test_log("test thread waking");
}

void test_strcmp(char *str1, char *str2, char *msg, ...)
{
	if (str1 == NULL || str2 == NULL || strcmp(str1, str2)) {
		va_list argp;
		va_start(argp, msg);
		vfail_msg(msg, argp);
		va_end(argp);
	}
}

void test_strncmp(char *str1, char *str2, size_t len, char *msg, ...)
{
	if (str1 == NULL || str2 == NULL || strncmp(str1, str2, len)) {
		va_list argp;
		va_start(argp, msg);
		vfail_msg(msg, argp);
		va_end(argp);
	}
}

void test_expect(char *expected, char *got)
{
	test_strcmp(expected, got, "expected: '%s', got: '%s'", expected, got);
}

void test_expectn(char *expected, char *got, size_t len)
{
	test_strncmp(expected, got, len, "expected: '%s', got: '%s'", expected, got);
}

void test_expectiov(struct iovec *expected, struct iovec *got)
{
	test_assert(expected->iov_len == got->iov_len, "expected '%.*s' (length mismatch) %zu != %zu",
			(int)expected->iov_len, (char *)expected->iov_base,
			expected->iov_len, got->iov_len);
	if (expected->iov_len != got->iov_len) return;
	test_strncmp(expected->iov_base, got->iov_base, expected->iov_len,
			"expected: '%.*s', got: '%.*s'",
			(int)expected->iov_len, (char *)expected->iov_base,
			(int)got->iov_len, (char *)got->iov_base);
}

void test_log(char *msg, ...)
{
	va_list argp;
	sem_wait(&log_lock);
	fprintf(stderr, "%lu: ", clock());
	sem_post(&log_lock);
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
}

void test_name(char *str, ...)
{
	char *b;
	va_list argp;
	loglevel = 127;
	sem_init(&log_lock, 0, 1);
	va_start(argp, str);
	b = malloc(_vscprintf(str, argp) + 1);
	vsprintf(b, str, argp);
	printf("%-70s", b);
	test_log("  (%s)\n", b);
	va_end(argp);
	free(b);
}

int test_skip(char *str, ...)
{
	char *b;
	va_list argp;
	sem_init(&log_lock, 0, 1);
	va_start(argp, str);
	b = malloc(_vscprintf(str, argp) + 1);
	vsprintf(b, str, argp);
	printf("(skipped) %-60s", b);
	test_log("  (%s)", b);
	va_end(argp);
	free(b);
	return 0;
}

void test_rusage()
{
	struct rusage ru = {0};
	if (getrusage(RUSAGE_SELF, &ru)) {
		perror("getrusage");
		return;
	}
	test_log("user  :   %lis.%li\n", ru.ru_utime.tv_sec, ru.ru_utime.tv_usec);
	test_log("system:   %lis.%li\n", ru.ru_stime.tv_sec, ru.ru_stime.tv_usec);
	test_log("maxrss:   %li\n", ru.ru_maxrss);
	test_log("ixrss:    %li\n", ru.ru_ixrss);
	test_log("idrss:    %li\n", ru.ru_idrss);
	test_log("isrss:    %li\n", ru.ru_isrss);
	test_log("minflt:   %li\n", ru.ru_minflt);
	test_log("majflt:   %li\n", ru.ru_majflt);
	test_log("nswap:    %li\n", ru.ru_nswap);
	test_log("inblock:  %li\n", ru.ru_inblock);
	test_log("oublock:  %li\n", ru.ru_oublock);
	test_log("msgsnd:   %li\n", ru.ru_msgsnd);
	test_log("msgrcv:   %li\n", ru.ru_msgrcv);
	test_log("nsignals: %li\n", ru.ru_nsignals);
	test_log("nvcsw:    %li\n", ru.ru_nvcsw);
	test_log("nivcsw:   %li\n", ru.ru_nivcsw);
}
