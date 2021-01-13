/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/job.h"
#include "../src/net.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>

void net_stop(int signo);

void *runtest(void *arg)
{
	char invalid[] = "./src_does_not_exist";
	char valid[] = "./0000-0024.c";
	char *arg0[] = { invalid, NULL };
	char *arg1[] = { valid, NULL };
	char **argv = arg0;
	int argc = (int) sizeof arg0 / sizeof arg0[0] - 1;

	test_name("net_stop()");

	test_assert(net_send(&argc, argv) == -1, "net_send() - invalid source file");
	argv = arg1;
	test_assert(net_send(&argc, argv) == 0, "net_send() - valid source file");

	/* we're done here, wake parent thread */
	pthread_kill(*((pthread_t *)arg), SIGINT);
	return NULL;
}

void sigcaught(int signo)
{
	test_log("signal %i caught, test done", signo);
}

int main(void)
{
	void *ret = NULL;
	const int test_timeout = 1;
	struct timespec ts = { test_timeout, 0 };
	struct sigaction sa = { .sa_handler = sigcaught };
	pthread_attr_t attr;
	pthread_t thread;
	pthread_t self = pthread_self();
	pthread_attr_init(&attr);
	sigaction(SIGINT, &sa, NULL);
	pthread_create(&thread, &attr, &runtest, &self);
	net_stop(SIGINT);
	nanosleep(&ts, NULL);
	pthread_cancel(thread);
	pthread_join(thread, &ret);
	test_assert(ret != PTHREAD_CANCELED, "test timeout after %is", test_timeout);
	pthread_attr_destroy(&attr);
	return fails;
}
