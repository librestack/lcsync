/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/job.h"
#include <errno.h>
#include <unistd.h>

void *test_f(void *arg)
{
	test_log("inside job %02i\n", *(int *)arg);
	return arg;
}

int main()
{
	int i;
	job_t *job;
	job_queue_t *q = NULL;

	test_name("multiple thread job locking tests");

	/* create a bunch of threads and jobs */
	q = job_queue_create(32);
	for (i = 0; i < 16; i++) {
		test_log("pushing job %i\n", i);
		job_push_new(q, &test_f, &i, &free, 0);
	}
	job = job_new(&test_f, &i, NULL, 0);
	test_assert(job_push(q, job) == job, "job_push()");
	sem_wait(&job->done); /* wait on last job */
	free(job);
	job = job_trywait(q);
	test_assert(job == NULL, "no more jobs on queue");
	job_queue_destroy(q);
	return fails;
}
