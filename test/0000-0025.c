/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/job.h"
#include <errno.h>
#include <unistd.h>

char *flintstone;

void *test_f(void *arg)
{
	flintstone = (char *)arg;
	return arg;
}

int main()
{
	char barney[] = "Barney";
	char wilma[] = "Wilma";
	char betty[] = "Betty";
	char fred[] = "Fred";
	job_t *job;
	job_queue_t *q = NULL;

	test_name("job_queue_create() / job_push_new() / job_shift() etc.");

	flintstone = barney;

	/* create queue with no threads */
	q = job_queue_create(0);
	test_assert(q != NULL, "queue created");

	/* push on some jobs */
	job_t *j1 = job_push_new(q, &test_f, wilma, NULL);
	test_assert(q->next == j1, "(1) q->next set");
	test_assert(q->last == j1, "(1) q->last set");
	job_t *j2 = job_push_new(q, &test_f, betty, NULL);
	test_assert(q->next == j1, "(2) q->next set");
	test_assert(q->last == j2, "(2) q->last set");
	job_t *j3 = job_push_new(q, &test_f, fred, NULL);
	test_assert(q->next == j1, "(3) q->next set");
	test_assert(q->next->next == j2, "(3) q->next->next set");
	test_assert(q->last == j3, "(3) q->last set");

	/* shift them back off and check values */
	job = job_shift(q);
	test_assert(job->f == &test_f, "(1) job function set");
	test_assert(job->arg == wilma, "(1) job arg set: '%s'", job->arg);
	free(job);
	job = job_trywait(q);
	test_assert(job->f == &test_f, "(2) job function set");
	test_assert(job->arg == betty, "(2) job arg set: '%s'", job->arg);
	free(job);
	job = job_wait(q);
	test_assert(job->f == &test_f, "(3) job function set");
	test_assert(job->arg == fred, "(3) job arg set: '%s'", job->arg);
	free(job);
	job = job_trywait(q);
	test_assert(job == NULL, "no more jobs on queue");
	job_queue_destroy(q);

	/* create a single thread so we have a deterministic order for jobs */
	q = job_queue_create(1);
	test_assert(q != NULL, "queue created");
	job_push_new(q, &test_f, fred, &free);		/* free first two jobs */
	job_push_new(q, &test_f, wilma, &free);
	job = job_push_new(q, &test_f, betty, NULL);	/* don't free this, we need it */
	sem_wait(&job->done); /* wait on this last job */
	free(job);
	job = job_trywait(q);
	test_assert(job == NULL, "no more jobs on queue");
	test_assert(strcmp(flintstone, betty) == 0, "resident Flintstone is %s", flintstone);
	job_queue_destroy(q);

	/* create a bunch of threads and jobs */
	q = job_queue_create(16);
	for (int i = 0; i < 25; i++) {
		job_push_new(q, &test_f, fred, &free);
		job_push_new(q, &test_f, wilma, &free);
	}
	job = job_new(&test_f, betty, NULL, 0);
	test_assert(job_push(q, job) == job, "job_push()");
	sem_wait(&job->done); /* wait on last job */
	free(job);
	job = job_trywait(q);
	test_assert(job == NULL, "no more jobs on queue");
	job_queue_destroy(q);
	return fails;
}
