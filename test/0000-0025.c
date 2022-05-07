/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/job.h"
#include <errno.h>
#include <unistd.h>

char *flintstone;

void *test_void(void *arg)
{
	return arg;
}

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
	job_t *j1 = job_push_new(q, &test_f, wilma, strlen(wilma), NULL, 0);
	test_assert(q->next == j1, "(1) q->next set");
	test_assert(q->last == j1, "(1) q->last set");
	job_t *j2 = job_push_new(q, &test_f, betty, strlen(betty), NULL, 0);
	test_assert(q->next == j1, "(2) q->next set");
	test_assert(q->last == j2, "(2) q->last set");
	job_t *j3 = job_push_new(q, &test_f, fred, strlen(fred), NULL, 0);
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
	job_push_new(q, &test_f, fred, strlen(fred), &free, 0);		/* free first two jobs */
	job_push_new(q, &test_f, wilma, strlen(wilma), &free, 0);
	job = job_push_new(q, &test_f, betty, strlen(betty), NULL, 0);	/* don't free this, we need it */
	sem_wait(&job->done); /* wait on this last job */
	free(job);
	job = job_trywait(q);
	test_assert(job == NULL, "no more jobs on queue");
	test_assert(strcmp(flintstone, betty) == 0, "resident Flintstone is %s", flintstone);
	job_queue_destroy(q);

	/* create a bunch of threads and jobs */
	q = job_queue_create(16);
	for (int i = 0; i < 25; i++) {
		job_push_new(q, &test_f, fred, strlen(fred), &free, 0);
		job_push_new(q, &test_f, wilma, strlen(wilma), &free, 0);
	}
	job = job_new(&test_f, betty, strlen(betty), NULL, 0);
	test_assert(job_push(q, job) == job, "job_push()");
	sem_wait(&job->done); /* wait on last job */
	free(job);
	job = job_trywait(q);
	test_assert(job == NULL, "no more jobs on queue");
	job_queue_destroy(q);

	int i = 2;
	q = job_queue_create(1);
	job = job_new(&test_void, &i, sizeof i, NULL, JOB_COPY|JOB_FREE);
	test_assert(job_push(q, job) == job, "job_push()");
	sem_wait(&job->done); /* wait on last job */
	free(job);
	job_queue_destroy(q);

	/* push 8 jobs without JOB_COPY, followed by 8 with it set */
	q = job_queue_create(0);
	for (int i = 0; i < 8; i++) {
		job_push_new(q, NULL, &i, sizeof i, NULL, 0);
	}
	for (int i = 0; i < 8; i++) {
		job_push_new(q, NULL, &i, sizeof i, NULL, JOB_COPY);
	}
	/* without the JOB_COPY flag, we always get back the last value of i=8 */
	for (int i = 0; i < 8; i++) {
		job = job_shift(q);
		test_assert(*(int *)job->arg == 8, "job->arg (orig) is %i", *(int *)job->arg);
		free(job);
	}
	/* verify JOB_COPY gives us a correct (unchanged) copy back */
	for (int i = 0; i < 8; i++) {
		job = job_shift(q);
		test_assert(*(int *)job->arg == i, "job->arg (copy) is %i", *(int *)job->arg);
		free(job->arg);
		free(job);
	}
	job_queue_destroy(q);

	/* shift all jobs from queue, then add more */
	q = job_queue_create(1);
	for (int i = 0; i < 8; i++) {
		job_push_new(q, NULL, &i, sizeof i, &free, 0);
	}
	job = job_push_new(q, NULL, &i, sizeof i, NULL, 0);
	sem_wait(&job->done);
	free(job);
	test_assert(q->next == NULL, "q->next == NULL");
	test_assert(q->last == NULL, "q->last == NULL");
	job = job_push_new(q, NULL, &i, sizeof i, NULL, 0);
	sem_wait(&job->done);
	free(job);
	job_queue_destroy(q);

	return fails;
}
