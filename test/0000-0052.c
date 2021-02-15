/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld.h"
#include "../src/job.h"
#include <librecast.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

struct mld_filter_s {
	vec_t   grp[BLOOM_VECTORS];
	vec_t   t[BLOOM_VECTORS];
};

struct mld_s {
	int sock;
	job_queue_t *timerq;
	int len;
	mld_filter_t filter[];
};

unsigned int vec_pop(vec_t *v)
{
	unsigned int pop = 0;
	for (int i = 0; i < BLOOM_VECTORS; i++) {
		for (int j = 0; j < 16; j++) {
			pop += __builtin_popcount(v[i].u8[j]);
		}
	}
	return pop;
}

int main(void)
{
	unsigned pop;
	test_name("mld_timer_tick() - decrement bloom timers");
	mld_t *mld = mld_init(1);

	/* make sure we start at zero */
	pop = vec_pop(mld->filter[0].t);
	test_assert(pop == 0, "pop == %u", pop);

	/* timer tick on zero vectors has no effect */
	mld_timer_tick(mld, 0, 0, 0);
	pop = vec_pop(mld->filter[0].t);
	test_assert(pop == 0, "pop == %u", pop);

	/* set a timer, check pop has gone up */
	mld_timer_refresh(mld, 0, 42, 0);
	pop = vec_pop(mld->filter[0].t);
	test_assert(pop > 0, "pop == %u", pop);

	/* tick down the timer to zero and check again */
	for (int i = 0; i < MLD_TIMEOUT; i++) {
		mld_timer_tick(mld, 0, 0, 0);
	}
	pop = vec_pop(mld->filter[0].t);
	test_assert(pop == 0, "pop == %u", pop);

	mld_free(mld);
	return fails;
}
