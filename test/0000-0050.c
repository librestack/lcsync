/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld.h"
#include <librecast.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int main(void)
{
	vec_t grp[BLOOM_VECTORS] = {0};
	test_name("vec_get_epi8() / vec_set_epi8() / vec_inc_epi8() / vec_dec_epi8()");
	test_assert(vec_get_epi8(grp, 42) == 0, "vec_get_epi8(0) - init");
	vec_set_epi8(grp, 42, 41);
	test_assert(vec_get_epi8(grp, 42) == 41, "vec_get_epi8(42) - set");
	vec_inc_epi8(grp, 42);
	test_assert(vec_get_epi8(grp, 42) == 42, "vec_get_epi8(42) - inc");
	vec_dec_epi8(grp, 42);
	test_assert(vec_get_epi8(grp, 42) == 41, "vec_get_epi8(41) - dec");
	return fails;
}
