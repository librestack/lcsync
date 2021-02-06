/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/mld.h"

int main(void)
{
	const int interfaces = 1;
	mld_t *mld;
	test_name("mld_listen_report()");
	mld = mld_init(interfaces);
	// TODO create MLD2_LISTEN_REPORT
	// TODO process MLD2_LISTEN_REPORT with state machine
	mld_free(mld);
	return fails;
}
