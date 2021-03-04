/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include <errno.h>
#ifndef HASH_BLAKE3
#include <sodium.h>
#endif
#include <stdlib.h>
#include "arg.h"
#include "file.h"
#include "log.h"
#include "globals.h"

int main(int argc, char *argv[])
{
	loginit();
	if ((arg_parse(&argc, &argv)))
		return EXIT_FAILURE;
#ifdef sodium_init
	if (sodium_init() == -1) {
		perror("sodium_init()");
		return EXIT_FAILURE;
	}
#endif
	DEBUG("loglevel=%u", loglevel);
	DEBUG("blocksize=%zu", blocksize);
	DEBUG("channels=%u", 1U << net_send_channels);
	return action(&argc, argv);
}
