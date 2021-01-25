/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include <errno.h>
#include <sodium.h>
#include <stdlib.h>
#include "arg.h"
#include "file.h"
#include "log.h"
#include "globals.h"

int main(int argc, char *argv[])
{
	if ((arg_parse(&argc, &argv)))
		return EXIT_FAILURE;
	if (sodium_init() == -1) {
		perror("sodium_init()");
		return EXIT_FAILURE;
	}
	DEBUG("loglevel=%u", loglevel);
	return action(&argc, argv);
}
