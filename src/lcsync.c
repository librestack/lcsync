/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2022 Brett Sheffield <bacs@librecast.net> */

#include <errno.h>
#include <sodium.h>
#include <stdlib.h>
#include "arg.h"
#include "file.h"
#include "globals.h"
#include "log.h"

int main(int argc, char *argv[])
{
	loginit();
	if ((arg_parse(&argc, &argv)))
		return EXIT_FAILURE;
	return action(&argc, argv);
}
