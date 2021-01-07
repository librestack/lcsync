/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include <err.h>
#include <errno.h>
#include <libgen.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "file.h"

static void print_usage_and_exit(char *progname, int rc)
{
	errx(rc, "usage: '%s source destination'", basename(progname));
}

int main(int argc, char **argv)
{
	struct stat sb[2];
	if (argc != 3)
		print_usage_and_exit(argv[0], EXIT_FAILURE);
	if (sodium_init() == -1) {
		perror("sodium_init()");
		_exit(EXIT_FAILURE);
	}
	if (strcmp(argv[1], "--hex") == 0) {
		file_dump(argv[2]);
		_exit(EXIT_SUCCESS);
	}
	for (int i = 0; i < 2; i++) {
		if (stat(argv[i+1], &sb[i])) {
			if (!(i % 2))
				err(EXIT_FAILURE, "stat()");
		}
		switch (sb[i].st_mode & S_IFMT) {
			case S_IFREG:
				break;
			default:
				if (!i) {
					err(EXIT_FAILURE, "source and destination must "
						"be a regular file\n");
					return 1;
				}
		}
	}
	return file_sync(argv[1], argv[2]);
}
