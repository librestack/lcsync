/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/file.h"
#include "../src/mtree.h"
#include <errno.h>
#include <unistd.h>

int main()
{
	test_name("file_sync()");

	const size_t nchunks = 127;
	const size_t blocksz = file_chunksize();
	FILE *fds, *fdd;
	char src[] = "0000-0012.src.tmp.XXXXXX";
	char dst[] = "0000-0012.dst.tmp.XXXXXX";
	test_assert(mkstemp(src) != -1, "mkstemp()");
	size_t byt;
	size_t off = strlen(src) - 6;
	memcpy(dst + off, src + off, 6);

	/* write some data chunks */
	fds = fopen(src, "w");
	char *data = calloc(1, blocksz);
	for (size_t i = 1; i <= nchunks; i++) {
		data[0] = (char)i;
		fwrite(data, 1, blocksz, fds);
	}
	fwrite(data, 1, 17, fds); /* write a few extra bytes */
	fclose(fds);

	/* sync the files */
	char *argv[] = { src, dst, NULL };
	int argc = sizeof argv / sizeof argv[0];
	file_sync(&argc, argv);

	/* verify data matches */
	fdd = fopen(dst, "r");
	test_assert(fdd != NULL, "destination file '%s' does not exist", dst);
	if (fdd) {
		for (size_t i = 1; i <= nchunks; i++) {
			byt = fread(data, 1, blocksz, fdd);
			test_assert(byt == blocksz, "%zu/%zu bytes read", byt, blocksz);
			test_assert(data[0] == (char)i, "reading chunk %zu", i);
		}
		byt = fread(data, 1, 17, fdd);
		test_assert(byt == 17, "check we got last bytes");
		fclose(fdd);

		/* scribble on the destination */
		fdd = fopen(dst, "r+");
		test_assert(fseek(fdd, blocksz * 7, SEEK_SET) != -1, "fseek()");
		test_assert(fputc('x', fdd) == 'x', "fputc()");
		test_assert(fseek(fdd, blocksz * 3, SEEK_SET) != -1, "fseek()");
		test_assert(fputc('x', fdd) == 'x', "fputc()");
		test_assert(fseek(fdd, blocksz * 11, SEEK_SET) != -1, "fseek()");
		test_assert(fputc('x', fdd) == 'x', "fputc()");
		test_assert(fputc('y', fdd) == 'y', "fputc()");
		test_assert(fputc('z', fdd) == 'z', "fputc()");
		fclose(fdd);

		/* re-sync, checking it took one round per chunk */
		test_assert(file_sync(&argc, argv) == 3, "file_sync() - resync");

		/* check matched */
		fdd = fopen(dst, "r");
		for (size_t i = 1; i <= nchunks; i++) {
			byt = fread(data, 1, blocksz, fdd);
			test_assert(byt == blocksz, "%zu/%zu bytes read", byt, blocksz);
			test_assert(data[0] == (char)i, "reading chunk %zu", i);
		}
		byt = fread(data, 1, 17, fdd);
		test_assert(byt == 17, "check we got last bytes");
		fclose(fdd);
	}
	free(data);

	return fails;
}
