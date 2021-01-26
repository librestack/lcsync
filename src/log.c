/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * log.c
 *
 * this file is part of LIBRESTACK
 *
 * Copyright (c) 2012-2020 Brett Sheffield <bacs@librecast.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING in the distribution).
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <semaphore.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include "log.h"

#define LOG_BUFSIZE 128

unsigned int loglevel = LOG_LOGLEVEL_DEFAULT;
static int uselock;
static sem_t loglock;

void loginit(void)
{
	uselock = 1;
	sem_init(&loglock, 0, 1);
}

void logwait(void)
{
	if (uselock) sem_wait(&loglock);
}

void logdone(void)
{
	if (uselock) sem_post(&loglock);
}

void logmsg(unsigned int level, const char *fmt, ...)
{
	int len;
	char *mbuf = NULL;
	char buf[LOG_BUFSIZE];
	char *b = buf;
	va_list argp;
	if ((level & loglevel) != level) return;
	va_start(argp, fmt);
	len = vsnprintf(buf, LOG_BUFSIZE, fmt, argp);
	if (len > LOG_BUFSIZE) {
		/* need a bigger buffer, resort to malloc */
		mbuf = malloc(len + 1);
		va_end(argp);
		va_start(argp, fmt);
		vsprintf(mbuf, fmt, argp);
		b = mbuf;
	}
	va_end(argp);
	if (uselock) logwait();
	if (level == LOG_INFO)
		fprintf(stdout, "%s\n", b);
	else
		fprintf(stderr, "%s\n", b);
	if (uselock) logdone();
	free(mbuf);
}
