/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * log.h
 *
 * this file is part of LIBRESTACK
 *
 * Copyright (c) 2012-2021 Brett Sheffield <bacs@librecast.net>
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

#ifndef __LSD_LOG
#define __LSD_LOG 1

#define DEBUG_ON 1

#define LOG_LEVELS(X) \
	X(0,    LOG_NONE,       "none")                                 \
	X(1,    LOG_SEVERE,     "severe")                               \
	X(2,    LOG_ERROR,      "error")                                \
	X(4,    LOG_WARNING,    "warning")                              \
	X(8,    LOG_INFO,       "info")                                 \
	X(16,   LOG_TRACE,      "trace")                                \
	X(32,   LOG_FULLTRACE,  "fulltrace")                            \
	X(64,   LOG_DEBUG,      "debug")
#undef X

#define LOG_ENUM(id, name, desc) name = id,
enum {
	LOG_LEVELS(LOG_ENUM)
};

#define LOG_LOGLEVEL_DEFAULT 15
#define LOG_LOGLEVEL_VERBOSE 127
extern unsigned int loglevel;

#define LOG(lvl, ...) if ((lvl & loglevel) == lvl) logmsg(lvl, __VA_ARGS__)
#define INFO(...) do { LOG(LOG_INFO, __VA_ARGS__); } while(0)
#define ERROR(...) do { LOG(LOG_ERROR, __VA_ARGS__); } while(0)
#define BREAK(lvl, ...) do {LOG(lvl, __VA_ARGS__); break;} while(0)
#define CONTINUE(lvl, ...) do {LOG(lvl, __VA_ARGS__); continue;} while(0)
#define DIE(...) do {LOG(LOG_SEVERE, __VA_ARGS__);  _exit(EXIT_FAILURE);} while(0)

#ifdef DEBUG_ON
#define DEBUG(...) do { if (DEBUG_ON) LOG(LOG_DEBUG, __VA_ARGS__); } while(0)
#else
#define DEBUG(...) while(0)
#endif

#define FMTV(iov) (int)(iov).iov_len, (const char *)(iov).iov_base
#define ERRMSG(err) {LOG(LOG_ERROR, err_msg(err));}
#define FAIL(err) {LOG(LOG_ERROR, err_msg(err));  return err;}
#define FAILMSG(err, ...) do {LOG(LOG_ERROR, __VA_ARGS__);  return err;} while(0)
#define TRACE(...) do {LOG(LOG_TRACE, __VA_ARGS__);} while(0)
#define WARN(...) do {LOG(LOG_WARNING, __VA_ARGS__);} while(0)

/* initialize logger & enable locking (optional) */
void loginit(void);

/* grab the log semaphore */
void logwait(void);

/* release log semaphore */
void logdone(void);

/* format log message */
void logmsg(unsigned int level, const char *fmt, ...)
#ifdef __GNUC__
	__attribute__((format(printf, 2 ,3)))
#endif
;

#endif /* __LSD_LOG */
