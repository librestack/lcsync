/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020-2022 Brett Sheffield <bacs@librecast.net> */

#ifndef _LIBRESTACK_MISC_H__
#define _LIBRESTACK_MISC_H__ 1

#include <stdarg.h>
#include <stdint.h>

#define verify_expr(R, E) \
	(_GL_VERIFY_TRUE (R, "verify_expr (" #R ", " #E ")") ? (E) : (E))

/* return next highest power of two */
uint32_t next_pow2(uint32_t v);

/* return size of buffer to allocate for vsnprintf() */
int _vscprintf (const char * format, va_list argp);

#endif /* _LIBRESTACK_MISC_H__ */
