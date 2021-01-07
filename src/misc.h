/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _LIBRESTACK_MISC_H__
#define _LIBRESTACK_MISC_H__ 1

#include <stdint.h>

/* return next highest power of two */
uint32_t next_pow2(uint32_t v);

/* return size of buffer to allocate for vsnprintf() */
int _vscprintf (const char * format, va_list argp);

#endif /* _LIBRESTACK_MISC_H__ */
