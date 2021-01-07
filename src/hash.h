/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _HASH_H
#define _HASH_H 1

#include <sodium.h>
#define HASHSIZE crypto_generichash_BYTES
#define HEXLEN HASHSIZE * 2 + 1

#endif /* _HASH_H */
