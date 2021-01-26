/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _HASH_H
#define _HASH_H 1

#include <sodium.h>
#define HASHSIZE crypto_generichash_BYTES
#define HEXLEN HASHSIZE * 2 + 1

void hash_hex_debug(unsigned char *hash, size_t len);

#endif /* _HASH_H */
