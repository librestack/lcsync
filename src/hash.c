/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include "hash.h"
#include "log.h"

void hash_hex_debug(unsigned char *hash, size_t len)
{
	char hex[HEXLEN];
	sodium_bin2hex(hex, HEXLEN, hash, len);
	DEBUG("%s", hex);
}

int hash_generic_key(unsigned char *hash, size_t hashlen, unsigned char *in, size_t inlen, unsigned char *key, size_t keylen)
{
	return crypto_generichash(hash, hashlen, in, inlen, key, keylen);
}

int hash_generic(unsigned char *hash, size_t hashlen, unsigned char *in, size_t inlen)
{
	return hash_generic_key(hash, hashlen, in, inlen, NULL, 0);
}
