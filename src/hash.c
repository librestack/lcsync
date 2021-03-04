/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include "hash.h"
#include "log.h"
#ifdef HASH_BLAKE3
#include <assert.h>
#include <stdio.h>
#endif

#ifndef sodium_bin2hex
/* Derived from original code by CodesInChaos
 * sodium_bin2hex() from libsodium
 * License: ISC */
char * sodium_bin2hex(char *const hex, const size_t hex_maxlen,
	const unsigned char *const bin, const size_t bin_len)
{
	size_t       i = (size_t) 0U;
	unsigned int x;
	int          b;
	int          c;

	assert (bin_len >= SIZE_MAX / 2 || hex_maxlen <= bin_len * 2U); // sodium_misuse()
	while (i < bin_len) {
		c = bin[i] & 0xf;
		b = bin[i] >> 4;
		x = (unsigned char) (87U + c + (((c - 10U) >> 8) & ~38U)) << 8 |
		    (unsigned char) (87U + b + (((b - 10U) >> 8) & ~38U));
		hex[i * 2U] = (char) x;
		x >>= 8;
		hex[i * 2U + 1U] = (char) x;
		i++;
	}
	hex[i * 2U] = 0U;

	return hex;
}
#endif

void hash_hex_debug(unsigned char *hash, size_t len)
{
	char hex[HEXLEN];
	sodium_bin2hex(hex, HEXLEN, hash, len);
	DEBUG("%s", hex);
}

int hash_generic_key(unsigned char *hash, size_t hashlen, unsigned char *in, size_t inlen, unsigned char *key, size_t keylen)
{
#ifdef HASH_BLAKE3
	(void)keylen; /* unused */
	blake3_hasher hasher;
	//assert(keylen == 32);
	blake3_hasher_init_keyed(&hasher, key);
	blake3_hasher_update(&hasher, in, inlen);
	blake3_hasher_finalize(&hasher, hash, hashlen);
	return 0;
#else
	return crypto_generichash(hash, hashlen, in, inlen, key, keylen);
#endif
}

int hash_generic(unsigned char *hash, size_t hashlen, unsigned char *in, size_t inlen)
{
#ifdef HASH_BLAKE3
	blake3_hasher hasher;
	blake3_hasher_init(&hasher);
	blake3_hasher_update(&hasher, in, inlen);
	blake3_hasher_finalize(&hasher, hash, hashlen);
	return 0;
#else
	return hash_generic_key(hash, hashlen, in, inlen, NULL, 0);
#endif
}

void hash_generic_final(hash_state *state, unsigned char *hash, size_t hashlen)
{
#ifdef HASH_BLAKE3
	blake3_hasher_finalize(state, hash, hashlen);
#else
	crypto_generichash_final(state, hash, hashlen);
#endif
}

void hash_generic_update(hash_state *state, unsigned char *in, size_t inlen)
{
#ifdef HASH_BLAKE3
	blake3_hasher_update(state, in, inlen);
#else
	crypto_generichash_update(state, in, inlen);
#endif
}

void hash_generic_init(hash_state *state, unsigned char *key, size_t keylen, size_t hashlen)
{
#ifdef HASH_BLAKE3
	(void) hashlen;
	if (key) {
		assert(keylen == 32);
		blake3_hasher_init_keyed(state, key);
	}
	else {
		blake3_hasher_init(state);
	}
#else
	crypto_generichash_init(state, key, keylen, hashlen);
#endif
}
