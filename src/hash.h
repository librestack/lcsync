/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _HASH_H
#define _HASH_H 1

#define HASH_BLAKE3 1

#ifdef HASH_BLAKE3
#include <blake3.h>
typedef blake3_hasher hash_state;
#define HASHSIZE BLAKE3_OUT_LEN
#else
#include <sodium.h>
typedef crypto_generichash_state hash_state;
#define HASHSIZE crypto_generichash_BYTES
//#define HASHMAXBYTES crypto_generichash_BYTES_MAX
#endif
#define HEXLEN HASHSIZE * 2 + 1

#ifdef HASH_BLAKE3
char * sodium_bin2hex(char *const hex, const size_t hex_maxlen,
	const unsigned char *const bin, const size_t bin_len);
#endif

void hash_hex_debug(unsigned char *hash, size_t len);

/* wrapper for our hash function, in case we want to change it */
int hash_generic(unsigned char *hash, size_t hashlen, unsigned char *in, size_t inlen);
int hash_generic_key(unsigned char *hash, size_t hashlen, unsigned char *in, size_t inlen, unsigned char *key, size_t keylen);
void hash_generic_init(hash_state *state, unsigned char *key, size_t keylen, size_t hashlen);
void hash_generic_update(hash_state *state, unsigned char *in, size_t inlen);
void hash_generic_final(hash_state *state, unsigned char *hash, size_t hashlen);

#endif /* _HASH_H */
