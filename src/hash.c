#include "hash.h"
#include "log.h"

void hash_hex_debug(unsigned char *hash, size_t len)
{
	char hex[HEXLEN];
	sodium_bin2hex(hex, HEXLEN, hash, len);
	DEBUG("%s", hex);
}
