/* global defaults */

#include <stddef.h>
#include "globals.h"

int (*action)(int *argc, char *argv[]);
int hex;
char *progname;
size_t blocksize = 1024;
uint8_t net_send_channels = 3;
