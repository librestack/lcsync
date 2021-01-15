/* global defaults */

#include <stddef.h>
#include "globals.h"

int (*action)(int *argc, char *argv[]);
int hex;
char *progname;
size_t blocksize = 4096;
size_t net_send_channels = 7;
