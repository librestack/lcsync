/* global defaults */

#include <stddef.h>

int (*action)(int *argc, char *argv[]);
int hex;
char *progname;
size_t net_send_channels = 3;
