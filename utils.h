#pragma once

#include <sys/types.h>
#include <stdint.h>

#define min(a,b) ((a) < (b) ? (a) : (b))
int new_ll_socket(char *device);
uint16_t checksum(u_char *data, size_t len);
uint16_t checksum2(u_char *data1, size_t len1, u_char *data2, size_t len2);
void dumpascii(char *data, size_t len);
void hexdump(char *data, size_t len);
