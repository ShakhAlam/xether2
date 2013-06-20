#ifndef XLAYER_IPADDR_H_INCLUDED
#define XLAYER_IPADDR_H_INCLUDED
#include <stdio.h>
#include "types.h"

#define IP_ADDRSTRLEN 16

uint32_t 		oct_to_ip( const uint8_t oct[4], uint32_t *ipn);
unsigned char* ip_to_oct(uint32_t ipn, uint8_t oct[4]);
char *			ip_to_str(uint32_t ipn, char *buf, size_t n);
int 				str_to_ip(const char *ipstr, uint32_t *ipn);
int 				str_to_ipoct(const char *str, uint8_t oct[4]);
char *			oct_to_ipstr(const uint8_t oct[4], char * buf, size_t n);

#endif
