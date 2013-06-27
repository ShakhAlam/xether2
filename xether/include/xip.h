#ifndef XLAYER_XIP_H
#define XLAYER_XIP_H
 
#include "xlayer.h"
#include "ipaddr.h"

#define IP_PRINT_BUF 256


struct layer *alloc_ip(struct layer *m,size_t len);
struct layer *ip_decode(const char *buf,size_t len);
int	ip_set(struct ip *iph,
				 uint8_t tos, uint16_t len, uint16_t id, 
				 uint16_t off,uint8_t ttl, uint8_t proto, 
				 uint16_t sum, uint32_t src, uint32_t dst);
			

int ip_sum(struct layer *m);
void ipprint(struct layer *m);
char *ipsprint(char *buf, size_t n,struct layer *m);
#endif
