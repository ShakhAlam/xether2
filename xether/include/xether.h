#ifndef XETHER_H_INCLUDED
#define XETHER_H_INCLUDED

#include "xlayer.h"
#include "macaddr.h"

#define ETHER_PRINT_BUF 256
#define XETHER_MTU 1514


struct layer *alloc_ether(struct layer *m,size_t len);
struct layer *ether_decode(const char *buf,size_t len);
int ethersrcmp( struct ether_header *e1, struct ether_header *e2);
int etherdstcmp( struct ether_header *e1, struct ether_header *e2);
int ethersetsrc( struct ether_header *etp, const struct MAC *src);
int ethersetdst( struct ether_header *etp, const struct MAC *dst);

int ether_set(struct ether_header *etp, 
	 			  const struct MAC *src, 
	           const struct MAC *dst, 
	           uint16_t ether_type);
	           
char *
ethersprint(char *buf, size_t n,struct layer *m);
void 
etherprint(struct layer *m);


#endif

