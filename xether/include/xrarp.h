#ifndef XLAYER_XARP_HINCLUDED
#define XLAYER_XARP_HINCLUDED

#include "xlayer.h"
#include "datalink.h"
#include "macaddr.h"
#include <time.h>

#define ARP_PRINT_BUF 256
struct layer *alloc_rarp(struct layer *m,size_t len);
struct layer *rarp_decode(const char *buf,size_t len);
char*
rarpsprint(char *buf, size_t n, struct layer *m);

void
rarpprint(struct layer *m);

int
RARPReply(struct datalink *dl,struct MAC *srcmac, uint32_t srcip,struct MAC *dstmac, uint32_t dstip);

int
RARPRequest(struct datalink *dl,struct MAC *srcmac, struct MAC *dstmac, uint32_t srcip, uint32_t dstip, int timeout);

int
rarp_set(struct ether_arp *arph,
			uint16_t hrd,  /* hardware type. (0x01)*/
			uint16_t pro,  /* protocol type. (ETHERTYPE)*/ 
			uint8_t hln,	/* hardware address length. (6)*/
			uint8_t pln,	/* protocol address length. (4)*/
			uint16_t op,	/* operation code. (ARPOP_[REQUEST|REPLY])*/
		   struct MAC *sha, /* source hardware address. if NULL its set to zero. */
		   uint32_t spa, 	/* source protocol address. */
		   struct MAC *tha, /* target hardware address. if NULL its set to zero. */
		   uint32_t tpa); 	/* target protocol address. */ 

#endif

