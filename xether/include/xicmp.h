#ifndef XLAYER_XICMP_HINCLUDED
#define XLAYER_XICMP_HINCLUDED

#include "xlayer.h"

struct icmp_hdr{
	uint8_t icmp_type;
	uint8_t icmp_code;
	uint16_t icmp_cksum;
	uint32_t icmp_idseq;
};

#define ICMP_PRINT_BUF 256

struct layer *alloc_icmp(struct layer *m,size_t len);

struct layer *icmp_decode(const char *buf,size_t len);
void icmpprint(struct layer *m);
char *icmpsprint(char *buf, size_t n, struct layer *m);
int icmp_sum(struct layer *m);
int icmp_set(struct icmp_hdr *icmph,
		uint8_t type, uint8_t code, uint32_t seqid, uint16_t cksum);
int
ICMPEchoRequest(struct datalink *dl,struct MAC *srcmac, struct MAC *dstmac,uint32_t src, 
						uint32_t dst, uint16_t id, uint16_t seq);

int
ICMPEchoReply(struct datalink *dl,struct MAC *srcmac, struct MAC *dstmac,uint32_t src, 
						uint32_t dst, uint16_t id, uint16_t seq);

#endif
