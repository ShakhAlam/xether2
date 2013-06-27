#ifndef XLAYER_UDP_H_INCLUDED
#define XLAYER_UDP_H_INCLUDED

#include "xlayer.h"
#define UDP_PRINT_BUF 256

struct UDPSocket
{
	struct MAC mac;
	uint32_t   ip;
	uint16_t   port;	
	struct MAC gatewaymac;
 
	
	uint32_t   gatewayip;

	uint32_t   hostip;
	uint16_t   hostport;

	struct	  layer *sendbuf;
	struct 	  layer *recvbuf;
};

u_long 
UDPSend(struct datalink *dl,struct UDPSocket *sock, char *data, size_t len);
int
createUDPSocket(struct UDPSocket *ts, struct MAC *srcmac, struct MAC *dstmac,
	    uint32_t srcip, uint32_t dstip, uint16_t srcport, uint32_t dstport);
struct layer * alloc_udp(struct layer *m,size_t len);
struct layer *udp_decode(const char *buf,size_t len);
int udp_set(struct udphdr *udph,uint16_t sport,uint16_t dport, uint16_t ulen, uint16_t sum);
int udp_sum(struct layer *m);
char * udpsprint(char *buf, size_t n,struct layer *m);
void udpprint(struct layer *m);

#endif
