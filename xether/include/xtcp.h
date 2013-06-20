#ifndef XLAYER_XTCP_H_INCLUDED
#define XLAYER_XTCP_H_INCLUDED


#include "xlayer.h"
#include "macaddr.h"

#define TCP_PRINT_BUF 512
#define TCP_DEF_RCVWIN 65536

struct TCPSocket
{
	struct MAC mac;
	uint32_t   ip;
	uint16_t   port;	
	
	struct MAC gatewaymac;
	uint32_t   gatewayip;

	uint32_t   hostip;
	uint16_t   hostport;
	
	uint32_t   seq;
	uint32_t   nextseq;	
	uint32_t   ack;

    uint16_t   rcvwin;

	struct	  layer *sendbuf;
	struct 	  layer *recvbuf;
};

struct layer *alloc_tcp(struct layer *m,size_t len);
struct layer *tcp_decode(const char *buf,size_t len);
char *tcpsprint(char *buf, size_t n, struct layer *m);
void tcpprint(struct layer *m);
int tcp_sum(struct layer *m);
int tcp_set(struct tcphdr * tcph,
			uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
			uint8_t hln, uint8_t flags, uint16_t win, uint16_t sum, uint16_t urp);

u_long 
SYN_ttl(struct TCPSocket *sock , struct datalink *dl,unsigned char ttl);

u_long 
TCPSend_ttl(struct TCPSocket *sock , struct datalink *dl, uint8_t flag, char *data, size_t len,unsigned char ttl);

u_long PSHACK(struct TCPSocket *sock , struct datalink *dl,char *data,int len);
u_long RSTACK(struct TCPSocket *sock , struct datalink *dl);
u_long RST(struct TCPSocket *sock , struct datalink *dl);
u_long FINACK(struct TCPSocket *sock , struct datalink *dl);
u_long ACK(struct TCPSocket *sock , struct datalink *dl);
u_long SYNACK(struct TCPSocket *sock , struct datalink *dl);
u_long SYN(struct TCPSocket *sock , struct datalink *dl);
u_long TCPSend(struct TCPSocket *sock , struct datalink *dl, uint8_t flag, char *data, size_t len);
int createSocket(struct TCPSocket *ts, struct MAC *srcmac, struct MAC *dstmac,
	    uint32_t srcip, uint32_t dstip, uint16_t srcport, uint32_t dstport);
							
#endif
