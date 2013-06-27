#ifndef LAYER_H_INCLUDED
#define LAYER_H_INCLUDED

#ifdef _WIN32
#include <winsock2.h>
#include "types.h"
#include "./netinet/if_ether.h"
#include "./netinet/in_systm.h"
#include "./netinet/ip.h"
#include "./netinet/tcp.h"
#include "./netinet/udp.h"
#include "./netinet/ip_icmp.h"

#endif

#ifndef _WIN32

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "types.h"
#endif

#include <stdlib.h>
#include <stdio.h>

#include "datalink.h" 
#include "xether.h"
#include "xarp.h"
#include "xip.h"
#include "xicmp.h"
#include "xudp.h"
#include "xdhcp.h"
#include "xtcp.h"
#include "xapp.h"


/* types casts */
typedef struct ether_header 	*xeth;
typedef struct ether_arp 		*xarp;
typedef struct icmp_hdr			*xicmp;
typedef struct ip 				*xip;
typedef struct tcphdr 			*xtcp;
typedef struct udphdr 			*xudp;
typedef struct dhcp				*xdhcp;

/* application data */
struct app{
	unsigned char *data;
	size_t len;
};

typedef void printfn(void *);
typedef void sprintfn(char *,size_t,void*);

/* layer link element */
struct layer{
	int    type;
	size_t size;
	void * proto;
	void (*print)(struct layer*);
	char * (*sprint)(char*,size_t,struct layer*);
	struct layer *prev;	
	struct layer *next;
	struct pcap_pkthdr *pkthdr;

};


#define LT_NONE  	0
#define LT_ETHER 	1
#define LT_ARP   	2
#define LT_IP	 	3
#define LT_ICMP		4

#define LT_UDP   	5
#define LT_TCP	 	6
#define LT_BREAK 	7	
#define LT_APP   	8
#define LT_MIN 	1
#define LT_MAX		68

#define LT_TELNET	23
#define LT_DHCP		67
#define LT_SMTP	25
#define LT_POP3	110

#define NULL_PKT_HDR (struct pcap_pkthdr*)0


#define x_print(a) (a)->print( (a)->proto ) )
#define x_sprint(buf,n,a) (a)->sprint((buf),(n),(a)->proto))
#define x_appsprint(buf,n,a) (a)->sprint((buf),(n),(a)))
#define PRINT_BUF 8192*2


struct layer  *alloclayer(int prototype,size_t len);
struct layer  *addlayer      ( struct layer *plafter, struct layer * pladd );
struct layer  *appendlayers  ( struct layer *head, struct layer *tail );
struct layer  *rmlayer       ( struct layer *rml );
struct layer  *rmnextlayer   ( struct layer *rmafter );
int			   rmlayers      ( struct layer *head );
struct layer  *findlayer     ( struct layer *head, int type );
struct layer  *getlayer      ( struct layer *head, unsigned int index );

struct layer  *recvlayers    ( struct datalink *dl,int *nrecv );
ssize_t        sendlayers    ( struct datalink *dl,struct layer * head );

void           printlayers   ( struct layer *head );
struct layer  *readlayers    ( FILE *fp, int *nrecv );
int            writelayers	 ( struct layer *head, FILE *fp );

int writelayers_pcap(struct layer *head,
					 int writehdr, 
					 bpf_u_int32 linktype, 
					 FILE *fp );
struct layer  * readlayers_pcap(FILE *fp);


/* Thanks to The NetBSD project */
void 				ascii_print(register const unsigned char *cp, register unsigned int length);
int	ascii_sprint(char *buf,u_int size, register const u_char *cp, register u_int length);

struct psuedohdr  {
  struct in_addr source_address;
  struct in_addr dest_address;
  unsigned char place_holder;
  unsigned char protocol;
  unsigned short length;
};

unsigned short trans_check(unsigned char proto, char *packet,int length,
									struct in_addr source_address,
			   					struct in_addr dest_address);
unsigned short checksum(unsigned short *addr,int len);


#endif

