#ifndef DATALINK_H_INCLUDED
#define DATALINK_H_INCLUDED

//#ifdef HAVE_CONFIG_H
#include "../config.h"
//#endif 

#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include "../libpcap/pcap.h"
#include "../libpcap/pcap-int.h"
#include "../libpcap/bpf/net/bpf.h"
#include <unistd.h>
#include <sys/socket.h>

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>

#ifndef SIOCGARP

#include <net/route.h>
#include <net/if_dl.h>
#include <sys/param.h>
#include <sys/sysctl.h>

#endif /* SIOCGARP */
 
#else 
#include "types.h"
#include <tchar.h>
#include <winsock2.h>
#include "../wpcap/pcap.h"
#include "../wpcap/pcap-int.h"
#include "../wpcap/net/bpf.h"
#include <windowsx.h>   			/* for GlobalAllocPtr() */
#include "../wpcap/packet32.h"    /* Needed for all PACKET.LIB functions */
#include "../wpcap/ntddndis.h"    /* Needed for MAC address OID struct */

/*#include "ntddpack.h" */

#endif /* _WIN32 */

#define MAX_NUM_ADAPTER 10
#define ADAPTER_NAME_LEN 256

struct datalink *get_if_list(int *num_if);
void free_if_list(struct datalink *pdl);
int getmacbyname(char *szAdapterName,unsigned char xmac[6]);  /* WIN32 only   */
char *ctl_if_list(int family,int flags,size_t *lenp); 	     /* POSIX sysctl */

struct datalink{
	char 			dl_name[ADAPTER_NAME_LEN]; /* NUL terminated datalink name */
	unsigned char 	dl_mac[6];					/* Media Access Control		*/
	struct pcap *		dl_pcap;					/* Packet capture descriptor */
	bpf_u_int32		dl_bpfnet;
	bpf_u_int32		dl_bpfmask;
};

typedef struct datalink *xdl;

ssize_t
recvData(const struct datalink *dl,unsigned char *data, size_t len);

unsigned char *
recv_pcap(const struct datalink *dl,
		  unsigned char *data, 
		  size_t len,
		  struct pcap_pkthdr *hdr);
ssize_t 
sendData(const struct datalink *dl,unsigned char *data, size_t len);

unsigned char *
nextData(const struct datalink *dl, int *len);

unsigned char *
next_pcap(const struct datalink *dl, int *len);

void
closeDatalink(const struct datalink *dl);

int 
filterDatalink(const struct datalink *dl, char *filter);

int 
openDatalink(struct datalink *dl);

int
if_menu(struct datalink *dl);

int
if_open(struct datalink *dl, int n);

int
if_openbyname(struct datalink *dl, const char *ifname);

int 
open_link_byname(struct datalink *dl, char * name, int to_ms);

#endif
