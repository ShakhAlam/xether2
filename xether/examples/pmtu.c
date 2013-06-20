#include "xlayer.h"
#include "datalink.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

static char *szProgName;
static void
usage(void)
{
	fprintf(stderr,"usage: %s <src ip> <dst ip> <gateway>\n",szProgName);
	exit(0);
}
static void
ckerr(int rc, int ec,const char *szMsg)
{
 if(rc == ec){
 	fprintf(stderr,"%s: %s %s\n",szProgName,szMsg,
				(errno==0)?"":strerror(errno));
	exit(1);
 }				
} 

int
PMTUDiscover(struct MAC *srcmac,struct MAC *dstmac,
	     uint32_t srcip, uint32_t dstip)
{

  struct layer *stack,*f,*m;  
  xicmp icmph;
  xip	iph;

  char data[1500-sizeof(struct ip)-sizeof(struct udphdr)],hop[30];		  
  struct UDPSocket udps;

  time_t t1,t2;
  int n;

  filterDatalink("icmp");  

  m = alloclayer(LT_ETHER);

  ether_set( m->proto , srcmac ,dstmac, ETHERTYPE_IP);
	
  m->next = alloclayer(LT_IP);



  ip_set(m->next->proto,0,
        (sizeof(struct ip)+sizeof(struct udphdr))+sizeof(data),
	(u_short)rand()%0xFFFF,IP_DF, /* set the Dont Fragment Flag */
	128,IPPROTO_UDP,0,srcip,dstip);
			      
  m->next->next = alloclayer(LT_UDP);
		
  
  m->next->next->next = allocapplayer(sizeof(data));

  memcpy(m->next->next->next->proto,data,sizeof(data));

	
  udp_set(m->next->next->proto,
	  8973,9132,
	  sizeof(struct udphdr)+sizeof(data),0);
			
  m->next->next->prev = m->next;

			
  if( udp_sum(m->next->next) < 0)
	fprintf(stderr,"tcp sum error\n");
		
	
  ip_sum(m->next);

  sendlayers(m);
  rmlayers(m);	
	
  t1 = time(0);
  stack = recvlayers(&n);
  while(1){
  	if( stack != NULL ){
		
		if( ( f = findlayer(stack,LT_ICMP) ) != NULL ){
			icmph = (xicmp)f->proto;

			iph = (xip)stack->next->proto;

			printlayers(f);
			ip_to_str(iph->ip_src.s_addr,hop,sizeof(hop));
			printf("%s says next hop MTU is %d\n",hop,htons(icmph->icmp_nextmtu));
			return htons(icmph->icmp_nextmtu);
		}
	}
  	t2 = time(0);
	if(t1+20 <= t2)
		return -1;
	stack = recvlayers(&n);
  }
}

int
main(int argc, char **argv)
{
  struct MAC m,d;
  uint32_t mip,dip,rip;
  szProgName = *argv;
  errno = 0;
  if( argc < 4 )  
	usage();
  if( if_menu(&m) < 0 )	
  	exit(1);
  filterDatalink("icmp");
  ckerr(str_to_ip(argv[1],&mip),0,"Invalid IP specified as source\n");
  ckerr(str_to_ip(argv[2],&dip),0,"Invalid IP specified as destination\n");
  ckerr(str_to_ip(argv[3],&rip),0,"Invalid IP specified as gateway\n");
  ckerr(ARPRequest(&m,&d,mip,rip,5),-1,"error: no route to host.\n");  
  ARPReply(&m,mip,&d,rip);
  
  ckerr(PMTUDiscover(&m,&d,mip,dip),-1,
  	"Error:Path MTU Discovery failed.\n");
  
  exit(0);
}
