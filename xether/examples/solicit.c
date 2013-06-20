#include "datalink.h"
#include <stdio.h>
#include "datalink.h"
#include "xlayer.h"
#include <stdlib.h>
void
ICMPRouterSolicit(struct MAC *srcmac,uint32_t mip);

void 
usage(const char *pgmname)
{ 
 fprintf(stderr,"usage: %s <src ip>\n");
 exit(0);
}

int
main(int argc, char **argv)
{
	struct MAC m;
	uint32_t mip;
	int *i;
	if(argc<2) usage(*argv);

	if(if_menu(&m) < 0 )
		exit(1);	

	filterDatalink("icmp");
	str_to_ip(argv[1],&mip);	

	ICMPRouterSolicit(&m,mip);

	exit(0);
}
void
ICMPRouterSolicit(struct MAC *srcmac,uint32_t mip)
{
	struct layer *head;
	long t1=0,t2=0;
	struct MAC dstmac;
	int d;


	for(d=0;d<6;d++)
		dstmac.mac[d]=0xFF;	

	head = alloclayer(LT_ETHER);

	ether_set(head->proto , srcmac ,&dstmac, ETHERTYPE_IP);
	
	head->next = alloclayer(LT_IP);

	ip_set(head->next->proto,
			0,sizeof(struct ip)+sizeof(struct icmp),rand()%255,0,
			64,IPPROTO_ICMP,0,mip,-1);
	
	ip_sum(head->next);
	
	head->next->next = alloclayer(LT_ICMP);
	
	icmp_set(head->next->next->proto,ICMP_ROUTERSOLICIT,0,0,0,0);
	
	icmp_sum(head->next->next);

	sendlayers(head);
	rmlayers(head);
}	




