#include <stdio.h>
#include <conio.h>
#include "xlayer.h"
#include "datalink.h"
//tsyn 24.148.24.70 3434 207.229.143.32 110 24.148.1.252
//tsyn 24.148.1.39 4356 64.58.76.177 80 24.148.1.252
#ifndef _WIN32
#define kbhit 0
#
int if_menu(struct MAC *m);

void
usage(const char *pgm)
{
 fprintf(stderr,"usage: %s <src ip> <dst ip> <start port> <end port> <gateway ip>\n",pgm);
 exit(0);
}

int
main(int argc, char **argv)
{
  struct layer *head,*tcp;
  struct TCPSocket ts;
  struct MAC imac,dmac;
  uint32_t ip,dip,gip;
  uint16_t eport;
  int n;

  if(argc < 6)
	usage(*argv);
  if(if_menu(&imac) < 0)
	exit(1);
  
  str_to_ip(argv[1],&ip);
  str_to_ip(argv[2],&dip);
  str_to_ip(argv[5],&gip);

  if( ARPRequest(&imac,&dmac,ip,gip,5) < 0 ){
	fprintf(stderr,"error: no route to host.\n");
	exit(1);
  }
  ARPReply(&imac,ip,&dmac,gip);
  eport = atoi(argv[4]);	
  createSocket(&ts,&imac,&dmac,ip,dip,atoi(argv[3]),atoi(argv[3]));
  filterDatalink("tcp");
  head = NULL;
  while(!kbhit()){
	if(ts.hostport++ < eport)
	      SYN(&ts);
	if( ( head = recvlayers(&n) ) == NULL)
		continue;		
	if( (tcp = findlayer(head,LT_TCP) ) != NULL ){ 
		struct tcphdr *t;				
		t = (xtcp)tcp->proto;
		if( ( ( t->th_flags & TH_SYN ) == TH_SYN)  && ( ( t->th_flags & TH_ACK ) == TH_ACK) ){
			printf("recv: SYN-ACK from port %d\n",ntohs(t->th_sport));
			printlayers(tcp);
			RST(&ts);			
		}
	}
	rmlayers(head);
  }
  closeDatalink();
  exit(0);
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

//tscan 24.148.1.23 64.58.76.223 79 81 24.148.1.252


