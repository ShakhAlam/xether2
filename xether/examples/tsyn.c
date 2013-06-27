#include <stdio.h>
#include "xlayer.h"
#include "datalink.h"
//tsyn 24.148.24.70 3434 207.229.143.32 110 24.148.1.252
//tsyn 24.148.1.39 4356 64.58.76.177 80 24.148.1.252
// fix the trailer problem with ip total length field
// fix the window size problem
// fix the ack for fin before push in FIN-PSH-ACK
// fix the  		i = (xip)head->next->proto; problen. wont work in DLT_RAW

void
usage(const char *pgm)
{
 fprintf(stderr,"usage: %s <src ip> <src port> <dst ip> <dst port> <gateway ip> <real ip>\n",pgm);
 exit(0);
}

int
main(int argc, char **argv)
{
  struct layer *head,*tcp;
  struct TCPSocket ts;
  struct MAC imac,dmac;
  uint32_t real_ip,ip,dip,gip;
  int n,connected;
  char buf[100];
  char *a;
  struct datalink dl;
  if(argc < 7)
	usage(*argv);
  fprintf(stderr,"-----------TSYN-----------\n");

  if(if_menu(&dl) < 0)
	exit(1);

  memcpy(&imac.mac,dl.dl_mac,6);

  str_to_ip(argv[1],&ip);
  str_to_ip(argv[3],&dip);
  str_to_ip(argv[5],&gip);
  str_to_ip(argv[6],&real_ip);
  if( dl.dl_pcap->linktype == DLT_EN10MB || dl.dl_pcap->linktype == DLT_EN3MB ){
	  if( ARPRequest(&dl,&imac,&dmac,real_ip,gip,5) < 0 ){
		fprintf(stderr,"error: gateway did not reply arp.\n");
		exit(1);
  	  } 
	  ARPReply(&dl,&imac,ip,&dmac,gip);
  }
	
  createSocket(&ts,&imac,&dmac,ip,dip,atoi(argv[2]),atoi(argv[4]));
  ts.rcvwin=65535;

  connected = -2;
  head = NULL;
  while(1){
   	if(connected==1){
   		/*if(fgets(buf,sizeof(buf),stdin) == NULL){
   			FINACK(&dl,&ts);
			closeDatalink(&dl);
			exit(1);
		}*/
		strcpy(buf,"GET /\r\n");
         PSHACK(&ts,&dl,buf,strlen(buf));
		connected = 2;
	}
	else{
		if(connected<-1){
            SYN(&ts,&dl);
			connected = -1;
		}
		
	}

	
    if( ( head = recvlayers(&dl,&n) ) == NULL)
		continue;
	
	
	if( (tcp = findlayer(head,LT_TCP) ) != NULL ){ 

		struct tcphdr *t;
		struct ip * i;
		
		
		t = (xtcp)tcp->proto;
 		i = (xip)head->next->proto;

		if( (i->ip_src.s_addr) != ts.hostip || t->th_sport != htons(ts.hostport) )
			continue;


		printlayers(tcp);

		if( ( t->th_flags & TH_RST) == TH_RST){
			fprintf(stderr,"\nConnection reset by peer.\n");
			rmlayers(head);			
			break;
			
		}

		if( tcp->next != NULL ){
			printf("recv: PSH-ACK\n");
			
			ts.seq = ntohl(t->th_ack);
			ts.ack = ntohl(t->th_seq) + tcp->next->size;
             ACK(&ts,&dl);
		}

		if( ( t->th_flags & TH_FIN ) == TH_FIN){
			ts.seq = ntohl(t->th_ack);
			ts.ack = ntohl(t->th_seq) + 1;
             //ACK(&ts,&dl);
             FINACK(&ts,&dl);
			rmlayers(head);
			fprintf(stderr,"\nConnection closed by peer.\n");
			continue;
		}
	
		if( ( ( t->th_flags & TH_SYN ) == TH_SYN)  && ( ( t->th_flags & TH_ACK ) == TH_ACK) ){
			printf("recv: SYN-ACK\n");
			if( t->th_seq == ts.seq + 1 )
				printf("T.H.S\n");
			ts.ack = ntohl(t->th_seq) + 1;
			ts.seq = ntohl(t->th_ack);
             ACK(&ts,&dl);
			printf("send: ACK\n");			
			connected = 1;
			
		}
		
		
	}

	rmlayers(head);
  }

  closeDatalink(&dl);

  exit(0);
}
