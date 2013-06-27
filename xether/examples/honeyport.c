#include <stdio.h>
#include "xlayer.h"
#include "datalink.h"
/* The honeyport project */
/*xon */


void
usage(const char *pgm)
{
 fprintf(stderr,"usage: %s <src ip> <gateway ip> <savefile>\n",pgm);
 exit(0);
}

int
main(int argc, char **argv)
{
  struct layer *head,*tcp;
  FILE *fp;
  struct TCPSocket ts;
  struct MAC imac,dmac;
  uint32_t ip,dip,gip;
  int n,connected;
  char buf[128];
  char *a;
  struct datalink dl;
  if(argc < 3)
	usage(*argv);
  fprintf(stderr,"-----------HONEY PORT v1.0-----------\n");

  if(if_menu(&dl) < 0)
	exit(1);

  if( ( fp = fopen(argv[3],"wb") ) == NULL ){
	perror(*argv);
	exit(1);
  }

  memcpy(&imac.mac,dl.dl_mac,6);

  str_to_ip(argv[1],&ip);
  str_to_ip(argv[2],&gip);

  if( dl.dl_pcap->linktype == DLT_EN10MB || dl.dl_pcap->linktype == DLT_EN3MB ){
	  if( ARPRequest(&dl,&imac,&dmac,ip,gip,5) < 0 ){
		fprintf(stderr,"error: no route to host.\n");
		exit(1);
  	  } 
	  ARPReply(&dl,&imac,ip,&dmac,gip);
  }

  writelayers_pcap(NULL,1,dl.dl_pcap->linktype,fp);
	
  createSocket(&ts,&imac,&dmac,ip,0,0,0);
  ts.rcvwin=30660;

  connected = -2;
  head = NULL;
  while(1){
   	if(connected==1){

		strcpy(buf," login: ");
        PSHACK(&ts,&dl,buf,strlen(buf));
		connected = 2;
	}


	
    if( ( head = recvlayers(&dl,&n) ) == NULL)
		continue;
	
	
	if( (tcp = findlayer(head,LT_TCP) ) != NULL ){ 

		struct tcphdr *t;
		struct ip * i;
		
		
		t = (xtcp)tcp->proto;
 		i = (xip)head->next->proto;

		if( (i->ip_dst.s_addr) != ts.ip )
			continue;

		writelayers_pcap(head,0,dl.dl_pcap->linktype,fp);

		ts.port = ntohs(t->th_dport);
		ts.hostip = i->ip_src.s_addr;
		ts.hostport = ntohs(t->th_sport);

		printlayers(tcp);

		if( ( t->th_flags & TH_RST) == TH_RST){
			fprintf(stderr,"\nConnection reset by peer.\n");
			rmlayers(head);			
			continue;
			
		}

		if( tcp->next != NULL ){
			printf("recv: PSH-ACK\n");
			
			ts.seq = ntohl(t->th_ack);
			ts.ack = ntohl(t->th_seq) + tcp->next->size;
             ACK(&ts,&dl);
			if(  memchr(tcp->next->proto,'\n',tcp->next->size) != NULL ){
				if(connected == -1 ){
					strcpy(buf,"Login incorrect\r\n");
					connected = -2;
				}
				else
					strcpy(buf,"Password: ");
        			PSHACK(&ts,&dl,buf,strlen(buf));
				connected = -2;
			}
			

		}

		if( ( t->th_flags & TH_ACK ) == TH_ACK && ( t->th_flags & TH_SYN ) != TH_SYN){
			
			connected++;
			if(connected > 3)
				connected=-2;
		}

		if( ( t->th_flags & TH_FIN ) == TH_FIN){
			ts.seq = ntohl(t->th_ack);
			ts.ack = ntohl(t->th_seq) + 1;
             ACK(&ts,&dl);
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
			ts.seq = 0; 
             RSTACK(&ts,&dl);
			printf("send: RSTACK\n");			
			connected = 1;

		}

		if( ( ( t->th_flags & TH_SYN ) == TH_SYN)  && ( ( t->th_flags & TH_ACK ) != TH_ACK) ){
			printf("recv: SYN \n");


			ts.ack = ntohl(t->th_seq) + 1;
			ts.seq = rand()%RAND_MAX;
             SYNACK(&ts,&dl);
			printf("send: SYN-ACK\n");			
			connected = 0;

			continue;
		}
		
		
	}

	rmlayers(head);
  }

  closeDatalink(&dl);
  close(fp);
  exit(0);
}

