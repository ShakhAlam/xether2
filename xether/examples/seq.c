#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/types.h>

#include "xlayer.h"
#include "datalink.h"

void
usage(const char *pgm)
{
 fprintf(stderr,"usage: %s <src ip> <src port> <dst ip> <dst port> <gateway ip> <number of sequences>\n",pgm);
 exit(0);
}

struct iseq{
	int port;
	uint32_t seq;
	uint32_t delta;
	int gamma;
};

void
report(struct iseq *isq){
 	struct iseq *p,*q;
	
	printf("Sequence report\nPORT\tSEQ\tDELTA\tGAMMA\n");
	isq[0].delta = 0;
	isq[0].gamma = 0;
	
	for( q = isq , p = &isq[1] ; p[0].port != -1 ; ++p ,++q ){
		p->delta = p->seq - q->seq;
		p->gamma = p->delta - q->delta; 
		printf("%d\t%lu\t%lu\t%d\n",
		p->port,p->seq,p->delta,p->gamma);
	}
	
}

int
main(int argc, char **argv)
{
  struct layer *head,*tcp;
  struct TCPSocket ts;
  struct MAC imac,dmac;
  uint32_t ip,dip,gip,i,nseq,oseq=0,del,odel=0,last_syn,loop;
  int iport,cport;
  int n,connected;
  char buf[100];
  char *a;
  struct datalink dl;
  struct iseq *isq,*q;

    
  if(argc < 7)
	usage(*argv);

  fprintf(stderr,"-----------Sequence Numbers-----------\n");
  iport = atoi(argv[2]);
  nseq = atoi(argv[6]);
  if(nseq <= 0 ){
	fprintf(stderr,"number of sequences must be greater than 0;\n");
	exit(1);
  }
  
  isq = (struct iseq*)calloc(nseq+1,sizeof(struct iseq));
  if( isq == NULL ){
  	perror(*argv);
	exit(1);
  }
  isq[nseq].port = -1;
   
  if(if_menu(&dl) < 0)
	exit(1);
  //filterDatalink(&dl,"arp");

  memcpy(&imac.mac,dl.dl_mac,6);
  printf("%x:%x:%x:%x:%x:%x",dl.dl_mac[0],dl.dl_mac[1],dl.dl_mac[2],dl.dl_mac[3],dl.dl_mac[4],dl.dl_mac[5]);
  str_to_ip(argv[1],&ip);
  str_to_ip(argv[3],&dip);
  str_to_ip(argv[5],&gip);
 // if( dl.dl_pcap->linktype == DLT_EN10MB || dl.dl_pcap->linktype == DLT_EN3MB ){
	  if( ARPRequest(&dl,&imac,&dmac,ip,gip,5) < 0 ){
		fprintf(stderr,"error: no route to host.\n");
		exit(1);
  	  } 
	  ARPReply(&dl,&imac,ip,&dmac,gip);
  //}
	
  createSocket(&ts,&imac,&dmac,ip,dip,atoi(argv[2]),atoi(argv[4]));
  ts.rcvwin=65535;

  connected = -2;
  head = NULL;
  i=0;
  last_syn = ts.seq;
  loop =1;


   while(loop){
    if(i<nseq){
    	ts.seq = rand()%0xFFFFFFFF;
	ts.ack =0;
	ts.port++;
	SYN(&ts,&dl);
	i++;
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


		//printlayers(tcp);

		if( ( t->th_flags & TH_RST) == TH_RST){
			fprintf(stderr,"\nReceived RST.\n");
			rmlayers(head);			
			break;
			
		}

	
		if( ( ( t->th_flags & TH_SYN ) == TH_SYN)  && ( ( t->th_flags & TH_ACK ) == TH_ACK) ){

 			
			del = htonl(t->th_seq)- htonl(oseq);
			cport = ntohs(t->th_dport)-iport;
			if( cport < 0  || cport >= nseq ){
				printf("unexpected dport\n");
				
			}
			else{
				printf("setting cport %d with port %d seq %lu\n",
				cport,ntohs(t->th_dport),ntohl(t->th_seq));
				isq[cport].port = ntohs(t->th_dport);
				isq[cport].seq = ntohl(t->th_seq);
				
			}
			
			printf("recv: SYN,ACK DPORT=%d SEQ = %lu DELTA=%lu  GAMMA=%d\n",
				ntohs(t->th_dport),
				ntohl(t->th_seq),del,del-odel);
			oseq = t->th_seq;
			odel= del;
			if( last_syn+1 == ntohl(t->th_ack) || isq[cport].port >= iport+nseq-1){
				loop = 0;
				break;
			}
			ts.ack = ntohl(t->th_seq);
			ts.seq = ntohl(t->th_ack);
			ts.port = ntohs(t->th_dport);
	             	RSTACK(&ts,&dl);
	
			printf("sent: RST,ACK\n");			
			connected = 1;
			
		}
		
		
	}

	rmlayers(head);
    
  }
   
  closeDatalink(&dl);
  report(isq);
  free(isq);
  exit(0);
}

