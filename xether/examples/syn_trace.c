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
 fprintf(stderr,"usage: %s <src ip> <src port> <dst ip> <dst port> <gateway ip> <real src ip>\n",pgm);
 exit(0);
}

int
main(int argc, char **argv)
{
  struct layer *head,*tcp;
  struct TCPSocket ts;
  struct MAC imac,dmac;
  uint32_t ip,dip,gip,rip;
  int n;
  char buf[100];
  char *a;
  struct datalink dl;
  unsigned char ttl=1;	
  if(argc < 6)
	usage(*argv);
  fprintf(stderr,"-----------TSYN-----------\n");

  if(if_menu(&dl) < 0)
	exit(1);

  memcpy(&imac.mac,dl.dl_mac,6);

  str_to_ip(argv[1],&ip);
  str_to_ip(argv[3],&dip);
  str_to_ip(argv[5],&gip);
  str_to_ip(argv[6],&rip);
  if( dl.dl_pcap->linktype == DLT_EN10MB || dl.dl_pcap->linktype == DLT_EN3MB ){
	  if( ARPRequest(&dl,&imac,&dmac,rip,gip,5) < 0 ){
		fprintf(stderr,"error: gateway did not reply arp.\n");
		exit(1);
  	  } 
	  ARPReply(&dl,&imac,ip,&dmac,gip);
  }
	
  createSocket(&ts,&imac,&dmac,ip,dip,atoi(argv[2]),atoi(argv[4]));
  ts.rcvwin=65535;

  head = NULL;
// we send a syn with ttl = 1
// then we increment

  while(	 ttl < 64){
            SYN_ttl(&ts,&dl,ttl);
		ttl++;

  }

  closeDatalink(&dl);

  exit(0);
}
