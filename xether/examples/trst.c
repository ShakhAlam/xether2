#include <stdio.h>
#include "xlayer.h"
#include "datalink.h"


void
usage(const char *pgm)
{
 fprintf(stderr,"usage: %s <src ip> <dst ip> <src port> <dst port> <gateway ip> <seq> <ack>\n",pgm);

 exit(0);
}

int
main(int argc, char **argv)
{
  struct layer *head,*tcp;
  struct TCPSocket ts;
  struct MAC imac,dmac;
  struct datalink dl;
  uint32_t ip,dip,gip;

  int n;

  if(argc < 6)
	usage(*argv);
  if(if_menu(&dl) < 0)
	exit(1);
  memcpy(&imac.mac,dl.dl_mac,6);
  
  str_to_ip(argv[1],&ip);
  str_to_ip(argv[2],&dip);
  str_to_ip(argv[5],&gip);

  if( ARPRequest(&dl,&imac,&dmac,ip,gip,5) < 0 ){
	fprintf(stderr,"error: no route to host.\n");
	exit(1);
  }

  ARPReply(&dl,&imac,ip,&dmac,gip);

  createSocket(&ts,&imac,&dmac,ip,dip,atoi(argv[3]),atoi(argv[4]));
  ts.seq = atoi(argv[6]);
  ts.ack = atoi(argv[7]);  
  RST(&ts,&dl);			

  closeDatalink(&dl);
  exit(0);
}
