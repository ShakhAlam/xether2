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

int
main(int argc, char **argv)
{
	struct layer *head;
	struct MAC m,rt;
	struct datalink dl;
	uint32_t mip,dip,rip;
	if(argc<4) usage(*argv);

	if(if_menu(&dl) < 0 )
		exit(1);	
	str_to_ip(argv[1],&mip);	
	str_to_ip(argv[2],&dip);
	str_to_ip(argv[3],&rip);

	if(dl.dl_pcap->linktype != DLT_RAW)
		ARPRequest(&dl,&m,&rt,mip,rip,5);

	ICMPEchoRequest(&dl,&m,&rt,mip,dip,0x2341,0x1432);
	exit(0);
}

		


