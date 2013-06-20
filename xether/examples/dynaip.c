#include "../xlayer.h"

static char *prog_name;
int
main(int argc, char **argv)
{
 uint32_t ip,rip;
 prog_name = *argv;

 if(argc<3)
	usage();

 if( str_to_ip(argv[1],&ip) == 0){
	fprintf(stderr,"%s: invalid IPv4 address %s\n",prog_name,argv[1]);
 }
	
 if( str_to_ip(argv[2],&rip) == 0){
	fprintf(stderr,"%s: invalid IPv4 address %s\n",prog_name,argv[1]);
 }
 dynaip(ip,rip);	
 exit(0);
}

void
usage()
{
 fprintf(stderr,"usage: %s <ip> <route>\n",prog_name);
 exit(0);
}

int
dynaip(uint32_t ip,uint32_t rip)
{


}