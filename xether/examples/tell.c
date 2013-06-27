#include <stdio.h>
#include <stdlib.h>
#include "xlayer.h"
#include "datalink.h"
static char *szProgName;
static void
ckerr(int rc, int ec,const char *szMsg)
{
 if(rc == ec){
 	fprintf(stderr,"%s: %s %s\n",szProgName,szMsg,
				(errno==0)?"":strerror(errno));
	exit(1);
 }				
} 

int
main(int argc, char **argv)
{
	struct MAC lmac,rmac;
	uint32_t mip,rip;
	char macstr[20];

	if(argc < 3 ) {
		fprintf(stderr,"usage: %s <dest ip> <tell ip>\n",*argv);
		exit(0);
	}
	szProgName = *argv;
    ckerr(str_to_ip(argv[2],&mip),0,"Invalid IP specified as source\n");
    ckerr(str_to_ip(argv[1],&rip),0,"Invalid IP specified as destination\n");
	ckerr(if_menu(&lmac),-1,"Error: interface not configured\n");
    ckerr(ARPRequest(&lmac,&rmac,mip,rip,5),-1,"error: no route to host.\n");

    ARPReply(&lmac,mip,&rmac,rip);

	mac_to_str(&rmac,macstr,sizeof(macstr));
	printf("%s has %s was told\n",macstr,argv[1]);
	return 0;
}

