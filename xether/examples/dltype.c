#include <stdio.h>
#include "xlayer.h"

int
main(int argc, char **argv)
{
 struct datalink dl;

 if( if_menu(&dl) < 0 ){
    fprintf(stderr,"error opening interface\n");
    exit(1);
 }
 switch(dl.dl_pcap->linktype){
    case DLT_EN10MB:
        printf("Link type is Ethernet II 10/100Mb\n");

    break;
    case DLT_IEEE802:
            printf("Link type is Ethernet IEEE802.3\n");
    break;
    case DLT_RAW:
        printf("Link type is Point To Point Protocol\n");
    break;

 }
 closeDatalink(&dl);

 return 0;
}
