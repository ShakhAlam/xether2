#include "datalink.h"
#include "xlayer.h"

int
main(int argc, char **argv)
{
        struct datalink *dl;
        int nif,n,i;
        uint32_t ip,mask;
        char ipb[100];

        if( ( dl = get_if_list(&nif) ) == NULL ){
                perror(*argv);
                exit(EXIT_FAILURE);
        }

        for(n = 0; n < nif; n++ ){
                printf("%s: ",dl[n].dl_name);
                for(i=0;i<6;i++)
                        printf("%02x:",dl[n].dl_mac[i]);
		printf("\n");

        }

        free(dl);
        exit(0);
}
//cl prnif.obj wdatalink.c packet.lib
