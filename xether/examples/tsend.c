//cl tsend.c xlayer.lib packet.lib ws2_32.lib wpcap.lib
//cl test.c xlayer.lib packet.lib ws2_32.lib wpcap.lib
//cl t1.c xlayer.lib packet.lib ws2_32.lib wpcap.lib
#include <stdio.h>
#include "datalink.h"
#include "xlayer.h"
#include <stdlib.h>

int
main(int argc, char **argv)
{
	struct layer *head;
	struct MAC m,rt;
	uint32_t mip,rip;
	char macbuf[200];

	if(if_menu(&m) < 0 )
		exit(1);	

	str_to_ip("24.148.24.70",&mip);	
	str_to_ip("24.148.1.252",&rip);
        printf("sending ARP request\n");
	ARPRequest(&m,&rt,mip,rip,5);

	mac_to_str(&rt,macbuf,sizeof(macbuf));	
	printf("%s\n",macbuf);
	exit(0);
}

int
if_menu(struct MAC *m){
	struct datalink *pdl;
	int nif,i,j;
	char buf[100];
	if( (pdl = get_if_list(&nif) ) == NULL){
		fprintf(stderr,"Error getting interface list\n");
		return -1;
	}
	
	for(i=0;i<nif;i++){
		printf("%d: %s\n",i+1,pdl[i].dl_name);
	}
	j = i;
	do{
	 printf("Please choose interface (1-%d):\n",j);
	 fgets(buf,sizeof(buf),stdin);
	 sscanf(buf,"%d",&i);
	}while(i<1 || i>nif);

	if(openDatalink(pdl[i-1].dl_name) == -1){
		fprintf(stderr,"Error opening interface %s\n",pdl[i-1].dl_name);
		return -1;
	}
	if(m != NULL)
		memcpy(m,pdl[i-1].dl_mac,6);
	return 0;
}


		

