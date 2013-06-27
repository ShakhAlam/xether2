#include <stdio.h>
#include "datalink.h"
#include "xlayer.h"
#include <stdlib.h>
int
main(int argc, char **argv)
{
	struct layer *head;
	struct MAC m;
	uint32_t mip;
	uint8_t opt[6];

	if(if_menu(&m) < 0 )
		exit(1);	
	str_to_ip("24.148.1.23",&mip);
	printf("sending...\n");
	opt[0] = DHCP_OPT_MASK;
	opt[1] = DHCP_OPT_ROUTE;
	opt[2] = DHCP_OPT_DNS;
	opt[3] = DHCP_OPT_DOMAIN_NAME;
	opt[4] = DHCP_OPT_ROUTE;
	opt[5] = DHCP_OPT_BCAST_ADDR;
	//m.mac[4]=6;	
	dhcp_request(&m,
				0x723457,mip,"abcdef", opt, 6);
	exit(0);
}




		



