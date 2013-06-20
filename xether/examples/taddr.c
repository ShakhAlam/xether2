#include <stdio.h>
#include <string.h>
#include "types.h"
#include "ipaddr.h"

int
main(int argc, char **argv)
{
	uint32_t ipn;
	char buf[100];

	strcpy(buf,"127.0.0.1");
	ipn = str_to_ip(buf,NULL);

	if(ip_to_str(ipn,buf,sizeof(buf)) == NULL)
		printf("error\n");
	printf("%s\n",buf);
	exit(0);
}