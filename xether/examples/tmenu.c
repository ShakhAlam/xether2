//cl tmenu.c xlayer.lib packet.lib ws2_32.lib wpcap.lib

#include <stdio.h>
#include "datalink.h"
#include "xlayer.h"
#include <stdlib.h>

int
main(int argc, char **argv)
{
	struct datalink dl;
	char macbuf[200];
	
	if(if_menu(&dl) < 0 )
		exit(1);	
//	closeDatalink(&dl);
	exit(0);
}



		

