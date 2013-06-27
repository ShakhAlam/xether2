#include <stdio.h>
#include <stdlib.h>
#include "xlayer.h"

int
main(int argc, char **argv)
{
	struct datalink dl;
	char buf[1500];
	int nrecv;
	if( if_menu(&dl) < 0){
		perror("if_menu()");
		exit(1);
	}
	while( 1){
		if( ( nrecv = recvData(&dl,buf,sizeof(buf) ) ) >  0 ){
			
			fwrite(buf,sizeof(char),nrecv,stdout);

		}
		
	}
	exit(0);

}
