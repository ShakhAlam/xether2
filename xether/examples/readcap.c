#include <stdio.h>
#include "datalink.h"
#include "xlayer.h"
#include <stdlib.h>

int
main(int argc, char **argv)
{
	struct layer *head;
	int n;
	FILE *fp;
	if(argc< 2){
           fprintf(stderr,"usage: %s <packet file>\n",*argv);
           exit(0);
    	}

    	if( ( fp = fopen(argv[1],"rb") ) == NULL){

		fprintf(stderr,"Error opening t.pac\n");
		exit(1);
	}

	head = readlayers_pcap(fp);

    	if(n == -1)
		printf("ERROR!\n");
    
	
	printlayers(head);
	
	rmlayers(head);	
		
	fclose(fp);		

	return 0;
}	
