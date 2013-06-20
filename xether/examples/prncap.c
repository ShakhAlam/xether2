/* Debug the datalink modules */
#include "xlayer.h"

int
main(int argc ,char **argv)
{
	FILE *fin,*fout;
	struct layer *m;
	struct datalink dl;

	if( argc < 2 ){
		fprintf(stderr,"usage: %s <filename>",*argv);
		exit(1);
	}

	if( ( fin = fopen(argv[1],"rb") ) == NULL ){
		fprintf(stderr,"%s: error opening file %s\n",*argv,argv[1]);
		perror(*argv);
		exit(1);
	}

	if( ( m = readlayers_pcap(fin) ) == NULL ){
		fprintf(stderr,"%s: error reading file %s\n",*argv,argv[1]);
		perror(*argv);
		exit(1);
	}
	fclose(fin);


	
	printlayers(m);
	

	printf("_--------_\n");
	rmlayers(m);

	return 0;
}
