/* Debug the datalink modules */
#include "xlayer.h"


/*struct layer  * readlayers_pcap(FILE *fp);
int writelayers_pcap(struct layer *head,int write_hdr, FILE *fp);*/

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

	if_menu(&dl);

	sendlayers(&dl,m);
	
	printlayers(m);
	if( ( fout = fopen("rt.cap","wb") ) == NULL ){
		fprintf(stderr,"%s: error opening file rt.cap for writting\n",*argv);
		perror(*argv);
		exit(1);
	}



	if( writelayers_pcap(m,1,dl.dl_pcap->linktype,fout) < 0){
		fprintf(stderr,"%s: error writting to file rt.cap\n",*argv);
		perror(*argv);
		exit(1);	
	}
	
	fflush(fout);
	fclose(fout);


	printf("_--------_\n");
	rmlayers(m);

	return 0;
}
/*
struct pcap_file_header {
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;	
	bpf_u_int32 sigfigs;
	bpf_u_int32 snaplen;
	bpf_u_int32 linktype;	
};
*/

/*
struct pcap_pkthdr {
	struct timeval ts;
	bpf_u_int32 caplen;
	bpf_u_int32 len;
};
*/

/*
struct layer  * 
readlayers_pcap(FILE *fp)
{
	struct pcap_file_header pfh;
	struct pcap_pkthdr pkthdr;
	char *buf;
	struct layer *head,**px;
	head = NULL;
	px = &head;
	if( fread(&pfh,sizeof(pfh),1,fp) != 1)
		return NULL;
	printf("magic: %lu %lu\n",pfh.magic,htons(pfh.magic));
	printf("version_major: %d\n",pfh.version_major);
	printf("version_minor: %d\n",pfh.version_minor);
	printf("thiszone: %d\n",pfh.thiszone);	
	printf("sigfigs: %d\n",pfh.sigfigs);
	printf("snaplen: %d\n",pfh.snaplen);

	buf = malloc(pfh.snaplen);
	if( buf ==  NULL ){
		fprintf(stderr,"error: memory allocation failed\n");
		exit(1);
	}

	printf("linktype: %d " ,pfh.linktype);

	while( !feof(fp) ){
		if( fread(&pkthdr,sizeof(pkthdr),1,fp) != 1){

			fprintf(stderr,"error reading pcap_pkthdr\n");
			free(buf);
			return head;
		}


		printf(" packet caplen : %d\tlen : %d\n",pkthdr.caplen,pkthdr.len);
		if(pkthdr.len > pfh.snaplen){
			fprintf(stderr," pkthdr.len > pfh.snaplen \n" );
			free(buf);
			return NULL;
		}

		if( fread(buf,sizeof(char),pkthdr.len,fp) != pkthdr.len ){
			fprintf(stderr,"error reading packet\n");
			free(buf);
			return head;
		}

		switch( pfh.linktype )
		{
		case DLT_NULL:
			printf("no linklayer encapsulation\n");
		break;

		case DLT_EN10MB:
			printf(" Ethernet 10MB\n");
			*px = ether_decode(buf,pkthdr.len);

			(*px)->pkthdr = malloc(sizeof(pkthdr));

			memcpy((*px)->pkthdr,&pkthdr,sizeof(pkthdr));

			while( *px != NULL)
				px = &(*px)->next;


		break;

		case DLT_EN3MB:
			printf(" Experimental Ethernet (3Mb)\n");

		break;
		case DLT_AX25:
			printf(" Amateur Radio AX.25\n");		
		break;

		case DLT_PRONET:
			printf(" Proteon ProNET Token Ring\n");
		break;

		break;
		case DLT_CHAOS:
			printf(" Chaos\n");

		break;
		case DLT_IEEE802:
			printf(" IEEE 802 Networks\n");

		break;
		case DLT_ARCNET:
			printf(" ARCNET\n");

		break;
		case DLT_SLIP:
			printf(" Serial Line IP\n");
		break;
		case DLT_PPP:
			printf(" Point-to-point Protocol\n");

		break;
		case DLT_FDDI:
			printf(" FDDI\n");
		break;
		case DLT_ATM_RFC1483:
			printf(" LLC/SNAP encapsulated atm\n");
		break;
		case DLT_RAW:
			printf(" IP encapsulation\n");
			*px = ip_decode(buf,pkthdr.len);
			(*px)->pkthdr = malloc(sizeof(pkthdr));
			memcpy((*px)->pkthdr,&pkthdr,sizeof(pkthdr));

			while( *px != NULL)
				px = &(*px)->next;
			
		break;
		case DLT_SLIP_BSDOS:
			printf(" BSD/OS Serial Line IP\n");

		break;
		case DLT_PPP_BSDOS:
			printf(" BSD/OS Point-to-point Protocol\n");

		break;
		}
	}
	free(buf);
	return head;
}

int
writelayers_pcap(struct layer *head,int write_hdr, FILE *fp)
{
	struct layer *m,*n;
	size_t len;
	if(write_hdr){
		struct pcap_file_header pfh;
		pfh.magic=0xa1b2c3d4;
		pfh.version_major=2;
		pfh.version_minor=4;
		pfh.thiszone=0;
		pfh.sigfigs=0;
		pfh.snaplen=-1;
		pfh.linktype=DLT_EN10MB;
		if( fwrite(&pfh,sizeof(pfh),1,fp) != 1)
				return -1;
	}
	for( m = head ; m != NULL ; m=m->next){
		if( m->pkthdr != NULL ){
			printf("reading pkthdr\n");
			len = m->size;
			for(n=m->next;n != NULL && n->pkthdr == NULL;n=n->next)
				len +=n->size;
			m->pkthdr->len=len;
			m->pkthdr->caplen=len;
			printf( "fwrite(m->pkthdr,sizeof(struct pcap_pkthdr),1,fp) != 1 %d\n",len);
			if( fwrite(m->pkthdr,sizeof(struct pcap_pkthdr),1,fp) != 1)
				return -1;
			len=0;			
		}
		if( m->size <= 0 )
			continue;
		printf("fwrite(m->proto,sizeof(char),m->size,fp) != m->size %d\n",m->size);
		if( fwrite(m->proto,sizeof(char),m->size,fp) != m->size )
				return -1;
	}
	
 return 0;
}*/
