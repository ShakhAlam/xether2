#include "../include/xlayer.h"

struct layer *
alloclayer(int prototype,size_t len)
{
	struct layer *m;
	
	if(prototype < LT_MIN || prototype > LT_MAX)
		return NULL;
		
	if( (m = calloc(1,sizeof(struct layer)) ) == NULL)
		return NULL;
	m->type = prototype;
	m->pkthdr = NULL;
	
	switch(prototype){
		case -1:
			return m;
		case LT_ETHER:
			if( alloc_ether(m,len) == NULL){
				free(m);
				return NULL;
			}
			
			return m;
			
		break;
		case LT_ARP:
			if( alloc_arp(m,len) == NULL){
				free(m);
				return NULL;
			}
			return m;
		break;
		case LT_IP:
			if( alloc_ip(m,len) == NULL){
				free(m);
				return NULL;
			}
			
			return m;

		break;
		case LT_ICMP:
			if( alloc_icmp(m,len) == NULL){
				free(m);
				return NULL;
			}
			
			return m;

		break;
		case LT_UDP:
			if( alloc_udp(m,len) == NULL){
				free(m);
				return NULL;
			}
			
			return m;
			
		break;
		case LT_DHCP:
			if( alloc_dhcp(m,len) == NULL){
				free(m);
				return NULL;
			}

			return m;
		break;
		case LT_TCP:
			if( alloc_tcp(m,len) == NULL){
				free(m);
				return NULL;
			}
			return m;

		break;
		case LT_BREAK:
			
		break;
		default:
			return NULL;
		break;
	}

	return (m);
}


int 
freelayer(struct layer *pl)
{
	if(pl != NULL)
		free(pl);
	return 0;
}

struct layer*
addlayer(struct layer *plafter, struct layer * pladd)
{
	if(plafter == NULL || pladd == NULL)
		return NULL;
	
	pladd->next = plafter->next;
	plafter->next = pladd;
	pladd->prev = plafter;
	return pladd;
}

struct layer* 
appendlayers(struct layer *head,struct layer *tail){ 
	struct layer **px; 
	px = &head; 
	while( (*px) != NULL) 
		px = &(*px)->next; 
	*px = tail;
	tail->prev = head;	 
	return head; 
}

struct layer *
rmlayer(struct layer *rml)
{
	struct layer *t;

	if(rml == NULL)
		return NULL;
	if(rml->next != NULL){
		
		t = rml->next;
		if(rml->proto != NULL)
			free(rml->proto);
		if(rml->pkthdr != NULL)
			free(rml->pkthdr);
		free(rml);
		return t;
	}
	else{
		if(rml->proto != NULL)
			free(rml->proto);
		if(rml->pkthdr != NULL && rml->pkthdr != NULL_PKT_HDR)
			free(rml->pkthdr);
		free(rml);
		return NULL;	
	}
	return NULL;
}

struct layer*
rmnextlayer(struct layer *rmafter)
{
	if(rmafter->next != NULL){
		if(rmafter->next->next != NULL){
			struct layer *tmp;
			tmp = rmafter->next->next;
			if(rmafter->next->proto != NULL)
				free(rmafter->next->proto);
			if(rmafter->next->pkthdr != NULL && rmafter->next->pkthdr != NULL_PKT_HDR)
				free(rmafter->next->pkthdr);
			free(rmafter->next);
			
			rmafter->next = tmp;
			tmp->prev = rmafter;
			return rmafter;
		}
		else
		{
			if(rmafter->next->proto != NULL)
				free(rmafter->next->proto);
			if(rmafter->next->pkthdr != NULL && rmafter->next->pkthdr != NULL_PKT_HDR)
				free(rmafter->next->pkthdr);
			free(rmafter->next);
			return rmafter;
		}
	}
	return rmafter;
}

int
rmlayers(struct layer *head)
{
   
	if(head == NULL)
		return 0;
		
	rmlayers(head->next);

	if(head->proto != NULL)
			free(head->proto);
			
	if(head->pkthdr != NULL && head->pkthdr != NULL_PKT_HDR )
			free(head->pkthdr);
			
		
	free(head);
	
    head = NULL;	
	return 0;
}
 
	
struct layer*
findlayer(struct layer *head,int type)
{
	struct layer *t;
	for(t = head; t != NULL; t = t->next){
		if(t->type == type)
			return t;
	}
	return (NULL);
}

int
numlayers(struct layer *head)
{
	struct layer *t;
	int i = 0;
	for(t = head; t != NULL; t = t->next){
		i++;
	}
	return i;
}
struct layer *
getlayer(struct layer *head, unsigned int index)
{
	struct layer *in;
	unsigned int i = 0;
	for(in=head;in != NULL; in = in->next){
		if(i == index)
			return in;
		i++;
	}
	return NULL;
}

ssize_t
sendlayers(struct datalink *dl,struct layer * head)
{
	unsigned char *sendbuf = NULL;
	size_t nsend;
	ssize_t totsent;
	int flag,oflag;
	struct layer *player;

	if(head == NULL)
		return -1;
	totsent = 0;
	nsend = 0;
	oflag=flag= 0;
	if(head->pkthdr  == NULL)
		head->pkthdr  = NULL_PKT_HDR;
	for(player = head; player != NULL; player = player->next){
		switch(player->type){
			case LT_BREAK:
				nsend = sendData(dl,sendbuf,nsend);
				totsent += nsend;
				nsend = 0;
			default:
				if(player->proto == NULL){
					fprintf(stderr,"sendlayers: player->proto == NULL\n");
					return -1;
				}
				if( player->pkthdr != NULL){
					
					flag=!flag;
					if(flag == 0){
						flag=!flag;
						nsend = sendData(dl,sendbuf,nsend);
						totsent += nsend;
						nsend = 0;
					}
					
				}
				if( ( sendbuf =  realloc(sendbuf,player->size+nsend) ) == NULL)
					return -1;
	
				memcpy(sendbuf+nsend,player->proto,player->size);
				nsend += player->size;
			break;
		}

	}

	if(nsend<=0)
		return -1;

	nsend = sendData(dl,sendbuf,nsend);
	free(sendbuf);
	totsent += nsend;
	return totsent;
}

void
setheader(struct layer *head, struct pcap_pkthdr *hdr)
{

	if( hdr == NULL)
		head->pkthdr = NULL_PKT_HDR;
	else{
		head->pkthdr = malloc(sizeof(struct pcap_pkthdr));
		memcpy(head->pkthdr,hdr,sizeof(struct pcap_pkthdr));
	}
}


struct layer *
recvlayers(struct datalink *dl,int *nrecv)
{
	unsigned char buf[1514],*p=buf;
	size_t len;	
	struct pcap_pkthdr pkthdr;
	struct layer *recv;

	if( recv_pcap(dl,buf,sizeof(buf),&pkthdr) == NULL )
						
			return NULL; 	
	len = pkthdr.caplen;

	/* select datalink type here */
	switch(dl->dl_pcap->linktype){

		case DLT_NULL:
			fprintf(stderr,"xlayer:Datalink type NULL\n");
		//break;
		case DLT_EN10MB:
			if( ( recv = ether_decode(buf,len) ) == NULL){
				*nrecv = 0;
				return NULL;
			}
			recv->pkthdr = malloc(sizeof(pkthdr));

			memcpy(recv->pkthdr,&pkthdr,sizeof(pkthdr));

			*nrecv = len;	

	 	
		return recv;

		case DLT_EN3MB:

		break;
		case DLT_AX25:
		
		break;

		case DLT_PRONET:

		break;
		case DLT_CHAOS:
		break;
		case DLT_IEEE802:
		break;
		case DLT_ARCNET:
		break;
		case DLT_SLIP:
			fprintf(stderr,"xlayer:Datalink type SLIP\n");

		break;
		case DLT_PPP:
			fprintf(stderr,"xlayer:Datalink type PPP\n");
		break;
		case DLT_FDDI:
		break;
		case DLT_ATM_RFC1483:
		break;
		//case DLT_PPP_SERIAL:
			/* PPP over serial. skip 4 bytes */
		//	p = (buf+4);
			//len-=4;
		case DLT_RAW:
			if( ( recv = ip_decode(p,len) ) == NULL ){
				*nrecv =0;
				return NULL;
			}
			recv->pkthdr = malloc(sizeof(pkthdr));

			memcpy(recv->pkthdr,&pkthdr,sizeof(pkthdr));

			*nrecv = len;	
			

		return recv;
		case DLT_SLIP_BSDOS:
		break;
		case DLT_PPP_BSDOS:
		break;
	}

	return NULL;
}


void
printlayers(struct layer *head)
{
	struct layer *player;
	int n;
	if(head == NULL)
		return;
	putc('\n',stdout);
	for(n=0;n<80;n++)
		putc('_',stdout);
	putc('\n',stdout);
	
	for(player = head; player != NULL; player = player->next){
		if(player->print==NULL)
				continue;
		player->print(player);	
	}
}

int
writelayers(struct layer *head,FILE *fp){
	struct layer *player;
	if(head == NULL){
		fprintf(stderr,"xlayer::writelayers: link head is NULL");
		return -1;
	}
	if(fp == NULL){
		fprintf(stderr,"xlayer::writelayers: file ptr is NULL");
		return -1;
	}
	
	for(player = head; player != NULL; player = player->next){
		if( fwrite(&player->type,sizeof(int),1,fp) != sizeof(int) ){
			perror("fwrite");
			fprintf(stderr,"fwrite player->type failed\n");
			return -1;
		}
		if( fwrite(&player->size,sizeof(size_t),1,fp) 
			!= sizeof(size_t) ){
			perror("fwrite");
			fprintf(stderr,"fwrite player->size failed\n");

			return -1;
		}

		if(fwrite(player->proto,sizeof(char),player->size,fp) 
			!= player->size){
			perror("fwrite");
			fprintf(stderr,"fwrite player->proto %d failed\n",
				player->size);

			return -1;
		}
	}
	return 0;	
}

struct layer*
readlayers(FILE *fp,int *nrecv){

	ssize_t len = 0;
	size_t n=0;
	struct layer *recv,**lp;
	int prototype = 0;
	size_t size = 0;


	if(fp == NULL)
		return NULL;
		
	recv = NULL;
	lp	= &recv;
	
	while(!feof(fp)){
		if( fread(&prototype,sizeof(int),1,fp) != 1)
				return recv;
		if( fread(&size,sizeof(size_t),1,fp) != 1)
				return recv;

			
		if(prototype<LT_MIN || prototype > LT_MAX){
			fprintf(stderr,"Error reading frames from datafile : Wrong protocol type\n");
			return recv;
		}
		
		if(size<0 || size > 1514){
			fprintf(stderr,"Error reading frames from datafile : Segment exceeds MTU\n");
			return recv;
		}
		
		/*fprintf(stderr,"reading prototype of %d of size %d\n",prototype,size);*/
		
		if(prototype == LT_APP){
			if( ( *lp = allocapplayer(size) ) == NULL){
				fprintf(stderr,"Error allocating application layer\n");
				return recv;
			}
			
		}
		
		else{
			if( ( *lp = alloclayer(prototype,size) ) == NULL){
				fprintf(stderr,"Error allocating layer\n");
				return recv;
			}
		}	
		
		fread((*lp)->proto,sizeof(char),size,fp);
		n++;
		lp = &(*lp)->next;	
	}
	fseek(fp,0,SEEK_SET);
	/*printlayers(*lp);*/
	
	*nrecv = n;	
	return recv;

}

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

	buf = malloc(pfh.snaplen);
	if( buf ==  NULL ){
		fprintf(stderr,"error: memory allocation failed\n");
		return NULL;
	}

	

	while( !feof(fp) ){
		if( fread(&pkthdr,sizeof(pkthdr),1,fp) != 1){

			
			free(buf);
			return head;
		}

		
		if(pkthdr.len > pfh.snaplen){
			fprintf(stderr," pkthdr.len > pfh.snaplen \n" );
			free(buf);
			return head;
		}

		if( fread(buf,sizeof(char),pkthdr.len,fp) != pkthdr.len ){
			fprintf(stderr,"error reading packet\n");
			free(buf);
			return head;
		}

		switch( pfh.linktype )
		{
		case DLT_NULL:
			
		//break;

		case DLT_EN3MB:
			
		case DLT_EN10MB:
			
			*px = ether_decode(buf,pkthdr.len);

			(*px)->pkthdr = malloc(sizeof(pkthdr));

			memcpy((*px)->pkthdr,&pkthdr,sizeof(pkthdr));

			while( *px != NULL)
				px = &(*px)->next;


		break;

		case DLT_AX25:
			
		break;

		case DLT_PRONET:
			
		break;

		break;
		case DLT_CHAOS:
			

		break;
		case DLT_IEEE802:
			

		break;
		case DLT_ARCNET:
			

		break;
		case DLT_SLIP:
			
		break;
		case DLT_PPP:
			

		break;
		case DLT_FDDI:
			
		break;
		case DLT_ATM_RFC1483:
			
		break;
		case DLT_RAW:
			
			*px = ip_decode(buf,pkthdr.len);
			(*px)->pkthdr = malloc(sizeof(pkthdr));
			memcpy((*px)->pkthdr,&pkthdr,sizeof(pkthdr));

			while( *px != NULL)
				px = &(*px)->next;
			
		break;
		case DLT_SLIP_BSDOS:
			

		break;
		case DLT_PPP_BSDOS:
			

		break;
		}
	}
	free(buf);
	return head;
}

int
writelayers_pcap(struct layer *head,int writehdr, bpf_u_int32 linktype, FILE *fp)
{
	struct layer *m,*n;
	size_t len;
	if(writehdr){
		struct pcap_file_header pfh;
		pfh.magic=0xa1b2c3d4;
		pfh.version_major=2;
		pfh.version_minor=4;
		pfh.thiszone=0;
		pfh.sigfigs=0;
		pfh.snaplen=65535;
		pfh.linktype=linktype;
		if( fwrite(&pfh,sizeof(pfh),1,fp) != 1)
				return -1;
	}
	for( m = head ; m != NULL ; m=m->next){
		if( m->pkthdr != NULL ){
			if( m->pkthdr == NULL_PKT_HDR)
				m->pkthdr = calloc(sizeof(struct pcap_pkthdr),1);

			len = m->size;
			for(n=m->next;n != NULL && n->pkthdr == NULL;n=n->next)
				len +=n->size;
			m->pkthdr->len=len;
			m->pkthdr->caplen=len;
			
			if( fwrite(m->pkthdr,sizeof(struct pcap_pkthdr),1,fp) != 1)
				return -1;
			len=0;			
		}
		if( m->size <= 0 )
			continue;
		
		if( fwrite(m->proto,sizeof(char),m->size,fp) != m->size )
				return -1;
	}
	
 return 0;
}

unsigned short checksum(unsigned short *addr,int len)
{
        register int sum = 0;
        u_short answer = 0;
        register u_short *w = addr;
        register int nleft = len;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(u_char *)(&answer) = *(u_char *)w ;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}


unsigned short trans_check(unsigned char proto,
			   char *packet,
			   int length,
			   struct in_addr source_address,
			   struct in_addr dest_address)
{
  char *psuedo_packet;
  unsigned short answer;
  struct psuedohdr psuedohdr;
  
  psuedohdr.protocol = proto;
  psuedohdr.length = htons(length);
  psuedohdr.place_holder = 0;

  psuedohdr.source_address = source_address;
  psuedohdr.dest_address = dest_address;
  
  if((psuedo_packet = (char *)malloc(sizeof(psuedohdr) + length)) == NULL)  {
    perror("malloc");
    exit(1);
  }
  
  memcpy(psuedo_packet,&psuedohdr,sizeof(psuedohdr));
  memcpy((psuedo_packet + sizeof(psuedohdr)),
	 packet,length);
   
  answer = (unsigned short)checksum((unsigned short *)psuedo_packet,(int)(length + sizeof(psuedohdr)));
  free(psuedo_packet);
  return answer;
}


