#include "../include/xicmp.h"

 
struct layer *
alloc_icmp(struct layer *m,size_t len)
{
	if(m == NULL )
		return NULL;
	if( len == 0 )
		len = sizeof(struct icmp_hdr);
	
	if(  len < sizeof(struct icmp_hdr) )
		return NULL;

	if( ( m->proto = calloc(1,len) ) == NULL)
				return NULL;

	m->size = len;
	m->type = LT_ICMP;
	m->print = icmpprint;
	m->sprint = icmpsprint;
	return m;
}

struct layer *
icmp_decode(const char *buf,size_t len){
	struct layer *m;
	
	if(len < sizeof(struct icmp_hdr))
		return NULL;

	m = alloclayer(LT_ICMP,sizeof(struct icmp_hdr) );

	memcpy(m->proto,buf,sizeof(struct icmp_hdr));

	switch( ( (xicmp)( m->proto ))->icmp_type){
	
		case ICMP_PARAMPROB:		
		case ICMP_SOURCEQUENCH:		
		case ICMP_TIMXCEED:
		case ICMP_UNREACH:
		case ICMP_REDIRECT:
			m->next = ip_decode(buf+sizeof(struct icmp_hdr) ,len-sizeof(struct icmp_hdr));
		break;
		
		case ICMP_ECHOREPLY:
		case ICMP_ECHO:
			m->next = app_decode(buf+sizeof(struct icmp_hdr),len-sizeof(struct icmp_hdr));
		break;		
	}
			
	return m;
}


int
icmp_set(struct icmp_hdr *icmph,
			uint8_t type, uint8_t code, uint32_t seqid, uint16_t cksum)
{

		icmph->icmp_type = type;
		icmph->icmp_code = code;

		icmph->icmp_idseq = htonl(seqid);
		icmph->icmp_cksum = cksum;
			
		return 0;
}

int
icmp_sum(struct layer *m){
	xicmp icmph;

	icmph = (xicmp)m->proto;

	/* next 28 bytes of data is also part of the sum if part of ICMP protocol */
	
	if(m->next != NULL &&  m->next->type == LT_IP
	   && m->next->next != NULL && m->next->next->size >= 8){
		unsigned char *buf;
		buf = malloc(m->size + m->next->size + 8);
		memcpy(buf,m->proto,m->size);
		memcpy(buf+m->size,m->next->proto,m->next->size);
		memcpy(buf+m->next->size+m->size,m->next->next->proto,8);
		icmph->icmp_cksum = checksum((unsigned short*)buf,m->size+m->next->size+8);
		free(buf);
		return 0;
	}
	if( m->next != NULL && m->next->type == LT_APP){
		unsigned char *buf;
		buf = malloc(m->size + m->next->size );
		memcpy(buf,m->proto,m->size);
		memcpy(buf+m->size,m->next->proto,m->next->size);
		
		icmph->icmp_cksum = checksum((unsigned short*)buf,m->size+m->next->size);
		free(buf);
		return 0;
	}

	icmph->icmp_cksum = checksum((unsigned short*)icmph,(int)sizeof(struct icmp_hdr));
	return 0;
}

void
icmpprint(struct layer *m)
{
	struct icmp *icmph;
	icmph = (struct icmp *)m->proto;
	printf("ICMP{\n Type(%d):",icmph->icmp_type);
	switch(icmph->icmp_type){
		case ICMP_ECHOREPLY:
		
			printf(" ICMP_ECHOREPLY ID(%d) SEQ(%d) ",ntohs(icmph->icmp_id),ntohs(icmph->icmp_seq) );
			
		break;
		case ICMP_UNREACH:
			printf(" ICMP_UNREACH Code(%d): ",icmph->icmp_code);
			
			switch(icmph->icmp_code){
				case ICMP_UNREACH_NET:
				
					printf(" ICMP_UNREACH_NET ");
				
				break;
				case ICMP_UNREACH_HOST:
				
					printf(" ICMP_UNREACH_HOST ");				
				
				break;
				case ICMP_UNREACH_PROTOCOL:
				
					printf(" ICMP_UNREACH_PROTOCOL ");				
				
				break;
				case ICMP_UNREACH_PORT:
				
					printf(" ICMP_UNREACH_PORT ");								
				
				break;
				case ICMP_UNREACH_NEEDFRAG:
				
					printf(" ICMP_UNREACH_NEEDFRAG ");								
				
				break;
				case ICMP_UNREACH_SRCFAIL:
				
					printf(" ICMP_UNREACH_SRCFAIL ");								
				
				break;
				case ICMP_UNREACH_NET_UNKNOWN:
				
					printf(" ICMP_UNREACH_NET_UNKNOWN ");								
				
				
				break;
				case ICMP_UNREACH_HOST_UNKNOWN:
				
				
					printf(" ICMP_UNREACH_HOST_UKNOWN ");								
				
				break;
				case ICMP_UNREACH_ISOLATED:
				
				
					printf(" ICMP_UNREACH_ISOLATED ");												
				
				break;
				case ICMP_UNREACH_NET_PROHIB:
				
					printf(" ICMP_UNREACH_NET_PROHIB ");												
				
				break;
				case ICMP_UNREACH_HOST_PROHIB:
				
				
					printf(" ICMP_UNREACH_HOST_PROHIB ");												
				
				break;
				case ICMP_UNREACH_TOSNET:
				
					printf(" ICMP_UNREACH_TOSNET ");																
				
				break;
				case ICMP_UNREACH_TOSHOST:
				
				
					printf(" ICMP_UNREACH_TOSHOST ");																
				
				break;

				default:
					printf(" -unknown code- ");
				break;
			}		
		break;
		case ICMP_SOURCEQUENCH:
			
			printf(" ICMP_SOURCEQUENCH ");
			
		break;
		case ICMP_REDIRECT:{
			char ipbuf[IP_ADDRSTRLEN+1];
			ip_to_str(icmph->icmp_gwaddr.s_addr,ipbuf,sizeof(ipbuf));
			printf(" ICMP_REDIRECT to gateway[%s] Code(%d):",ipbuf,icmph->icmp_code);
			switch(icmph->icmp_code){
				case ICMP_REDIRECT_NET:
			
					printf(" ICMP_REDIRECT_NET ");
			
				break;
				case ICMP_REDIRECT_HOST:

					printf(" ICMP_REDIRECT_HOST ");				
			
				break;
				case ICMP_REDIRECT_TOSNET:
			
					printf(" ICMP_REDIRECT_TOSNET ");
				
				break;
				case ICMP_REDIRECT_TOSHOST:
			
					printf(" ICMP_REDIRECT_TOSHOST ");
			
				break;
				default:
					printf(" -unknown code- ");
				break;				
			}
		}		
		break;
		case ICMP_ECHO:
			printf(" ICMP_ECHO id(%d) seq(%d) ",icmph->icmp_id,icmph->icmp_seq);
		
		break;
		case ICMP_ROUTERADVERT:
			printf(" ICMP_ROUTERADVERT ");		
		break;
		case ICMP_ROUTERSOLICIT:
			printf(" ICMP_ROUTERSOLICIT ");		
		break;
		case ICMP_TIMXCEED:
			printf(" ICMP_TIMXCEED ");
			switch(icmph->icmp_code){
				case ICMP_TIMXCEED_INTRANS:
				
				printf(" ICMP_TIMXCEED_INTRANS ");
				
				break;
				case ICMP_TIMXCEED_REASS:
				
				printf(" ICMP_TIMXCEED_REASS ");				
				
				break;
				default:
					printf(" -unknown code- ");
				break;					
			}		
		break;
		case ICMP_PARAMPROB:
		printf(" ICMP_PARAMPROB ");
			switch(icmph->icmp_code){
				case ICMP_PARAMPROB_OPTABSENT:
				printf(" ICMP_PARAMPROB_OPTABSENT ");				
				break;
				default:
				
				break;
			}
		break;
		case ICMP_TSTAMP:
			printf(" ICMP_TSTAMP ");
		break;
		case ICMP_TSTAMPREPLY:
			printf(" ICMP_TSTAMPREPLY ");
		break;
		case ICMP_IREQ:
			printf(" ICMP_IREQ ");
		break;
		case ICMP_IREQREPLY:
			printf(" ICMP_IREQREPLY ");
		break;
		case ICMP_MASKREQ:
			printf(" ICMP_IREQREPLY ");
		break;
		case ICMP_MASKREPLY:
			printf(" ICMP_MASKREPLY ");		
		break;
		default:
			printf(" -unknown type- ");
	}
	printf(" checksum(0x%X)\n};\n",ntohs(icmph->icmp_cksum));
	
}

char *
icmpsprint(char *buf, size_t n, struct layer *m)
{
	xicmp icmph;
	icmph = (xicmp)m->proto;
	
	if(n<= ICMP_PRINT_BUF)
		return NULL;
		
	sprintf(buf,"ICMP{\r\n type(%d) ",icmph->icmp_type);
	switch(icmph->icmp_type){
		case ICMP_ECHOREPLY:
			strcat(buf,"ICMP_ECHOREPLY ");
		break;
		case ICMP_UNREACH:
			switch(icmph->icmp_code){
				case ICMP_UNREACH_NET:
				
					strcat(buf," ICMP_UNREACH_NET ");
				
				break;
				case ICMP_UNREACH_HOST:
				
					strcat(buf," ICMP_UNREACH_HOST ");				
				
				break;
				case ICMP_UNREACH_PROTOCOL:
				
					strcat(buf," ICMP_UNREACH_PROTOCOL ");				
				
				break;
				case ICMP_UNREACH_PORT:
				
					strcat(buf," ICMP_UNREACH_PORT ");								
				
				break;
				case ICMP_UNREACH_NEEDFRAG:
				
					strcat(buf," ICMP_UNREACH_NEEDFRAG ");								
				
				break;
				case ICMP_UNREACH_SRCFAIL:
				
					strcat(buf," ICMP_UNREACH_SRCFAIL ");								
				
				break;
				case ICMP_UNREACH_NET_UNKNOWN:
				
					strcat(buf," ICMP_UNREACH_NET_UNKNOWN ");								
				
				
				break;
				case ICMP_UNREACH_HOST_UNKNOWN:
				
				
					strcat(buf,"ICMP_UNREACH_HOST_UKNOWN");								
				
				break;
				case ICMP_UNREACH_ISOLATED:
				
				
					strcat(buf," ICMP_UNREACH_ISOLATED ");												
				
				break;
				case ICMP_UNREACH_NET_PROHIB:
				
					strcat(buf," ICMP_UNREACH_NET_PROHIB ");												
				
				break;
				case ICMP_UNREACH_HOST_PROHIB:
				
				
					strcat(buf," ICMP_UNREACH_HOST_PROHIB ");												
				
				break;
				case ICMP_UNREACH_TOSNET:
				
					strcat(buf," ICMP_UNREACH_TOSNET ");																
				
				break;
				case ICMP_UNREACH_TOSHOST:
				
				
					strcat(buf," ICMP_UNREACH_TOSHOST ");																
				
				break;

				default:
					strcat(buf,"-unknown code-");
				break;
			}		
		break;
		case ICMP_SOURCEQUENCH:
			strcat(buf," ICMP_SOURCEQUENCH ");
			
		break;
		case ICMP_REDIRECT:
			switch(icmph->icmp_code){
				case ICMP_REDIRECT_NET:
					strcat(buf," ICMP_REDIRECT_NET ");
				break;
				case ICMP_REDIRECT_HOST:

					strcat(buf," ICMP_REDIRECT_HOST ");				
				break;
				case ICMP_REDIRECT_TOSNET:
					strcat(buf," ICMP_REDIRECT_TOSNET ");
				
				break;
				case ICMP_REDIRECT_TOSHOST:
					strcat(buf," ICMP_REDIRECT_TOSHOST ");
				break;
				default:
					strcat(buf,"-unknown code-");
				break;				
			}		
		break;
		case ICMP_ECHO:
			strcat(buf," ICMP_ECHO ");		
		break;
		case ICMP_ROUTERADVERT:
			strcat(buf," ICMP_ROUTERADVERT ");		
		break;
		case ICMP_ROUTERSOLICIT:
			strcat(buf," ICMP_ROUTERSOLICIT ");		
		break;
		case ICMP_TIMXCEED:
			switch(icmph->icmp_code){
				case ICMP_TIMXCEED_INTRANS:
				
				strcat(buf," ICMP_TIMXCEED_INTRANS ");
				
				break;
				case ICMP_TIMXCEED_REASS:
				
				strcat(buf," ICMP_TIMXCEED_REASS ");				
				
				break;
				default:
					strcat(buf,"-unknown code-");
				break;					
			}		
		break;
		case ICMP_PARAMPROB:
			switch(icmph->icmp_code){
				case ICMP_PARAMPROB_OPTABSENT:
				strcat(buf," ICMP_PARAMPROB_OPTABSENT ");				
				break;
				default:
				
				break;
			}
		break;
		case ICMP_TSTAMP:
			strcat(buf," ICMP_TSTAMP ");
		break;
		case ICMP_TSTAMPREPLY:
			strcat(buf," ICMP_TSTAMPREPLY ");
		break;
		case ICMP_IREQ:
			strcat(buf," ICMP_IREQ ");
		break;
		case ICMP_IREQREPLY:
			strcat(buf," ICMP_IREQREPLY ");
		break;
		case ICMP_MASKREQ:
			strcat(buf," ICMP_IREQREPLY ");
		break;
		case ICMP_MASKREPLY:
			strcat(buf," ICMP_MASKREPLY ");		
		break;
		default:
			strcat(buf," -unknown type- ");
	}
	strcat(buf,"\r\n }; ");
	return buf;
}


int
ICMPEchoRequest(struct datalink *dl,struct MAC *srcmac, struct MAC *dstmac,uint32_t src, 
						uint32_t dst, uint16_t id, uint16_t seq)
{
	struct layer *head,**i;
	long t1=0,t2=0;

	
	i = &head;	
	if(dl->dl_pcap->linktype == DLT_EN10MB ){
		*i = alloclayer(LT_ETHER,0);
	
		ether_set( (*i)->proto , srcmac ,dstmac, ETHERTYPE_IP);

		i = &(*i)->next;
	}

	*i = alloclayer(LT_IP,0);
	ip_set((*i)->proto,
			0,sizeof(struct ip)+8,rand()%255,0,
			64,IPPROTO_ICMP,0,src,dst);
	
	ip_sum(*i);
	
	i = &(*i)->next;
	
	*i = alloclayer(LT_ICMP,0);
	
	icmp_set((*i)->proto,ICMP_ECHO,0,(id<<16)+seq,0);
	
	icmp_sum(*i);

	sendlayers(dl,head);
	rmlayers(head);
	return 0;

}

int
ICMPEchoReply(struct datalink *dl,struct MAC *srcmac, struct MAC *dstmac,uint32_t src, 
						uint32_t dst, uint16_t id, uint16_t seq)
{
	struct layer *head,**i;
	long t1=0,t2=0;

	
	i = &head;	
	if(dl->dl_pcap->linktype == DLT_EN10MB ){
		*i = alloclayer(LT_ETHER,0);
	
		ether_set( (*i)->proto , srcmac ,dstmac, ETHERTYPE_IP);

		i = &(*i)->next;
	}

	*i = alloclayer(LT_IP,0);
	ip_set((*i)->proto,
			0,sizeof(struct ip)+sizeof(struct icmp),rand()%255,0,
			64,IPPROTO_ICMP,0,src,dst);
	
	ip_sum(*i);
	
	i = &(*i)->next;
	
	*i = alloclayer(LT_ICMP,0);
	
	icmp_set((*i)->proto,ICMP_ECHOREPLY,0,(id<<16)+seq,0);
	
	icmp_sum(*i);

	sendlayers(dl,head);
	rmlayers(head);
	return 0;

}
