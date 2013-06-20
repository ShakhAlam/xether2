#include "../include/xip.h"


struct layer *
alloc_ip(struct layer *m,size_t len)
{
	if(m == NULL )
		return NULL;

	if( len == 0 )
		len = sizeof(struct ip);

	if( len < sizeof(struct ip) )
		return NULL;

	if( ( m->proto = calloc(1,len) ) == NULL)
				return NULL;

	m->size = len;
	m->type = LT_IP;
	m->print = ipprint;
	m->sprint = ipsprint;
	m->next = NULL;
	m->prev = NULL;
	
	
	return m;
}

struct layer *
ip_decode(const char *buf,size_t len){
	struct layer *m;
	xip iph;
	int hlen;
	uint16_t tlen;

	if(len < sizeof(struct ip) )
		return NULL;

	iph = (xip)buf;

	hlen = (iph->ip_hl)<<2;

	if(len - hlen < 0 ){
		fprintf(stderr,"Xether:ip_decode found IP packet with wrong header length.\n");

		return NULL;
	}
 
	tlen = ntohs(iph->ip_len);

	if( len - tlen < 0 ){
		fprintf(stderr,"Xether:ip_decode found IP packet with wrong total length.\n");
		return NULL;
	}

	m = alloclayer(LT_IP,hlen);
	
	memcpy(m->proto,buf,hlen);

	iph = (xip)m->proto;

	if(len-hlen > 0)
	switch( iph->ip_p  ){
		case IPPROTO_ICMP:
			m->next = icmp_decode(buf+hlen,tlen-hlen);		
		break;
		case IPPROTO_TCP:
			m->next = tcp_decode(buf+hlen,tlen-hlen);		
		break;
		case IPPROTO_UDP:
			m->next = udp_decode(buf+hlen,tlen-hlen);		
		break;
		default:
			m->next = app_decode(buf+hlen,tlen-hlen);
		break;
	}
	return m;
}

int
ip_set(struct ip *iph,
			uint8_t tos, uint16_t len, uint16_t id, uint16_t off,
			uint8_t ttl, uint8_t proto, uint16_t sum, uint32_t src, uint32_t dst)
{

	iph->ip_hl	= 5;
	iph->ip_v	= 4;
	iph->ip_tos		= tos;
   iph->ip_len = htons(len);
	iph->ip_id	= htons(id);
	iph->ip_off	= htons(off);
	iph->ip_ttl	= ttl;
	iph->ip_p	= proto;
	iph->ip_sum	= htons(sum);
	iph->ip_src.s_addr	= src;
	iph->ip_dst.s_addr	= dst;
	
	return 0;
}

int
ip_sum(struct layer *m)
{
	struct ip *iph;
	iph = (xip)m->proto;
	
	iph->ip_sum = checksum((unsigned short*)iph,(int)sizeof(struct ip));
	return 0;
}

void
ipprint(struct layer *m)
{
	char ipbuf[IP_ADDRSTRLEN+1];
	struct ip *iph;
	iph = (xip)m->proto;
	
	printf("IP{\n");	
	printf(" v(%d)",iph->ip_v);
	printf(" hl(%d)",iph->ip_hl);
	printf(" tos(%d)",iph->ip_tos);
	printf(" len(%d)",ntohs(iph->ip_len));
	printf(" id(0x%04x)",ntohs(iph->ip_id));
	printf(" off(%d)",ntohs(iph->ip_off));
	printf(" ttl(%d)",iph->ip_ttl);
	printf(" sum(0x%X)",ntohs(iph->ip_sum));

	printf("\n src[%s] ->",ip_to_str(iph->ip_src.s_addr,ipbuf,sizeof(ipbuf)) );

	printf(" dst[%s]\n};\n",ip_to_str(iph->ip_dst.s_addr,ipbuf,sizeof(ipbuf)));
}

char *
ipsprint(char *buf, size_t n,struct layer *m)
{
	struct in_addr ipa;
	struct ip *iph;
	char tbuf[100];
	
	iph = (xip)m->proto;
	
	strcpy(buf,"IP{\r\n ");	
	sprintf(tbuf," v(%d) hl(%d) tos(%d)  len(%d)  id(%d) off(%d)  ttl(%d) sum(0x%X)\r\n",
				iph->ip_v,
				iph->ip_hl,
				iph->ip_tos,
				ntohs(iph->ip_len),
				ntohs(iph->ip_id),
				ntohs(iph->ip_off),
				iph->ip_ttl,
				ntohs(iph->ip_sum));
				
	strcat(buf,tbuf);
	
	memcpy(&ipa,&iph->ip_src,4);
	sprintf(tbuf," src[%s] ->",inet_ntoa(ipa));
	strcat(buf,tbuf);

	memcpy(&ipa,&iph->ip_dst,4);
	sprintf(tbuf," dst[%s]\r\n }; ",inet_ntoa(ipa));
	strcat(buf,tbuf);
	
	return buf;
}
