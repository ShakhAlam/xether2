#include "../include/xudp.h"

struct layer *
alloc_udp(struct layer *m,size_t len)
{
	if(m == NULL  )
		return NULL;
	
	if( len == 0)
		len = sizeof(struct udphdr);

	if( len < sizeof(struct udphdr) )
		return NULL;

	if( ( m->proto = calloc(1,sizeof(struct udphdr)) ) == NULL)
				return NULL;

	m->size = sizeof(struct udphdr);
	m->type = LT_UDP;
	m->print = udpprint;
	m->sprint = udpsprint;
	m->next = NULL;
	return m;
}

struct layer *
udp_decode(const char *buf,size_t len){
	struct layer *m;
	
	if(len < sizeof(struct udphdr) )
		return NULL;
	m = alloclayer(LT_UDP,sizeof(struct udphdr) );
	
	memcpy(m->proto,buf,sizeof(struct udphdr));
	
	/* Multiplex UDP based application protocols here */
	switch( ntohs( ((xudp)m->proto)->uh_sport )){
		case LT_DHCP:
		case LT_DHCP+1:
		m->next = dhcp_decode(buf+sizeof(struct udphdr),len-sizeof(struct udphdr));
		return m;						
	}
	
	switch( ntohs( ((xudp)m->proto)->uh_dport )){
		case LT_DHCP:
		case LT_DHCP+1:
		m->next = dhcp_decode(buf+sizeof(struct udphdr),len-sizeof(struct udphdr));
		return m;						
	}
		
	if(len-sizeof(struct udphdr)>0)
		m->next = app_decode(buf+sizeof(struct udphdr),len-sizeof(struct udphdr));
		
	return m;
}


int
udp_set(struct udphdr *udph,
			uint16_t sport,uint16_t dport, uint16_t ulen, uint16_t sum)
{
	udph->uh_sport = htons(sport);
	udph->uh_dport = htons(dport);
	udph->uh_ulen =  htons(ulen);
	udph->uh_sum = htons(sum);
	return 0;
}

int
udp_sum(struct layer *m)
{
	char data[1500];
	struct in_addr saddr,daddr;
	
	if( m == NULL || m->prev == NULL || m->next == NULL)
		return -1;
		
	if( m->prev->type != LT_IP)
		return -1;
		
	if(m->next->size >= sizeof(data)-sizeof(struct udphdr) )
		return -1;
		
	memcpy(data,m->proto,sizeof(struct udphdr));
	
	memcpy(data+sizeof(struct udphdr),m->next->proto,m->next->size);
	
	saddr.s_addr = ((xip)(m->prev->proto))->ip_src.s_addr;
	daddr.s_addr = ((xip)(m->prev->proto))->ip_dst.s_addr;
	
	((xudp)(m->proto))->uh_sum = trans_check(IPPROTO_UDP,data,
			    sizeof(struct udphdr)+m->next->size,
			    saddr,
			    daddr);	
			    
	return 0;
}

void
udpprint(struct layer *m)
{
	struct udphdr *udph;
	udph = (xudp)m->proto;
	printf("UDP{");
	printf(" sport(%d) ",ntohs(udph->uh_sport));
	printf("dport(%d) ",ntohs(udph->uh_dport));
	printf("ulen(%d) ",ntohs(udph->uh_ulen));
	printf("sum(0x%04x)\n};\n",ntohs(udph->uh_sum));

}

char *
udpsprint(char *buf, size_t n,struct layer *m)
{
	struct udphdr *udph;
	udph = (xudp)m->proto;

	if(n <= UDP_PRINT_BUF)
		return NULL;
	sprintf(buf,"UDP{\r\n sport(%d) dport(%d) ulen(%d) sum(%d)\r\n}; ",
	ntohs(udph->uh_sport),ntohs(udph->uh_dport),ntohs(udph->uh_ulen),ntohs(udph->uh_sum));
	
	return buf;

}

int
createUDPSocket(struct UDPSocket *ts, struct MAC *srcmac, struct MAC *dstmac,
	    uint32_t srcip, uint32_t dstip, uint16_t srcport, uint32_t dstport)
{
	//char szbpf[1024],ips[25],ipd[25];

	srand(time(NULL));
	
	memcpy(&ts->mac,srcmac,6);
	memcpy(&ts->gatewaymac,dstmac,6);

	ts->ip = srcip;
	ts->port = srcport;
	ts->hostip = dstip;
	ts->hostport = dstport;
	
	/*sprintf(szbpf,"(ip src %s and dst %s) and (udp src port %d and dst port %d)",
			ip_to_str(dstip,ips,sizeof(ips)),ip_to_str(srcip,ipd,sizeof(ipd)),dstport,srcport);


	if(filterDatalink(szbpf) < 0 ){
		fprintf(stderr,"error filtering datalink\n");
	}
	*/
	return 0;
}

u_long 
UDPSend(struct datalink *dl,struct UDPSocket *sock, char *data, size_t len)
{
	struct layer *m;
	
	m = alloclayer(LT_ETHER,0);

	ether_set( m->proto , &sock->mac ,&sock->gatewaymac, ETHERTYPE_IP);
	
	m->next = alloclayer(LT_IP,0);

	if(data == NULL) len = 0;

	ip_set(m->next->proto,0,(sizeof(struct ip)+sizeof(struct udphdr))+len,(u_short)rand()%0xFFFF,0,
			      128,IPPROTO_TCP,0,sock->ip,sock->hostip);
			      
	m->next->next = alloclayer(LT_UDP,0);
		
	if(data != NULL){

		m->next->next->next = allocapplayer(len);

		memcpy(m->next->next->next->proto,data,len);

	}
	
 	udp_set(m->next->next->proto,
			sock->port,sock->hostport,
			sizeof(struct udphdr)+len,0);
			
	m->next->next->prev = m->next;

			
	if( udp_sum(m->next->next) < 0)
	
		fprintf(stderr,"tcp sum error\n");
		
	
	ip_sum(m->next);

	sendlayers(dl,m);
	rmlayers(m);	
	return len;
}