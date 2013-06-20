#include "../include/xtcp.h"
/* struct TCPSocket *sock , struct datalink *dl*/
struct layer *
alloc_tcp(struct layer *m,size_t len)
{

	if(m == NULL )
		return NULL;
	
	if( len == 0 ) 
		len = sizeof(struct tcphdr); 
	if( len < sizeof(struct tcphdr) )
		return NULL;

	if( ( m->proto = calloc(1,len ) ) == NULL)
				return NULL;

	m->size = len;
	m->type = LT_TCP;
	m->print =  tcpprint;
	m->sprint = tcpsprint;
	m->next = NULL;
	return m;
}



struct layer *
tcp_decode(const char *buf,size_t len){
	struct layer *m;
	size_t n = 0,p = 0;
	xtcp tcph;

	if(len < sizeof(struct tcphdr) )
		return NULL;

	tcph = (xtcp)buf;
	
	
	/* Check for tcp options from offset and realloc tcp proto */
	
	if( tcph->th_off != 0)	
		p = tcph->th_off << 2;
	else
		p = sizeof(struct tcphdr);

	if( len - p < 0 ){
		fprintf(stderr,"Xether:tcp_decode found a segment with wrong offest information.\n");
		return NULL;
	}
	if( (m = calloc(1,sizeof(struct layer)) ) == NULL)
                return NULL;

        if( ( m->proto = calloc(1,p) ) == NULL)
                                return NULL;

	m->size = p;
        m->type = LT_TCP;
        m->print =  tcpprint;
        m->sprint = tcpsprint;
        m->next = NULL;

	memcpy(m->proto,buf,p);
	
	/* Demultiplex TCP application protocols here */
	
	m->next = app_decode(buf+p, len - p );
		
	return m;
}

int
tcp_set(struct tcphdr * tcph,
			uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
			uint8_t offset, uint8_t flags, uint16_t win, uint16_t sum, uint16_t urp)
{

	tcph->th_sport = htons(sport);
	tcph->th_dport = htons(dport);
	tcph->th_seq = htonl(seq);
	tcph->th_ack = htonl(ack);
	//tcph->th_x2  = offset;
	tcph->th_off = offset;
	tcph->th_flags = flags;
	tcph->th_win = htons(win);	
	tcph->th_sum = htons(sum);
	tcph->th_urp = htons(urp);
	return 0;
}

int
tcp_sum(struct layer *m)
{
	
	char data[1500];
	int len;
	struct in_addr saddr,daddr;
	
	if( m == NULL || m->prev == NULL)
		return -1;
		
	if( m->prev->type != LT_IP)
		return -1;
	
	if( m->next != NULL ){	

		if(m->next->size >= sizeof(data)-sizeof(struct tcphdr))
			return -1;

		memcpy(data+sizeof(struct tcphdr),m->next->proto,m->next->size);

		len = sizeof(struct tcphdr) + m->next->size;

	}	
	else
		len = sizeof(struct tcphdr);

	
	memcpy(data,m->proto, sizeof(struct tcphdr) );
		
	
	saddr.s_addr = ((xip)(m->prev->proto))->ip_src.s_addr;
	daddr.s_addr = ((xip)(m->prev->proto))->ip_dst.s_addr;

	
	((xtcp)(m->proto))->th_sum = trans_check(IPPROTO_TCP,data,
			    len,/*+m->next->size,*/
			    saddr,
			    daddr);	
	return 0;
}

void
tcpprint(struct layer *m)
{
	struct tcphdr *tcph;
	tcph = (xtcp)m->proto;
	printf("TCP{\n");
	printf(" sport[%d]->",ntohs(tcph->th_sport));
	printf(" dport[%d]",ntohs(tcph->th_dport));
	printf(" seq(%lu)",ntohl(tcph->th_seq));
	printf(" ack(%lu)",ntohl(tcph->th_ack));
	printf(" off(%d)",tcph->th_off);
	printf("\n flags[");
	if((tcph->th_flags&TH_SYN)== TH_SYN)
			printf("-SYN-");	
	if((tcph->th_flags&TH_ACK)== TH_ACK)
			printf("-ACK-");
	if((tcph->th_flags&TH_PUSH)== TH_PUSH)
			printf("-PSH-");
	if((tcph->th_flags&TH_RST)== TH_RST)
			printf("-RST-");
	if((tcph->th_flags&TH_FIN)== TH_FIN)
			printf("-FIN-");
	if((tcph->th_flags&TH_URG)== TH_URG)
			printf("-URG-");			
	printf("] win(%d)",ntohs(tcph->th_win));	
	printf(" sum(0x%X)",ntohs(tcph->th_sum));
	printf(" urp(%d)\n};\n",ntohs(tcph->th_urp));
}


char *
tcpsprint(char *buf, size_t n, struct layer *m){
	
	struct tcphdr *tcph;
	tcph = (xtcp)m->proto;
	
	sprintf(buf,
	"TCP{\r\n sport[%d]->dport[%d] seq(%lu) ack(%lu) off(%d) win(%d) sum(0x%X) urp(%d)\r\n flags[",
	ntohs(tcph->th_sport),ntohs(tcph->th_dport),ntohl(tcph->th_seq),ntohl(tcph->th_ack),tcph->th_off,
	ntohs(tcph->th_win),ntohs(tcph->th_sum),ntohs(tcph->th_urp));
	
	if((tcph->th_flags&TH_SYN)== TH_SYN)
			strcat(buf,"-SYN-");	
	if((tcph->th_flags&TH_ACK)== TH_ACK)
			strcat(buf,"-ACK-");
	if((tcph->th_flags&TH_PUSH)== TH_PUSH)
			strcat(buf,"-PSH-");
	if((tcph->th_flags&TH_RST)== TH_RST)
			strcat(buf,"-RST-");
	if((tcph->th_flags&TH_FIN)== TH_FIN)
			strcat(buf,"-FIN-");
	if((tcph->th_flags&TH_URG)== TH_URG)
			strcat(buf,"-URG-");			
	strcat(buf,"]\r\n }; ");
	
	return (char*)0;
}

int
createSocket(struct TCPSocket *ts, struct MAC *srcmac, struct MAC *dstmac,
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
	ts->seq = rand()%0xFFFFFFFF;
	ts->nextseq = 0;
	ts->ack = 0;
	ts->rcvwin = (uint16_t)TCP_DEF_RCVWIN;
	/*sprintf(szbpf,"(ip src %s and dst %s) and (tcp src port %d and dst port %d)",
			ip_to_str(dstip,ips,sizeof(ips)),ip_to_str(srcip,ipd,sizeof(ipd)),dstport,srcport);


	if(filterDatalink(szbpf) < 0 ){
		fprintf(stderr,"error filtering datalink\n");
	}

	printf("%s\n",szbpf);*/

	return 0;
}

u_long 
TCPSend(struct TCPSocket *sock , struct datalink *dl, uint8_t flag, char *data, size_t len)
{
	struct layer **m,*head;

	m = &head;
	/* switch link type here */

	if(dl->dl_pcap->linktype == DLT_EN10MB || dl->dl_pcap->linktype == DLT_NULL){
		*m = alloclayer(LT_ETHER,0);

		ether_set( (struct ether_header*)(*m)->proto , &sock->mac ,&sock->gatewaymac, ETHERTYPE_IP);
		m = &(*m)->next;
	}

	*m = alloclayer(LT_IP,0);

	if(data == NULL) len = 0;

	ip_set((struct ip*)(*m)->proto,0,(sizeof(struct ip)+sizeof(struct tcphdr))+len,(u_short)rand()%0xFFFF,0,
			      128,IPPROTO_TCP,0,sock->ip,sock->hostip);
			      
	(*m)->next = alloclayer(LT_TCP,0);
		
	if(data != NULL){

		(*m)->next->next = allocapplayer(len);

		memcpy((*m)->next->next->proto,data,len);

	}
	
 	tcp_set((struct tcphdr*)(*m)->next->proto,
			sock->port,sock->hostport,
			sock->seq,sock->ack,
			sizeof(struct tcphdr)/4,flag,sock->rcvwin,0,0);
			
	(*m)->next->prev = *m;

			
	if( tcp_sum((*m)->next) < 0)
	
		fprintf(stderr,"tcp sum error\n");
		
	
	ip_sum(*m);

	sendlayers(dl,head);
	rmlayers(head);
	return sock->seq;
}

u_long 
TCPSend_ttl(struct TCPSocket *sock , struct datalink *dl, uint8_t flag, char *data, size_t len,unsigned char ttl)
{
	struct layer **m,*head;

	m = &head;
	/* switch link type here */

	if(dl->dl_pcap->linktype == DLT_EN10MB){
		*m = alloclayer(LT_ETHER,0);

		ether_set( (*m)->proto , &sock->mac ,&sock->gatewaymac, ETHERTYPE_IP);
		m = &(*m)->next;
	}

	*m = alloclayer(LT_IP,0);

	if(data == NULL) len = 0;

	ip_set((*m)->proto,0,(sizeof(struct ip)+sizeof(struct tcphdr))+len,(u_short)rand()%0xFFFF,0,
			     ttl,IPPROTO_TCP,0,sock->ip,sock->hostip);
			      
	(*m)->next = alloclayer(LT_TCP,0);
		
	if(data != NULL){

		(*m)->next->next = allocapplayer(len);

		memcpy((*m)->next->next->proto,data,len);

	}
	
 	tcp_set((*m)->next->proto,
			sock->port,sock->hostport,
			sock->seq,sock->ack,
			sizeof(struct tcphdr)/4,flag,sock->rcvwin,0,0);
			
	(*m)->next->prev = *m;

			
	if( tcp_sum((*m)->next) < 0)
	
		fprintf(stderr,"tcp sum error\n");
		
	
	ip_sum(*m);

	sendlayers(dl,head);
	rmlayers(head);
	return sock->seq;
}
u_long 
SYN(struct TCPSocket *sock , struct datalink *dl)
{
	return TCPSend(sock,dl,TH_SYN,NULL,0);
} 
u_long 
SYN_ttl(struct TCPSocket *sock , struct datalink *dl,unsigned char ttl)
{
	return TCPSend_ttl(sock,dl,TH_SYN,NULL,0,ttl);
} 

u_long 
SYNACK(struct TCPSocket *sock , struct datalink *dl)
{
	return TCPSend(sock,dl,TH_SYN|TH_ACK,NULL,0);
}

u_long 
ACK(struct TCPSocket *sock , struct datalink *dl)
{
	return TCPSend(sock,dl,TH_ACK,NULL,0);
}

u_long 
FINACK(struct TCPSocket *sock , struct datalink *dl)
{
	return TCPSend(sock,dl,TH_FIN|TH_ACK,NULL,0);
}

u_long 
RST(struct TCPSocket *sock , struct datalink *dl)
{
	return TCPSend(sock,dl,TH_RST,NULL,0);
}

u_long 
RSTACK(struct TCPSocket *sock , struct datalink *dl)
{
	return TCPSend(sock,dl,TH_RST|TH_ACK,NULL,0);
}

u_long 
PSHACK(struct TCPSocket *sock , struct datalink *dl,char *data,int len)
{
	return TCPSend(sock,dl,TH_PUSH|TH_ACK,data,len);
}

