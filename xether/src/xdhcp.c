#include "../include/xdhcp.h"

struct dopt
{
	uint8_t opt;
	uint8_t len;
};

struct layer *
alloc_dhcp(struct layer *m,size_t len)
{

	if(m == NULL || len < 0 )
		return NULL;

	if( len == 0 )
		len = sizeof(struct dhcp);
	
	if( ( m->proto = calloc(1,len) ) == NULL)
				return NULL;

	m->size = len;

	m->type = LT_DHCP;

	m->print = dhcpprint;

	m->sprint = dhcpsprint;

	return m;
}

struct layer *
dhcp_decode(const char *buf,size_t len)
{
	struct layer *m;

	m = alloclayer(LT_DHCP,len);	
	memcpy(m->proto,buf,m->size);

	return m;
}

int	
dhcp_set(struct dhcp *dhcph,
		uint8_t opc, uint8_t htype, uint8_t hlen, 
		uint8_t hops,uint32_t xid, uint16_t secs, 
		uint16_t flags, uint32_t ciaddr, uint32_t yiaddr,
		uint32_t siaddr, uint32_t giaddr,uint8_t *chaddr,
		const char *sname,const char *file,struct dhcp_opt *options, int nopt)
{
	int i,b;

	dhcph->opcode = opc;

	dhcph->htype = htype;

	dhcph->hlen = hlen;

	dhcph->hops = hops;

	dhcph->xid = htonl(xid);

	dhcph->secs = htons(secs);

	dhcph->flags = htons(flags);

	dhcph->ciaddr = htonl(ciaddr);

	dhcph->yiaddr = htonl(yiaddr);

	dhcph->siaddr = htonl(siaddr);

	dhcph->giaddr = htonl(giaddr);

	dhcph->magic = htonl(DHCP_MAGIC);

	if(hlen>DHCP_CHADDR_LEN)
		return -1;
	
    memcpy(dhcph->chaddr,chaddr,hlen);

	if(sname)
		strncpy(dhcph->sname,sname,DHCP_SNAME_LEN);

	if(file)
		strncpy(dhcph->file,file,DHCP_FILE_LEN);

	if(nopt <= 0 || options == NULL)
		return 0;

	for(i=b=0;i<nopt && b+options[i].len+2 < DHCP_OPT_LEN;i++){

		dhcph->options[b++] = options[i].opt;
		dhcph->options[b++] = options[i].len;
		memcpy(&dhcph->options[b],options[i].value,options[i].len);

		b += options[i].len;

	}

	dhcph->options[b] = 0xFF;

	return 0;
}

int	
dhcp_send(struct datalink *dl, struct MAC *srcmac, struct MAC *dstmac,
				 uint32_t srcip, uint32_t dstip,
				 uint8_t opc, uint8_t htype, uint8_t hlen, 
				 uint8_t hops,uint32_t xid, uint16_t secs, 
				 uint16_t flags, uint32_t ciaddr, uint32_t yiaddr,
				 uint32_t siaddr, uint32_t giaddr,uint8_t *chaddr,
				 const char *sname,
				 const char *file,
				 struct dhcp_opt *options,
				 int nopt)
{
	struct layer *head,**i,*u,*ip;
	struct dhcp *dhcph;
	int n,b;

	uint16_t srcport,dstport;

	switch(opc){
		case DHCP_OP_REQUEST:
			srcport = 68;
			dstport = 67;
		break;
		case DHCP_OP_REPLY:
			srcport = 68;
			dstport = 67;
		break;			
	}

	i = &head;

	*i = alloclayer(LT_ETHER,0);
	
	ether_set( (*i)->proto , srcmac ,NULL, ETHERTYPE_IP);

	i = &(*i)->next;
	
	*i = alloclayer(LT_IP,0);

	ip_set((*i)->proto,
			0,
			sizeof(struct ip)+sizeof(struct udphdr)+sizeof(struct dhcp),
			rand()%255,0,
			64,IPPROTO_UDP,0,0,-1);
	
	ip_sum(*i);

	ip = *i;

	i = &(*i)->next;

	*i = alloclayer(LT_UDP,0);

	udp_set((*i)->proto,srcport,dstport,sizeof(struct udphdr)+sizeof(struct dhcp),0);	

	u = *i;

	i = &(*i)->next;

	*i = alloclayer(LT_DHCP,0);

	dhcph = (*i)->proto;

	dhcph->opcode = opc;
	dhcph->htype = htype;
	dhcph->hlen = hlen;
	dhcph->hops = hops;
	dhcph->xid = htonl(xid);
	dhcph->secs = htons(secs);
	dhcph->flags = htons(flags);
	dhcph->ciaddr = htonl(ciaddr);
	dhcph->yiaddr = htonl(yiaddr);
	dhcph->siaddr = htonl(siaddr);
	dhcph->giaddr = htonl(giaddr);
	dhcph->magic = htonl(DHCP_MAGIC);
	if(hlen>DHCP_CHADDR_LEN)
		return -1;
	memcpy(dhcph->chaddr,chaddr,hlen);
	if(sname)
	strncpy(dhcph->sname,sname,DHCP_SNAME_LEN);
	if(file)
	strncpy(dhcph->file,file,DHCP_FILE_LEN);
	if(nopt <= 0 || options == NULL)
		return 0;

	for(n=b=0;n<nopt && b+options[n].len+2 < DHCP_OPT_LEN;n++){
		dhcph->options[b++] = options[n].opt;
		dhcph->options[b++] = options[n].len;
		memcpy(&dhcph->options[b],options[n].value,options[n].len);
		b += options[n].len;
	}

	dhcph->options[b] = 0xFF;

	u->prev = ip;
	udp_sum(u);
	sendlayers(dl,head);
	rmlayers(head);


	return 0;

}

static void
prnips(uint8_t *p,int n)
{
	int i;
	struct in_addr ina;
	for(i = 0 ; i < n ; i ++ ){
		ina.s_addr = *(((uint32_t*)p)+i);
		printf("%s ",inet_ntoa(ina));
	}
}

static void
sprnips(char *buf, uint8_t *p,int n)
{
	int i;
	char tbuf[20];
	struct in_addr ina;
	for(i = 0 ; i < n ; i ++ ){
		ina.s_addr = *(((uint32_t*)p)+i);
		sprintf(tbuf,"%s ",inet_ntoa(ina));
		strcat(buf,tbuf);
	}
}
void 
dhcpprint(struct layer *m)
{
	char *opc;
	struct in_addr ina;
	struct dopt *dop;
	int i,n;
	uint8_t *p;
	switch( ((xdhcp)m->proto)->opcode){
		case DHCP_OP_REQUEST:
			opc = " REQUEST ";
		break;
		case DHCP_OP_REPLY:
			opc = " REPLY ";
		break;
		default:
			opc = " UNKNOWN ";
	}

	printf("DHCP{\nopcode(%s) htype(%d) hlen(%d) hops(%d) xid:(0x%x)\nsecs: %d flags: %d ",
		opc,((xdhcp)m->proto)->htype,((xdhcp)m->proto)->hlen,((xdhcp)m->proto)->hops,
		ntohl( ((xdhcp)m->proto)->xid ),ntohs( ((xdhcp)m->proto)->secs ),
		ntohs(((xdhcp)m->proto)->flags));
	ina.s_addr = ((xdhcp)m->proto)->ciaddr;
	printf(" ciaddr:[%s]", inet_ntoa(ina) );
	ina.s_addr = ((xdhcp)m->proto)->yiaddr;
	printf(" yiaddr:[%s]\n", inet_ntoa(ina) );
	ina.s_addr = ((xdhcp)m->proto)->siaddr;
	printf("siaddr: %s ", inet_ntoa(ina) );
	ina.s_addr = ((xdhcp)m->proto)->giaddr;
	printf(" giaddr: %s ", inet_ntoa(ina) );
	printf(" chaddr");
	for(i=0;i<((xdhcp)m->proto)->hlen;i++){
		printf(":%X",((xdhcp)m->proto)->chaddr[i]);
	}
	printf("\nsname(%s) file(%s) magic(0x%x)\n",
		(((xdhcp)m->proto)->sname[0]==0)?"NOT GIVEN":((xdhcp)m->proto)->sname,
		(((xdhcp)m->proto)->file[0]==0)?"NOT GIVEN":((xdhcp)m->proto)->file,
		((xdhcp)m->proto)->magic);
	for( dop =(struct dopt*)((xdhcp)m->proto)->options; dop->opt != DHCP_OPT_END && dop->len >= 1; 
		 dop =(struct dopt*)(( ( uint8_t *)(dop+1) ) + dop->len) )
	{
		p = (uint8_t*)dop+1;
		p++;
		printf("|\noption(%d) len(%d) |",dop->opt,dop->len);
		if(dop->len == 0 ) continue;
		switch(dop->opt){

		case DHCP_OPT_MASK:
			ina.s_addr = *((uint32_t*)p);
			printf(" subnet mask [%s]",inet_ntoa(ina));

		break;
		
		case DHCP_OPT_TOFF:
			printf(" time offset [%x:%x:%x:%x] ",
				p[1],p[2],p[3],p[4]);
		break;
		
		case DHCP_OPT_ROUTE:
			n = dop->len/DHCP_OPT_ROUTE_LEN;
			printf(" router ");
			prnips(p,n);
		break;
		
		case DHCP_OPT_TS:
			n = dop->len/DHCP_OPT_TS_LEN;
			printf(" time server ");
			prnips(p,n);
		break;
		
		case DHCP_OPT_NS:
			n = dop->len/DHCP_OPT_NS_LEN;
			printf(" name server ");
			prnips(p,n);
		break;
		
		case DHCP_OPT_DNS:
			n = dop->len/DHCP_OPT_DNS_LEN;
			printf(" DNS ");
			prnips(p,n);
		break;
		
		case DHCP_OPT_LOGS:
			n = dop->len/DHCP_OPT_LOGS_LEN;
			printf(" log server ");
			prnips(p,n);
		break;
		
		case DHCP_OPT_CKS:
			n = dop->len/DHCP_OPT_CKS_LEN;
			printf(" cookie server ");
			prnips(p,n);
		break;
		
		case DHCP_OPT_LPRS:
			n = dop->len/DHCP_OPT_LPRS_LEN;
			printf(" print server ");
			prnips(p,n);
		break;
		
		case DHCP_OPT_IMPRS:
			n = dop->len/DHCP_OPT_IMPRS_LEN;
			printf(" impress server ");
			prnips(p,n);
		break;
		
		case DHCP_OPT_RLS:
			n = dop->len/DHCP_OPT_RLS_LEN;
			printf(" resource location server ");
			prnips(p,n);
		break;
		
		case DHCP_OPT_HOSTNAME:

			printf(" Hostname %.*s ",dop->len,p);
			
		break;
		
		case DHCP_OPT_BOOTF_SIZE:
			printf("boot file size: %d ",ntohs(*((uint16_t*)p)));
		break;
		
		case DHCP_OPT_MDUMP:
			printf("dump file name: %.*s ",dop->len,p);
		break;
		
		case DHCP_OPT_DOMAIN_NAME:
			printf("domain name: %.*s ",dop->len,p);
		break;
		
		case DHCP_OPT_SWAPS:
			ina.s_addr = *(((uint32_t*)p));
			printf("swap server %s ",inet_ntoa(ina));			
		break;
		
		case DHCP_OPT_ROOT_PATH:
			printf("root path: %.*s ",dop->len,p);
		break;
		
		case DHCP_OPT_EXT_PATH:
			printf("extensions path: %.*s ",dop->len,p);
		break;
		
		case DHCP_OPT_IPF:
			printf("IP forwarding: %s ", (*p)?"enabled":"disabled");
		break;
		
		case DHCP_OPT_SRCRT:
			printf("source routing: %s ", (*p)?"enabled":"disabled");
		break;
		
		case DHCP_OPT_PF:
			printf("policy filter IP/mask pairs: ");
			n = dop->len/DHCP_OPT_PF_LEN;
			prnips(p,n);
		break;
		
		case DHCP_OPT_MDRS:
			printf("max dgram reasm size: %d ",ntohs(*((uint16_t*)p)));
		break;
		
		case DHCP_OPT_TTL:
			printf("default ttl: %d ",*p);
		break;
		
		case DHCP_OPT_PMTU_TIMEO:
			printf("Path MTU timeout: %d ",ntohl(*((uint32_t*)p)));
		break;
		
		case DHCP_OPT_PMTU_TAB:
			printf("Path MTU Table: ");
			n = dop->len/DHCP_OPT_PMTU_TAB_LEN;
			for(i = 0 ; i < n ; i ++ ){
				printf("%d ", ntohs(*((uint16_t*)p)) );
			}
		break;
		
		case DHCP_OPT_IMTU:
			printf("Interface MTU: ");
			printf("%d ", ntohs(*((uint16_t*)p)) );
		break;
		
		case DHCP_OPT_ALL_SUBLOCAL:
			printf("All subnets are %s local", (*p)?"":"NOT");
		break;
		
		case DHCP_OPT_BCAST_ADDR:
			printf("Broadcast Address: ");
			prnips(p,1);
		break;
		
		case DHCP_OPT_PERF_MASK_DISC:
			printf("Do %s perform ICMP mask request ", (*p)?"":"NOT");
		break;
		
		case DHCP_OPT_REP_MASK:
			printf("Do %s reply for ICMP mask request ", (*p)?"":"NOT");
		break;
		
		case DHCP_OPT_PERF_ROUTE_DISC:
			printf("Do %s perform ICMP router discovery ", (*p)?"":"NOT");
		break;
		
		case DHCP_OPT_ROUTE_SOLICIT_ADDR:
			printf("Router Solicit Address: ");
			prnips(p,1);
		break;
		
		case DHCP_OPT_STATIC_ROUTE:
			n = dop->len/4;
			printf(" Static Routes ");
			prnips(p,n);
			
		break;
		
		case DHCP_OPT_TRAILER_ENCAP:
			printf("Do %s use trailers ", (*p)?"":"NOT");
		break;
		
		case DHCP_OPT_ARP_CACHE_TIMEO:
			printf("ARP Cache Timeout %d",ntohl(*((uint32_t*)p)) );
		break;
		
		
		case DHCP_OPT_ETHER_ENCAP:
			printf("Ethernet Encapsulation Type: %s ", 
				(*p)?"Ethernet II":"IEEE 802.3");
		break;
		
		case DHCP_OPT_TCP_TTL:
			printf("TCP Default TTL %d ",*p);
		break;
		
		case DHCP_OPT_TCP_KEEP_ALIVE:
			printf("TCP Keep-alive: %d seconds.", ntohl(*((uint32_t*)p)) );
		break;
		
		case DHCP_OPT_CNIS:
			printf("Network Information Service Domain: %.*s ",dop->len ,p);
		break;
		
		case DHCP_OPT_NIS_SERV:
			printf("Network Information Servers: ");
			n = dop->len/DHCP_OPT_NIS_SERV_LEN;
			prnips(p,n);
		break;
		
		case DHCP_OPT_NTP_SERV:
			printf("Network Time Protocol Servers: ");
			n = dop->len/DHCP_OPT_NTP_SERV_LEN;
			prnips(p,n);
		break;
		
		case DHCP_OPT_VEND_SPEC:
			printf("Vendor Specific Data: ");
			for(i=0;i<dop->len;i++)
				printf("%x:",*( ( (unsigned char *)dop+1 ) + i + 1) );
		break;
		
		case DHCP_OPT_NBMS_SERV:
			printf("NetBIOS over TCP/IP Name Server: ");
			n = dop->len/DHCP_OPT_NBMS_SERV_LEN;
			prnips(p,n);
		break;
		
		case DHCP_OPT_NBDD_SERV:
			printf("NetBIOS over TCP/IP Datagram Distribution Server: ");
			n = dop->len/DHCP_OPT_NBDD_SERV_LEN;
			prnips(p,n);
		break;
		
		case DHCP_OPT_NBNODE_TYPE:
			printf("NetBIOS over TCP/IP Node Type: ");
			switch(*p){
			case	0x1: 
				printf(" B-node ");
			break;
			
			case	0x2:
				printf(" P-node ");
			break;
			
			case 0x4:
				printf(" M-node ");
			break;
			

			case 0x8:
				printf(" H-node ");
			break;
			}
		break;
		
		case DHCP_OPT_NBSCOPE:
			printf("NetBIOS over TCP/IP Scope: %*.s ",dop->len,p);
		break;
		
		case DHCP_OPT_XFS:
			printf("X Window System Font Server:");
			n = dop->len/DHCP_OPT_XFS_LEN;
			prnips(p,n);
		break;
		
		case DHCP_OPT_XDM:
			printf("X Window System Display Manager:");
			n = dop->len/DHCP_OPT_XDM_LEN;
			prnips(p,n);
		break;
		
		case DHCP_OPT_REQ_IP:
			printf("Requested IP: ");
			prnips(p,1);
		break;
		
		case DHCP_OPT_LEASE_TIME:
			printf("Lease Time: %d seconds.", ntohl(*((uint32_t*)p)) );
		break;

		
		case DHCP_OPT_OVERLOAD:
			printf("Overload : ");
			switch(*p){
			case DHCP_OPT_OVERLOAD_FILE:
				printf("File ");
			break;
			
			case DHCP_OPT_OVERLOAD_SNAME:
				printf("SName ");
			break;
			
			case DHCP_OPT_OVERLOAD_BOTH:
				printf("File and SName");
			break;
			}
		break;

		case DHCP_OPT_TYPE:
			printf("Message Type: DHCP ");
			switch(*p){
			case DHCP_OPT_TYPE_DISCOVER:
				printf("Discover");
			break;
			case DHCP_OPT_TYPE_OFFER:
				printf("Offer ");
			break;
			case DHCP_OPT_TYPE_REQUEST:
				printf("Request ");
			break;
			case DHCP_OPT_TYPE_DECLINE:
				printf("Decline ");			
			break;
			case DHCP_OPT_TYPE_ACK:
				printf("Acknowledge ");
			break;
			case DHCP_OPT_TYPE_NAK:
				printf("Negative Acknowledge");
			break;
			case DHCP_OPT_TYPE_RELEASE:
				printf("Release ");
			break;
			}
		break;
		case DHCP_OPT_SERV_ID:
			printf("Server ID: ");
			prnips(p,1);
		break;
		case DHCP_OPT_PARAM_REQ:
			printf("Parameter Request: ");
			for(i=0;i<dop->len;i++)
				printf("%x:",*( ( (unsigned char *)dop+1 ) + i + 1) );
			
		break;
		case DHCP_OPT_MSG:
			printf("Server Messasge: %.*s ",dop->len,p);
		break;
		case DHCP_OPT_MSG_SIZE:
			printf("max msg size: %d ",ntohs(*((uint16_t*)p)));
		break;
		case DHCP_OPT_RENEW_TIME:
			printf("Renew Time: %d seconds.", ntohl(*((uint32_t*)p)) );
		break;
		case DHCP_OPT_REBIND_TIME:
			printf("Rebind Time: %d seconds.", ntohl(*((uint32_t*)p)) );
		break;
		case DHCP_OPT_CLASS_ID:
			printf("Class ID: ");
			for(i=0;i<dop->len;i++)
				printf("%x:",*( ( (unsigned char *)dop+1 ) + i + 1) );
			
		break;
		case DHCP_OPT_CLIENT_ID:
			printf("Client ID: Type(%d) ID ",*p);
			for(i=1;i<dop->len;i++)
				printf("%x:",*( ( (unsigned char *)dop+1 ) + i + 1) );
						
		break;

		case DHCP_OPT_TFTP_SERVNAME:
			printf(" TFTP Server %.*s ",dop->len,p);
		break;
		
		case DHCP_OPT_BOOT_FILENAME:
			printf(" Boot filename %.*s ",dop->len,p);
		break;
		
		default:
		for(i=0;i<dop->len;i++)
				printf("%x:",*( ( (unsigned char *)dop+1 ) + i + 1) );
		break;
		}
	}

	printf("\n};\n");

}

char *
dhcpsprint(char *buf, size_t len,struct layer *m)
{
	char *opc;
	struct in_addr ina;
	struct dopt *dop;
	int i,n;
	uint8_t *p;
	char tbuf[512];
	
	switch( ((xdhcp)m->proto)->opcode){
		case DHCP_OP_REQUEST:
			opc = " REQUEST ";
		break;
		case DHCP_OP_REPLY:
			opc = " REPLY ";
		break;
		default:
			opc = " UNKNOWN ";
	}

	sprintf(buf,"DHCP{\nopcode(%s) htype(%d) hlen(%d) hops(%d) xid:(0x%x)\nsecs: %d flags: %d ",
		opc,((xdhcp)m->proto)->htype,((xdhcp)m->proto)->hlen,((xdhcp)m->proto)->hops,
		ntohl( ((xdhcp)m->proto)->xid ),ntohs( ((xdhcp)m->proto)->secs ),
		ntohs(((xdhcp)m->proto)->flags));
	ina.s_addr = ((xdhcp)m->proto)->ciaddr;
	sprintf(tbuf," ciaddr:[%s]", inet_ntoa(ina) );
	strcat(buf,tbuf);
	ina.s_addr = ((xdhcp)m->proto)->yiaddr;
	sprintf(tbuf," yiaddr:[%s]\n", inet_ntoa(ina) );
	strcat(buf,tbuf);
	ina.s_addr = ((xdhcp)m->proto)->siaddr;
	sprintf("siaddr: %s ", inet_ntoa(ina) );
	strcat(buf,tbuf);	
	ina.s_addr = ((xdhcp)m->proto)->giaddr;
	sprintf(" giaddr: %s ", inet_ntoa(ina) );
	strcat(buf,tbuf);	
	sprintf(tbuf," chaddr");
	strcat(buf,tbuf);
	for(i=0;i<((xdhcp)m->proto)->hlen;i++){
		sprintf(tbuf,":%X",((xdhcp)m->proto)->chaddr[i]);
		strcat(buf,tbuf);
	}
	sprintf(tbuf,"\nsname(%s) file(%s) magic(0x%x)\n",
		(((xdhcp)m->proto)->sname[0]==0)?"NOT GIVEN":((xdhcp)m->proto)->sname,
		(((xdhcp)m->proto)->file[0]==0)?"NOT GIVEN":((xdhcp)m->proto)->file,
		((xdhcp)m->proto)->magic);
	strcat(buf,tbuf);		
	for( dop =(struct dopt*)((xdhcp)m->proto)->options; dop->opt != DHCP_OPT_END && dop->len >= 1; 
		 dop =(struct dopt*)(( ( uint8_t *)(dop+1) ) + dop->len) )
	{
		p = (uint8_t*)dop+1;
		p++;
		sprintf(tbuf,"|\noption(%d) len(%d) |",dop->opt,dop->len);
		strcat(buf,tbuf);
		if(dop->len == 0 ) continue;
		switch(dop->opt){

		case DHCP_OPT_MASK:
			ina.s_addr = *((uint32_t*)p);
			sprintf(tbuf," subnet mask [%s]",inet_ntoa(ina));
			strcat(buf,tbuf);

		break;
		case DHCP_OPT_TOFF:
			sprintf(tbuf," time offset [%x:%x:%x:%x] ",
				p[1],p[2],p[3],p[4]);
			strcat(buf,tbuf);				
		break;
		case DHCP_OPT_ROUTE:
			n = dop->len/DHCP_OPT_ROUTE_LEN;
			sprintf(tbuf," router ");
			strcat(buf,tbuf);
			sprnips(tbuf,p,n);
			strcat(buf,tbuf);			
		break;
		case DHCP_OPT_TS:
			n = dop->len/DHCP_OPT_TS_LEN;
			sprintf(tbuf," time server ");
			strcat(buf,tbuf);
			sprnips(tbuf,p,n);
			strcat(buf,tbuf);
		break;
		case DHCP_OPT_NS:
			n = dop->len/DHCP_OPT_NS_LEN;
			sprintf(tbuf," name server ");
			strcat(buf,tbuf);
			sprnips(tbuf,p,n);
			strcat(buf,tbuf);
		break;
		case DHCP_OPT_DNS:
			n = dop->len/DHCP_OPT_DNS_LEN;
			sprintf(tbuf," DNS ");
			strcat(buf,tbuf);
			sprnips(tbuf,p,n);
			strcat(buf,tbuf);
		break;
		case DHCP_OPT_LOGS:
			n = dop->len/DHCP_OPT_LOGS_LEN;
			sprintf(tbuf," log server ");
			strcat(buf,tbuf);			
			sprnips(tbuf,p,n);
			strcat(buf,tbuf);
		break;
		case DHCP_OPT_CKS:
			n = dop->len/DHCP_OPT_CKS_LEN;
			
			sprintf(buf," cookie server ");
			strcat(buf,tbuf);			
			sprnips(tbuf,p,n);
			strcat(buf,tbuf);
		break;
		case DHCP_OPT_LPRS:
			n = dop->len/DHCP_OPT_LPRS_LEN;
			printf(" print server ");
			strcat(buf,tbuf);			
			sprnips(tbuf,p,n);
			strcat(buf,tbuf);
		break;
		case DHCP_OPT_IMPRS:
			n = dop->len/DHCP_OPT_IMPRS_LEN;
			printf(" impress server ");
			strcat(buf,tbuf);			
			sprnips(tbuf,p,n);
			strcat(buf,tbuf);
		break;
		case DHCP_OPT_RLS:
			n = dop->len/DHCP_OPT_RLS_LEN;
			printf(" resource location server ");
			strcat(buf,tbuf);			
			sprnips(tbuf,p,n);
			strcat(buf,tbuf);
		break;
		case DHCP_OPT_HOSTNAME:

			sprintf(tbuf," Hostname %.*s ",dop->len,p);
			strcat(buf,tbuf);						
			
		break;
		case DHCP_OPT_BOOTF_SIZE:
			sprintf(tbuf,"boot file size: %d ",ntohs(*((uint16_t*)p)));
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_MDUMP:
			sprintf(tbuf,"dump file name: %.*s ",dop->len,p);
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_DOMAIN_NAME:
			sprintf(tbuf,"domain name: %.*s ",dop->len,p);
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_SWAPS:
			ina.s_addr = *(((uint32_t*)p));
			sprintf(tbuf,"swap server %s ",inet_ntoa(ina));			
			strcat(buf,tbuf);			
		break;
		case DHCP_OPT_ROOT_PATH:
			sprintf(tbuf,"root path: %.*s ",dop->len,p);
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_EXT_PATH:
			sprintf(tbuf,"extensions path: %.*s ",dop->len,p);
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_IPF:
			sprintf(tbuf,"IP forwarding: %s ", (*p)?"enabled":"disabled");
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_SRCRT:
			sprintf(tbuf,"source routing: %s ", (*p)?"enabled":"disabled");
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_PF:
			sprintf(tbuf,"policy filter IP/mask pairs: ");
			strcat(buf,tbuf);						
			n = dop->len/DHCP_OPT_PF_LEN;
			sprnips(tbuf,p,n);
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_MDRS:
			sprintf(tbuf,"max dgram reasm size: %d ",ntohs(*((uint16_t*)p)));
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_TTL:
			sprintf(tbuf,"default ttl: %d ",*p);
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_PMTU_TIMEO:
			sprintf(tbuf,"Path MTU timeout: %d ",ntohl(*((uint32_t*)p)));
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_PMTU_TAB:
			sprintf(tbuf,"Path MTU Table: ");
			strcat(buf,tbuf);						
			n = dop->len/DHCP_OPT_PMTU_TAB_LEN;
			for(i = 0 ; i < n ; i ++ ){
				sprintf(tbuf,"%d ", ntohs(*((uint16_t*)p)) );
				strcat(buf,tbuf);							
			}
		break;
		case DHCP_OPT_IMTU:
			sprintf(tbuf,"Interface MTU: %d ", ntohs(*((uint16_t*)p)) );
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_ALL_SUBLOCAL:
			sprintf(tbuf,"All subnets are %s local", (*p)?"":"NOT");
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_BCAST_ADDR:
			sprintf(tbuf,"Broadcast Address: ");
			strcat(buf,tbuf);			
			sprnips(tbuf,p,1);
			strcat(buf,tbuf);			
		break;
		case DHCP_OPT_PERF_MASK_DISC:
			sprintf(tbuf,"Do %s perform ICMP mask request ", (*p)?"":"NOT");
			strcat(buf,tbuf);			
		break;
		case DHCP_OPT_REP_MASK:
			sprintf(tbuf,"Do %s reply for ICMP mask request ", (*p)?"":"NOT");
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_PERF_ROUTE_DISC:
			sprintf(tbuf,"Do %s perform ICMP router discovery ", (*p)?"":"NOT");
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_ROUTE_SOLICIT_ADDR:
			sprintf(tbuf,"Router Solicit Address: ");
			strcat(buf,tbuf);						
			sprnips(tbuf,p,1);
		break;
		case DHCP_OPT_STATIC_ROUTE:
			n = dop->len/4;
			sprintf(tbuf," Static Routes ");
			strcat(buf,tbuf);						
			sprnips(tbuf,p,n);
			strcat(buf,tbuf);						
			
		break;
		case DHCP_OPT_TRAILER_ENCAP:
			sprintf(tbuf,"Do %s use trailers ", (*p)?"":"NOT");
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_ARP_CACHE_TIMEO:
			sprintf(tbuf,"ARP Cache Timeout %d",ntohl(*((uint32_t*)p)) );
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_ETHER_ENCAP:
			sprintf(tbuf,"Ethernet Encapsulation Type: %s ", 
				(*p)?"Ethernet II":"IEEE 802.3");
			strcat(buf,tbuf);							
		break;
		
		case DHCP_OPT_TCP_TTL:
			sprintf(tbuf,"TCP Default TTL %d ",*p);
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_TCP_KEEP_ALIVE:
			sprintf(tbuf,"TCP Keep-alive: %d seconds.", ntohl(*((uint32_t*)p)) );
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_CNIS:
			sprintf(tbuf,"Network Information Service Domain: %.*s ",dop->len ,p);
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_NIS_SERV:
			sprintf(tbuf,"Network Information Servers: ");
			strcat(buf,tbuf);						
			n = dop->len/DHCP_OPT_NIS_SERV_LEN;
			sprnips(tbuf,p,n);
		break;
		case DHCP_OPT_NTP_SERV:
			sprintf(tbuf,"Network Time Protocol Servers: ");
			strcat(buf,tbuf);						
			n = dop->len/DHCP_OPT_NTP_SERV_LEN;
			sprnips(tbuf,p,n);
		break;
		case DHCP_OPT_VEND_SPEC:
			sprintf(tbuf,"Vendor Specific Data: ");
			for(i=0;i<dop->len;i++){
				sprintf(tbuf,"%x:",*( ( (unsigned char *)dop+1 ) + i + 1) );
				strcat(buf,tbuf);							
			}
		break;
		case DHCP_OPT_NBMS_SERV:
			sprintf(tbuf,"NetBIOS over TCP/IP Name Server: ");
			strcat(buf,tbuf);						
			n = dop->len/DHCP_OPT_NBMS_SERV_LEN;
			sprnips(tbuf,p,n);
		break;
		case DHCP_OPT_NBDD_SERV:
			sprintf(tbuf,"NetBIOS over TCP/IP Datagram Distribution Server: ");
			
			n = dop->len/DHCP_OPT_NBDD_SERV_LEN;
			sprnips(tbuf,p,n);
		break;
		case DHCP_OPT_NBNODE_TYPE:
			sprintf(tbuf,"NetBIOS over TCP/IP Node Type: ");
			strcat(buf,tbuf);			
			switch(*p){
			case	0x1: 
				sprintf(tbuf," B-node ");
			break;
			case	0x2:
				sprintf(tbuf," P-node ");
			break;
			case 0x4:
				sprintf(tbuf," M-node ");
			break;

			case 0x8:
				sprintf(tbuf," H-node ");
			break;
			}
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_NBSCOPE:
			sprintf(tbuf,"NetBIOS over TCP/IP Scope: %*.s ",dop->len,p);
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_XFS:
			sprintf(tbuf,"X Window System Font Server:");
			strcat(buf,tbuf);						
			n = dop->len/DHCP_OPT_XFS_LEN;
			sprnips(tbuf,p,n);
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_XDM:
			sprintf(tbuf,"X Window System Display Manager:");
			strcat(buf,tbuf);						
			n = dop->len/DHCP_OPT_XDM_LEN;
			sprnips(tbuf,p,n);
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_REQ_IP:
			ina.s_addr = *((uint32_t*)p);
			sprintf(tbuf,"Requested IP: ",inet_ntoa(ina));
			strcat(buf,tbuf);			
		break;
		case DHCP_OPT_LEASE_TIME:
			sprintf(tbuf,"Lease Time: %d seconds.", ntohl(*((uint32_t*)p)) );
			strcat(buf,tbuf);						
		break;

		
		case DHCP_OPT_OVERLOAD:
			sprintf(tbuf,"Overload : ");
			strcat(buf,tbuf);						
			switch(*p){
			case DHCP_OPT_OVERLOAD_FILE:
				sprintf(tbuf,"File ");
			break;
			case DHCP_OPT_OVERLOAD_SNAME:
				sprintf(tbuf,"SName ");
			break;
			case DHCP_OPT_OVERLOAD_BOTH:
				sprintf(tbuf,"File and SName");
			break;
			}
		break;

		case DHCP_OPT_TYPE:
			sprintf(tbuf,"Message Type: DHCP ");
			strcat(buf,tbuf);						
			switch(*p){
			case DHCP_OPT_TYPE_DISCOVER:
				sprintf(tbuf,"Discover");
			break;
			case DHCP_OPT_TYPE_OFFER:
				sprintf(tbuf,"Offer ");
			break;
			case DHCP_OPT_TYPE_REQUEST:
				sprintf(tbuf,"Request ");
			break;
			case DHCP_OPT_TYPE_DECLINE:
				sprintf(tbuf,"Decline ");			
			break;
			case DHCP_OPT_TYPE_ACK:
				sprintf(tbuf,"Acknowledge ");
			break;
			case DHCP_OPT_TYPE_NAK:
				sprintf(tbuf,"Negative Acknowledge");
			break;
			case DHCP_OPT_TYPE_RELEASE:
				sprintf(tbuf,"Discover");
			break;
			}
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_SERV_ID:
			ina.s_addr = *((uint32_t*)p);
			sprintf(tbuf,"Server ID: ",inet_ntoa(ina));
			strcat(buf,tbuf);			
		break;
		case DHCP_OPT_PARAM_REQ:
			sprintf(tbuf,"Parameter Request: ");
			strcat(buf,tbuf);						
			for(i=0;i<dop->len;i++){
				sprintf(tbuf,"%x:",*( ( (unsigned char *)dop+1 ) + i + 1) );
				strcat(buf,tbuf);							
			}			
		break;
		case DHCP_OPT_MSG:
			sprintf(tbuf,"Server Messasge: %.*s ",dop->len,p);
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_MSG_SIZE:
			sprintf(tbuf,"max msg size: %d ",ntohs(*((uint16_t*)p)));
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_RENEW_TIME:
			sprintf(tbuf,"Renew Time: %d seconds.", ntohl(*((uint32_t*)p)) );
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_REBIND_TIME:
			sprintf(tbuf,"Rebind Time: %d seconds.", ntohl(*((uint32_t*)p)) );
			strcat(buf,tbuf);						
		break;
		case DHCP_OPT_CLASS_ID:
			sprintf(tbuf,"Class ID: ");
			strcat(buf,tbuf);			
			for(i=0;i<dop->len;i++){
				sprintf(tbuf,"%x:",*( ( (unsigned char *)dop+1 ) + i + 1) );
				strcat(buf,tbuf);							
			}
			
		break;
		case DHCP_OPT_CLIENT_ID:
			sprintf(tbuf,"Client ID: Type(%d) ID ",*p);
			strcat(buf,tbuf);						
			for(i=1;i<dop->len-1;i++){
				sprintf(tbuf,"%x:",*( ( (unsigned char *)dop+1 ) + i + 1) );
				strcat(buf,tbuf);							
			}
						
		break;
		
		case DHCP_OPT_TFTP_SERVNAME:
			sprintf(tbuf," TFTP Server: %s ",p);
			strcat(buf,tbuf);
		break;
		
		case DHCP_OPT_BOOT_FILENAME:
			sprintf(tbuf," Boot filename: %s ",p);
			strcat(buf,tbuf);
		break;
		
		default:
		 	for(i=0;i<dop->len;i++){
				sprintf(tbuf,"%x:",*( ( (unsigned char *)dop+1 ) + i + 1) );
				strcat(buf,tbuf);							
		 	}
		break;
		}
	}

	sprintf(tbuf,"\n};\n");
	strcat(buf,tbuf);							
	return NULL;
}

int	
dhcp_discover(struct datalink *dl, struct MAC *srcmac,
			uint32_t txid, 
			uint32_t rqaddr, const char *hostname, uint8_t *rqopt, uint8_t numopt)
{

	struct dhcp_opt opt[5];
	int n;


	opt[0].opt 	= DHCP_OPT_TYPE;
	opt[0].len 	= DHCP_OPT_TYPE_LEN;
	opt[0].value = malloc(opt[0].len);
	opt[0].value[0] = DHCP_OPT_TYPE_DISCOVER;
	opt[1].opt 	= DHCP_OPT_CLIENT_ID;
	opt[1].len	= 7;
	opt[1].value = malloc(opt[1].len);
	opt[1].value[0] = 1;
	memcpy(&(opt[1].value[1]),srcmac->mac,6);
	opt[2].opt	= DHCP_OPT_REQ_IP;
	opt[2].len	= DHCP_OPT_REQ_IP_LEN;
	opt[2].value = malloc(opt[2].len);
	*((uint32_t*)(opt[2].value)) = rqaddr;
	opt[3].opt	= DHCP_OPT_HOSTNAME;
	opt[3].len	= strlen(hostname) + 1;
	opt[3].value = malloc(opt[3].len);
	strcpy(opt[3].value,hostname);
	opt[4].opt	= DHCP_OPT_PARAM_REQ;
	opt[4].len	= numopt;
	opt[4].value = malloc(opt[4].len);
	memcpy(opt[4].value,rqopt,numopt);
	
	dhcp_send(dl,srcmac,NULL,0,-1,
			DHCP_OP_REQUEST, 1, 6, 
			0,htonl(txid), 0, 
			0,0,0,
			0,0,srcmac->mac,
			NULL,NULL,opt,5);
	for(n = 0 ; n < 5 ; n ++ )
		free(opt[n].value);
	
	return 0;
}

int	
dhcp_offer(struct datalink *dl, struct MAC *srcmac,struct MAC *dstmac,uint32_t srcip, uint32_t dstip,
			uint32_t yiaddr,uint32_t siaddr,uint32_t giaddr,
			struct MAC *chaddr,const char *sname,const char *file,
			uint32_t txid,uint32_t leasetime,uint32_t mask,uint32_t route,
			uint32_t *dns,int ndns,const char *domain)
{

	struct dhcp_opt opt[6];
	int n;
	opt[0].opt 	= DHCP_OPT_TYPE;
	opt[0].len 	= DHCP_OPT_TYPE_LEN;
	opt[0].value = malloc(opt[0].len);
	opt[0].value[0] = DHCP_OPT_TYPE_OFFER;

	opt[1].opt 	= DHCP_OPT_SERV_ID;
	opt[1].len	= 4;
	opt[1].value = malloc(opt[1].len);
	*((uint32_t*)(opt[1].value)) = siaddr;


	opt[2].opt	= DHCP_OPT_LEASE_TIME;
	opt[2].len	= DHCP_OPT_LEASE_TIME_LEN;
	opt[2].value = malloc(opt[2].len);

	*((uint32_t*)(opt[2].value)) = htonl(leasetime);

	opt[3].opt	= DHCP_OPT_MASK;
	opt[3].len	= DHCP_OPT_MASK_LEN;
	opt[3].value = malloc(opt[3].len);
	*((uint32_t*)(opt[3].value)) = mask;

	opt[4].opt	= DHCP_OPT_ROUTE;
	opt[4].len	= DHCP_OPT_ROUTE_LEN;
	opt[4].value = malloc(opt[4].len);
	*((uint32_t*)(opt[4].value)) = route;

	opt[4].opt	= DHCP_OPT_ROUTE;
	opt[4].len	= DHCP_OPT_ROUTE_LEN;
	opt[4].value = malloc(opt[4].len);
	*((uint32_t*)(opt[4].value)) = route;
	opt[5].opt	= DHCP_OPT_DNS;
	opt[5].len	= DHCP_OPT_DNS_LEN*ndns;
	opt[5].value = malloc(opt[5].len);
	for(n=0;n<ndns;n++){
		*(((uint32_t*)opt[5].value)+n) = dns[n];
	}

	dhcp_send(dl,srcmac,dstmac,srcip,dstip,
			DHCP_OP_REPLY, 1, 6, 
			0,htonl(txid), 0, 
			0,0,yiaddr,
			siaddr,giaddr,chaddr->mac,
			sname,file,opt,6);

	for(n = 0 ; n < 6 ; n ++ )
		free(opt[n].value);

	return 0;
}

int	
dhcp_request(struct datalink *dl, struct MAC *srcmac,
			uint32_t txid, 
			uint32_t rqaddr, const char *hostname, uint8_t *rqopt, uint8_t numopt)
{
	struct dhcp_opt opt[5];
	int n;

	opt[0].opt 	= DHCP_OPT_TYPE;
	opt[0].len 	= DHCP_OPT_TYPE_LEN;
	opt[0].value = malloc(opt[0].len);
	opt[0].value[0] = DHCP_OPT_TYPE_REQUEST;
	opt[1].opt 	= DHCP_OPT_CLIENT_ID;
	opt[1].len	= 7;
	opt[1].value = malloc(opt[1].len);
	opt[1].value[0] = 1;
	memcpy(&(opt[1].value[1]),srcmac->mac,6);
	opt[2].opt	= DHCP_OPT_REQ_IP;
	opt[2].len	= DHCP_OPT_REQ_IP_LEN;
	opt[2].value = malloc(opt[2].len);
	*((uint32_t*)(opt[2].value)) = rqaddr;
	opt[3].opt	= DHCP_OPT_HOSTNAME;
	opt[3].len	= strlen(hostname) + 1;
	opt[3].value = malloc(opt[3].len);
	strcpy(opt[3].value,hostname);
	opt[4].opt	= DHCP_OPT_PARAM_REQ;
	opt[4].len	= numopt;
	opt[4].value = malloc(opt[4].len);
	memcpy(opt[4].value,rqopt,numopt);
	
	dhcp_send(dl,srcmac,NULL,0,-1,DHCP_OP_REQUEST, 
			1, 6, 0,htonl(txid), 0,0,0,0,0,0,
			srcmac->mac, NULL,NULL,opt,5);
	for(n = 0 ; n < 5 ; n ++ )
		free(opt[n].value);
	
	return 0;
}

int 
dhcp_ack(struct datalink *dl, struct MAC *srcmac,struct MAC *dstmac,uint32_t srcip, uint32_t dstip,
			uint32_t yiaddr,uint32_t siaddr,uint32_t giaddr,
			struct MAC *chaddr,const char *sname,const char *file,
			uint32_t txid,uint32_t leasetime,uint32_t mask,uint32_t route,
			uint32_t *dns,int ndns,const char *domain)
{

	struct dhcp_opt opt[6];
	int n;
	opt[0].opt 	= DHCP_OPT_TYPE;
	opt[0].len 	= DHCP_OPT_TYPE_LEN;
	opt[0].value = malloc(opt[0].len);
	opt[0].value[0] = DHCP_OPT_TYPE_ACK;

	opt[1].opt 	= DHCP_OPT_SERV_ID;
	opt[1].len	= 4;
	opt[1].value = malloc(opt[1].len);
	*((uint32_t*)(opt[1].value)) = siaddr;


	opt[2].opt	= DHCP_OPT_LEASE_TIME;
	opt[2].len	= DHCP_OPT_LEASE_TIME_LEN;
	opt[2].value = malloc(opt[2].len);

	*((uint32_t*)(opt[2].value)) = htonl(leasetime);

	opt[3].opt	= DHCP_OPT_MASK;
	opt[3].len	= DHCP_OPT_MASK_LEN;
	opt[3].value = malloc(opt[3].len);
	*((uint32_t*)(opt[3].value)) = mask;

	opt[4].opt	= DHCP_OPT_ROUTE;
	opt[4].len	= DHCP_OPT_ROUTE_LEN;
	opt[4].value = malloc(opt[4].len);
	*((uint32_t*)(opt[4].value)) = route;

	opt[5].opt	= DHCP_OPT_DNS;
	opt[5].len	= DHCP_OPT_DNS_LEN*ndns;
	opt[5].value = malloc(opt[5].len);
	for(n=0;n<ndns;n++){
		*(((uint32_t*)opt[5].value)+n) = dns[n];
	}

	dhcp_send(dl,srcmac,dstmac,srcip,dstip,

			DHCP_OP_REPLY, 1, 6, 
			0,htonl(txid), 0, 
			0,0,yiaddr,
			siaddr,giaddr,chaddr->mac,
			sname,file,opt,6);

	for(n = 0 ; n < 6 ; n ++ )
		free(opt[n].value);

	return 0;
}

int	
dhcp_release(struct datalink *dl, struct MAC *srcmac,struct MAC *dstmac,uint32_t srcip, uint32_t dstip,
			uint32_t ciaddr,uint32_t siaddr,
			uint32_t txid)
{

	struct dhcp_opt opt[3];
	int n;
	opt[0].opt 	= DHCP_OPT_TYPE;
	opt[0].len 	= DHCP_OPT_TYPE_LEN;
	opt[0].value = malloc(opt[0].len);
	opt[0].value[0] = DHCP_OPT_TYPE_RELEASE;

	opt[1].opt 	= DHCP_OPT_SERV_ID;
	opt[1].len	= 4;
	opt[1].value = malloc(opt[1].len);
	*((uint32_t*)(opt[1].value)) = siaddr;


	opt[2].opt 	= DHCP_OPT_CLIENT_ID;
	opt[2].len	= 7;
	opt[2].value = malloc(opt[2].len);
	opt[2].value[0] = 1;
	memcpy(&(opt[2].value[1]),srcmac->mac,6);

	dhcp_send(dl,srcmac,dstmac,srcip,dstip,
			DHCP_OP_REQUEST, 1, 6, 
			0,htonl(txid), 0, 
			0,ciaddr,0,
			siaddr,0,srcmac->mac,
			NULL,NULL,opt,3);

	for(n = 0 ; n < 3 ; n++ )
		free(opt[n].value);


	return 0;
}

int dhcp_nack(struct datalink *dl, struct MAC *srcmac,struct MAC *cmac,uint32_t srcip,
			uint32_t siaddr,uint32_t giaddr,const char *msg,
			uint32_t txid)

{
	struct dhcp_opt opt[3];
	int n;
	opt[0].opt 	= DHCP_OPT_TYPE;
	opt[0].len 	= DHCP_OPT_TYPE_LEN;
	opt[0].value = malloc(opt[0].len);
	opt[0].value[0] = DHCP_OPT_TYPE_NAK;

	opt[1].opt 	= DHCP_OPT_SERV_ID;
	opt[1].len	= 4;
	opt[1].value = malloc(opt[1].len);
	*((uint32_t*)(opt[1].value)) = siaddr;

	opt[2].opt 	= DHCP_OPT_MSG;
	opt[2].len = strlen(msg)+1;
	opt[2].value = malloc(opt[2].len);
	strcpy(opt[2].value,msg);

	dhcp_send(dl,srcmac,NULL,srcip,-1,
			DHCP_OP_REQUEST, 1, 6, 
			0,htonl(txid), 0, 
			0,0,0,
			siaddr,0,cmac->mac,
			NULL,NULL,opt,3);

	for(n = 0 ; n < 3 ; n++ )
		free(opt[n].value);

	free(opt);
	return 0;
}

int 
dhcp_decline(struct datalink *dl, struct MAC *srcmac,struct MAC *dstmac,uint32_t srcip, uint32_t dstip,
			uint32_t ciaddr,uint32_t siaddr,
			uint32_t txid)

{
	struct dhcp_opt opt[3];
	int n;
	opt[0].opt 	= DHCP_OPT_TYPE;
	opt[0].len 	= DHCP_OPT_TYPE_LEN;
	opt[0].value = malloc(opt[0].len);
	opt[0].value[0] = DHCP_OPT_TYPE_DECLINE;

	opt[1].opt 	= DHCP_OPT_SERV_ID;
	opt[1].len	= 4;
	opt[1].value = malloc(opt[1].len);
	*((uint32_t*)(opt[1].value)) = siaddr;


	opt[2].opt 	= DHCP_OPT_CLIENT_ID;
	opt[2].len	= 7;
	opt[2].value = malloc(opt[1].len);
	opt[2].value[0] = 1;
	memcpy(&(opt[1].value[1]),srcmac->mac,6);

	dhcp_send(dl,srcmac,dstmac,srcip,dstip,
			DHCP_OP_REQUEST, 1, 6, 
			0,htonl(txid), 0, 
			0,ciaddr,0,
			siaddr,0,srcmac->mac,
			NULL,NULL,opt,3);

	for(n = 0 ; n < 3 ; n++ )
		free(opt[n].value);


	return 0;
}

