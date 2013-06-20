#include "../include/xether.h"

      
struct layer *
ether_decode(const char *buf,size_t len){
	struct layer *m;
	if(len < sizeof(struct ether_header) )
		return NULL;
	m = alloclayer(LT_ETHER,sizeof(struct ether_header));
	memcpy(m->proto,buf,sizeof(struct ether_header));
	switch(ntohs( ((xeth)(m->proto))->ether_type )){
		case ETHERTYPE_REVARP:
		case ETHERTYPE_ARP:
			m->next = arp_decode(buf+sizeof(struct ether_header),len-sizeof(struct ether_header));		
		break;
		case ETHERTYPE_IP:
			m->next = ip_decode(buf+sizeof(struct ether_header),len-sizeof(struct ether_header));		
		break;
		default:
			m->next = app_decode(buf+sizeof(struct ether_header),len-sizeof(struct ether_header));
		break;
	}
	return m;
}

int
ethersrcmp(struct ether_header *e1, struct ether_header *e2){
	if(memcmp(e1->ether_shost,e2->ether_shost,ETHER_ADDRLEN) == 0)
		return 1;
	return 0;
}

int
etherdstcmp(struct ether_header *e1, struct ether_header *e2){
	if(memcmp(e1->ether_dhost,e2->ether_dhost,ETHER_ADDRLEN) == 0)
		return 1;
	return 0;
}


int
ethersetsrc(struct ether_header *etp, const struct MAC *src)
{
	if(src == NULL || etp == NULL)
		return -1;
	memcpy(etp->ether_shost,src->mac,ETHER_ADDRLEN);
	return 0;
}

int
ethersetdst(struct ether_header *etp, const struct MAC *dst)
{
	if( dst == NULL || etp == NULL)
		return -1;
	memcpy(etp->ether_shost,dst->mac,ETHER_ADDRLEN);
	return 0;
}

int
ether_set(struct ether_header *etp, 
	 const struct MAC *src, 
	 const struct MAC *dst, 
	 u_int16_t ether_type)
{
	if(etp == NULL)
		return -1;
	if(src == NULL)
		memset(etp->ether_shost,-1,ETHER_ADDRLEN);
	else
		memcpy(etp->ether_shost,src->mac,ETHER_ADDRLEN);
	if(dst == NULL)
		memset(etp->ether_dhost,-1,ETHER_ADDRLEN);
	else
		memcpy(etp->ether_dhost,dst->mac,ETHER_ADDRLEN);
				

	etp->ether_type = htons(ether_type);
	return 0;
}


void 
etherprint(struct layer *m)
{
	struct ether_addr src,dst;
	struct ether_header *eth;
	eth = (xeth)m->proto;
	
	memcpy(&dst,eth->ether_dhost,6);
	memcpy(&src,eth->ether_shost,6);
	printf("\nEthernet{\n %02X:%02X:%02X:%02X:%02X:%02X->",eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],
						eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
	
	printf("%02X:%02X:%02X:%02X:%02X:%02X",eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],
						eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);
						
	printf("  %X\n};\n",ntohs(eth->ether_type));
	
}

char *
ethersprint(char *buf, size_t n,struct layer *m)
{

	struct ether_addr src,dst;
	struct ether_header *eth;
	eth = (xeth)m->proto;
	
	if(n<ETHER_PRINT_BUF)
		return NULL;
		
	memcpy(&dst,eth->ether_dhost,6);
	memcpy(&src,eth->ether_shost,6);
	sprintf(buf,"\r\n Ethernet{ \r\n %02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X   %X \r\n}; ",
						eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5],
						eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5],
						ntohs(eth->ether_type)
			 );
			 
	return buf;
	
}

struct layer *
alloc_ether(struct layer *m,size_t len)
{
	if(m == NULL )
		return NULL;
	if( len == 0 )
		len = sizeof(struct ether_header);
	if ( len < sizeof(struct ether_header) )
		return NULL;
	if( ( m->proto = calloc(1,sizeof(struct ether_header)) ) == NULL)
				return NULL;
	
	m->size = sizeof(struct ether_header);
	m->type = LT_ETHER;
	m->print = etherprint;
	m->sprint = ethersprint;
	m->next = NULL;
	return m;
}

