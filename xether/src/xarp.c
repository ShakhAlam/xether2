#include "../include/xarp.h"


struct layer *
alloc_arp(struct layer *m,size_t len)
{
	if( m == NULL || len < 0)
		return NULL;
	if( len ==  0)
		len = sizeof(struct ether_arp) ;
	
	if( ( m->proto = calloc(1,sizeof(struct ether_arp)) ) == NULL)
				return NULL;
	m->size = sizeof(struct ether_arp);
	m->type = LT_ARP;
	m->print = arpprint;
	m->sprint = arpsprint;
	m->next = NULL;
	
	return m;
}

struct layer *
arp_decode(const char *buf,size_t len){
	struct layer *m;
	
	if(len < sizeof(struct ether_arp) )
		return NULL;
	m = alloclayer(LT_ARP,sizeof(struct ether_arp));
	
	memcpy(m->proto,buf,sizeof(struct ether_arp));
	return m;
}

int
arp_set(struct ether_arp *arph,
			uint16_t hrd,  /* hardware type. (0x01)*/
			uint16_t pro,  /* protocol type. (ETHERTYPE)*/ 
			uint8_t hln,	/* hardware address length. (6)*/
			uint8_t pln,	/* protocol address length. (4)*/
			uint16_t op,	/* operation code. (ARPOP_[REQUEST|REPLY])*/
		   struct MAC *sha, /* source hardware address. if NULL its set to zero. */
		   uint32_t spa, 	/* source protocol address. */
		   struct MAC *tha, /* target hardware address. if NULL its set to zero. */
		   uint32_t tpa) 	/* target protocol address. */ 
{

	uint8_t ospa[4],otpa[4];

	
	ip_to_oct(spa,ospa);
	ip_to_oct(tpa,otpa);
	
	arph->arp_hrd = htons(hrd);
	arph->arp_pro = htons(pro);
	arph->arp_hln = hln;
	arph->arp_pln = pln;
	arph->arp_op  = htons(op);
	if(sha == NULL)
		memset(arph->arp_sha,0,6);
	else		
		memcpy(arph->arp_sha,sha->mac,6);

	memcpy(arph->arp_spa,ospa,4);
	
	if(tha == NULL)
		memset(arph->arp_tha,0,6);
	else		
		memcpy(arph->arp_tha,tha->mac,6);
	

	memcpy(arph->arp_tpa,otpa,4);
	
	return 0;
}

int
ARPRequest(struct datalink *dl,struct MAC *srcmac, struct MAC *dstmac, uint32_t srcip, uint32_t dstip, int timeout)
{
	struct layer *head,*f;
	long t1=0,t2=0;
	int n;
	uint8_t odstip[4];
	

	ip_to_oct(dstip,odstip);
	
	head = alloclayer(LT_ETHER,0);

	ether_set( head->proto , srcmac , NULL, ETHERTYPE_ARP);
	
	head->next = alloclayer(LT_ARP,0);

	
	arp_set( head->next->proto, 0x1, ETHERTYPE_IP, 6, 4, ARPOP_REQUEST,
				srcmac , srcip, NULL, dstip);	
		
	sendlayers(dl,head);

    	rmlayers(head);
	t1 = time(0);
	head = recvlayers(dl,&n);
	while(1){
		
		if(head != NULL){


			if( ( f = findlayer(head,LT_ARP)) != NULL){
					
				
				if( memcmp( ((xarp)(f->proto))->arp_spa , odstip,4) == 0){
	
						
						memcpy(dstmac->mac,((xarp)(f->proto))->arp_sha,6);
	
						return 0;
				}
				else{

					rmlayers(head);
	
					head = NULL;
				}		
			}
		}
		
		t2 = time(0);
		if(t1+timeout <= t2) return -1;

		head = recvlayers(dl,&n);

		
	}
	
	return -1;
	
}

int
ARPReply(struct datalink *dl,struct MAC *srcmac, uint32_t srcip,struct MAC *dstmac, uint32_t dstip)
{
	struct layer *head,**i;
	long t1=0,t2=0;
	
	i = &head;	

	*i = alloclayer(LT_ETHER,0);
	
	ether_set( (*i)->proto , srcmac , dstmac, ETHERTYPE_ARP);
	
	i = &(*i)->next;
	
	*i = alloclayer(LT_ARP,0);
	
	arp_set( (*i)->proto, 0x1, ETHERTYPE_IP,6,4, ARPOP_REPLY,
				srcmac, srcip, dstmac, dstip);
	
	sendlayers(dl,head);
	rmlayers(head);
	return 0;
	
}	

void
arpprint(struct layer *m)
{
	struct ether_addr src,dst;
	struct ether_arp *arph;
	
	arph = (xarp)m->proto;
	
	memcpy(&src,arph->arp_sha,6);
	memcpy(&dst,arph->arp_tpa,6);
	printf("ARP{\r\n %d.%d.%d.%d:%02X:%02X:%02X:%02X:%02X:%02X->%d.%d.%d.%d:%02X:%02X:%02X:%02X:%02X:%02X\r\n};\r\n",
						arph->arp_spa[0],arph->arp_spa[1],arph->arp_spa[2],arph->arp_spa[3],
						arph->arp_sha[0],arph->arp_sha[1],arph->arp_sha[2],
						arph->arp_sha[3],arph->arp_sha[4],arph->arp_sha[5],
						arph->arp_tpa[0],arph->arp_tpa[1],arph->arp_tpa[2],arph->arp_tpa[3],
						arph->arp_tha[0],arph->arp_tha[1],arph->arp_tha[2],
						arph->arp_tha[3],arph->arp_tha[4],arph->arp_tha[5]);
}

char*
arpsprint(char *buf, size_t n, struct layer *m)
{
	struct ether_addr src,dst;
	
	struct ether_arp *arph;
	
	arph = (xarp)m->proto;
	
	if(n <= ARP_PRINT_BUF)
		return NULL;
		
	memcpy(&src,arph->arp_sha,6);
	memcpy(&dst,arph->arp_tpa,6);

	sprintf(buf,"ARP{ \r\n %d.%d.%d.%d:%02X:%02X:%02X:%02X:%02X:%02X->%d.%d.%d.%d:%02X:%02X:%02X:%02X:%02X:%02X \r\n}; ",
						arph->arp_spa[0],arph->arp_spa[1],arph->arp_spa[2],arph->arp_spa[3],
						arph->arp_sha[0],arph->arp_sha[1],arph->arp_sha[2],
						arph->arp_sha[3],arph->arp_sha[4],arph->arp_sha[5],
						arph->arp_tpa[0],arph->arp_tpa[1],arph->arp_tpa[2],arph->arp_tpa[3],
						arph->arp_tha[0],arph->arp_tha[1],arph->arp_tha[2],
						arph->arp_tha[3],arph->arp_tha[4],arph->arp_tha[5]);
	return buf;
}
