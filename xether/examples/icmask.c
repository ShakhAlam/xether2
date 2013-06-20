#include <stdio.h>
#include "xlayer.h"

int
main(int argc,char **argv)
{
 struct datalink dl;
 struct layer *m;
 struct MAC srcmac,dstmac;
 uint32_t sip,dip,rip;

 if(argc < 4){
       fprintf(stderr,"usage: %s <src ip> <dst ip> <gateway>\n");
       exit(1);
 }
 if( str_to_ip(argv[1],&sip) == 0 ){
    fprintf(stderr,"%s: invalid src IP address %s\n",argv[1]);
    exit(1);
 }
 if( str_to_ip(argv[2],&dip) == 0 ){
    fprintf(stderr,"%s: invalid dst IP address %s\n",argv[1]);
    exit(1);
 }
 if( str_to_ip(argv[3],&rip) == 0 ){
    fprintf(stderr,"%s: invalid router IP address %s\n",argv[1]);
    exit(1);
 }

 if( if_menu(&dl) < 0 ){
    fprintf(stderr,"error opening interface\n");
    exit(1);
 }

 memcpy(srcmac.mac,dl.dl_mac,6);

 if( ARPRequest(&dl,&srcmac,&dstmac,sip,rip,5) < 0 ){
    fprintf(stderr,"error: no reply from router\n");
    exit(1);
 }

 m = alloclayer(LT_ETHER);

 ether_set(m->proto,&srcmac,&dstmac,ETHERTYPE_IP);

 m->next = alloclayer(LT_IP);

 ip_set(m->next->proto,0,sizeof(struct ip)+sizeof(struct icmp),rand()%255,
        0,64,IPPROTO_ICMP,0,sip,dip);
 ip_sum(m->next);
 m->next->next = alloclayer(LT_ICMP);
 icmp_set(m->next->next->proto,ICMP_MASKREQ,0,(20<<16)+20,0);
 m->next->next->next = allocapplayer(sizeof(uint32_t));

 str_to_ip("255.255.255.0",&sip);
  *((uint32_t*)(m->next->next->next->proto)) = sip;

 icmp_sum(m->next->next);
 sendlayers(&dl,m);
 rmlayers(m);
 closeDatalink(&dl);

 return 0;
}
