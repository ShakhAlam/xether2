/* $EtherX: datalink.c,v 1.1 2002/08/16 14:49:12 daemoneye Exp $ */

#include "../include/datalink.h"

#ifndef _WIN32 /* This must be UNIX */

struct datalink *
get_if_list(int *num_if)
{

	struct datalink *pdl = NULL;
	int ndl;
	struct sockaddr_in *sain;
	
#ifdef SIOCGARP		/* Older UNIX systems use this ioctl while others use sysctl MIB to obtain MACs*/
	struct sockaddr_in *arpsain;
	struct ifconf ifc;
	struct ifreq *ifr,ifrcp;
	char *buf,*ptr;
	int sockfd,n;
    struct arpreq arprq;
#else
	struct sockaddr_dl *sdl;
	struct if_msghdr *ifm;
	char *ret,*next,*lim;
	unsigned char *mac;
	size_t lenp;
	int n;
#endif


	ndl = 0;

#ifdef SIOCGARP
    if( ( buf = malloc(1024) ) == NULL ) 
		return NULL;

    if( ( sockfd = socket(AF_INET,SOCK_DGRAM,0) ) < 0 )
		return NULL;

    ifc.ifc_len = 1024;
    ifc.ifc_buf = buf;

    if( ioctl(sockfd,SIOCGIFCONF,&ifc) < 0 )
		return NULL;

    ifr = (struct ifreq*)buf;

    for(ptr = buf; ptr < buf + ifc.ifc_len;){
		ifr = (struct ifreq*)ptr;
		switch(ifr->ifr_addr.sa_family){
#ifdef AF_INET6
			case AF_INET6:
				ptr += sizeof(struct sockaddr_in6) + sizeof(ifr->ifr_name);
			break;
#endif
			default:
				ptr += sizeof(struct sockaddr) + sizeof(ifr->ifr_name);
			break;
		}

		if( ifr->ifr_addr.sa_family != AF_INET)
			continue;
		ifrcp = *ifr;

		if( ioctl(sockfd,SIOCGIFFLAGS,&ifrcp) < 0 )
			return NULL;
		    
		if( (ifrcp.ifr_flags & IFF_UP) == 0 )
			continue;

		sain = (struct sockaddr_in*)&ifr->ifr_addr;
		
		arpsain = (struct sockaddr_in*)&arprq.arp_pa;

		memset(arpsain,0,sizeof(struct sockaddr_in));
		memcpy(&arpsain->sin_addr,&sain->sin_addr,sizeof(struct in_addr));

		arpsain->sin_family = AF_INET;
		arpsain->sin_port = 0;
		
		/*fprintf(stderr,"%s : %s\n",ifr->ifr_name,inet_ntoa(sain->sin_addr));
		*/
		ndl++;
		pdl = realloc(pdl,ndl*sizeof(struct datalink));

		strncpy(pdl[ndl-1].dl_name,ifr->ifr_name,ADAPTER_NAME_LEN-1);
                if( ioctl(sockfd,SIOCGARP,&arprq) < 0 ){
			for(n=0;n<6;n++)
				pdl[ndl-1].dl_mac[n] = 0;
		}
		else
			for(n=0;n<6;n++)
				pdl[ndl-1].dl_mac[n] = (unsigned char)arprq.arp_ha.sa_data[n];
		
	}

        free(buf);

#else

	if( ( ret = ctl_if_list(AF_INET,0,&lenp) ) == NULL)
		return NULL;

	lim = ret + lenp;
	ndl = 0;
	for(next = ret; next < lim; next += ifm->ifm_msglen){
		ifm = (struct if_msghdr*) next;
		sdl = (struct sockaddr_dl*) (ifm+1);

		if(ifm->ifm_type != RTM_IFINFO || !(ifm->ifm_flags & IFF_UP))
			continue;
		ndl++;
		pdl = realloc(pdl,ndl*sizeof(struct datalink));

		strncpy(pdl[ndl-1].dl_name,sdl->sdl_data,ADAPTER_NAME_LEN-1);

 		mac = (unsigned char *)sdl->sdl_data+sdl->sdl_nlen;

		for(n = 0; n<6; n++)
			pdl[ndl-1].dl_mac[n] = mac[n];		
	}
	free(ret);

#endif /* SIOCGARP */

	*num_if = ndl;

	
	return pdl;
}


#ifndef SIOCGARP
char *
ctl_if_list(int family,int flags,size_t *lenp)
{
	int mib[6];
	char *buf;

	mib[0] = CTL_NET;
	mib[1] = AF_ROUTE;
	mib[2] = 0;
	mib[3] = family;
	mib[4] = NET_RT_IFLIST;
	mib[5] = flags;

	if( sysctl(mib,6,NULL,lenp,NULL,0) < 0 ){
		fprintf(stderr,"sysctl error\n");
		return(NULL);
	}
	if( ( buf = malloc(*lenp)) == NULL)
		return(NULL);

	if(sysctl(mib,6,buf,lenp,NULL,0) < 0){
		fprintf(stderr,"sysctl error2\n");
		free(buf);
		return(NULL);
	}
	return buf;
}	
#endif /* SIOCGARP */


#else /* This is for Win32 */
struct datalink *
get_if_list(int *num_if){

	char rawAdapterList[MAX_NUM_ADAPTER][ADAPTER_NAME_LEN] ={ 0 };
	int  rawNumAdapters;
	struct datalink *pdl;
	int        i,j,k;
	DWORD dwVersion;
	DWORD dwWindowsMajorVersion;
	/* unicode strings (winnt) */
	WCHAR		AdapterName[512]={0};//*p /* string that contains a list of the network adapters */
	char *p;

	/* ascii strings (win95)  */
	char		AdapterNamea[512]={0}; /* string that contains a list of the network adapters */
	char		*tempa,*temp1a;
	ULONG		AdapterLength;
	rawNumAdapters = 0;
	/* obtain the name of the adapters installed on this machine */
	AdapterLength=511;

	j=i=0;	
fprintf(stderr,"in get_if_list\n");

	/* the data returned by PacketGetAdapterNames is different in Win95 and in WinNT. */
	/* We have to check the os on which we are running */
	dwVersion=GetVersion();
	dwWindowsMajorVersion =  (DWORD)(LOBYTE(LOWORD(dwVersion)));
	//if (!(dwVersion >= 0x80000000 && dwWindowsMajorVersion >= 4)){  
		/* Windows NT */
		PacketGetAdapterNames((char *)AdapterName,&AdapterLength);
		p=AdapterName;
		printf("%s\n",p);

		while(*p && p[1]){			
			for(k=0;*p && k<=(int)AdapterLength;p++,k++){
				rawAdapterList[j][k]=((char*)p)[0];
				printf("%c",((char*)p)[0]);
			}
			rawAdapterList[j][++k]=0;
			p++; j++;
		}


		rawNumAdapters = j;		
	//}
	//else	/* windows 95 98 ME */
	//{ 
	//	PacketGetAdapterNames((char*)AdapterNamea,&AdapterLength);
	//	tempa=AdapterNamea;
	//	temp1a=AdapterNamea;

	//	while ((*tempa!='\0')||(*(tempa-1)!='\0')){
	//		if (*tempa=='\0') {
	//			memcpy(rawAdapterList[i],temp1a,tempa-temp1a);
	//			temp1a=tempa+1;
	//			i++;
	//		}
	//		tempa++;
	//	}		  
	//	rawNumAdapters = i;
	//}
	pdl = NULL;
	for(i = 0; i < rawNumAdapters; i++){
		pdl = realloc(pdl,(i+1) * sizeof(struct datalink));

		if( rawAdapterList[i][0] == '*')
			strcpy(pdl[i].dl_name,&rawAdapterList[i][1]);
		else
		 strcpy(pdl[i].dl_name,rawAdapterList[i]);

		memset(pdl[i].dl_mac,0,6);

		getmacbyname(pdl[i].dl_name,pdl[i].dl_mac);
	

	}

	*num_if = rawNumAdapters;

	return pdl;
}


int getmacbyname(char *szAdapterName,unsigned char xmac[6]){

  PPACKET_OID_DATA  oid_data;         // Defined in Ntddpack.h
  unsigned int      io_ctl_buff_len;  // OID memory allocation
  unsigned char     *mac;             
  LPADAPTER lpAdapter;         	     

  lpAdapter = PacketOpenAdapter(szAdapterName);

  if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE)){

    return(-1);
  }


  // Prepare variables for call to PacketRequest()
  io_ctl_buff_len = sizeof(PACKET_OID_DATA) + sizeof(unsigned long) - 1;
  oid_data = (struct _PACKET_OID_DATA *)GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT, io_ctl_buff_len);
  if (oid_data == NULL){

    return -1;
  }

  oid_data->Oid = OID_802_3_PERMANENT_ADDRESS;
  oid_data->Length = 6;

  // Query the adapter to get MAC address
  if ((PacketRequest(lpAdapter,0, oid_data)) > 0)
     mac = (unsigned char *)oid_data->Data;
  else{

    return -1;
  }
	xmac[0] = mac[0];
	xmac[1] = mac[1];
	xmac[2] = mac[2];
	xmac[3] = mac[3];
	xmac[4] = mac[4];
  	xmac[5] = mac[5]; 


  PacketCloseAdapter(lpAdapter);
  return 0;
}
#endif /*_WIN32*/

void
free_if_list(struct datalink *pdl)
{
	free(pdl);
}


/* pcap specific operations */


int 
openDatalink(struct datalink *dl)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device;
	if(dl == NULL )
		return -1;

	device =dl->dl_name;

	if ( (dl->dl_pcap = pcap_open_live(device,1514,-1,-1,errbuf) ) == NULL){
			
			fprintf(stderr,"error:pcap_open_live:%s",
			errbuf);
			return -1;
	}

	pcap_lookupnet(device,&dl->dl_bpfnet,&dl->dl_bpfmask,errbuf);

	return 0;
}

int 
filterDatalink(const struct datalink *dl, char *filter)
{
	struct bpf_program bpfp;

	if(dl == NULL)
		return -1;
	if(pcap_compile(dl->dl_pcap,&bpfp,filter,0,dl->dl_bpfnet) == -1)
		return -1;
	if(pcap_setfilter(dl->dl_pcap,&bpfp) == -1)
		return -1;
	return 0;
}

void
closeDatalink(const struct datalink *dl)
{
	pcap_close(dl->dl_pcap);
}

unsigned char *
next_pcap(const struct datalink *dl, int *len)
{
	unsigned char *ptr;
	struct pcap_pkthdr hdr;
	while( ( ptr = (unsigned char*)pcap_next(dl->dl_pcap,&hdr)) == NULL);
	*len = hdr.caplen;
	return (ptr);
}

unsigned char *
recv_pcap(const struct datalink *dl,
		  unsigned char *data, 
		  size_t len,
		  struct pcap_pkthdr *hdr)
{
	unsigned char *pkt;
	
	while( ( pkt = (unsigned char*)pcap_next(dl->dl_pcap,hdr)) == NULL);

	if(len < (size_t)hdr->caplen)			
			return NULL;
	
	memcpy(data,pkt,len);

	return (data);
}

unsigned char *
nextData(const struct datalink *dl, int *len)
{
	char * ptr;
	struct pcap_pkthdr hdr;
	if( ( ptr = (char *)pcap_next(dl->dl_pcap,&hdr) )  != NULL){
		*len = hdr.caplen;
		return (unsigned char*)ptr; 
	}
	else{
		*len = 0;
		return NULL;
	}
	
}

ssize_t 
sendData(const struct datalink *dl,unsigned char *data, size_t len)
{

#ifdef WIN32
	return pcap_sendpacket(dl->dl_pcap,data,len);
#else
	return pcap_write(dl->dl_pcap,data,len);
#endif

}


ssize_t
recvData(const struct datalink *dl,unsigned char *data, size_t len)
{
	unsigned char *pkt;
	int n;
	if(data == NULL)
		return -1;
	
        if( ( pkt = nextData(dl,&n) ) != NULL ){
		if(len < (unsigned int)n){
			
			return -1;
		}

		memcpy(data,pkt,n);
		return n;
	}
	
	return -1;
}

int
if_openbyname(struct datalink *dl, const char *ifname){
	struct datalink *pdl;
	int nif,i,j;

	if( (pdl = get_if_list(&nif) ) == NULL){
		fprintf(stderr,"Error getting interface list\n");
		return -1;
	}
	j = -1;
	for(i=0;i<nif;i++){
		if(strcmp(pdl[i].dl_name,ifname) == 0){
			j = i;
			break;
		}
	}
	if( j == -1)
		return -1;

	if(openDatalink(pdl+j) == -1){
		fprintf(stderr,"Error opening interface %s\n",pdl[j].dl_name);
		return -1;
	}
	
	memcpy(dl,pdl+j,sizeof(struct datalink));

	free(pdl);
	return 0;
}

int
if_open(struct datalink *dl, int n){
	struct datalink *pdl;
	int nif;

	if( (pdl = get_if_list(&nif) ) == NULL){
		fprintf(stderr,"Error getting interface list\n");
		return -1;
	}
	
	if( n >= nif)
		return -1;

	if(openDatalink(pdl+n) == -1){
		fprintf(stderr,"Error opening interface %s\n",pdl[n].dl_name);
		return -1;
	}

	memcpy(dl,pdl+n,sizeof(struct datalink));

	free(pdl);
	return 0;
}

int
if_menu(struct datalink *dl){
	struct datalink *pdl;
	int nif,i,j;
	char buf[100];
	if( (pdl = get_if_list(&nif) ) == NULL){
		fprintf(stderr,"Error getting interface list\n");
		return -1;
	}
	
	for(i=0;i<nif;i++){
		printf("%d: %s\n",i+1,pdl[i].dl_name);
	}
	j = i;
	do{
	 printf("Please choose interface (1-%d):\n",j);
	 fgets(buf,sizeof(buf),stdin);
	 sscanf(buf,"%d",&i);
	}while(i<1 || i>nif);
	i--;
	if(openDatalink(pdl+i) == -1){
		fprintf(stderr,"Error opening interface %s\n",pdl[i].dl_name);
		return -1;
	}
	
	memcpy(dl,pdl+i,sizeof(struct datalink));
	free(pdl);
	return 0;
}

int 
open_link_byname(struct datalink *dl, char * name, int to_ms)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	if(dl == NULL )
		return -1;


	if ( (dl->dl_pcap = pcap_open_live(name,1514,-1,to_ms,errbuf) ) == NULL){
			
			fprintf(stderr,"error:pcap_open_live:%s",
			errbuf);
			return -1;
	}

	pcap_lookupnet(name,&dl->dl_bpfnet,&dl->dl_bpfmask,errbuf);

	return 0;
}

