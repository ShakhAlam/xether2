#include "../include/ipaddr.h"

uint32_t 
oct_to_ip( const uint8_t oct[4], uint32_t *ipn)
{ 

	uint32_t n = 0;  
	n |= (oct[3] << 24); 
	n |= (oct[2] << 16);  
	n |= (oct[1] << 8); 
	n |=  oct[0]; 
	if(ipn != (void*)0)
		*ipn = n;
	return n; 
}

uint8_t*
ip_to_oct(uint32_t ipn, uint8_t oct[4])
{

	uint32_t mask = 0xFF;
		
	oct[3] = (uint8_t)mask & (ipn >> 24),
	oct[2] = (uint8_t)mask & (ipn >> 16),
	oct[1] = (uint8_t)mask & (ipn >> 8),
	oct[0] = (uint8_t)mask & ipn;
	
	return oct;
}

char *
ip_to_str(uint32_t ipn, char *buf, size_t n)
{
	uint32_t mask = 0xFF;
	
	if(n <= IP_ADDRSTRLEN)
		return (char*)0;
		
	sprintf(buf,"%d.%d.%d.%d",
					mask & ipn,
					mask & (ipn >> 8),
					mask & (ipn >> 16),
					mask & (ipn >> 24));
	return buf;
}

int
str_to_ip(const char *ipstr, uint32_t *ipn)
{
	int o0,o1,o2,o3;
	uint32_t i=0;
	o0 = o1 = o2 = o3 = 0;
	if( sscanf(ipstr," %u.%u.%u.%u ",&o0,&o1,&o2,&o3)  != 4)
		return 0;

	
	i |= (o3 << 24); 
	i |= (o2 << 16);  
	i |= (o1 << 8); 
	i |=  o0; 
	
	if(ipn != (void *)0)
		*ipn = i;
		
	return i;
}

int
str_to_ipoct(const char *str, uint8_t oct[4])
{
	uint32_t ipn;
	if(!str_to_ip(str,&ipn))
		return -1;
		
	ip_to_oct(ipn,oct);	
	return 0;
}

char *
oct_to_ipstr(const uint8_t oct[4], char * buf, size_t n)
{
	uint32_t ipn;
	oct_to_ip(oct,&ipn);
	return ip_to_str(ipn,buf,n);	
}

