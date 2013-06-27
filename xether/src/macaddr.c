#include "../include/macaddr.h"

int  get_hw_addr(char* buf,const char* str);

int
oct_to_mac(const uint8_t oct[6], struct MAC *m)
{
	int n;
	if(m == (struct MAC*)0)
		return -1;
		
		for(n=0;n<6;n++){
			m->mac[n] = oct[n];	
		}
	return 0;
}

int
mac_to_oct(const struct MAC *m, uint8_t oct[6])
{
	int n;
	
	for(n=0;n<6;n++){
		oct[n] = m->mac[n];
	}
	return 0;
}

char *
mac_to_str(const struct MAC *m, char *buf, size_t n){
	if(n <=  ETHER_ADDRSTRLEN)
		return (char *)0;
	sprintf(buf,"%02X:%02X:%02X:%02X:%02X:%02X",
					m->mac[0],m->mac[1],m->mac[2],m->mac[3],m->mac[4],m->mac[5]);
	return buf;
}

int
str_to_mac(const char *str, struct MAC *m){
	return get_hw_addr(m->mac,str);
}

int
str_to_macoct(const char *str, uint8_t oct[6])
{
	return get_hw_addr(oct,str);
}

char *
oct_to_macstr(uint8_t oct[6], char *buf, size_t n)
{
	if(n <=  ETHER_ADDRSTRLEN)
		return (char *)0;
	sprintf(buf,"%02X:%02X:%02X:%02X:%02X:%02X",
					oct[0],oct[1],oct[2],oct[3],oct[4],oct[5]);
	return buf;
}

int
mac_cpy(struct MAC *m1, struct MAC *m2){
	memcpy(m1->mac,m2->mac,6);
	return 0;
}

int 
get_hw_addr(char* buf,const char* str){

	int i;
	char c,val;
     for(i=0;i<6;i++){
        if( !(c = tolower(*str++))) return 0;
        if(isdigit(c)) val = c-'0';
        else if(c >= 'a' && c <= 'f') val = c-'a'+10;
        else return 0;
        *buf = val << 4;
        if( !(c = tolower(*str++))) return 0;
        if(isdigit(c)) val = c-'0';
        else if(c >= 'a' && c <= 'f') val = c-'a'+10;
        else return 0;
        *buf++ |= val;
        if(*str == ':')str++;
     }
	 return 1;
}
