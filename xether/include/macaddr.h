#ifndef XLAYER_MAC_H_INCLUDED
#define XLAYER_MAC_H_INCLUDED

#include "types.h"
#include <stdio.h>
#include <ctype.h>

#define ETHER_ADDRSTRLEN  18
#define ETHER_ADDRLEN	  6

struct MAC{
	uint8_t mac[6]; 
};


int 	oct_to_mac		(const uint8_t oct[6], struct MAC *m);
int 	mac_to_oct		(const struct MAC *m, uint8_t oct[6]);
char * 	mac_to_str(const struct MAC *m, char *buf, size_t n);
int 	str_to_mac		(const char *str, struct MAC *m);
int 	str_to_macoct	(const char *str, uint8_t oct[6]);
char * oct_to_macstr	(uint8_t oct[6], char *buffer, size_t n);
int 	mac_cpy			(struct MAC *m1, struct MAC *m2);


#endif
