
#include <stdio.h>
#include "xlayer.h"


int
main(void)
{
	char buf[128];
	struct icmp *i;
	i = (struct icmp*)buf; 
	i->icmp_id = 1213;
	printf("%d\n",i->icmp_id);
	return 0;
}