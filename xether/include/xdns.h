#ifndef XDNS_H_INCLUDED
#define XDNS_H_INCLUDED

/*struct dns
{
	uint16_t 	id;			 /* Identity */
	uint8_t 		q:1;		 /* Query/Response flag 	*/
	uint8_t	 	query:4;  /* Query Type 			*/
#define DNS_QUERY_STANDARD 0
#define DNS_QUERY_INVERSE  0
#define DNS_QUERY_STATUS   2

	uint8_t		a:1;		/* Authorative answer 				*/
	uint8_t		t:1;		/* Truncation	 						*/
	uint8_t		r:1;		/* Ask for recursive service 			*/
	uint8_t		v:1;		/* Recursive service available 		*/
	uint8_t		b:3;		/* Reserved 							*/
	uint8_t		rcode:4; /* Response code 						*/
#define 0 DNS_RES_NO_ERROR     /* No error condition. 			*/
#define 1 DNS_RES_FORMAT_ERROR /* Unable to interpret query due to format error. */
#define 2 DNS_RES_SERV_FAIL    /* Unable to process due to server failure. 		*/
#define 3 DNS_RES_NO_ENTRY     /* Name in query does not exist. 				*/
#define 4 DNS_RES_NO_SUPPORT	 /* Type of query not supported. 5 Query refused. 	*/

	uint16_t		quesc;		/* questions   */
	uint16_t		ansc;		/* answers     */
	uint16_t		authc;		/* authorative */
	uint16_t		ac;			/* additional  */
};*/

struct dns
{
	uint16_t 	tid;			/* Transaction ID */
	uint16_t		flags;		/* Flags 		*/
	uint16_t		quesc;		/* questions   	*/
	uint16_t		ansc;		/* answers     	*/
	uint16_t		authc;		/* authorative 	*/
	uint16_t		ac;			/* additional  	*/
};

#define DNS_QUERY_STANDARD 0
#define DNS_QUERY_INVERSE  1
#define DNS_QUERY_STATUS   2
#define 0 DNS_RES_NO_ERROR     /* No error condition. 			*/
#define 1 DNS_RES_FORMAT_ERROR /* Unable to interpret query due to format error. */
#define 2 DNS_RES_SERV_FAIL    /* Unable to process due to server failure. 		*/
#define 3 DNS_RES_NO_ENTRY     /* Name in query does not exist. 				*/
#define 4 DNS_RES_NO_SUPPORT	 /* Type of query not supported. 5 Query refused. 	*/

#endif
