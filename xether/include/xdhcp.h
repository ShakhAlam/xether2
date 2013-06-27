#ifndef DHCP_H_INCLUDED
#define DHCP_H_INCLUDED
#include "xlayer.h"


#define DHCP_CHADDR_LEN			16
#define DHCP_SNAME_LEN			64
#define DHCP_FILE_LEN			128
#define DHCP_OPT_LEN			312

struct dhcp
{
      uint8_t opcode;
      uint8_t htype;
      uint8_t hlen;
      uint8_t hops;
      uint32_t xid;
      uint16_t secs;
      uint16_t flags;
      uint32_t ciaddr;
      uint32_t yiaddr;
      uint32_t siaddr;
      uint32_t giaddr;
      uint8_t chaddr[DHCP_CHADDR_LEN];
      char sname[DHCP_SNAME_LEN];
      char file[DHCP_FILE_LEN];
	  uint32_t magic;
      uint8_t options[DHCP_OPT_LEN];
};

struct dhcp_opt
{
	uint8_t opt;
	uint8_t len;
	uint8_t *value;
};
#define DHCP_OP_REQUEST			0x01
#define DHCP_OP_REPLY			0x02
#define DHCP_OPT_PAD			0
#define DHCP_OPT_END			255
#define DHCP_MAGIC				0x63825363

#define DHCP_OPT_MASK			1
#define DHCP_OPT_MASK_LEN		4
#define DHCP_OPT_TOFF			2
#define DHCP_OPT_TOFF_LEN		4
#define DHCP_OPT_ROUTE			3
#define DHCP_OPT_ROUTE_LEN		4	
#define DHCP_OPT_TS				4
#define DHCP_OPT_TS_LEN			4
#define DHCP_OPT_NS				5
#define DHCP_OPT_NS_LEN			4
#define DHCP_OPT_DNS			6
#define DHCP_OPT_DNS_LEN		4
#define DHCP_OPT_LOGS			7
#define DHCP_OPT_LOGS_LEN		4
#define DHCP_OPT_CKS			8
#define DHCP_OPT_CKS_LEN		4
#define DHCP_OPT_LPRS			9
#define DHCP_OPT_LPRS_LEN		4
#define DHCP_OPT_IMPRS			10
#define DHCP_OPT_IMPRS_LEN		4
#define DHCP_OPT_RLS			11
#define DHCP_OPT_RLS_LEN		4
#define DHCP_OPT_HOSTNAME		12
#define DHCP_OPT_HOSTNAME_LEN	1
#define DHCP_OPT_BOOTF_SIZE		13
#define DHCP_OPT_BOOTF_SIZE_LEN	4
#define DHCP_OPT_MDUMP			14
#define DHCP_OPT_MDUMP_LEN		1
#define DHCP_OPT_DOMAIN_NAME		15
#define DHCP_OPT_DOMAIN_NAME_LEN	1
#define DHCP_OPT_SWAPS				16
#define DHCP_OPT_SWAPS_LEN			4
#define DHCP_OPT_ROOT_PATH			17
#define DHCP_OPT_ROOT_PATH_LEN		1
#define DHCP_OPT_EXT_PATH			18
#define DHCP_OPT_EXT_PATH_LEN		1
#define DHCP_OPT_IPF				19
#define DHCP_OPT_IPF_LEN			1
#define DHCP_OPT_SRCRT				20
#define DHCP_OPT_SRCRT_LEN			4
#define DHCP_OPT_PF					21
#define DHCP_OPT_PF_LEN				8
#define DHCP_OPT_MDRS				22
#define DHCP_OPT_MDRS_LEN			2
#define DHCP_OPT_TTL				23
#define DHCP_OPT_TTL_LEN			1
#define DHCP_OPT_PMTU_TIMEO			24
#define DHCP_OPT_PMTU_TIMEO_LEN		4
#define DHCP_OPT_PMTU_TAB			25
#define DHCP_OPT_PMTU_TAB_LEN		4
#define DHCP_OPT_IMTU				26
#define DHCP_OPT_IMTU_LEN			2
#define DHCP_OPT_ALL_SUBLOCAL		27
#define DHCP_OPT_ALL_SUBLOCAL_LEN	1
#define DHCP_OPT_BCAST_ADDR			28
#define DHCP_OPT_BCAST_ADDR_LEN		4
#define DHCP_OPT_PERF_MASK_DISC		29
#define DHCP_OPT_PERF_MASK_DISC_LEN	1
#define DHCP_OPT_REP_MASK			30
#define DHCP_OPT_REP_MASK_LEN		4
#define DHCP_OPT_PERF_ROUTE_DISC		31
#define DHCP_OPT_PERF_ROUTE_DISC_LEN	4
#define DHCP_OPT_ROUTE_SOLICIT_ADDR		32
#define DHCP_OPT_ROUTE_SOLICIT_ADDR_LEN		4
#define DHCP_OPT_STATIC_ROUTE			33
#define DHCP_OPT_STATIC_ROUTE_LEN		8
#define DHCP_OPT_TRAILER_ENCAP			34
#define DHCP_OPT_TRAILER_ENCAP_LEN			1
#define DHCP_OPT_ARP_CACHE_TIMEO		35
#define DHCP_OPT_ARP_CACHE_TIMEO_LEN	4
#define DHCP_OPT_ETHER_ENCAP			36
#define DHCP_OPT_ETHER_ENCAP_LEN		1
#define DHCP_OPT_TCP_TTL			37
#define DHCP_OPT_TCP_TTL_LEN		4
#define DHCP_OPT_TCP_KEEP_ALIVE		38
#define DHCP_OPT_TCP_KEEP_ALIVE_LEN	4
#define DHCP_OPT_CNIS				40
#define DHCP_OPT_CNIS_LEN			1
#define DHCP_OPT_NIS_SERV			41
#define DHCP_OPT_NIS_SERV_LEN		4
#define DHCP_OPT_NTP_SERV			42
#define DHCP_OPT_NTP_SERV_LEN		4
#define DHCP_OPT_VEND_SPEC			43
#define DHCP_OPT_VEND_SPEC_LEN		4
#define DHCP_OPT_NBMS_SERV			44
#define DHCP_OPT_NBMS_SERV_LEN		4
#define DHCP_OPT_NBDD_SERV			45
#define DHCP_OPT_NBDD_SERV_LEN		4
#define DHCP_OPT_NBNODE_TYPE		46
#define DHCP_OPT_NBNODE_TYPE_LEN	1
#define DHCP_OPT_NBSCOPE			47
#define DHCP_OPT_NBSCOPE_LEN		1
#define DHCP_OPT_XFS				48
#define DHCP_OPT_XFS_LEN			4
#define DHCP_OPT_XDM				49
#define DHCP_OPT_XDM_LEN			4
#define DHCP_OPT_REQ_IP				50
#define DHCP_OPT_REQ_IP_LEN			4
#define DHCP_OPT_LEASE_TIME			51
#define DHCP_OPT_LEASE_TIME_LEN		4
#define DHCP_OPT_OVERLOAD			52
#define DHCP_OPT_OVERLOAD_LEN		1
#define DHCP_OPT_OVERLOAD_FILE		1
#define DHCP_OPT_OVERLOAD_SNAME		2
#define DHCP_OPT_OVERLOAD_BOTH		3
#define DHCP_OPT_TYPE				53
#define DHCP_OPT_TYPE_LEN			1
#define DHCP_OPT_TYPE_DISCOVER		1
#define DHCP_OPT_TYPE_OFFER			2
#define DHCP_OPT_TYPE_REQUEST		3
#define DHCP_OPT_TYPE_DECLINE		4
#define DHCP_OPT_TYPE_ACK			5
#define DHCP_OPT_TYPE_NAK			6
#define DHCP_OPT_TYPE_RELEASE		7
#define DHCP_OPT_SERV_ID			54
#define DHCP_OPT_SERV_ID_LEN		4
#define DHCP_OPT_PARAM_REQ		55
#define DHCP_OPT_PARAM_REQ_LEN		1
#define DHCP_OPT_MSG				56
#define DHCP_OPT_MSG_LEN			1
#define DHCP_OPT_MSG_SIZE			57
#define DHCP_OPT_MSG_SIZE_LEN		2
#define DHCP_OPT_RENEW_TIME			58
#define DHCP_OPT_RENEW_TIME_LEN		4
#define DHCP_OPT_REBIND_TIME		59
#define DHCP_OPT_REBIND_TIME_LEN	4
#define DHCP_OPT_CLASS_ID			60
#define DHCP_OPT_CLASS_ID_LEN		1
#define DHCP_OPT_CLIENT_ID			61
#define DHCP_OPT_CLIENT_ID_LEN		2
#define DHCP_OPT_TFTP_SERVNAME		66
#define DHCP_OPT_TFTP_SERVNAME_LEN	1
#define DHCP_OPT_BOOT_FILENAME		67
#define DHCP_OPT_BOOT_FILENAME_LEN		1

struct layer *alloc_dhcp(struct layer *m,size_t len);
struct layer *dhcp_decode(const char *buf,size_t len);
int	dhcp_set(struct dhcp *dhcph,
		 uint8_t opc, uint8_t htype, uint8_t hlen, 
		 uint8_t hops,uint32_t xid, uint16_t secs, 
		 uint16_t flags, uint32_t ciaddr, uint32_t yiaddr,
		 uint32_t siaddr, uint32_t giaddr,uint8_t *chaddr,
		 const char *sname,const char *file,struct dhcp_opt *options,
		 int nopt);

int 
dhcp_decline(struct datalink *dl, struct MAC *srcmac,struct MAC *dstmac,uint32_t srcip, uint32_t dstip,
			uint32_t ciaddr,uint32_t siaddr,
			uint32_t txid);
int dhcp_nack(struct datalink *dl, struct MAC *srcmac,struct MAC *cmac,uint32_t srcip,
			uint32_t siaddr,uint32_t giaddr,const char *msg,
			uint32_t txid);

int	
dhcp_release(struct datalink *dl, struct MAC *srcmac,struct MAC *dstmac,uint32_t srcip, uint32_t dstip,
			uint32_t ciaddr,uint32_t siaddr,
			uint32_t txid);

int 
dhcp_ack(struct datalink *dl, struct MAC *srcmac,struct MAC *dstmac,uint32_t srcip, uint32_t dstip,
			uint32_t yiaddr,uint32_t siaddr,uint32_t giaddr,
			struct MAC *chaddr,const char *sname,const char *file,
			uint32_t txid,uint32_t leasetime,uint32_t mask,uint32_t route,
			uint32_t *dns,int ndns,const char *domain);

int	
dhcp_request(struct datalink *dl, struct MAC *srcmac,
			uint32_t txid, 
			uint32_t rqaddr, const char *hostname, uint8_t *rqopt, uint8_t numopt);

int	
dhcp_offer(struct datalink *dl, struct MAC *srcmac,struct MAC *dstmac,uint32_t srcip, uint32_t dstip,
			uint32_t yiaddr,uint32_t siaddr,uint32_t giaddr,
			struct MAC *chaddr,const char *sname,const char *file,
			uint32_t txid,uint32_t leasetime,uint32_t mask,uint32_t route,
			uint32_t *dns,int ndns,const char *domain);

int	
dhcp_discover(struct datalink *dl, struct MAC *srcmac,
			uint32_t txid, 
			uint32_t rqaddr, const char *hostname, uint8_t *rqopt, uint8_t numopt);

			
void dhcpprint(struct layer *m);
char *dhcpsprint(char *buf, size_t n,struct layer *m);


#endif
