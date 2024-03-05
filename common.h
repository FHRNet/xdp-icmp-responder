/* Settings */
// ICMP maximum payload size to truncate responses to
#define ICMP_MAXIMUM_DATALEN 68

// Default outgoing TTL to use
#define DEFAULT_TTL 96

// Rate limit per src IP (pps)
#define ICMP_IP_RATELIMIT 10

// ICMP global rate limit (pps)
#define ICMP_G_RATELIMIT 1000

// IP rate limit LRU HASH max entries (IPs)
#define RATELIMIT_MAX_ENTRIES 32768


// Program specifics
#define RATELIMIT_BUCKET_SIZE 1000000000 // 1 second
struct ratelimitmap {
	__u64 bucket_time;
	__u64 bucket_packets;
};

enum func_action {
    FUNC_ATTACH,
    FUNC_DETACH
};

enum g_ratelimiter_types {
    G_RATELIMIT_TYPE_ICMP
};

__u16 ethoffset = 0;


// Atomic add
#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif


// From linux/icmp.h
#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/
#define NR_ICMP_TYPES		18

// From linux/if_ether.h
#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define ETH_TLEN	2		/* Octets in ethernet type field */
#define ETH_HLEN	14		/* Total octets in header.	 */
#define ETH_ZLEN	60		/* Min. octets in frame sans FCS */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define ETH_FRAME_LEN	1514		/* Max. octets in frame sans FCS */
#define ETH_FCS_LEN	4		/* Octets in the FCS		 */

#define ETH_MIN_MTU	68		/* Min IPv4 MTU per RFC791	*/
#define ETH_MAX_MTU	0xFFFFU		/* 65535, same as IP_MAX_MTU	*/

#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define ETH_P_IPV6 0x86DD
#define ETH_P_IP 0x0800