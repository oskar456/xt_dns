#ifndef _XT_DNS_H_
#define _XT_DNS_H_

/* DNS constants */
#define NS_QR			0x80	/* 10000000 */
#define NS_QR_QUERY		0x00	/* 0xxxxxxx */
#define NS_QR_RESPONSE		0x80	/* 1xxxxxxx */

#define NS_OPCODE		0x78	/* 01111000 */
#define NS_OPCODE_QUERY		0x00	/* x0000xxx */
#define NS_OPCODE_IQUERY	0x08	/* x0001xxx */
#define NS_OPCODE_STATUS	0x10	/* x0010xxx */

//#define NS_T_MX			0x0f

enum {
	XT_DNS_QUERY	= 1 << 0,
	XT_DNS_RESPONSE	= 1 << 1,
	XT_DNS_QTYPE	= 1 << 2,
	XT_DNS_EDNS0	= 1 << 3,
	XT_DNS_BUFSIZE	= 1 << 4,
};

struct xt_dns_info {
	u_int8_t flags;
	u_int8_t invert_flags;
	u_int8_t qtype;	/* record type */
	u_int16_t bufsize[2];	/* edns0 bufsize [min:max] */
};

#endif
