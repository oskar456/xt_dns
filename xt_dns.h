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

#define DNS_F_INVERT		0x01


struct xt_dns_info {
	u_int8_t invert;
	u_int8_t type;	/* record type */
};



#endif

