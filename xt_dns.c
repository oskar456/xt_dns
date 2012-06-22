/*
 *	xt_dns
 *	Copyright (c) Bartlomiej Korupczynski, 2011
 *
 *	This is kernel part of module used to match DNS MX queries
 * 
 *	This file is distributed under the terms of the GNU General Public
 *	License (GPL). Copies of the GPL can be obtained from gnu.org/gpl.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

#include "xt_dns.h"
#include "config.h"


#ifdef CONFIG_NETFILTER_DEBUG
#define NFDEBUG(format, args...)  printk(format , ## args)
#warning debugging on
#else
#define NFDEBUG(format, args...)
#endif


// uncomment following line if you get compilation error
//#define HAVE_XT_MATCH_PARAM


#ifdef HAVE_XT_MATCH_PARAM
static bool dns_mt(const struct sk_buff *skb, const struct xt_match_param *par)
#else
static bool dns_mt(const struct sk_buff *skb, struct xt_action_param *par)
#endif
{
	const struct xt_dns_info *info = par->matchinfo;

	u8 *dns;
	size_t len;
	bool is_match;

	/* skip fragments */
	if (par->fragoff)
		return false;

	/* find UDP payload */
	dns = skb->data + (par->thoff + sizeof(struct udphdr));
	len = skb_headlen(skb) - (par->thoff + sizeof(struct udphdr));

	/* minimum DNS query payload is 17 bytes (for "." root zone) */
	if (len < 17)
		return false;

	NFDEBUG("ipt_dns[%d]: %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x [...] %02x%02x %02x%02x %02x\n",
		len,
		dns[0], dns[1], dns[2], dns[3], dns[4], dns[5], dns[6], dns[7],
		dns[8], dns[9], dns[10], dns[11],
		dns[len-5], dns[len-4], dns[len-3], dns[len-2], dns[len-1]);

	/* !response_flag && opcode == query; qdcount=1, ancount=0, nscount=0, arcount=0, query for MX only */
	is_match = ((dns[2] & (NS_QR|NS_OPCODE)) == (NS_QR_QUERY|NS_OPCODE_QUERY))
		&& (dns[4] == 0x00) && (dns[5] == 0x01) && (dns[6] == 0x00) && (dns[7] == 0x00)
		&& (dns[8] == 0x00) && (dns[9] == 0x00) && (dns[10] == 0x00) && (dns[11] == 0x00)
		&& (dns[len-5] == 0x00) && (dns[len-4] == 0x00) && (dns[len-3] == info->type)
		&& (dns[len-2] == 0x00) && (dns[len-1] == 0x01);

	/* !response_flag && opcode == query; qdcount=1, ancount=0, nscount=0, arcount=1, query for MX only, EDNS0 header with zero length */
	is_match = is_match || ((dns[2] & (NS_QR|NS_OPCODE)) == (NS_QR_QUERY|NS_OPCODE_QUERY))
		&& (dns[4] == 0x00) && (dns[5] == 0x01) && (dns[6] == 0x00) && (dns[7] == 0x00)
		&& (dns[8] == 0x00) && (dns[9] == 0x00) && (dns[10] == 0x00) && (dns[11] == 0x01)
		&& (dns[len-16] == 0x00) && (dns[len-15] == 0x00) && (dns[len-14] == info->type)
		&& (dns[len-13] == 0x00) && (dns[len-12] == 0x01) && (dns[len-11] == 0x00)
		&& (dns[len-10] == 0x00) && (dns[len-9] == 0x29)
		&& (dns[len-2] == 0x00) && (dns[len-1] == 0x00);
	return (is_match ^ info->invert) ? true : false;
}

#ifdef HAVE_XT_MATCH_PARAM
static bool dns_mt_check(const struct xt_mtchk_param *par)
#else
static int dns_mt_check(const struct xt_mtchk_param *par)
#endif
{
	const struct ipt_ip *ip = par->entryinfo;
//	const struct xt_dns_info *info = par->matchinfo;

	/* we can deal with UDP only */
	if (ip->proto != IPPROTO_UDP)
		return -EPROTOTYPE;

	return 0;
}

static int dns_mt6_check(const struct xt_mtchk_param *par)
{
	const struct ip6t_ip6 *ip = par->entryinfo;
//	const struct xt_dns_info *info = par->matchinfo;

	/* we can deal with UDP only */
	if (ip->proto != IPPROTO_UDP)
		return -EPROTOTYPE;

	return 0;
}


static struct xt_match dns_reg[] __read_mostly = {
	{
		.name		= "dns",
		.revision	= 0,
		.family		= NFPROTO_IPV4,
		.checkentry	= dns_mt_check,
		.match		= dns_mt,
		.matchsize	= sizeof(struct xt_dns_info),
		.me		= THIS_MODULE
	},
	{
		.name		= "dns",
		.revision	= 0,
		.family		= NFPROTO_IPV6,
		.checkentry	= dns_mt6_check,
		.match		= dns_mt,
		.matchsize	= sizeof(struct xt_dns_info),
		.me		= THIS_MODULE
	},
};

static int __init dns_init(void)
{
	printk("registering %s %s: %s, %s\n", "xt_dns", VERSION, __DATE__, __TIME__);
	return xt_register_matches(dns_reg, ARRAY_SIZE(dns_reg));
}

static void __exit dns_exit(void)
{
//	printk("unregistering %s\n", "xt_dns");
	xt_unregister_matches(dns_reg, ARRAY_SIZE(dns_reg));
}

module_init(dns_init);
module_exit(dns_exit);
MODULE_AUTHOR("Bartlomiej Korupczynski <bartek@klolik.org>");
MODULE_DESCRIPTION("Xtables: DNS query match");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_dns");
MODULE_ALIAS("ip6t_dns");

