/*
 *	libxt_dns
 *      Copyright (c) Ondrej Caletka, 2013
 *	based on libxt_dns (c) Bartlomiej Korupczynski, 2011
 *
 *	This is userspace part of module used to match DNS MX queries
 * 
 *	This file is distributed under the terms of the GNU General Public
 *	License (GPL). Copies of the GPL can be obtained from gnu.org/gpl.
 */

#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <arpa/nameser.h>

#include "xt_dns.h"
#include "config.h"

// uncomment this for older version of iptables
//#define xtables_error exit_error


/* match arguments */
#define A_TYPE	"dns-query"

struct {
	char *name;
	u_int8_t type;
} dns_types[] = {
	{ "A", ns_t_a },
	{ "NS", ns_t_ns },
	{ "CNAME", ns_t_cname },
	{ "SOA", ns_t_soa },
	{ "PTR", ns_t_ptr },
	{ "MX", ns_t_mx },
	{ "TXT", ns_t_txt },
	{ "AAAA", ns_t_aaaa },
	{ "SRV", ns_t_srv },
	{ "A6", ns_t_a6 },
	{ "ANY", ns_t_any },
	{ NULL },
};

static const struct option dns_opts[] = {
	{ .name = A_TYPE, 1, NULL, '1' },
	{ .name = NULL }
};

static const char* find_type_name(u_int8_t type)
{
	int i;

	for (i=0; dns_types[i].name != NULL; i++) {
		if (dns_types[i].type != type)
			continue;

		return dns_types[i].name;
	}

	return NULL;
}

static u_int8_t get_type(char *name)
{
	int i;

	/* find by name */
	for (i=0; dns_types[i].name != NULL; i++) {
		if (strcasecmp(dns_types[i].name, name))
			continue;

		return dns_types[i].type;
	}

	/* is name numeric? */
	for (i=0; name[i] != '\0'; i++) {
		if (name[i]<'0' || name[i]>'9')
			return ns_t_invalid;
	}

	i = atoi(name);
	if (i < 1 || i > 255)
		return ns_t_invalid;

	return i;
}


static void dns_help(void)
{
	printf("dns match options:\n--%s {A|NS|CNAME|SOA|PTR|MX|TXT|AAAA|SRV|A6|ANY|0-255}\n", A_TYPE);
}

static void dns_init(struct xt_entry_match *m)
{
	struct xt_dns_info *info = (void *) m->data;

	info->invert = 0;
	info->type = ns_t_any;
}

static int dns_parse(int c, char **argv, int invert, unsigned int *flags,
          const void *entry, struct xt_entry_match **match)
{
	struct xt_dns_info *info = (void *) (*match)->data;
	u_int8_t type;

	if (c != '1')
		return false;

	if ((type = get_type(optarg)) == 0)
		xtables_error(PARAMETER_PROBLEM, "Unknown DNS query type");
	info->invert = invert;
	info->type = type;
	return true;
}

static void dns_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	struct xt_dns_info *info = (void *) match->data;
	const char *name = find_type_name(info->type);

	if (info->invert)
		printf("! ");

	if (name)
		printf("%s:%s ", A_TYPE, name);
	else
		printf("%s:%d ", A_TYPE, info->type);
}

static void dns_save(const void *ip, const struct xt_entry_match *match)
{
	struct xt_dns_info *info = (void *) match->data;
	const char *name = find_type_name(info->type);

	if (info->invert)
		printf("! ");

	if (name)
		printf("--%s %s ", A_TYPE, name);
	else
		printf("--%s %d ", A_TYPE, info->type);
}

static struct xtables_match dns_match = {
	.family		= AF_INET,
	.name		= "dns",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_dns_info)),
	.userspacesize	= 0,
	.help		= dns_help,
	.init		= dns_init,
	.parse		= dns_parse,
	.print		= dns_print,
	.save		= dns_save,
	.extra_opts	= dns_opts,
};

static struct xtables_match dns_match6 = {
	.family		= AF_INET6,
	.name		= "dns",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_dns_info)),
	.userspacesize	= 0,
	.help		= dns_help,
	.init		= dns_init,
	.parse		= dns_parse,
	.print		= dns_print,
	.save		= dns_save,
	.extra_opts	= dns_opts,
};

void _init(void)
{
	xtables_register_match(&dns_match);
	xtables_register_match(&dns_match6);
}

