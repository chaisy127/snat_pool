#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <xtables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

enum {
	FROM_POOL = 0,
};

#define MAX_ADDR_NUM	100
struct ip_addr_pool {
	unsigned int size;
	u_int32_t ips[MAX_ADDR_NUM];
};

struct ipt_natinfo {
	struct xt_entry_target t;
	struct ip_addr_pool mr;
};

static void pool_help(void)
{
	printf(
			"pool target options:\n"
			" --pool [<ipaddr>[,<ipaddr[,<...>]>]]\n");
}

static const struct xt_option_entry pool_opts[] = {
	{
		.name = "pool",
		.id = FROM_POOL,
		.type = XTTYPE_STRING,
		.flags = XTOPT_MAND | XTOPT_MULTI
	},
	XTOPT_TABLEEND,
};

static struct ipt_natinfo *
set_contents(struct ipt_natinfo *info, char *arg)
{
	unsigned int size;
	char *tok;
	unsigned int i = 0;

	size = XT_ALIGN(sizeof(struct ipt_natinfo));
	info = realloc(info, size);
	if (!info)
		xtables_error(OTHER_PROBLEM, "Out of memory\n");

	tok = strtok(arg, ",");
	if (tok) {
		while (tok && i < MAX_ADDR_NUM) {
			info->mr.ips[i] = (u_int32_t)inet_addr(tok);
			info->mr.size ++;
			tok = strtok(NULL, ",");
			i ++;
		}
	}
	else {
		info->mr.ips[i] = (u_int32_t)inet_addr(arg);
		info->mr.size ++;
	}

	return info;
}

static void pool_parse(struct xt_option_call *cb)
{
	const struct ipt_entry *entry = cb->xt_entry;
	struct ipt_natinfo *info = (void *)(*cb->target);
	int portok;

	if (entry->ip.proto == IPPROTO_TCP
		|| entry->ip.proto == IPPROTO_UDP
		|| entry->ip.proto == IPPROTO_SCTP
		|| entry->ip.proto == IPPROTO_DCCP
		|| entry->ip.proto == IPPROTO_ICMP)
		portok = 1;
	else 
		portok = 0;

	xtables_option_parse(cb);
	switch(cb->entry->id)
	{
		case FROM_POOL:
		{
			char *arg;
			arg = strdup(cb->arg);
			if (!arg)
				xtables_error(RESOURCE_PROBLEM, "strdup");

			info = set_contents(info, arg);
			free(arg);
			*cb->target = &(info->t);
			break;
		}
	}
}

static void 
pool_save(const void *ip, const struct xt_entry_target *target)
{
	const struct ipt_natinfo *info = (const void *)target;
	unsigned int i = 0;

	printf(" --pool ");
	for (i = 0; i < info->mr.size; i++) {
		struct in_addr ia;
		char *addr;
		ia.s_addr = info->mr.ips[i];
		addr = inet_ntoa(ia);
		if (i == info->mr.size - 1)
			printf("%s", addr);
		else 
			printf("%s,", addr);
	}
}

static struct xtables_target pool_tg_reg = {
	.name = "POOL",
	.version = XTABLES_VERSION,
	.family = NFPROTO_IPV4,
	.size = XT_ALIGN(sizeof(struct ip_addr_pool)),
	.userspacesize = XT_ALIGN(sizeof(struct ip_addr_pool)),
	.help = pool_help,
	.x6_parse = pool_parse,
	.save = pool_save,
	.x6_options = pool_opts,
};

void _init(void)
{
	xtables_register_target(&pool_tg_reg);
}
