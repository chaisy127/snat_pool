#include <linux/types.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_nat_rule.h>
#include <linux/netfilter_ipv4.h>
#include <linux/jiffies.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wiggers.torvalds@yahoo.com");
MODULE_DESCRIPTION("xtables: SNAT from ip-pool");

#define MAX_ADDR_NUM	100

struct ip_addr_pool {
	unsigned int size;
	__be32 ips[MAX_ADDR_NUM];
};

static int pool_check(const struct xt_tgchk_param *pr)
{
	return 0;
}

static unsigned int
	pool_target(struct sk_buff *skb, 
		const struct xt_action_param *par)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	const struct ip_addr_pool *mr = par->targinfo;

	unsigned int indx = jiffies % (mr->size);
	struct nf_nat_range newrange;

	newrange.min_ip = mr->ips[indx];
	newrange.max_ip = mr->ips[indx];
	newrange.flags = IP_NAT_RANGE_MAP_IPS;
	NF_CT_ASSERT(par->hooknum == NF_INET_POST_ROUTING
			|| par->hooknum == NF_INET_LOCAL_IN);

	ct = nf_ct_get(skb, &ctinfo);
	return nf_nat_setup_info(ct, &newrange, IP_NAT_MANIP_SRC);
}

static struct xt_target pool_reg __read_mostly = {
	.name = "POOL",
	.family = NFPROTO_IPV4,
	.target = pool_target,
	.targetsize = sizeof(struct ip_addr_pool),
	.table = "nat",
	.hooks = (1 << NF_INET_POST_ROUTING) | (1 << NF_INET_LOCAL_IN),
	.checkentry = pool_check,
	.me = THIS_MODULE,
};

static int __init pool_target_init(void)
{
	return xt_register_target(&pool_reg);
}

static void __exit pool_target_exit(void)
{
	xt_unregister_target(&pool_reg);
}

module_init(pool_target_init);
module_exit(pool_target_exit);
