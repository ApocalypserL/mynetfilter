#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leon Huang");
MODULE_DESCRIPTION("My hookfn for TCP/IP-DTN");

static int myhookfn(int hooknum, struct sk_buff *skb, \
		const struct net_device *in, \
		const struct net_device *out, \
		int (*okfn)(struct sk_buff *))
{
	const struct iphdr *iph = ip_hdr(skb);	//get ip header
	printk(<0>"%lu\n", iph->saddr);
	printk(<0>"%lu\n", iph->daddr);
	if(iph->protocol = IPPROTO_TCP)
	{
		printk(<0>"This is a TCP packet\n");
	}
	else if(iph->protocol = IPPROTO_UDP)
	{
		printk(<0>"This is a UDP packet\n");
	}
	else printk(<0>"Something Wrong\n");
	return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
	.hook = my_hookfn,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_FIRST,
	.owner = THIS_MODULE,
};

int nf_register_hook(struct nf_hook_ops *reg)
{
	struct nf_hook_ops *elem;
	int err;
	err = mutex_lock_interruptible(&nf_hook_mutex);
	if(err < 0) return err;
	list_for_each_entry(elem, &nf_hooks[reg->pf][reg->hooknum], list)
	{
		if(reg->priority < elem->priority) break;
	}
	list_add_rcu(&reg->list, elem->list.prev);
	mutex_unlock(&nf_hook_mutex);
	return 0;
}

void nf_unregister_hook(struct nf_hook_ops *reg)
{
	mutex_lock(&nf_hook_mutex);
	list_del_rcu(&reg->list);
	mutex_unlock(&nf_hook_mutex);
	synchronize_net();
}

static int __init myhookfn_init(void)
{
	if(nf_register_hook(&nfho))
	{
		printk(KERN_ERR "nf_register_hook() failed\n");
		return -1;
	}
	return 0;
}

static void __exit myhookfn_exit(void)
{
	nf_unregister_hook(&nfho);
}

module_init(myhookfn_init);
module_exit(myhookfn_exit);
