#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>

static unsigned int myhookfn(void *priv, \
	       	struct sk_buff *skb, \
		const struct nf_hook_state *state)
{
	const struct iphdr *iph = ip_hdr(skb);	//get ip header
	printk(KERN_INFO"%u", iph->saddr);
	printk(KERN_INFO"%u", iph->daddr);
	if(iph->protocol == IPPROTO_TCP)
	{
		printk(KERN_INFO"This is a TCP packet\n");
	}
	else if(iph->protocol == IPPROTO_UDP)
	{
		printk(KERN_INFO"This is a UDP packet\n");
	}
	else printk(KERN_INFO"Something Wrong\n");
	return NF_ACCEPT;
}

static struct nf_hook_ops nfho={
	.hook	= myhookfn,
	.pf	= PF_INET,
	.hooknum	= NF_INET_LOCAL_OUT,
	.priority	= NF_IP_PRI_FIRST,
};

static int __init myhookfn_init(void)
{
	return nf_register_hook(&nfho);	
}

static void __exit myhookfn_exit(void)
{
	nf_unregister_hook(&nfho);
}

module_init(myhookfn_init);
module_exit(myhookfn_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leon Huang");
MODULE_DESCRIPTION("My hookfn");
