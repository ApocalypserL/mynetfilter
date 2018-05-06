/* IMPORTANT WARNING
 * THIS VERSION WORK ON LINUX KERNEL VERSION
 * BEFORE 4.13 */
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
#include <sys/types.h>
#include <sys/socket.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <arpa/inet.h>

/* My own hook function
 * Analyse the packet passing LOCAL_OUT
 * Get its saddr & daddr & data
 * What to do then? IDK */
static unsigned int myhookfn(void *priv, \
	       	struct sk_buff *skb, \
		const struct nf_hook_state *state)
{
	const struct iphdr *iph = ip_hdr(skb);

	char s_saddr[16];
	char s_daddr[16];
	struct in_addr saddr;
	struct in_addr daddr;
	saddr.s_addr = htonl(iph->saddr);
	daddr.s_addr = htonl(iph->daddr);
	inet_ntop(AF_INET, (void *)&saddr, s_saddr, (socklen_t)sizeof(s_saddr));
	inet_ntop(AF_INET, (void *)&daddr, s_daddr, (socklen_t)sizeof(s_daddr));
	printk(KERN_INFO"%s\n", s_saddr);
	printk(KERN_INFO"%s\n", s_daddr);

	switch(iph->protocol)
	{
		case IPPROTO_ICMP:
			printk(KERN_INFO"This is a ICMP.\n");
			break;
		case IPPROTO_TCP:
			printk(KERN_INFO"This is a TCP.\n");
			break;
		case IPPROTO_UDP:
			printk(KERN_INFO"This is a UDP.\n");
			break;
		default:
			printk(KERN_INFO"IDK what it is.\n");
			break;
	}
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
