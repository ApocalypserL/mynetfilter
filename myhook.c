/* IMPORTANT WARNING */
/* Since the structure of sk_buff has been changed after
 * kernel version 2.6.x, so this module should be
 * installed in a kernel later than 2.6.x */
#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
#endif

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>

#define NETLINK_MYOWN	31

struct packet_info
{
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	sk_buff_data_t data_h;
	sk_buff_data_t data_e;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
static unsigned int hack_skb(void *priv, \
	       	struct sk_buff *skb, \
		const struct nf_hook_state *state)
#else
static unsigned int hack_skb(const struct nf_hook_ops *ops, \
		struct sk_buff *skb, \
		const struct net_device *in, \
		const struct net_device *out, \
		int (*okfn)(struct sk_buff *))
#endif
{	
	struct packet_info info;
	const struct iphdr *iph = ip_hdr(skb);

	if(skb->protocol == IPPROTO_ICMP)
	{
		return NF_ACCEPT;
	}
		
	info.data_e = skb->tail;
	info.data_h = skb->transport_header;

	info.saddr = iph->saddr;
	info.daddr = iph->daddr;

	switch(iph->protocol)
	{
		case IPPROTO_TCP:
			{
				const struct tcphdr *tcph = tcp_hdr(skb);
				info.sport = tcph->source;
				info.dport = tcph->dest;
				info.data_h += tcp_hdrlen(skb) + tcp_optlen(skb);
				break;
			}
		case IPPROTO_UDP:
			{
				const struct udphdr *udph = udp_hdr(skb);
				info.sport = udph->source;
				info.dport = udph->dest;
				info.data_h += sizeof(struct udphdr);
				break;
			}
		default:
			break;
	}

	
	printk(KERN_ALERT"%u\n", info.saddr);
	printk(KERN_ALERT"%u\n", info.daddr);
	return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
	.hook	= hack_skb,
	.pf	= PF_INET,
	.hooknum	= NF_INET_LOCAL_OUT,
	.priority	= NF_IP_PRI_FIRST,
};

static int __init hack_skb_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	return nf_register_net_hook(&init_net, &nfho);
#else
	return nf_register_hook(&nfho);
#endif	
}

static void __exit hack_skb_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	nf_unregister_net_hook(&init_net, &nfho);
#else
	nf_unregister_hook(&nfho);
#endif
}

module_init(hack_skb_init);
module_exit(hack_skb_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leon Huang");
