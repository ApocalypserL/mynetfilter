/* IMPORTANT WARNING
 * THIS VERSION WORKS ONLY ON
 * LINUX KERNEL VERSION LATER THAN 4.13 */
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
};

static struct sock *nlfd;

static void recv_from_user(struct sk_buff *skb)
{

}

static int send_to_user(struct packet_info *info)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct packet_info *packet;
	int size;
	int ret;
	unsigned int old_tail;

	size = NLMSG_SPACE(sizeof(*info));
	skb = alloc_skb(size, GFP_ATOMIC);
	nlh = nlmsg_put(skb, 0, 0, 0, size - sizeof(*nlh), 0);
	packet = NLMSG_DATA(nlh);
	old_tail = skb->tail;
	memcpy(packet, info, sizeof(struct packet_info));

	packet->saddr = info->saddr;
	packet->daddr = info->daddr;

	nlh->nlmsg_len = skb->tail - old_tail;
	NETLINK_CB(skb).dst_group = 0;

	ret = netlink_unicast(nlfd, skb, 0, MSG_DONTWAIT);
	return ret;
	
	if(skb)
	{
		kfree_skb(skb);
		return -1;
	}
}

static unsigned int hack_skb(void *priv, \
	       	struct sk_buff *skb, \
		const struct nf_hook_state *state)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct packet_info info;
	if(iph->protocol == IPPROTO_TCP)
	{
		info.saddr = iph->saddr;
		info.saddr = iph->daddr;
		send_to_user(&info);
	}
	/* Test code in early version 
	printk(KERN_INFO"%u", iph->saddr);
	printk(KERN_INFO"%u", iph->daddr);
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
	}*/
	return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
	.hook	= hack_skb,
	.pf	= PF_INET,
	.hooknum	= NF_INET_LOCAL_OUT,
	.priority	= NF_IP_PRI_FIRST,
};

static struct netlink_kernel_cfg ncfg = {
	.input 	= recv_from_user,
};

static int __init hack_skb_init(void)
{
	nlfd = netlink_kernel_create(&init_net, NETLINK_NETFILTER, &ncfg);
	if(!nlfd)
	{
		printk(KERN_ALERT"Initial Module Failed\n");
		return -1;
	}
	return nf_register_net_hook(&init_net, &nfho);	
}

static void __exit hack_skb_exit(void)
{
	if(nlfd)
	{
		sock_release(nlfd->sk_socket);
	}
	nf_unregister_net_hook(&init_net, &nfho);
}

module_init(hack_skb_init);
module_exit(hack_skb_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leon Huang");
