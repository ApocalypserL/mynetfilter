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
#define KERN_TO_USER 0

struct
{
	__u32 pid;
}user_proc;

struct packet_info
{
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
};

static struct sock *nlfd;

static int send_to_user(struct packet_info info)
{
	int ret;
	int size;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	sk_buff_data_t old_tail;

	size = NLMSG_SPACE(sizeof(struct packet_info));
	skb = alloc_skb(size, GFP_ATOMIC);

	nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(sizeof(struct packet_info)) - sizeof(struct nlmsghdr), 0);
	old_tail = skb->tail;
	memcpy(NLMSG_DATA(nlh), &info, sizeof(struct packet_info));
	nlh->nlmsg_len = skb->tail - old_tail;

	NETLINK_CB(skb).portid = 0;
	NETLINK_CB(skb).dst_group = 0;
	
	//printk(KERN_DEBUG"[kernel]sending data:%s\n", (char *)NLMSG_DATA((struct nlmsghdr *)skb->data));
	ret = netlink_unicast(nlfd, skb, user_proc.pid, 1);
	return ret;
}

static void recv_from_user(struct sk_buff *skb)
{
	struct sk_buff *__skb;
	struct nlmsghdr *nlh;

	__skb = skb_get(skb);
	if(__skb->len >= sizeof(struct nlmsghdr))
	{
		nlh = nlmsg_hdr(__skb);
		if((nlh->nlmsg_len >= sizeof(struct nlmsghdr)) && (skb->len >= nlh->nlmsg_len))
		{
			user_proc.pid = nlh->nlmsg_pid;
			printk(KERN_DEBUG "[kernel]netlink confirmed, user_proc_pid:%u\n", user_proc.pid);
		}
	}
	
	kfree_skb(__skb);
}

struct netlink_kernel_cfg cfg = {
	.input = recv_from_user,
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
	int ret = 0;	
	struct packet_info info;
	char *data_h;
	char *data_e;
	int payloadsize = 0;
	const struct iphdr *iph = ip_hdr(skb);
	if(skb->protocol == IPPROTO_ICMP)
	{
		return NF_ACCEPT;
	}
		
	printk(KERN_DEBUG "Packet hacked!\n");
	data_e = skb_tail_pointer(skb);
	data_h = skb_transport_header(skb);

	info.saddr = iph->saddr;
	info.daddr = iph->daddr;

	switch(iph->protocol)
	{
		case IPPROTO_TCP:
			{
				const struct tcphdr *tcph = tcp_hdr(skb);
				info.sport = tcph->source;
				info.dport = tcph->dest;
				data_h = data_h + tcp_hdrlen(skb) + tcp_optlen(skb);
				payloadsize = data_e - data_h;
				if(payloadsize < 0)
				{
					return NF_ACCEPT;
				}
				printk(KERN_DEBUG "protocol:%u, dest:%u, sport:%u, size:%d\n", iph->protocol, info.daddr, ntohs(info.sport), payloadsize);
				break;
			}
		case IPPROTO_UDP:
			{
				const struct udphdr *udph = udp_hdr(skb);
				info.sport = udph->source;
				info.dport = udph->dest;
				data_h += sizeof(struct udphdr);
				payloadsize = data_e - data_h;
				if(payloadsize < 0)
				{
					return NF_ACCEPT;
				}
				printk(KERN_DEBUG "protocol:%u, dest:%u, sport:%u, size:%d\n", iph->protocol, info.daddr, ntohs(info.sport), payloadsize);
				break;
			}
		default:
			return NF_ACCEPT;
	}
	if((user_proc.pid) > 0)
	{
		ret = send_to_user(info);
	}
	//printk(KERN_DEBUG"%u\n", info.daddr);
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
	user_proc.pid = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	nlfd = netlink_kernel_create(&init_net, NETLINK_MYOWN, &cfg);
#else
	nlfd = netlink_kernel_create(&init_net, NETLINK_MYOWN, &cfg);
#endif
	if(!nlfd)
	{
		printk(KERN_DEBUG" create netlink failed.\n");
		return -1;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	return nf_register_net_hook(&init_net, &nfho);
#else
	return nf_register_hook(&nfho);
#endif	
}

static void __exit hack_skb_exit(void)
{
	sock_release(nlfd->sk_socket);
	printk(KERN_DEBUG "delete netlink.\n");
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
