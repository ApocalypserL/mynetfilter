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

#define	NETLINK_MYOWN 31
#define KERN_TO_USER 0

struct
{
	__u32 pid;
}user_proc;

static struct sock *nlfd;

static int send_to_user(char *info)
{
	int ret;
	int size;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	sk_buff_data_t old_tail;

	size = NLMSG_SPACE(strlen(info));
	skb = alloc_skb(size, GFP_ATOMIC);

	nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(strlen(info)) - sizeof(struct nlmsghdr), 0);
	old_tail = skb->tail;
	memcpy(NLMSG_DATA(nlh), info, strlen(info));
	nlh->nlmsg_len = skb->tail - old_tail;

	NETLINK_CB(skb).portid = 0;
	NETLINK_CB(skb).dst_group = 0;
	
	printk(KERN_ALERT"[kernel]sending data:%s\n", (char *)NLMSG_DATA((struct nlmsghdr *)skb->data));
	ret = netlink_unicast(nlfd, skb, user_proc.pid, MSG_DONTWAIT);
	return ret;
}

static void recv_from_user(struct sk_buff *skb)
{
	struct sk_buff *__skb;
	struct nlmsghdr *nlh;
	char *data = "This is a answer message from kernel.";

	__skb = skb_get(skb);
	if(__skb->len >= sizeof(struct nlmsghdr))
	{
		nlh = nlmsg_hdr(__skb);
		if((nlh->nlmsg_len >= sizeof(struct nlmsghdr)) && (skb->len >= nlh->nlmsg_len))
		{
			user_proc.pid = nlh->nlmsg_pid;
			printk(KERN_ALERT"[kernel]receiving data:%s\n", (char *)NLMSG_DATA(nlh));
			printk(KERN_ALERT"[kernel]user_proc_pid:%u\n", user_proc.pid);
			send_to_user(data);
		}
	}
	
	kfree_skb(__skb);
}

struct netlink_kernel_cfg cfg = {
	.input = recv_from_user,
};

static int __init mynetlink_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	nlfd = netlink_kernel_create(&init_net, NETLINK_MYOWN, &cfg);
#else
	nlfd = netlink_kernel_create(&init_net, NETLINK_MYOWN, 0, recv_from_user, NULL, THIS_MODULE);
#endif
	if(!nlfd)
	{
		printk(KERN_ALERT"create netlink failed.\n");
		return -1;
	}
	printk(KERN_ALERT"create netlink succeeded.\n");
	return 0;
}

static void __exit mynetlink_exit(void)
{
	sock_release(nlfd->sk_socket);
	printk(KERN_ALERT"delete netlink succeeded.\n");
}

module_init(mynetlink_init);
module_exit(mynetlink_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leon");