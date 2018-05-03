#include <stdio.h>
#include <linux/netfilter.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/inet.h>

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

static int_init dtn_t(void)
{
	if(nf_register_hook(&nfho))
	{
		printk(KERN_ERR "nf_register_hook() failed\n");
		return -1;
	}
	return 0;
}

static void __exit dtn_t(void)
{
	nf_unregister_hook(&nfho);
}


