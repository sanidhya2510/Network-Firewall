#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs_struct.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/string.h>
#include <linux/pid.h>
#include <linux/ip.h>

// The IP address to block
static char *blocked_ip_addr = "";

static struct nf_hook_ops nfho;

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    char dest_ip[16];
    iph = ip_hdr(skb);
    sprintf(dest_ip, "%pI4", &iph->daddr);
    if (strcmp(dest_ip, blocked_ip_addr) == 0)
    {
        // Drop the packet
        pr_info("Blocking outbound request from the specified IP\n");
        return NF_DROP;
    }
    return NF_ACCEPT;
}


static int __init init_nf_module(void)
{
    pr_info("Custom firewall module loaded\n");

    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_POST_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);

    return 0;
}

static void __exit exit_nf_module(void)
{
    pr_info("Custom firewall module unloaded\n");
    nf_unregister_net_hook(&init_net, &nfho);
}

module_init(init_nf_module);
module_exit(exit_nf_module);

MODULE_LICENSE("GPL");
