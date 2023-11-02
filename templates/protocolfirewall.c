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

static char *protocol = "";
unordered_map<string, int> protocols_code = {{"udp", 17}, {"tcp", 6}, {"icmp", 1}};
static struct nf_hook_ops nfho;

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    iph = ip_hdr(skb);
    if (iph->protocol == protocols_code[protocol])
    {
        // Drop the packet
        pr_info("Blocking request to the specified Protocol\n");
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