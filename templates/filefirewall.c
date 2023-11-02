#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/inet_hashtables.h>
#include <linux/fs_struct.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/icmp.h>
#include <linux/tcp.h>
#include <linux/string.h>
#include <linux/pid.h>

static char *blocked_file_path = "";

static struct nf_hook_ops nfho;

static char *get_path_from_pid(int pid)
{
    struct path path;
    char *path_buf = NULL;
    char *result = NULL;

    if (!pid)
        return NULL;

    rcu_read_lock();
    if (!pid_task(find_vpid(pid), PIDTYPE_PID))
    {
        rcu_read_unlock();
        return NULL;
    }

    get_fs_root(current->fs, &path);
    path_buf = (char *)__get_free_page(GFP_KERNEL);
    if (!path_buf)
    {
        rcu_read_unlock();
        return NULL;
    }

    path_get(&path);
    snprintf(path_buf, PAGE_SIZE, "%s", d_path(&path, path_buf, PAGE_SIZE));

    result = path_buf;
    rcu_read_unlock();
    free_page((unsigned long)path_buf);

    return result;
}

static int get_pid_from_skb(struct sk_buff *skb)
{
    pr_info("sk is nil: %d\n", skb->sk->sk_socket == NULL);
    struct task_struct *task = get_pid_task(skb->sk->sk_socket->file->f_owner.pid, PIDTYPE_PID);
    pr_info("f_owner.pid: %d\n", skb->sk->sk_socket->file->f_owner.pid);
    pid_t pid = 0;
    if (task)
    {
        struct pid *pid_struct = get_task_pid(task, PIDTYPE_PID);
        if (pid_struct)
        {
            pid = pid_nr(pid_struct);
        }
        put_task_struct(task);
    }
    return pid;
}

static int get_pid_from_sock(struct socket *sock)
{
    pr_info("sk is nil: %d\n", sock == NULL);
    struct task_struct *task = get_pid_task(sock->file->f_owner.pid, PIDTYPE_PID);
    pr_info("f_owner.pid: %d\n", sock->file->f_owner.pid);
    pid_t pid = 0;
    if (task)
    {
        struct pid *pid_struct = get_task_pid(task, PIDTYPE_PID);
        if (pid_struct)
        {
            pid = pid_nr(pid_struct);
        }
        put_task_struct(task);
    }
    return pid;
}

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);
    if (iph->protocol == IPPROTO_TCP)
    {
        int sdif = inet_sdif(skb);
        bool refcounted;
        pr_info("tcp hit \n");
        struct sock *sk = __inet_lookup_skb(&tcp_hashinfo, skb, __tcp_hdrlen(tcph), tcph->source, tcph->dest, sdif, &refcounted);
        struct socket *sock = NULL;
        if (sk)
        {
            pr_info("sk is not nil\n");
            sock = sk->sk_socket;
        }
        int pid = get_pid_from_sock(sock);
        pr_info("pid: %d\n", pid);
        char *file_path = get_path_from_pid(pid);
        if (strcmp(file_path, blocked_file_path) == 0)
        {
            // Drop the ICMP packet
            pr_info("Blocking outbound ping request from the specified file\n");
            return NF_DROP;
        }
        return NF_ACCEPT;
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