#include <iostream>
#include <fstream>
#include <unordered_map>

using namespace std;

void generateCFile(const string& filename, unordered_map<string, string>& extraFlags) {
    string saveFilename = "./tmp/" + filename + ".c";
    ofstream file(saveFilename);

    if (!file) {
        cerr << "Error creating file!" << endl;
        return;
    }

    // Include files
    file << "#include <linux/module.h>\n";
    file << "#include <linux/kernel.h>\n";
    file << "#include <linux/netfilter.h>\n";
    file << "#include <linux/netfilter_ipv4.h>\n";
    file << "#include <linux/fs_struct.h>\n";
    file << "#include <net/ip.h>\n";
    file << "#include <linux/tcp.h>\n";
    file << "#include <linux/string.h>\n";
    file << "#include <linux/pid.h>\n";
    file << "#include <linux/ip.h>\n\n";

    // Global Varibales
    if(extraFlags.count("source")){
        file << "static char *sblocked_ip_addr = \"" +extraFlags["source"] + "\";\n";
        file << "static struct nf_hook_ops snfho;\n\n";
    }
    if(extraFlags.count("destination")){
        file << "static char *dblocked_ip_addr = \"" + extraFlags["destination"] + "\";\n";
        file << "static struct nf_hook_ops dnfho;\n\n";
    }
    if(extraFlags.count("port")){
        file << "int blocked_port = " + extraFlags["port"] + ";\n";
        file << "static struct nf_hook_ops pnfho;\n\n";
    }
    if(extraFlags.count("protocol")){
        file << "static char *protocol = \"" + extraFlags["protocol"] + "\";\n";
        file << "static struct nf_hook_ops pcnfho;\n\n";
    }
    if(extraFlags.count("file_path")){
        file << "static char *blocked_file_path = \"" + extraFlags["file_path"] + "\";\n";
        file << "static struct nf_hook_ops fhook;\n\n";
    }

    // Write templated dynamic functions
    if(extraFlags.count("source")){
        file << "unsigned int shook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){\n";
        file << "\tstruct iphdr *iph;\n";
        file << "\tchar source_ip[16];\n";
        file << "\tiph = ip_hdr(skb);\n";
        file << "\tsprintf(source_ip, \"%pI4\", &iph->saddr);\n";
        file << "\tif(strcmp(source_ip, sblocked_ip_addr) == 0){\n";
        file << "\t\treturn NF_DROP;\n";
        file << "\t}\n";
        file << "\treturn NF_ACCEPT;\n";
        file << "}\n\n";
    }
    if(extraFlags.count("destination")){
        file << "unsigned int dhook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){\n";
        file << "\tstruct iphdr *iph;\n";
        file << "\tchar dest_ip[16];\n";
        file << "\tiph = ip_hdr(skb);\n";
        file << "\tsprintf(dest_ip, \"%pI4\", &iph->daddr);\n";
        file << "\tif(strcmp(dest_ip, dblocked_ip_addr) == 0){\n";
        file << "\t\treturn NF_DROP;\n";
        file << "\t}\n";
        file << "\treturn NF_ACCEPT;\n";
        file << "}\n\n";
    }

    if(extraFlags.count("protocol")){
        unordered_map<string, int> protocols_code = {{"udp", 17}, {"tcp",6},{"icmp",1}};
        int protocol_code = protocols_code[extraFlags["protocol"]];
        file << "unsigned int pcnhook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){\n";
        file << "\tstruct iphdr *iph;\n";
        file << "\tiph = ip_hdr(skb);\n";
        file << "\tif(" + to_string(protocol_code) +" == (iph->protocol)){\n";
        file << "\t\treturn NF_DROP;\n";
        file << "\t}\n";
        file << "\treturn NF_ACCEPT;\n";
        file << "}\n\n";
    }

    if(extraFlags.count("port")){
        file << "unsigned int pnhook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){\n";
        file << "\tstruct iphdr *iph;\n";
        file << "\tstruct tcphdr *tcph;\n";
        file << "\tiph = ip_hdr(skb);\n";
        file << "\ttcph = tcp_hdr(skb);\n";
        file << "\tif(tcph->dest == htons(blocked_port)){\n";
        file << "\t\treturn NF_DROP;\n";
        file << "\t}\n";
        file << "\treturn NF_ACCEPT;\n";
        file << "}\n\n";
    }
    if(extraFlags.count("file_path")){
        file << "static char *get_path_from_pid(int pid){\n";
        file << "\tstruct path path;\n";
        file << "\tchar *path_buf = NULL;\n";
        file << "char *result = NULL;\n";
        file << "\tif(!pid){\n";
        file << "\t\treturn NULL;\n";
        file << "\t}\n";
        file << "\tget_fs_root(current->fs, &path);\n";
        file << "\tpath_buf = (char *)__get_free_page(GFP_KERNEL);\n";
        file << "\tif(!path_buf){\n";
        file << "\t\trcu_read_unlock();\n";
        file << "\t\treturn NULL;\n";
        file << "\t}\n";
        file << "\tpath_get(&path);\n";
        file << "\tsnprintf(path_buf, PAGE_SIZE, \"%s\", d_path(&path, path_buf, PAGE_SIZE));\n";
        file << "\tresult = path_buf;\n";
        file << "\trcu_read_unlock();\n";
        file << "\tfree_page((unsigned long)path_buf);\n";
        file << "\treturn result;\n";
        file << "}\n\n";
        file << "static int get_pid_from_sock(struct socket *sock){\n";
        file << "\tstruct task_struct *task = get_pid_task(sock->file->f_owner.pid, PIDTYPE_PID);\n";
        file << "\tpid_t pid = 0;\n";
        file << "\tif(task){\n";
        file << "\t\tstruct pid *pid_struct = get_task_pid(task, PIDTYPE_PID);\n";
        file << "\t\tif(pid_struct){\n";
        file << "\t\t\tpid = pid_nr(pid_struct);\n";
        file << "\t\t}\n";
        file << "\t\tput_task_struct(task);\n";
        file << "\t}\n";
        file << "\treturn pid;\n";
        file << "}\n\n";
        file << "unsigned int fhook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){\n";\
        file << "\tstruct iphdr *iph;\n";
        file << "\tstruct tcphdr *tcph;\n";
        file << "\tiph = ip_hdr(skb);\n";
        file << "\ttcph = tcp_hdr(skb);\n";
        file << "\tif(iph->protocol == IPPROTO_TCP){\n";
        file << "\t\tint sdif = inet_sdif(skb);\n";
        file << "\t\tbool refcounted\n";
        file << "\t\tstruct sock *sk = __inet_lookup_skb(&tcp_hashinfo, skb, tcph->source, tcph->dest, sdif, &refcounted);\n";
        file << "\t\tif(sk){\n";
        file << "\t\t\tsock = sk->sk_socket;\n";
        file << "\t\t}\n";
        file << "\t\tint pid = get_pid_from_sock(sock);\n";
        file << "\t\tchar *path = get_path_from_pid(pid);\n";
        file << "\t\tif(strcmp(path, blocked_file_path) == 0){\n";
        file << "\t\t\treturn NF_DROP;\n";
        file << "\t\t}\n";
        file << "\t}\n";
        file << "\treturn NF_ACCEPT;\n";
        file << "}\n\n";

    }
    // Init function
    file << "static int __init init_nf_module(void) {\n";
    file << "\tpr_info(\"Custom firewall module loaded\\n\");\n";
    if(extraFlags.count("source")){
        file << "\tsnfho.hook = shook_func;\n";
        file << "\tsnfho.hooknum = NF_INET_PRE_ROUTING;\n";
        file << "\tsnfho.pf = PF_INET;\n";
        file << "\tsnfho.priority = NF_IP_PRI_FIRST;\n";
        file << "\tnf_register_net_hook(&init_net, &snfho);\n";
    }
    if(extraFlags.count("destination")){
        file << "\tdnfho.hook = dhook_func;\n";
        file << "\tdnfho.hooknum = NF_INET_POST_ROUTING;\n";
        file << "\tdnfho.pf = PF_INET;\n";
        file << "\tdnfho.priority = NF_IP_PRI_FIRST;\n";
        file << "\tnf_register_net_hook(&init_net, &dnfho);\n";
    }
    if(extraFlags.count("protocol")){
        file << "\tpcnfho.hook = pcnhook_func;\n";
        file << "\tpcnfho.hooknum = NF_INET_POST_ROUTING;\n";
        file << "\tpcnfho.pf = PF_INET;\n";
        if(extraFlags["protocol"] == "tcp"){
            file << "\tpcnfho.priority = NF_IP_PRI_LAST;\n";
        }else{
            file << "\tpcnfho.priority = NF_IP_PRI_FIRST+10;\n";
        }
        file << "\tnf_register_net_hook(&init_net, &pcnfho);\n";
    }
    if(extraFlags.count("port")){
        file << "\tpnfho.hook = pnhook_func;\n";
        file << "\tpnfho.hooknum = NF_INET_POST_ROUTING;\n";
        file << "\tpnfho.pf = PF_INET;\n";
        file << "\tpnfho.priority = NF_IP_PRI_LAST;\n";
        file << "\tnf_register_net_hook(&init_net, &pnfho);\n";
    }
    if(extraFlags.count("file_path")){
        file << "\tfhook.hook = fhook_func;\n";
        file << "\tfhook.hooknum = NF_INET_POST_ROUTING;\n";
        file << "\tfhook.pf = PF_INET;\n";
        file << "\tfhook.priority = NF_IP_PRI_FIRST;\n";
        file << "\tnf_register_net_hook(&init_net, &fhook);\n";
    }
    file << "\treturn 0;\n";
    file << "}\n\n";

    file << "static void __exit exit_nf_module(void) {\n";
    file << "\tpr_info(\"Custom firewall module unloaded\\n\");\n";
    if(extraFlags.count("source")){
        file << "\tnf_unregister_net_hook(&init_net, &snfho);\n";
    }
    if(extraFlags.count("destination")){
        file << "\tnf_unregister_net_hook(&init_net, &dnfho);\n";
    }
    if(extraFlags.count("port")){
        file << "\tnf_unregister_net_hook(&init_net, &pnfho);\n";
    }
    if(extraFlags.count("protocol")){
        file << "\tnf_unregister_net_hook(&init_net, &pcnfho);\n";
    }
    if(extraFlags.count("file_path")){
        file << "\tnf_unregister_net_hook(&init_net, &fhook);\n";
    }
    file << "}\n\n";

    file << "module_init(init_nf_module);\n";
    file << "module_exit(exit_nf_module);\n\n";
    file << "MODULE_LICENSE(\"GPL\");\n\n";

    file.close();

    cout << "C file " << filename << " has been generated successfully." << endl;

    ofstream file2("./tmp/Makefile");

    if (!file2) {
        cerr << "Error creating file!" << endl;
        return;
    }
    file2 << "obj-m += " + filename+ ".o\n\n";
    file2 << "all:\n";
    file2 << "\tmake -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules\n\n";
    file2 << "clean:\n";
    file2 << "\tmake -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean\n\n";
    file2.close();
    cout << "Makefile has been generated successfully." << endl;
}

void parsergen(string filename, unordered_map<string, string>& extraFlags) {
    string name = "fw"+filename;
    generateCFile(name,extraFlags);
    system("cd ./tmp && sudo make");
    string command = "cd ./tmp && sudo insmod "+name+".ko";
    system(command.c_str());
}

void removeModule(string filename){
    string name = "fw"+filename;
    string command = "cd ./tmp && sudo rmmod "+name;
    string removeCommand = "cd ./tmp && sudo rm "+name+".c";
    system(command.c_str());
    system(removeCommand.c_str());
    system("cd ./tmp && sudo make clean");
    system("g++ cli.cpp -o firewall");
}
