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
            file << "\tpcnfho.priority = NF_IP_PRI_FIRST;\n";
        }
        file << "\tnf_register_net_hook(&init_net, &pcnfho);\n";
    }
    if(extraFlags.count("port")){
        file << "\tpnfho.hook = pnhook_func;\n";
        file << "\tpnfho.hooknum = NF_INET_POST_ROUTING;\n";
        file << "\tpnfho.pf = PF_INET;\n";
        file << "\tpnfho.priority = NF_IP_PRI_FIRST;\n";
        file << "\tnf_register_net_hook(&init_net, &pnfho);\n";
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
