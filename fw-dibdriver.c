#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>

#define MAX_PHRASE_LEN (32)
#define MAX_DATA_LEN (64)

struct blacklist_phrase {
    char phrase[MAX_PHRASE_LEN];
    struct list_head list;
};

static struct nf_hook_ops netfilter_ops;
static LIST_HEAD(blacklist);
static unsigned long total_bytes_received = 0;

static bool contains_blacklisted_phrase(const char *data, size_t len) {
    struct blacklist_phrase *node;

    list_for_each_entry(node, &blacklist, list) {
        if (strnstr(data, node->phrase, len)) {
            pr_warn("Blacklisted phrase %s!", node->phrase);
            return true;
        }
    }

    return false;
}

static void add_blacklisted_phrase(const char *phrase) {
    struct blacklist_phrase *node;
    node = kmalloc(sizeof(*node), GFP_KERNEL);
    if (!node)
        return;

    strncpy(node->phrase, phrase, sizeof(node->phrase) - 1);
    node->phrase[sizeof(node->phrase) - 1] = '\0';

    INIT_LIST_HEAD(&node->list);
    list_add_tail(&node->list, &blacklist);
}


static void init_blacklist(void) {
    add_blacklisted_phrase("caps");
    add_blacklisted_phrase("jea");
    add_blacklisted_phrase("yss");
}

static void free_blacklist(void) {
    struct blacklist_phrase *node, *tmp;

    list_for_each_entry_safe(node, tmp, &blacklist, list) {
        list_del(&node->list);
        kfree(node);
    }
}

static unsigned int main_hook(void *priv, struct sk_buff *package, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    char *data = kmalloc(sizeof(MAX_DATA_LEN), GFP_KERNEL);
    int data_len, packet_len, ip_header_len, tcp_header_len;

    if (!package)
        return NF_ACCEPT;

    ip_header = ip_hdr(package);

    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(package);

        packet_len = ntohs(ip_header->tot_len);
        ip_header_len = (ip_header->ihl * 4);
        tcp_header_len = (tcp_header->doff * 4);
        data_len = packet_len - ip_header_len - tcp_header_len;
        total_bytes_received += packet_len;

        if (data_len == 0 || data_len > MAX_DATA_LEN) {
            return NF_ACCEPT;
        }
        
        strcpy(data, (const char *)((unsigned char *)tcp_header + tcp_header_len));
        data[data_len] = '\0';

        pr_info("SRC: %pI4:%d, DST: %pI4:%d, %i. CONTENT: %s, TOTAL BYTES RECEIVED: %lu\n",
            &ip_header->saddr, ntohs(tcp_header->source),
            &ip_header->daddr, ntohs(tcp_header->dest),
            data_len,
            data,
            total_bytes_received);

        if (contains_blacklisted_phrase(data, data_len)) {
            pr_info("Dropping packet containing a blacklisted phrase(s)\n");
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

static int __init my_module_init(void) {
    netfilter_ops.hook = main_hook;
    netfilter_ops.pf = PF_INET;
    netfilter_ops.hooknum = NF_INET_PRE_ROUTING;
    netfilter_ops.priority = NF_IP_PRI_FIRST;

    init_blacklist();
    nf_register_net_hook(&init_net, &netfilter_ops);
    pr_info("TCP filter loaded.\n");
    return 0;
}

static void __exit my_module_exit(void) {
    nf_unregister_net_hook(&init_net, &netfilter_ops);
    free_blacklist();
    pr_info("TCP filter unloaded.\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lampaBiurkowa");
MODULE_DESCRIPTION("Netfilter kernel module");
