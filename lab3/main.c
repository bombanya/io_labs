#include <linux/module.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/moduleparam.h>
#include <linux/in.h>
#include <net/arp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/proc_fs.h>

#define BUF_SIZE 100
#define PACKET_SIZE 1600

static char* link = "enp0s3";
module_param(link, charp, 0);

static char* ifname = "vni%d";

static struct net_device_stats stats;

static struct net_device *child = NULL;
struct priv {
    struct net_device *parent;
};

static int rx = 0;
static int rx_icmp8 = 0;

static char packets[BUF_SIZE][PACKET_SIZE];

static struct proc_dir_entry *proc_file;

static void save_frame(struct iphdr* ip) {
    printk(KERN_INFO "saving\n");
    int str_off = 0;
    str_off += sprintf(packets[rx_icmp8 % BUF_SIZE], "\nsaddr: %d.%d.%d.%d\n",
                       ntohl(ip->saddr) >> 24, (ntohl(ip->saddr) >> 16) & 0x00FF,
                       (ntohl(ip->saddr) >> 8) & 0x0000FF, (ntohl(ip->saddr)) & 0x000000FF);
    str_off += sprintf(packets[rx_icmp8 % BUF_SIZE] + str_off, "daddr: %d.%d.%d.%d\ndata: ",
                       ntohl(ip->daddr) >> 24, (ntohl(ip->daddr) >> 16) & 0x00FF,
                       (ntohl(ip->daddr) >> 8) & 0x0000FF, (ntohl(ip->daddr)) & 0x000000FF);
    int payload_off = sizeof(struct icmphdr) + (ip->ihl * 4);
    int payload_len = ntohs(ip->tot_len) - payload_off;
    memcpy(packets[rx_icmp8 % BUF_SIZE] + str_off, (u8*)ip + payload_off, payload_len);
    packets[rx_icmp8 % BUF_SIZE][str_off + payload_len] = 0;
}

static char check_frame(struct sk_buff *skb) {
    struct iphdr *ip = (struct iphdr *)skb_network_header(skb);

    if (IPPROTO_ICMP == ip->protocol) {
        printk(KERN_INFO "icmp packet\n");

        struct icmphdr* icmp = (struct icmphdr*)((u8*)ip + (ip->ihl * 4));
        printk(KERN_INFO "icmp type: %d\n", icmp->type);

        if (icmp->type == ICMP_ECHO) {

            int payload_len = ntohs(ip->tot_len) - sizeof(struct icmphdr) - (ip->ihl * 4);

            printk(KERN_INFO "saddr: %d.%d.%d.%d\n",
                    ntohl(ip->saddr) >> 24, (ntohl(ip->saddr) >> 16) & 0x00FF,
                    (ntohl(ip->saddr) >> 8) & 0x0000FF, (ntohl(ip->saddr)) & 0x000000FF);
            printk(KERN_INFO "daddr: %d.%d.%d.%d\n",
                    ntohl(ip->daddr) >> 24, (ntohl(ip->daddr) >> 16) & 0x00FF,
                    (ntohl(ip->daddr) >> 8) & 0x0000FF, (ntohl(ip->daddr)) & 0x000000FF);

            printk(KERN_INFO "payload length: %d\n", payload_len);

            save_frame(ip);
            rx_icmp8++;
            return 1;
        }

    }
    return 0;
}

static rx_handler_result_t handle_frame(struct sk_buff **pskb) {
    check_frame(*pskb);
    rx++;
    stats.rx_packets++;
    stats.rx_bytes += (*pskb)->len;

    return RX_HANDLER_PASS;
}

static int open(struct net_device *dev) {
    netif_start_queue(dev);
    printk(KERN_INFO "%s: device opened", dev->name);
    return 0;
}

static int stop(struct net_device *dev) {
    netif_stop_queue(dev);
    printk(KERN_INFO "%s: device closed", dev->name);
    return 0;
}

static netdev_tx_t start_xmit(struct sk_buff *skb, struct net_device *dev) {
    struct priv *priv = netdev_priv(dev);

    stats.tx_packets++;
    stats.tx_bytes += skb->len;

    if (priv->parent) {
        skb->dev = priv->parent;
        skb->priority = 1;
        dev_queue_xmit(skb);
        return 0;
    }
    return NETDEV_TX_OK;
}

static struct net_device_stats *get_stats(struct net_device *dev) {
    return &stats;
}

static struct net_device_ops net_device_ops = {
        .ndo_open = open,
        .ndo_stop = stop,
        .ndo_get_stats = get_stats,
        .ndo_start_xmit = start_xmit
};

static void setup(struct net_device *dev) {
    int i;
    ether_setup(dev);
    memset(netdev_priv(dev), 0, sizeof(struct priv));
    dev->netdev_ops = &net_device_ops;

    //fill in the MAC address
    for (i = 0; i < ETH_ALEN; i++)
        dev->dev_addr[i] = (char)i;
}

static ssize_t procfile_read(struct file *file, char __user *buffer,
        size_t buffer_length, loff_t *offset) {

    printk(KERN_INFO "read from proc\n");

    if (*offset == 0) {
        if (buffer_length < 100) return 0;
        char* str_buffer = kmalloc(100 * sizeof(char), GFP_KERNEL);
        int str_len = 0;
        str_len += sprintf(str_buffer, "Packets received: %d\nICMP echo requests received: %d\n",
                           rx, rx_icmp8);
        if (copy_to_user(buffer, str_buffer, str_len)) {
            printk(KERN_ERR "error in proc\n");
            kfree(str_buffer);
            return 0;
        }
        kfree(str_buffer);
        int packets_to_copy = min(rx_icmp8, BUF_SIZE);
        int i = 0;
        while (i < packets_to_copy && str_len + strlen(packets[i]) <= buffer_length) {
            if (copy_to_user(buffer + str_len, packets[i], strlen(packets[i]))) {
                printk(KERN_ERR "error in proc\n");
                return 0;
            }
            str_len += strlen(packets[i]);
            i++;
        }
        *offset = str_len;
        return str_len;
    }
    else return 0;
}

static const struct proc_ops proc_file_fops = {
        .proc_read = procfile_read,
};

int __init vni_init(void) {
    int err = 0;
    struct priv *priv;
    child = alloc_netdev(sizeof(struct priv), ifname, NET_NAME_UNKNOWN, setup);
    if (child == NULL) {
        printk(KERN_ERR "%s: allocate error", THIS_MODULE->name);
        return -ENOMEM;
    }
    priv = netdev_priv(child);
    priv->parent = __dev_get_by_name(&init_net, link); //parent interface
    if (!priv->parent) {
        printk(KERN_ERR "%s: no such net: %s", THIS_MODULE->name, link);
        free_netdev(child);
        return -ENODEV;
    }
    if (priv->parent->type != ARPHRD_ETHER && priv->parent->type != ARPHRD_LOOPBACK) {
        printk(KERN_ERR "%s: illegal net type", THIS_MODULE->name);
        free_netdev(child);
        return -EINVAL;
    }

    //copy IP, MAC and other information
    memcpy(child->dev_addr, priv->parent->dev_addr, ETH_ALEN);
    memcpy(child->broadcast, priv->parent->broadcast, ETH_ALEN);
    if ((err = dev_alloc_name(child, child->name))) {
        printk(KERN_ERR "%s: allocate name, error %i", THIS_MODULE->name, err);
        free_netdev(child);
        return -EIO;
    }

    if ((proc_file = proc_create("var1", 0444, NULL, &proc_file_fops)) == NULL) {
        printk(KERN_ERR "could not initialize proc file\n");
        free_netdev(child);
        return -EIO;
    }

    register_netdev(child);
    rtnl_lock();
    netdev_rx_handler_register(priv->parent, &handle_frame, NULL);
    rtnl_unlock();
    printk(KERN_INFO "Module %s loaded", THIS_MODULE->name);
    printk(KERN_INFO "%s: create link %s", THIS_MODULE->name, child->name);
    printk(KERN_INFO "%s: registered rx handler for %s", THIS_MODULE->name, priv->parent->name);
    return 0;
}

void __exit vni_exit(void) {
    struct priv *priv = netdev_priv(child);
    if (priv->parent) {
        rtnl_lock();
        netdev_rx_handler_unregister(priv->parent);
        rtnl_unlock();
        printk(KERN_INFO "%s: unregister rx handler for %s", THIS_MODULE->name, priv->parent->name);
    }
    unregister_netdev(child);
    free_netdev(child);
    proc_remove(proc_file);
    printk(KERN_INFO "Module %s unloaded", THIS_MODULE->name);
}

module_init(vni_init);
module_exit(vni_exit);

MODULE_AUTHOR("Author");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Description");
