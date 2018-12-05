/*
 * ca_core.c
 * Copyright (C) 2016 yubo@yubo.org
 * 2016-02-14
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <asm/paravirt.h>
#include <linux/netfilter.h>

#ifdef CONFIG_IP_VS_CA_IPV6
#include <net/ipv6.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ipv6.h>
#endif

#include "ca.h"


unsigned long **sys_call_table;
unsigned long original_cr0;
struct syscall_links sys;

static int
ca_use_count_inc(void) {
    return try_module_get(THIS_MODULE);
}

static void
ca_use_count_dec(void) {
    module_put(THIS_MODULE);
}


static void
ip_vs_ca_modify_uaddr(int fd, struct sockaddr *uaddr, int len, int dir) {
    int err, ret = 0;
    struct socket *sock = NULL;
    struct sockaddr_storage sin;
    union nf_inet_addr addr;
    struct ip_vs_ca_conn *cp;

    err = copy_from_user(&sin, (struct sockaddr_storage *)uaddr, len);

    if (err){
        ret = -2;
        goto out;
    }

#ifdef CONFIG_IP_VS_CA_IPV6
    if (sin.ss_family != AF_INET && sin.ss_family != AF_INET6) 
#else
    if (sin.ss_family != AF_INET) 
#endif
    {
        ret = -3;
        goto out;
    }

    sock = sockfd_lookup(fd, &err);
    if (!sock){
        ret = -4;
        goto out;
    }

#ifdef CONFIG_IP_VS_CA_IPV6
    if (sin.ss_family == AF_INET6)
        addr.in6 = IP_VS_CA_GET_IP_V6(sin);
    else
#endif
        addr.ip = IP_VS_CA_GET_IP(sin);

    if (sock->type == SOCK_STREAM){

#ifdef CONFIG_IP_VS_CA_IPV6
        if (sin.ss_family == AF_INET6)
            cp = ip_vs_ca_conn_get(sin.ss_family, IPPROTO_TCP, &addr,
                    IP_VS_CA_GET_PORT_V6(sin), dir);
        else
#endif
            cp = ip_vs_ca_conn_get(sin.ss_family, IPPROTO_TCP, &addr,
                    IP_VS_CA_GET_PORT(sin), dir);

    } else if (sock->type == SOCK_DGRAM) {

#ifdef CONFIG_IP_VS_CA_IPV6
        if (sin.ss_family == AF_INET6)
            cp = ip_vs_ca_conn_get(sin.ss_family, IPPROTO_UDP, &addr,
                    IP_VS_CA_GET_PORT_V6(sin), dir);
        else
#endif
            cp = ip_vs_ca_conn_get(sin.ss_family, IPPROTO_UDP, &addr,
                    IP_VS_CA_GET_PORT(sin), dir);

    } else {
        ret = -5;
        goto out;
    }

#ifdef CONFIG_IP_VS_CA_IPV6
    if (sin.ss_family == AF_INET6)
        IP_VS_CA_DBG("lookup type:%d %pI6 port:%d %s\n",
                    sock->type,
                    &addr.in6, ntohs(IP_VS_CA_GET_PORT_V6(sin)),
                    cp ? "hit" : "not hit");
    else
#endif
        IP_VS_CA_DBG("lookup type:%d %pI4:%d %s\n",
                    sock->type,
                    &addr.ip, ntohs(IP_VS_CA_GET_PORT(sin)),
                    cp ? "hit" : "not hit");

    if (!cp) {
        ret = -6;
        goto out;
    }

    if (dir == IP_VS_CA_IN) {

#ifdef CONFIG_IP_VS_CA_IPV6
        if (sin.ss_family == AF_INET6) {
            IP_VS_CA_GET_IP_V6(sin) = cp->c_addr.in6;
            IP_VS_CA_GET_PORT_V6(sin) = cp->c_port;
        } else
#endif

        {
            IP_VS_CA_GET_IP(sin) = cp->c_addr.ip;
            IP_VS_CA_GET_PORT(sin) = cp->c_port;
        }
    } else {

#ifdef CONFIG_IP_VS_CA_IPV6
        if (sin.ss_family == AF_INET6) {
            IP_VS_CA_GET_IP_V6(sin) = cp->s_addr.in6;
            IP_VS_CA_GET_PORT_V6(sin) = cp->s_port;
        } else
#endif

        {
            IP_VS_CA_GET_IP(sin) = cp->s_addr.ip;
            IP_VS_CA_GET_PORT(sin) = cp->s_port;
        }
    }

    ip_vs_ca_conn_put(cp);

    if(copy_to_user(uaddr, (struct sockaddr *)&sin, len)) {
        ret = -7;
        goto out;
    }

out:
    if (sock && sock->file)
        sockfd_put(sock);

    IP_VS_CA_DBG("ip_vs_ca_modify_uaddr err:%d\n", ret);

    return;
}

/*
 * ./net/socket.c:1624
 */
asmlinkage static long
getpeername(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)
{
    int ret, len;

    IP_VS_CA_DBG("getpeername called\n");

    if (!ca_use_count_inc())
        return -1;

    ret = sys.getpeername(fd, usockaddr, usockaddr_len);
    if (ret < 0)
        goto out;

    get_user(len, usockaddr_len);
    ip_vs_ca_modify_uaddr(fd, usockaddr, len, IP_VS_CA_IN);

out:
    ca_use_count_dec();
    return ret;
}

asmlinkage static long
accept4(int fd, struct sockaddr __user *upeer_sockaddr,
        int __user *upeer_addrlen, int flags)
{
    int ret, len;

    IP_VS_CA_DBG("accept4 called\n");

    if (!ca_use_count_inc())
        return -1;

    ret = sys.accept4(fd, upeer_sockaddr, upeer_addrlen, flags);
    if (ret < 0){
        goto out;
    }

    get_user(len, upeer_addrlen);
    ip_vs_ca_modify_uaddr(fd, upeer_sockaddr, len, IP_VS_CA_IN);

out:
    ca_use_count_dec();
    return ret;
}

asmlinkage static long
accept(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen)
{
    IP_VS_CA_DBG("accept called\n");
    return accept4(fd, upeer_sockaddr, upeer_addrlen, 0);
}

asmlinkage static long
recvfrom(int fd, void __user *ubuf, size_t size, unsigned flags,
                struct sockaddr __user *addr, int __user *addr_len)
{
    int ret, len;

    IP_VS_CA_DBG("recvfrom called\n");

    if (!ca_use_count_inc())
        return -1;

    if(addr == NULL || addr_len == NULL){
        ret =  sys.recvfrom(fd, ubuf, size, flags, addr, addr_len);
        goto out;
    }


    ret = sys.recvfrom(fd, ubuf, size, flags, addr, addr_len);
    if (ret < 0)
        goto out;

    get_user(len, addr_len);
    ip_vs_ca_modify_uaddr(fd, addr, len, IP_VS_CA_IN);

out:
    ca_use_count_dec();
    return ret;
}

asmlinkage static long
connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
    int ret;

    IP_VS_CA_DBG("connect called\n");

    if (!ca_use_count_inc())
        return -1;

    ip_vs_ca_modify_uaddr(fd, uservaddr, addrlen, IP_VS_CA_OUT);
    ret = sys.connect(fd, uservaddr, addrlen);

    ca_use_count_dec();
    return ret;
}

asmlinkage static long
sendto(int fd, void __user *buff, size_t len, unsigned int flags,
            struct sockaddr __user *addr, int addr_len)
{
    int ret;

    IP_VS_CA_DBG("sendto called\n");

    if (!ca_use_count_inc())
        return -1;

    ip_vs_ca_modify_uaddr(fd, addr, addr_len, IP_VS_CA_OUT);
    ret = sys.sendto(fd, buff, len, flags, addr, addr_len);

    ca_use_count_dec();
    return ret;
}

const char *ip_vs_ca_proto_name(unsigned proto)
{
    static char buf[20];

    switch (proto) {
        case IPPROTO_IP:
            return "IP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_ICMP:
            return "ICMP";
#ifdef CONFIG_IP_VS_CA_IPV6
        case IPPROTO_ICMPV6:
            return "ICMPv6";
#endif
        default:
            sprintf(buf, "IP_%d", proto);
            return buf;
    }
}

static int ip_vs_ca_syscall_init(void)
{
    if (!(sys_call_table = find_sys_call_table())){
        IP_VS_CA_ERR("get sys call table failed.\n");
        return -1;
    }

    original_cr0 = read_cr0();
    write_cr0(original_cr0 & ~0x00010000);
    IP_VS_CA_DBG("Loading ip_vs_ca module, sys call table at %p\n", sys_call_table);

    sys.getpeername = (void *)(sys_call_table[__NR_getpeername]);
    sys.accept4	= (void *)(sys_call_table[__NR_accept4]);
    sys.recvfrom	= (void *)(sys_call_table[__NR_recvfrom]);
    sys.connect	= (void *)(sys_call_table[__NR_connect]);
    sys.accept	= (void *)(sys_call_table[__NR_accept]);
    sys.sendto	= (void *)(sys_call_table[__NR_sendto]);

    sys_call_table[__NR_getpeername]= (void *)getpeername;
    sys_call_table[__NR_accept4]	= (void *)accept4;
    sys_call_table[__NR_recvfrom]	= (void *)recvfrom;
    sys_call_table[__NR_connect]	= (void *)connect;
    sys_call_table[__NR_accept]	= (void *)accept;
    sys_call_table[__NR_sendto]	= (void *)sendto;

    write_cr0(original_cr0);

    return 0;
}

static void ip_vs_ca_syscall_cleanup(void)
{
    if (!sys_call_table){
        return;
    }

    write_cr0(original_cr0 & ~0x00010000);

    sys_call_table[__NR_getpeername] = (void *)sys.getpeername;
    sys_call_table[__NR_accept4]     = (void *)sys.accept4;
    sys_call_table[__NR_recvfrom]    = (void *)sys.recvfrom;
    sys_call_table[__NR_connect]     = (void *)sys.connect;
    sys_call_table[__NR_accept]      = (void *)sys.accept;
    sys_call_table[__NR_sendto]      = (void *)sys.sendto;

    write_cr0(original_cr0);
    //msleep(100);
    sys_call_table = NULL;
}

static unsigned int _ip_vs_ca_in_hook(struct sk_buff *skb);
static unsigned int ip_vs_ca_in_icmp(struct sk_buff *skb, struct ip_vs_ca_iphdr iph);
static unsigned int ip_vs_ca_in_icmp_v6(struct sk_buff *skb, struct ip_vs_ca_iphdr iph);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static unsigned int
ip_vs_ca_in_hook(const struct nf_hook_ops *ops, struct sk_buff *skb,
            const struct net_device *in,
            const struct net_device *out,
            const void *ignore)
{
    return _ip_vs_ca_in_hook(skb);
}
#else
static unsigned int
ip_vs_ca_in_hook(unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn) (struct sk_buff *))
{
    return _ip_vs_ca_in_hook(skb);
}
#endif

static unsigned int
ip_vs_ca_in_icmp(struct sk_buff *skb, struct ip_vs_ca_iphdr iph) {
#ifndef IP_VS_CA_ICMP
    return NF_ACCEPT;
#else
    struct ip_vs_ca_conn *cp;
    struct ip_vs_ca_protocol *pp;
    struct iphdr *ih;
    struct icmphdr _icmph, *icmph;
    struct ipvs_ca _ca, *ca;

    IP_VS_CA_DBG("icmp packet recv\n");

    ih = (struct iphdr *)skb_network_header(skb);

    icmph = skb_header_pointer(skb, iph.len, sizeof(_icmph), &_icmph);

    if (icmph == NULL) {
        IP_VS_CA_DBG("icmphdr NULL\n");
        return NF_ACCEPT;
    }

    if (ntohs(ih->tot_len) == sizeof(*ih) + sizeof(*icmph) + sizeof(*ca)
            && icmph->type == ICMP_ECHO
            && icmph->code == 0
            && icmph->un.echo.id == 0x1234
            && icmph->un.echo.sequence == 0) {
        ca = skb_header_pointer(skb, iph.len + sizeof(*icmph), sizeof(_ca), &_ca);

        if (ca == NULL) {
            IP_VS_CA_DBG("ca NULL\n");
            return NF_ACCEPT;
        }

        if (ca->code != 123
                || ca->toa.opcode != tcpopt_addr
                || ca->toa.opsize != TCPOLEN_ADDR) {
            IP_VS_CA_DBG("ca not hit. {.code:%d, .protocol:%d,"
                    " .toa.opcode:%d, .toa.opsize:%d}\n",
                    ca->code, ca->protocol, ca->toa.opcode, ca->toa.opsize);
            return NF_ACCEPT;
        }

        pp = ip_vs_ca_proto_get(ca->protocol);
        if (unlikely(!pp))
            return NF_ACCEPT;

        cp = pp->conn_get(AF_INET, skb, pp, &iph, iph.len);
        if (unlikely(cp)) {
            ip_vs_ca_conn_put(cp);
            return NF_ACCEPT;
        } else {
            int v;
            if (pp->icmp_process(AF_INET, skb, pp, &iph, ca,
                        &v, &cp) == 0) {
                return v;
            } else {
                return NF_ACCEPT;
            }
        }
    } else {
        IP_VS_CA_DBG("icmphdr not hit tot_len:%d, "
                "icmp{.type:%d, .code:%d, .echo.id:0x%04x,"
                " .echo.sequence:%d},"
                "want tot_len:%lu icmp.type:%d\n",
                ntohs(ih->tot_len), icmph->type,
                icmph->code, icmph->un.echo.id,
                icmph->un.echo.sequence,
                sizeof(*ih)+sizeof(*icmph)+sizeof(*ca),
                ICMP_ECHO);
        return NF_ACCEPT;
    }
#endif
}

#ifdef CONFIG_IP_VS_CA_IPV6
static unsigned int
ip_vs_ca_in_icmp_v6(struct sk_buff *skb, struct ip_vs_ca_iphdr iph) {
#ifndef IP_VS_CA_ICMP
    return NF_ACCEPT;
#else
    struct ipv6hdr *ih;
    struct icmp6hdr _icmph, *icmph;
    struct ip_vs_ca_protocol *pp;
    struct ip_vs_ca_conn *cp;
    unsigned int offset;
    struct ipvs_ca_v6 _ca, *ca;

    IP_VS_CA_DBG("icmpv6 packet recv\n");

    ih = ipv6_hdr(skb);

    offset = sizeof(struct ipv6hdr);

    icmph = skb_header_pointer(skb, offset, sizeof(_icmph), &_icmph);

    if (icmph == NULL) {
        IP_VS_CA_DBG("icmpv6hdr NULL\n");
        return NF_ACCEPT;
    }

    if (ntohs(ih->payload_len) == sizeof(*icmph) + sizeof(*ca)
            && icmph->icmp6_type == ICMPV6_ECHO_REQUEST
            && icmph->icmp6_code == 0
            && ntohs(icmph->icmp6_dataun.u_echo.identifier) == 0x1234
            && ntohs(icmph->icmp6_dataun.u_echo.sequence) == 0) {
        offset += sizeof(_icmph);
        ca = skb_header_pointer(skb, offset, sizeof(_ca), &_ca);

        if (ca == NULL) {
            IP_VS_CA_DBG("ca6 data NULL\n");
            return NF_ACCEPT;
        }

        if (ca->code != 123
                || ca->toa.opcode != tcpopt_addr_v6
                || ca->toa.opsize != TCPOLEN_ADDR_V6) {
            IP_VS_CA_DBG("ca6 not hit. {.code:%d, .protocol:%d,"
                    " .toa.opcode:%d, .toa.opsize:%d}\n",
                    ca->code, ca->protocol, ca->toa.opcode, ca->toa.opsize);
            return NF_ACCEPT;
        }

        pp = ip_vs_ca_proto_get(ca->protocol);
        if (unlikely(!pp)) {
            return NF_ACCEPT;
        }

        cp = pp->conn_get(AF_INET6, skb, pp, &iph, iph.len);
        if (unlikely(cp)) {
            ip_vs_ca_conn_put(cp);
            return NF_ACCEPT;
        } else {
            int v;
            if (pp->icmp_process_v6(AF_INET6, skb, pp, &iph, ca, &v, &cp) == 0) {
                return v;
            } else {
                return NF_ACCEPT;
            }
        }
    } else {
        IP_VS_CA_DBG("icmp6hdr not hit payload_len:%d, "
                "icmp6{.type:%d, .code:%d .echo.id:0x%04x,"
                " .echo.sequence:%d},"
                "icmph6_len:%lu, ca_len:%lu, "
                "want tot_len:%lu icmp.type:%d\n",
                ntohs(ih->payload_len),
                icmph->icmp6_type, icmph->icmp6_code,
                ntohs(icmph->icmp6_dataun.u_echo.identifier),
                ntohs(icmph->icmp6_dataun.u_echo.sequence),
                sizeof(*icmph), sizeof(*ca),
                sizeof(*icmph)+sizeof(*ca),
                ICMPV6_ECHO_REQUEST);
        return NF_ACCEPT;
    }
#endif
}
#endif

static unsigned int _ip_vs_ca_in_hook(struct sk_buff *skb)
{
    struct ip_vs_ca_iphdr iph;
    struct ip_vs_ca_conn *cp;
    struct ip_vs_ca_protocol *pp;
    int af;

    //EnterFunction();

    af = (skb->protocol == htons(ETH_P_IP)) ? AF_INET : AF_INET6;

    if (af != AF_INET && af != AF_INET6) {
        goto out;
    }

    ip_vs_ca_fill_iphdr(af, skb_network_header(skb), &iph);

    /*
     *      Big tappo: only PACKET_HOST, including loopback for local client
     *      Don't handle local packets on IPv6 for now
     */
    if (unlikely(skb->pkt_type != PACKET_HOST)) {
        /*
        IP_VS_CA_DBG("packet type=%d proto=%d daddr=%pI4 ignored\n",
                skb->pkt_type,
                iph.protocol, &iph.daddr.ip);
        */
        goto out;
    }

#ifdef CONFIG_IP_VS_CA_IPV6
    //if (af == AF_INET6) {
    if (iph.protocol == IPPROTO_ICMPV6) {
        int v;
        v = ip_vs_ca_in_icmp_v6(skb, iph);
        IP_VS_CA_DBG("icmp_v6 return v:%d af:%d, protocol:%d\n",
                v, af, iph.protocol);
        if (v == NF_ACCEPT)
            goto out;
        else
            return v;
    }
    //}
#endif
    if (iph.protocol == IPPROTO_ICMP) {
        int v;
        v = ip_vs_ca_in_icmp(skb, iph);
        IP_VS_CA_DBG("icmp return v:%d af:%d, protocol:%d\n",
                v, af, iph.protocol);
        if (v == NF_ACCEPT)
            goto out;
        else
            return v;
    }

    if (iph.protocol == IPPROTO_TCP) {
        /* Protocol supported? */
        pp = ip_vs_ca_proto_get(iph.protocol);
        if (unlikely(!pp)) {
            goto out;
        }

        /*
         * Check if the packet belongs to an existing connection entry
         */
        cp = pp->conn_get(af, skb, pp, &iph, iph.len);
        if (likely(cp)) {
            ip_vs_ca_conn_put(cp);
            goto out;
        } else {
            int v;
            /* create a new connection */
            if(pp->skb_process(af, skb, pp, &iph, &v, &cp) == 0) {
                //LeaveFunction();
                return v;
            } else {
                goto out;
            }
        }
    }

out:
    //LeaveFunction();
    return NF_ACCEPT;
}

static struct nf_hook_ops ip_vs_ca_ops[] __read_mostly = {
    {
        .hook     = (nf_hookfn *)ip_vs_ca_in_hook,
    #if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
        .owner    = THIS_MODULE,
    #endif
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_CONNTRACK_CONFIRM,
    },
#ifdef CONFIG_IP_VS_CA_IPV6
    {
        .hook     = (nf_hookfn *)ip_vs_ca_in_hook,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
        .owner    = THIS_MODULE,
#endif
        .pf       = NFPROTO_IPV6,
        .hooknum  = NF_INET_LOCAL_IN,
        .priority = NF_IP6_PRI_LAST,
    },
#endif
};

static int __init ip_vs_ca_init(void)
{
        int ret;

        ip_vs_ca_protocol_init();
        IP_VS_CA_DBG("ip_vs_ca_protocol_init done.\n");

        ret = ip_vs_ca_control_init();
        if (ret < 0){
                IP_VS_CA_ERR("can't modify syscall table.\n");
                goto out_err;
        }
        IP_VS_CA_DBG("ip_vs_ca_control_init done.\n");

        ret = ip_vs_ca_conn_init();
        if (ret < 0){
                IP_VS_CA_ERR("can't setup connection table.\n");
                goto cleanup_control;
        }
        IP_VS_CA_DBG("ip_vs_ca_conn_init done.\n");

        ret = nf_register_hooks(ip_vs_ca_ops, ARRAY_SIZE(ip_vs_ca_ops));
        if (ret < 0){
                IP_VS_CA_ERR("can't register hooks.\n");
                goto cleanup_conn;
        }
        IP_VS_CA_DBG("nf_register_hooks done.\n");

        ret = ip_vs_ca_syscall_init();
        if (ret < 0){
                IP_VS_CA_ERR("can't modify syscall table.\n");
                goto cleanup_nf_hooks;
        }
        IP_VS_CA_DBG("modify syscall table done.\n");

        IP_VS_CA_INFO("ip_vs_ca loaded.");
        return ret;

cleanup_nf_hooks:
        nf_unregister_hooks(ip_vs_ca_ops, ARRAY_SIZE(ip_vs_ca_ops));
cleanup_conn:
        ip_vs_ca_conn_cleanup();
cleanup_control:
        ip_vs_ca_control_cleanup();
out_err:
        return ret;
}

static void __exit ip_vs_ca_exit(void)
{
    nf_unregister_hooks(ip_vs_ca_ops, ARRAY_SIZE(ip_vs_ca_ops));
    ip_vs_ca_conn_cleanup();
    ip_vs_ca_protocol_cleanup();
    ip_vs_ca_control_cleanup();
    ip_vs_ca_syscall_cleanup();
    IP_VS_CA_INFO("ip_vs_ca unloaded.");
}

module_init(ip_vs_ca_init);
module_exit(ip_vs_ca_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yu Bo<yubo@yubo.org>");

