/**
 * @file test_port.c
 * @author your name (you@domain.com)
 * @brief
 * @version 0.1
 * @date 2023-01-18
 *
 * @copyright Copyright (c) 2023
 *
 */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <netinet/in.h>
#include <net/if.h>

#include <linux/ipv6.h>
#include <linux/tcp.h>
// #include <inttype.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define PACKET_LEN 500


void compute_tcp_checksum(struct ipv6hdr *pIph, unsigned short *ipPayload)
{
    register unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->payload_len);
    struct tcphdr *tcphdrp = (struct tcphdr *)(ipPayload);
    // add the pseudo header
    // the source ip
    uint8_t *src = (uint8_t *)(&pIph->saddr);
    uint8_t *dst = (uint8_t *)(&pIph->daddr);
    for(int i = 0; i < 16; i += 2)
    {
        sum += src[i] + (src[i + 1] << 8U);
    }

    for(int i = 0; i < 16; i += 2)
    {
        sum += dst[i] + (dst[i + 1] << 8U);
    }

    // protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    // the length
    sum += htons(tcpLen);

    // add the IP payload
    // initialize checksum to 0
    tcphdrp->check = 0;
    while(tcpLen > 1)
    {
        sum += *ipPayload++;
        tcpLen -= 2;
    }
    // if any bytes left, pad the bytes and add
    if(tcpLen > 0)
    {
        // printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload) & htons(0xFF00));
    }
    // Fold 32-bit sum to 16 bits: add carrier to result
    while(sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    // set computation result
    tcphdrp->check = (unsigned short)sum;
}

int main(int argc, char const *argv[])
{
    if(argc != 8 && argc != 9)
    {
        printf(" Usage:\n");
        printf(" %s <IF> <smac> <sip> <sport> <dmac> <dip> <dport>\n", argv[0]);
        printf(" %s <IF> <smac> <sip> <sport> <dmac> <dip> <dport> <vlan>\n", argv[0]);
        exit(1);
    }

    int sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    struct ifreq req;
    strncpy(req.ifr_name, argv[1], strlen(argv[1]));
    int32_t ret = ioctl(sd, SIOCGIFINDEX, &req);
    if(ret == -1)
    {
        printf("fail to get interface: %s\n", strerror(errno));
    }

    struct sockaddr_ll sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sll_family = AF_PACKET;
    sockaddr.sll_protocol = htons(ETH_P_ALL);
    sockaddr.sll_ifindex = req.ifr_ifindex; // 网卡eth0的index，非常重要，系统把数据往哪张网卡上发，就靠这个标识
    sockaddr.sll_pkttype = PACKET_OUTGOING; // 标识包的类型为发出去的包
    sockaddr.sll_halen = 6;                 // 目标MAC地址长度为6

    uint16_t vlan = 0;
    if(argc == 9)
    {
        vlan = atoi(argv[8]);
    }

    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    //uint32_t src_addr = inet_addr(argv[3]);
    inet_pton(AF_INET6, argv[3], (void *)&src_addr);
    uint16_t src_port = atoi(argv[4]);
    //uint32_t dst_addr = inet_addr(argv[6]);
    inet_pton(AF_INET6, argv[6], (void *)&dst_addr);
    uint16_t dst_port = atoi(argv[7]);

    uint8_t data[PACKET_LEN] = {0};
    uint8_t *buf = (uint8_t *)data;
    uint16_t pkt_len = 0;
    // dst mac
    sscanf(argv[5], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           buf,
           buf + 1,
           buf + 2,
           buf + 3,
           buf + 4,
           buf + 5);

    // src mac
    sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           buf + 6,
           buf + 7,
           buf + 8,
           buf + 9,
           buf + 10,
           buf + 11);
    buf += 12;
    pkt_len += 14;
    // vlan
    if(vlan)
    {
        *(uint16_t *)(buf) = htons(0x8100);
        buf += 2;

        *(uint16_t *)(buf) = htons(vlan);
        buf += 2;

        pkt_len += 4;
    }

    *(uint16_t *)(buf) = htons(0x86dd); // ipv6
    buf += 2;

    struct ipv6hdr *ip = (struct ipv6hdr *)buf;
    struct tcphdr *tcp = (struct tcphdr *)(buf + sizeof(struct ipv6hdr));

    // fabricate the UDP header
    tcp->source = htons(src_port);
    // destination port number
    tcp->dest = htons(dst_port);
    tcp->seq = 0x1111;
    tcp->ack_seq = 0;
    tcp->syn = 1;
    //tcp->rst = 1;
    // tcp->ack = 1;
    tcp->doff = 5;
    tcp->window = 0;

    ip->flow_lbl[0] = 0x66;
    ip->flow_lbl[1] = 0x77;
    ip->flow_lbl[2] = 0x88;
    ip->flow_lbl[3] = 0x99;
    ip->payload_len = htons(sizeof(struct tcphdr));
    ip->nexthdr = 6;
    ip->hop_limit = 64;     // hops

    ip->saddr = src_addr;
    ip->daddr = dst_addr;

    pkt_len += sizeof(struct ipv6hdr) + sizeof(struct tcphdr);

    compute_tcp_checksum(ip, (unsigned short *)tcp);

    uint8_t *t = (uint8_t *)(ip);
    *t = 0x60;
    int32_t len = sendto(sd, (void *)data, pkt_len, 0, (const struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if(len > 0)
    {
        printf("send data, len %d\n", len);
    }
    else
    {
        printf("fail to send data, %s\n", strerror(errno));
    }
err:
    close(sd);
    return 0;
}