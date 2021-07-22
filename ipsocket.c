#include "utils.h"
#include "ipsocket.h"
#include "tcpsocket.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

struct IpSocket *new_ip_socket(char *addr) {
    struct IpSocket *ip_soc;
    int soc;
    struct sockaddr_in sa;

    soc = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (soc < 0) {
        perror("socket failed");
        return NULL;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, addr, &sa.sin_addr.s_addr) < 0) {
        perror("inet_pton failed");
        close(soc);
        return NULL;
    }

    if (bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind failed");
        close(soc);
        return NULL;
    }

    ip_soc = (struct IpSocket *)malloc(sizeof(struct IpSocket));
    if (ip_soc == NULL) {
        perror("malloc");
        close(soc);
        return NULL;
    }

    ip_soc->soc = soc;
    ip_soc->frag_id = 0;
    if (inet_pton(AF_INET, addr, &ip_soc->local_addr.s_addr) < 0) {
        perror("inet_pton failed");
        close(soc);
        return NULL;
    }

    return ip_soc;
}

int close_ip_socket(struct IpSocket *ip) {
    close(ip->soc);
    free(ip);
    return 0;
}

int send_icmp_request(struct IpSocket *ip) {
    char packet[MAX_PACKET_SIZE];
    char *ptr;
    struct icmphdr *icmphdr;
    struct iphdr *iphdr;
    struct sockaddr_in sa;
    int psize;
    char dst[256];

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = ip->remote_addr.s_addr;

    memset(packet, 0, sizeof(packet));

    ptr = packet;

    iphdr = (struct iphdr *)ptr;
    ptr += sizeof(struct iphdr);

    //*
    iphdr->version = 4;
    iphdr->ihl = sizeof(struct iphdr)/4;
    iphdr->tos = 0;
    iphdr->tot_len = htons(sizeof(struct iphdr));//htons(sizeof(struct iphdr)+sizeof(struct icmphdr));
    iphdr->id = 12345;
    iphdr->frag_off = 0;
    iphdr->ttl = 64;
    iphdr->protocol = IPPROTO_ICMP;
    iphdr->saddr = ip->local_addr.s_addr;
    //inet_pton(AF_INET, "172.16.0.1", &iphdr->saddr);
    inet_pton(AF_INET, "172.16.0.2", &ip->remote_addr.s_addr);
    iphdr->daddr = ip->remote_addr.s_addr;
    //inet_pton(AF_INET, "172.16.0.2", &iphdr->daddr);
    iphdr->check = 0;
    iphdr->check = checksum((u_char *)iphdr, sizeof(struct iphdr));
    printf("%p\n", &ip->local_addr.s_addr);
    printf("%p\n", &ip->remote_addr.s_addr);
    puts(inet_ntop(AF_INET, &ip->local_addr.s_addr, dst, 256));
    puts(inet_ntop(AF_INET, &ip->remote_addr.s_addr, dst, 256));
    //*/

    icmphdr = (struct icmphdr *)ptr;
    ptr += sizeof(icmphdr);

    icmphdr->type = ICMP_ECHO;
    icmphdr->code = 0;
    icmphdr->un.echo.id = 0;//htons((unsigned short)getpid());
    icmphdr->un.echo.sequence = 0;//htons(0);
    icmphdr->checksum = 0;
    icmphdr->checksum = checksum((u_char *)icmphdr, sizeof(struct icmphdr));

    //psize = write(tcp_manager.ll_soc, packet, sizeof(struct iphdr) + 64);
    //psize = sendto(soc, packet, sizeof(struct iphdr)+sizeof(struct icmphdr), 0, (struct sockaddr *)&sa, sizeof(sa));
    psize = sendto(ip->soc, packet, sizeof(struct iphdr), 0, (struct sockaddr *)&sa, sizeof(sa));
    //psize = write(soc, packet, sizeof(struct iphdr));
    printf("%lu %lu\n", sizeof(struct sockaddr), sizeof(sa));
    //psize = write(soc, packet, 64);
    printf("ICMP %d %d\n", psize, errno);
    /*
    for (int i = 0; i < sizeof(struct iphdr)+64; i++) {
        printf("%02X ", packet[i]&0xFF);
        if (i%4 == 3) puts("");
    }
    puts("");
    //*/
    return psize;
}

int send_icmp_echo(struct IpSocket *ip) {
    char packet[MAX_PACKET_SIZE];
    struct icmphdr *icmphdr;
    char *ptr;
    int psize;
    
    ptr = packet;

    icmphdr = (struct icmphdr *)ptr;
    ptr += sizeof(icmphdr);

    icmphdr->type = ICMP_ECHO;
    icmphdr->code = 0;
    icmphdr->un.echo.id = htons((unsigned short)getpid());
    icmphdr->un.echo.sequence = 0;
    icmphdr->checksum = 0;
    icmphdr->checksum = checksum((u_char *)icmphdr, sizeof(struct icmphdr));

    inet_pton(AF_INET, "172.16.0.2", &ip->remote_addr.s_addr);
    psize = send_ip_packet(ip, packet, sizeof(struct icmphdr), 0);

    printf("ICMP ECHO: Size: %d, Error: %d\n", psize, errno);
    hexdump(packet, sizeof(struct icmphdr));

    return psize;
}

int analyze_icmp_packet(char *packet, size_t size) {
    struct icmphdr *icmphdr;
    int cs;
    
    icmphdr = (struct icmphdr *)packet;

    cs = checksum((u_char *)icmphdr, sizeof(struct icmphdr));
    if (cs) {
        printf("Invalid ICMP Checksum: %d %d\n", icmphdr->checksum, cs);
        return 0;
    }

    if (icmphdr->type == ICMP_ECHOREPLY) {
        printf("ICMP REPLY: %d", ntohs(icmphdr->un.echo.id));
        hexdump(packet, size);
    } else {
        puts("ICMP unknown");
    }
    

    return 0;
}

int send_ip_packet_one(struct IpSocket *ip, char *payload, size_t payload_len, char *option, size_t option_len, uint16_t frag_id, uint16_t frag_offset) {
    //char packet[MAX_PACKET_SIZE];
    char *packet;
    char *ptr;
    struct iphdr *iphdr;
    struct sockaddr_in sa;
    size_t total_size = sizeof(struct iphdr) + option_len + payload_len;
    int sent_size;
    struct tcphdr *tcphdr;

    //printf("%lu %lu %lu\n", sizeof(struct iphdr), option_len, payload_len);

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = ip->remote_addr.s_addr;

    if (MAX_PACKET_SIZE < total_size) {
        perror("packet is too large");
        return -1;
    }

    if (option && (option_len&3)) {
        perror("option length must be multiple of 4");
        return -1;
    }

    //memset(packet, 0, sizeof(packet));
    packet = (char *)malloc(total_size);
    ptr = packet;

    iphdr = (struct iphdr *)ptr;
    ptr += sizeof(struct iphdr);

    iphdr->version = 4;
    iphdr->ihl = sizeof(struct iphdr)/4 + option_len/4;
    iphdr->tos = 0;
    iphdr->tot_len = htons(total_size);
    iphdr->id = htons(frag_id);
    iphdr->frag_off = htons(frag_offset);
    iphdr->ttl = 64;
    iphdr->protocol = IPPROTO_TCP;
    iphdr->check = 0;
    iphdr->saddr = ip->local_addr.s_addr;
    iphdr->daddr = ip->remote_addr.s_addr;

    iphdr->check = checksum2((u_char *)&iphdr, sizeof(struct iphdr), (u_char *)option, option_len);
    
    if (option && option_len > 0) {
        memcpy(ptr, option, option_len);
        ptr += option_len;
    }
    if (payload && payload_len > 0) {
        memcpy(ptr, payload, payload_len);
        tcphdr = (struct tcphdr *)ptr;
        printf("AAAAAAAAAAAA %u\n", htonl(tcphdr->ack_seq));
        ptr += payload_len;
    }

    //hexdump(packet, total_size);

    //int status = write(ip->soc, packet, size);
    sent_size = sendto(ip->soc, packet, total_size, 0, (struct sockaddr *)&sa, sizeof(sa));
    hexdump(packet, total_size);
    
    //printf("Write: %d %d %lu\n", sent_size, (int)errno, total_size);

    free(packet);

    return sent_size;//write(ip->soc, packet, size);
}

int send_ip_packet(struct IpSocket *ip, char *payload, size_t payload_len, int dont_frag) {
    int flags;
    int len;
    int size = 0;
    int size_one;
    int offset = 0;
    char *ptr = payload;

    dont_frag &= 1;

    if (dont_frag && MAX_IP_PACKET_SIZE < payload_len) {
        perror("packet is not fragmentable");
        return -1;
    }

    while (offset < payload_len) {
        len = payload_len - offset;
        if (MAX_IP_PACKET_SIZE < len) {
            len = MAX_IP_PACKET_SIZE;
        }
        flags = (dont_frag<<1) | (offset+len == payload_len ? 0 : 4);
        size_one = send_ip_packet_one(ip, ptr, len, NULL, 0, ip->frag_id, ((offset)&0xFFF) | flags<<13);
        if (size_one < 0) {
            break;
        }
        size += size_one;
        offset += len;
        ptr += len;
    }

    ip->frag_id++;

    return size;
}

int is_correct_tcp_checksum(struct iphdr iphdr, char *payload, size_t payload_len) {
    struct pseudoIpHeader piphdr;
    uint16_t cs;

    memset(&piphdr, 0, sizeof(piphdr));

    piphdr.source.s_addr = iphdr.saddr;
    piphdr.dest.s_addr = iphdr.daddr;
    piphdr.zero = 0;
    piphdr.protocol = IPPROTO_TCP;
    piphdr.length = htons(payload_len);

    cs = checksum2((u_char *)&piphdr, sizeof(piphdr), (u_char *)payload, payload_len);

    //printf("TCP checksum: %u\n", cs);

    return cs == 0;
}

int analyze_ip_packet(char *packet, size_t size, struct iphdr *iphdr, char *option, size_t max_option_len, char *payload, size_t max_payload_len) {
    char *ptr;
    int lest;
    size_t option_len;

    if (size < sizeof(struct iphdr)) {
        perror("invalid ip header: length is too small");
        return -1;
    }
    
    ptr = packet;
    lest = size;

    memcpy(iphdr, ptr, sizeof(struct iphdr));
    ptr += sizeof(struct iphdr);
    lest -= sizeof(struct iphdr);

    option_len = iphdr->ihl*4 - sizeof(struct iphdr);
    if (option_len > 0) {
        if (option_len > lest) {
            perror("invalid ip header: option is too large");
            return -1;
        }
        if (option) {
            memcpy(option, ptr, min(option_len, max_option_len));
        }
        ptr += option_len;
        lest -= option_len;
    }

    if (checksum((u_char *)packet, sizeof(struct iphdr)+option_len) != 0) {
        perror("incorrect ip checksum");
        return -1;
    }

    if (max_payload_len < lest) {
        lest = max_payload_len;
    }

    memcpy(payload, ptr, lest);

    return lest;
}
