#pragma once

#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>

struct IpSocket {
    int soc;
    uint16_t frag_id;
    struct in_addr local_addr;
    struct in_addr remote_addr;
};

struct pseudoIpHeader {
    struct in_addr source;
    struct in_addr dest;
    uint8_t zero;
    uint8_t protocol;
    uint16_t length;
};

struct IpSocket *new_ip_socket(char *addr);
int close_ip_socket(struct IpSocket *ip);
int send_icmp_echo(struct IpSocket *ip);
int analyze_icmp_packet(char *packet, size_t size);
int send_ip_packet_one(struct IpSocket *ip, char *payload, size_t payload_len, char *option, size_t option_len, uint16_t frag_id, uint16_t frag_offset);
int send_ip_packet(struct IpSocket *ip, char *payload, size_t payload_len, int dont_frag);
int is_correct_tcp_checksum(struct iphdr iphdr, char *payload, size_t payload_len);
int analyze_ip_packet(char *packet, size_t size, struct iphdr *iphdr, char *option, size_t max_option_len, char *payload, size_t max_payload_len);
int send_icmp_request(struct IpSocket *ip);

#define MAX_PACKET_SIZE 1500
#define MAX_IP_PACKET_SIZE 1480
