#pragma once

#include <stdint.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <net/if.h>

typedef enum {
    TCP_CLOSED,
    TCP_RESERVED,
    TCP_SYNSENT,
    TCP_ESTAB,

    TCP_STATUS_NUM
} TcpStatus;

struct _tcp_send_param {
    uint16_t mss;
    uint32_t initial_seq_no;
    uint32_t current_seq_no;
    uint32_t next_seq_no;
    uint32_t unacked_seq_no;
};

struct _tcp_recv_param {
    uint32_t initial_seq_no;
    uint32_t next_seq_no;
};

struct TcpSocket {
    struct IpSocket *ip_soc;
    uint16_t local_port;
    uint16_t remote_port;
    struct _tcp_send_param send_param;
    struct _tcp_recv_param recv_param;
    TcpStatus status;
    time_t ts;
    pthread_mutex_t mutex;
};

#define MAX_TCP_CONNECTIONS 100
struct TcpManager {
    struct TcpSocket sockets[MAX_TCP_CONNECTIONS];
    pthread_mutex_t mutex;
    pthread_t recv_thread_id;
    int ll_soc;
    int term;
    char device[IF_NAMESIZE];
};

extern struct TcpManager tcp_manager;

int tcp_manager_init(char *device);
void tcp_manager_fin();
struct TcpSocket *new_tcp_socket(char *local_addr, uint16_t local_port);
int close_tcp_socket(struct TcpSocket *tcp);
int send_tcp_packet_one(struct TcpSocket *tcp, char *payload, size_t payload_len, char *option, size_t option_len, uint16_t window, uint8_t flag);
int tcp_send(struct TcpSocket *tcp, char *payload, size_t payload_len);
int tcp_connect(struct TcpSocket *tcp, char *remote_addr, uint16_t remote_port);
int analyze_tcp_packet(char *packet, int size, struct tcphdr *tcphdr, char *option, size_t max_option_len, char *payload, size_t max_payload_len);
int is_destination_app(struct iphdr *iphdr, struct tcphdr *tcphdr, struct TcpSocket *tcp);
void *tcp_recv_thread(void *);
int tcp_synsent_recv_handler(struct TcpSocket *tcp, struct tcphdr *tcphdr, char *payload, size_t payload_size);
int tcp_estab_recv_handler(struct TcpSocket *tcp, struct tcphdr *tcphdr, char *payload, size_t payload_size);

#define MAX_SEGMENT_SIZE 1460
#define NOFLAG 0x00
#define CWR 0x01
#define ECE 0x02
#define URG 0x04
#define ACK 0x08
#define PSH 0x10
#define RST 0x20
#define SYN 0x40
#define FIN 0x80
