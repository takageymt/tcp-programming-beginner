#include "utils.h"
#include "ipsocket.h"
#include "tcpsocket.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>

struct TcpManager tcp_manager;

int tcp_manager_init(char *device) {
    int status;
    int i;

    tcp_manager.term = 0;

    tcp_manager.ll_soc = new_ll_socket(device);
    if (tcp_manager.ll_soc < 0) {
        perror("new_ll_socket failed");
        return -1;
    }

    pthread_mutex_init(&tcp_manager.mutex, NULL);

    for (i = 0; i < MAX_TCP_CONNECTIONS; i++) {
        memset(&tcp_manager.sockets[i], 0, sizeof(struct TcpSocket));
        pthread_mutex_init(&tcp_manager.sockets[i].mutex, NULL);
        tcp_manager.sockets[i].status = TCP_CLOSED;
    }

    status = pthread_create(&tcp_manager.recv_thread_id, NULL, tcp_recv_thread, NULL);
    if (status != 0) {
        perror("pthread_create failed");
        return -1;
    }
    return 0;
}

void tcp_manager_fin() {
    tcp_manager.term = 1;
}

struct TcpSocket *new_tcp_socket(char *local_addr, uint16_t local_port) {
    struct TcpSocket *res_soc = NULL;
    int i;

    pthread_mutex_lock(&tcp_manager.mutex);
    for (i = 0; i < MAX_TCP_CONNECTIONS && !res_soc; i++) {
        pthread_mutex_lock(&tcp_manager.sockets[i].mutex);
        if (tcp_manager.sockets[i].status == TCP_CLOSED) {
            res_soc = &tcp_manager.sockets[i];
            res_soc->status = TCP_RESERVED;
            res_soc->local_port = htons(local_port);
            res_soc->ip_soc = new_ip_socket(local_addr);
            if (!res_soc->ip_soc) {
                close_tcp_socket(res_soc);
                res_soc = NULL;
            }
        }
        pthread_mutex_unlock(&tcp_manager.sockets[i].mutex);
    }
    pthread_mutex_unlock(&tcp_manager.mutex);

    if (i == MAX_TCP_CONNECTIONS) {
        perror("no available socket exists");
        return NULL;
    }
    return res_soc;
}

int close_tcp_socket(struct TcpSocket *tcp) {
    send_tcp_packet_one(tcp, NULL, 0, NULL, 0, 500, FIN);
    pthread_mutex_lock(&tcp->mutex);
    close_ip_socket(tcp->ip_soc);
    memset(tcp, 0, sizeof(struct TcpSocket));
    tcp->status = TCP_CLOSED;
    pthread_mutex_unlock(&tcp->mutex);
    return 0;
}

int send_tcp_packet_one(struct TcpSocket *tcp, char *payload, size_t payload_len, char *option, size_t option_len, uint16_t window, uint8_t flag) {
    char *packet;
    char *ptr;
    struct tcphdr *tcphdr;
    struct pseudoIpHeader piphdr;
    size_t size = sizeof(struct tcphdr) + option_len + payload_len;

    if (option && (option_len&3)) {
        perror("option length must be multiple of 4");
        return -1;
    }

    packet = (char *)malloc(size);
    ptr = packet;

    tcphdr = (struct tcphdr *)ptr;
    ptr += sizeof(struct tcphdr);

    memset(&piphdr, 0, sizeof(piphdr));
    piphdr.source.s_addr = tcp->ip_soc->local_addr.s_addr;
    piphdr.dest.s_addr = tcp->ip_soc->remote_addr.s_addr;
    piphdr.zero = 0;
    piphdr.protocol = IPPROTO_TCP;
    piphdr.length = htons(size);

    memset(tcphdr, 0, sizeof(struct tcphdr));
    tcphdr->source = tcp->local_port;
    tcphdr->dest = tcp->remote_port;
    tcphdr->seq = htonl(tcp->send_param.current_seq_no);
    printf("tcphdr->seq=%u %u\n", tcp->send_param.current_seq_no, ntohl(tcphdr->seq));
    tcphdr->ack_seq = htonl(tcp->recv_param.next_seq_no);
    printf("tcphdr->ack_seq=%u %u\n", tcp->recv_param.next_seq_no, ntohl(tcphdr->ack_seq));
    tcphdr->doff = 20/4 + option_len/4;
    tcphdr->syn = flag&SYN ? 1 : 0;
    tcphdr->ack = flag&ACK ? 1 : 0;
    tcphdr->fin = flag&FIN ? 1 : 0;
    tcphdr->psh = flag&PSH ? 1 : 0;
    tcphdr->check = 0;
    tcphdr->window = htons(window);
    //printf("%d %d %d\n", tcphdr->syn, tcphdr->ack, tcphdr->fin);
    
    if (option && option_len > 0) {
        memcpy(ptr, option, option_len);   
        ptr += option_len;
    }
    if (payload && payload_len > 0) {
        memcpy(ptr, payload, payload_len);
        ptr += payload_len;
    }

    tcphdr->check = checksum2((u_char *)&piphdr, sizeof(piphdr), (u_char *)packet, size);
    printf("tcphdr->ack_seq=%u %u\n", tcp->recv_param.next_seq_no, ntohl(tcphdr->ack_seq));

    size = send_ip_packet(tcp->ip_soc, packet, size, 1);
    printf("tcphdr->ack_seq=%u %u\n", tcp->recv_param.next_seq_no, ntohl(tcphdr->ack_seq));

    free(packet);

    return size;
}

int tcp_send(struct TcpSocket *tcp, char *payload, size_t payload_len) {
    int size = 0;
    int size_one;
    int offset = 0;
    int len;
    int sent;
    char *ptr = payload;

    if (!payload || payload_len <= 0) {
        return 0;
    }

    while (offset < payload_len) {
        puts("SEND");
        pthread_mutex_lock(&tcp->mutex);
        len = min(tcp->send_param.mss, payload_len - offset);
        tcp->send_param.current_seq_no = tcp->send_param.next_seq_no;
        sent = 0;
        size_one = 0;
        while (!sent || tcp->send_param.unacked_seq_no < tcp->send_param.next_seq_no) {
            printf(" send %d %d %d %d\n", tcp->send_param.unacked_seq_no, tcp->send_param.next_seq_no, tcp->send_param.current_seq_no, len);
            puts(ptr);
            size_one = send_tcp_packet_one(tcp, ptr, len, NULL, 0, 500, PSH | ACK);
            if (size_one < 0) {
                pthread_mutex_unlock(&tcp->mutex);
                break;
            }
            sent = 1;
            tcp->send_param.next_seq_no = tcp->send_param.current_seq_no + len;
            pthread_mutex_unlock(&tcp->mutex);
            sleep(5);
            pthread_mutex_lock(&tcp->mutex);
        }
        if (size_one < 0) {
            break;
        }
        pthread_mutex_unlock(&tcp->mutex);
        size += len;
        ptr += len;
        offset += len;
    }

    return size;
}

int tcp_connect(struct TcpSocket *tcp, char *remote_addr, uint16_t remote_port) {
    uint32_t init_seq;
    int size = 0;
    struct {
        uint8_t kind;
        uint8_t length;
        uint16_t mss;
    } option = {2, 4, MAX_SEGMENT_SIZE};

    if (tcp->status != TCP_RESERVED) {
        perror("socket has been used or already closed");
        return 1;
    }

    pthread_mutex_lock(&tcp->mutex);
    puts(remote_addr);
    inet_pton(AF_INET, remote_addr, &tcp->ip_soc->remote_addr.s_addr);
    tcp->remote_port = htons(remote_port);
    //init_seq = 0;//rand() & 0xFFFFFFFF;
    init_seq = 100;//rand() & 0xFFFFFFFF;
    printf("INITIAL %d\n", init_seq);
    tcp->send_param.unacked_seq_no = init_seq;
    tcp->send_param.initial_seq_no = init_seq;
    tcp->send_param.current_seq_no = init_seq;
    tcp->send_param.mss = MAX_SEGMENT_SIZE;
    tcp->status = TCP_SYNSENT;
    pthread_mutex_unlock(&tcp->mutex);
    
    while (!tcp_manager.term) {
        pthread_mutex_lock(&tcp->mutex);
        puts("CONNECT");
        if (tcp->status != TCP_SYNSENT) {
            pthread_mutex_unlock(&tcp->mutex);
            break;
        }
        //size = send_tcp_packet_one(tcp, NULL, 0, (char *)&option, sizeof(option), 500, SYN);
        size = send_tcp_packet_one(tcp, NULL, 0, NULL, 0, 500, SYN);
        tcp->send_param.next_seq_no = tcp->send_param.current_seq_no + 1;
        tcp->send_param.unacked_seq_no = tcp->send_param.current_seq_no;
        pthread_mutex_unlock(&tcp->mutex);
        if (size < 0) {
            break;
        }
        sleep(1);
    }
    puts("CONNECT OUT");

    return size;
}

int analyze_tcp_packet(char *packet, int size, struct tcphdr *tcphdr, char *option, size_t max_option_len, char *payload, size_t max_payload_len) {
    char *ptr;
    int lest;
    int option_len;

    if (size < sizeof(struct tcphdr)) {
        perror("invalid tcp header: length is too small");
        return -1;
    }

    ptr = packet;
    lest = size;

    memcpy(tcphdr, ptr, sizeof(struct tcphdr));
    ptr += sizeof(struct tcphdr);
    lest -= sizeof(struct tcphdr);

    option_len = tcphdr->doff - sizeof(struct tcphdr);
    if (option_len > 0) {
        if (option_len > lest) {
            perror("invalid option length: too large");
            return -1;
        }
        if (option) {
            memcpy(option, ptr, min(option_len, max_option_len));
        }
        ptr += option_len;
        lest -= option_len;
    }

    if (max_payload_len < lest) {
        lest = max_payload_len;
    }

    memcpy(payload, ptr, lest);

    return lest;
}

int is_destination_app(struct iphdr *iphdr, struct tcphdr *tcphdr, struct TcpSocket *tcp) {
    char dst[256];
    puts(inet_ntop(AF_INET, &iphdr->saddr, dst, sizeof(dst)));
    puts(inet_ntop(AF_INET, &iphdr->daddr, dst, sizeof(dst)));
    puts(inet_ntop(AF_INET, &tcp->ip_soc->remote_addr.s_addr, dst, sizeof(dst)));
    puts(inet_ntop(AF_INET, &tcp->ip_soc->local_addr.s_addr, dst, sizeof(dst)));
    printf("%d %d %d %d\n", ntohs(tcphdr->source), ntohs(tcphdr->dest), ntohs(tcp->remote_port), ntohs(tcp->local_port));
    if (iphdr->saddr != tcp->ip_soc->remote_addr.s_addr) return 0;
    if (iphdr->daddr != tcp->ip_soc->local_addr.s_addr) return 0;
    if (tcphdr->source != tcp->remote_port) return 0;
    if (tcphdr->dest != tcp->local_port) return 0;
    return 1;
}

void *tcp_recv_thread(void *arg) {
    char buf[MAX_PACKET_SIZE];
    char payload[MAX_PACKET_SIZE];
    int ip_size;
    int read_size;
    struct iphdr iphdr;
    struct tcphdr tcphdr;
    struct TcpSocket *tcp;
    //struct sockaddr_in from;
    //socklen_t from_len;
    int i;
    //char dst[256];

    while (!tcp_manager.term) {
        puts("READ");
        read_size = read(tcp_manager.ll_soc, buf, sizeof(buf));
        //read_size = recvfrom(tcp_manager.ll_soc, buf, sizeof(buf), 0, &from, &from_len);
        if (read_size < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                puts("AGAIN");
                sleep(1);
                continue;
            }
            perror("socket is not available");
            break;
        }

        //hexdump(buf, read_size);

        ip_size  = analyze_ip_packet(buf, read_size, &iphdr, NULL, 0, payload, MAX_IP_PACKET_SIZE);
        //hexdump(payload, ip_size);
        if (ip_size < 0) {
            perror("read error");
            continue;
        }
        if (iphdr.protocol == IPPROTO_ICMP) {
            puts("RECV ICMP");
            analyze_icmp_packet(payload, ip_size);
            continue;
        }
        if (iphdr.protocol != IPPROTO_TCP) {
            perror("not tcp");
            continue;
        }
        if (!is_correct_tcp_checksum(iphdr, payload, ip_size)) {
            perror("incorrect tcp checksum");
            continue;
        }
        memcpy(buf, payload, ip_size);
        read_size = analyze_tcp_packet(buf, ip_size, &tcphdr, NULL, 0, payload, MAX_SEGMENT_SIZE);
        /*
        printf("tcphdr check %u\n", tcphdr.check);
        piphdr.source.s_addr = iphdr.saddr;
        piphdr.dest.s_addr = iphdr.daddr;
        piphdr.zero = 0;
        piphdr.protocol = IPPROTO_TCP;
        piphdr.length = htons(ip_size);
        ((struct tcphdr *)buf)->check = 0;
        printf("calc 2 %u\n", checksum2((u_char *)&piphdr, sizeof(piphdr), (u_char *)buf, ip_size));
        puts(inet_ntop(AF_INET, &iphdr.saddr, dst, sizeof(dst)));
        puts(inet_ntop(AF_INET, &iphdr.daddr, dst, sizeof(dst)));
        printf("PORTS: %d %d\n", ntohs(tcphdr.source), ntohs(tcphdr.dest));
        */
        tcp = NULL;
        for (i = 0; i < MAX_TCP_CONNECTIONS; i++) {
            tcp = &tcp_manager.sockets[i];
            pthread_mutex_lock(&tcp->mutex);
            if (tcp->status == TCP_SYNSENT || tcp->status == TCP_ESTAB) {
                if (is_destination_app(&iphdr, &tcphdr, &tcp_manager.sockets[i])) {
                    perror("Found");
                    pthread_mutex_unlock(&tcp->mutex);
                    break;
                }
            }
            pthread_mutex_unlock(&tcp->mutex);
        }
        if (i == MAX_TCP_CONNECTIONS) {
            perror("destination is not match");
            continue;
        }

        pthread_mutex_lock(&tcp->mutex);
        switch (tcp->status) {
        case TCP_SYNSENT:
            tcp_synsent_recv_handler(tcp, &tcphdr, payload, read_size);
            break;
        case TCP_ESTAB:
            tcp_estab_recv_handler(tcp, &tcphdr, payload, read_size);
            break;
        default:
            perror("should not reach here");
            break;
        }
        pthread_mutex_unlock(&tcp->mutex);
    }
    close(tcp_manager.ll_soc);

    return NULL;
}

int tcp_synsent_recv_handler(struct TcpSocket *tcp, struct tcphdr *tcphdr, char *payload, size_t payload_size) {
    puts("SYNSENT");
    uint32_t seq = ntohl(tcphdr->seq);
    uint32_t ack_seq = ntohl(tcphdr->ack_seq);
    //dumpascii(payload, payload_size);
    printf("%u vs. %u\n", seq, tcp->recv_param.next_seq_no);

    //pthread_mutex_lock(&tcp->mutex);
    //printf("%d %d %d %d %d\n", tcphdr->ack, tcphdr->syn, ntohs(tcphdr->ack_seq), tcp->send_param.unacked_seq_no, tcp->send_param.next_seq_no);

    if (tcphdr->ack && tcphdr->syn) {
        if (tcp->send_param.unacked_seq_no <= ack_seq &&
            ack_seq <= tcp->send_param.next_seq_no) {
            tcp->status = TCP_ESTAB;
            tcp->send_param.unacked_seq_no = ack_seq;
            tcp->send_param.current_seq_no = ack_seq;
            tcp->send_param.next_seq_no = ack_seq;
            tcp->recv_param.initial_seq_no = seq;
            tcp->recv_param.next_seq_no = seq + 1;//(uint32_t)payload_size;
            printf("3way hand shake: %u %u\n", ack_seq, tcp->send_param.initial_seq_no);
            printf("3way hand shake acking: %u\n", seq+1);
            send_tcp_packet_one(tcp, NULL, 0, NULL, 0, 500, ACK);
        } else {
            puts("UNKO");
        }
    }
    //pthread_mutex_unlock(&tcp->mutex);
    return 0;
}

int tcp_estab_recv_handler(struct TcpSocket *tcp, struct tcphdr *tcphdr, char *payload, size_t payload_size) {
    uint32_t seq = ntohl(tcphdr->seq);
    uint32_t ack_seq = ntohl(tcphdr->ack_seq);
    puts("ESTAB");
    printf("%u vs. %u\n", seq, tcp->recv_param.next_seq_no);
    if (tcphdr->ack) {
        printf(" received %u ack.\n", ack_seq);
        if (tcp->send_param.unacked_seq_no < ack_seq &&
            ack_seq <= tcp->send_param.next_seq_no) {
            tcp->send_param.unacked_seq_no = ack_seq;
            printf("!!!!!! %u acked.\n", ack_seq);
        }
    }
    if (tcphdr->syn) {
        puts("ERRRRRRRRRRRRRRRRORRRRRRRRRRRRRRRRR");
    } else if (!tcphdr->ack && seq < tcp->recv_param.next_seq_no) {
        printf("%u already received.\n", seq);
        //send_tcp_packet_one(tcp, NULL, 0, NULL, 0, 500, ACK);
    } else if (tcp->recv_param.next_seq_no == seq) {
        tcp->recv_param.next_seq_no += payload_size;
        printf("!!!! %u recved. size: %lu\n", seq, payload_size);
        //dumpascii(payload, payload_size);
        send_tcp_packet_one(tcp, NULL, 0, NULL, 0, 500, ACK);
    } else {
        printf("NANIKORE %u %u\n", seq, ack_seq);
    }
    return 0;
}
