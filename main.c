#include "utils.h"
#include "tcpsocket.h"
#include "ipsocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

int main(int argc, char *argv[]) {
    struct TcpSocket *tcp;
    char data[256];

    if (argc < 6) {
        fprintf(stderr, "Usage: %s <iface> <local ip> <local port> <remote ip> <remote port>\n", argv[0]);
        exit(1);
    }
    if (tcp_manager_init(argv[1]) < 0) {
        exit(1);
    }

    tcp = new_tcp_socket(argv[2], atoi(argv[3]));

/*
    while(1) {
        send_icmp_echo(tcp->ip_soc);
        sleep(1);
    }
*/

    tcp_connect(tcp, argv[4], atoi(argv[5]));
    
    //signal(SIGINT, tcp_manager_fin);
    //signal(SIGTERM, tcp_manager_fin);
    //signal(SIGQUIT, tcp_manager_fin);

    //signal(SIGPIPE, SIG_IGN);
    //signal(SIGTTIN, SIG_IGN);
    //signal(SIGTTOU, SIG_IGN);

    puts("start tcp client");


    while (!tcp_manager.term) {
        printf("> ");
        fgets(data, sizeof(data), stdin);
        tcp_send(tcp, data, strlen(data));
    }

    puts("close tcp client");
    
    pthread_join(tcp_manager.recv_thread_id, NULL);
    
    close_tcp_socket(tcp);

    return 0;
}
