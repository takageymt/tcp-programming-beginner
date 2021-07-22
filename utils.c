#include "utils.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <unistd.h>

int new_ll_socket(char *device) {
    int soc;
    struct sockaddr_ll sa;
    struct ifreq ifreq;
    struct timeval tv;
    int ifindex;

    soc = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (soc < 0) {
        perror("socket failed");
        return -1;
    }

    /*
    memset(&ifreq, 0, sizeof(ifreq));
    strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name)-1);
    if (ioctl(soc, SIOCGIFINDEX, &ifreq) < 0) {
        perror("ioctl failed");
        close(soc);
        return -1;
    }
    ifindex = ifreq.ifr_ifindex;

    if (ioctl(soc, SIOCGIFHWADDR, &ifreq) < 0) {
        perror("ioctl failed");
        close(soc);
        return -1;
    }
    */

    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_IP);
    sa.sll_ifindex = if_nametoindex(device);//ifindex;
    //sa.sll_halen = IFHWADDRLEN;
    //memcpy(sa.sll_addr, &ifreq.ifr_hwaddr, IFHWADDRLEN);
    //memset(&sa.sll_addr, 0xff, IFHWADDRLEN);
    if (bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind failed");
        close(soc);
        return -1;
    }

    //tv.tv_sec = 1;
    //tv.tv_usec = 0;
    //setsockopt(soc, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));

    return soc;
}

uint16_t checksum(u_char *data, size_t len) {
    register uint32_t sum;
    register uint16_t *ptr;
    register int i;

    sum = 0;
    ptr = (uint16_t *)data;
    for (i = len; i > 1; i -= 2) {
        sum += *ptr;
        if (sum & 0x8000000) {
            sum = (sum>>16) + (sum&0xFFFF);
        }
        ptr++;
    }
    if (i == 1) {
        sum += *((uint8_t *)ptr);
        /*
        uint16_t val = 0;
        memcpy(&val, ptr, sizeof(u_int8_t));
        sum += val;
        */
    }
    while (sum>>16) {
        sum = (sum>>16) + (sum&0xFFFF);
    }

    return ~sum;
}

uint16_t checksum2(u_char *data1, size_t len1, u_char *data2, size_t len2) {
    register uint32_t sum;
    register uint16_t *ptr;
    register int i;

    if (!data2 || !len2) {
        return checksum(data1, len1);
    }

    sum = 0;
    ptr = (uint16_t *)data1;
    for (i = len1; i > 1; i -= 2) {
        sum += *ptr;
        if (sum & 0x8000000) {
            sum = (sum>>16) + (sum&0xFFFF);
        }
        ptr++;
    }
    if (i == 1) {
        sum += ((uint16_t)*((uint8_t *)ptr)<<8) + *data2;
        data2++;
        len2--;
    }
    ptr = (uint16_t *)data2;
    for (i = len2; i > 1; i -= 2) {
        sum += *ptr;
        if (sum & 0x8000000) {
            sum = (sum>>16) + (sum&0xFFFF);
        }
        ptr++;
    }
    if (i == 1) {
        sum += *((uint8_t *)ptr);
    }
    while (sum>>16) {
        sum = (sum>>16) + (sum&0xFFFF);
    }

    return ~sum;
}

void dumpascii(char *data, size_t len) {
    int i;
    puts("------------------DUMP DATA-----------------");
    for (i = 0; i < len; i++) {
        printf("%c", data[i]);
    }
    puts("");
}

void hexdump(char *data, size_t len) {
    int i;
    puts("------------------HEX DUMP-----------------");
    for (i = 0; i < len; i++) {
        printf("%02X ", data[i]&0xFF);
        if (i%4 == 3) puts("");
    }
    puts("");
}
