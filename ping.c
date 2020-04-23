/*
 * Description: CLI ping program for Linux.
 * Last Modified: 2020-04-21
 * Author: Trinity Lundgren
 */

#include <stdio.h>              // printf
#include <stdlib.h>             // malloc
#include <netinet/in.h>         // struct sockaddr_in, struct in_addr
#include <netdb.h>              // struct hostent, NI_MAXHOST
#include <arpa/inet.h>          // inet_ntoa, htons
#include <sys/socket.h>         // socket
#include <netinet/ip_icmp.h>    // icmphdr
#include <time.h>               // struct timespec
#include <sys/time.h>           // struct timeval
#include <strings.h>            // bzero
#include <sys/types.h>          // getpid
#include <unistd.h>             // getpid
#include <errno.h>              // perror
#include <signal.h>             // signal
#include <string.h>             // strlen

#include "utils.h"              // safe_strcpy


#ifndef PORT_NO
#define PORT_NO 0
#endif

#ifndef PING_PKT_SIZE
#define PING_PKT_SIZE 64
#endif

#ifndef TTL_VAL
#define TTL_VAL 64
#endif

#ifndef RECV_TIMEOUT
#define RECV_TIMEOUT 1
#endif

#ifndef PING_DELAY
#define PING_DELAY 1000000
#endif

#define getaddrinfo_flags (AI_CANONNAME | AI_IDN | AI_CANONIDN)

/*
 * Global variable governing infinite ping loop in send_ping; may be manipulated
 * by interrupt handler.
 */
int continue_ping_loop = 1;

/*
 * struct ping_icmp_packet and struct ping_ip_packet are for use as outgoing
 * and incoming ping packets, respectively. ping_ip_packet contains a
 * ping_icmp_packet struct and adds on an IP header (iphdr) struct to
 * facilitate parsing of received ping packets.
 */

typedef struct ping_icmp_packet {
    struct icmphdr header;
    char msg[PING_PKT_SIZE - sizeof(struct icmphdr)];
}ping_icmp_packet;

typedef struct ping_ip_packet {
    struct iphdr ip_header;
    ping_icmp_packet icmp_pkt;
}ping_ip_packet;

/*
 * IPv6 structs
 */

typedef struct icmp6_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seqno;
}icmp6_hdr;

typedef struct ping_icmp6_packet {
    icmp6_hdr header;
    char msg[PING_PKT_SIZE - sizeof(struct icmp6_hdr)];
}ping_icmp6_packet;

typedef struct ipv6_hdr {
    unsigned int
        version : 4,
        traffic_class : 8,
        flow_label : 20;
    uint16_t length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    struct in6_addr src;
    struct in6_addr dst;
}ipv6_hdr;


typedef struct ping_ip6_packet {
    ipv6_hdr ip_header;
    ping_icmp6_packet icmp_pkt;
}ping_ip6_packet;

/*
 * struct socket_st
 */
typedef struct socket_st {
    int fd;
    int socktype;
} socket_st;

void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

/*
 * New DNS lookup.
 */

char* dns_lookup(char* hostname, struct sockaddr_in** addr_con, int* family,
                 socklen_t* addlen) {
    struct addrinfo hints = {0};
    struct addrinfo* res;
    socklen_t size = NI_MAXHOST;
    char* ip = malloc(size*sizeof(char));
    int err;

    // Set hints values
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    err = getaddrinfo(hostname, NULL, &hints, &res);

    if (err != 0) {
        perror("getaddrinfo");
        printf("getaddrinfo %s\n", strerror(errno));
        printf("getaddrinfo : %s \n", gai_strerror(err));
        return NULL;
    }

    *family = res->ai_family;
    *addr_con = (struct sockaddr_in*)res->ai_addr;
    *addlen = res->ai_addrlen;

    char buf[NI_MAXHOST];
    int len = sizeof(struct sockaddr_in6);
    err = getnameinfo((struct sockaddr*)res->ai_addr, len, buf, sizeof(buf), NULL,
                      0, NI_NAMEREQD);

    inet_ntop(res->ai_family, &((*addr_con)->sin_addr), ip, size);

    return ip;
}

/*
 * dns_lookup_4 performs a forward DNS lookup (IPv4). Take as arguments
 * hostname and a pointer to a sockaddr_in struct; returns a string IPv4
 * address in dot-decimal notation and populates the fields of the passed
 * sockaddr_in struct.
 *
 * For example:
 *
 *     struct sockaddr_in addr_con;
 *     char* ip_addr = dns_lookup_4("www.google.com", &addr_con);
 *     printf("IP Address: %s", ip_addr);
 *
 *  Prints:
 *     IP Address: 172.217.0.36
 */

char* dns_lookup_4(char* hostname, struct sockaddr_in* addr_con) {
    struct hostent* host_entity;
    char* ip = (char*)malloc(NI_MAXHOST*sizeof(char));

    if ((host_entity = gethostbyname(hostname)) == NULL) {
        // Cannot find hostname IP address
        return NULL;
    }

    // Populate fields of address structure
    safe_strcpy(ip, NI_MAXHOST*sizeof(char),
                inet_ntoa(*(struct in_addr*)host_entity->h_addr_list[0]));
    addr_con->sin_family = host_entity->h_addrtype;
    addr_con->sin_port = htons(PORT_NO);
    addr_con->sin_addr.s_addr = *(long*)host_entity->h_addr_list[0];

    return ip;
}

/*
 * reverse_dns_lookup performs a Reverse DNS lookup.
 */

char* reverse_dns_lookup(struct sockaddr_in* addr_con, int family) {
    socklen_t len;
    char buf[NI_MAXHOST];


    // Calculate correct sockaddr size for address family
    int err;

    switch(family){
        case AF_INET:
            len = sizeof(struct sockaddr_in);
            err = getnameinfo((struct sockaddr*)addr_con, len, buf, sizeof(buf),
                              NULL, 0, NI_NAMEREQD);
            break;
        case AF_INET6:
            len = sizeof(struct sockaddr_in6);
            err = getnameinfo((struct sockaddr*)addr_con, len, buf, sizeof(buf),
                              NULL, 0, NI_NAMEREQD);
            break;
        default:
            printf("reverse_dns_lookup : %s\n", gai_strerror(EAI_FAMILY));
            return NULL;
    }

    if (err != 0) {
        printf("getnameinfo : %s\n", gai_strerror(err));
        return NULL;
    }

    int ret_buf_size = strlen(buf) + 1;
    char* ret_buf = malloc(ret_buf_size * sizeof(char));
    safe_strcpy(ret_buf, ret_buf_size, buf);
    return ret_buf;
}


/*
 * Interrupt handling function to allow user to interrupt infinite ping loop
 * without exiting the program.
 */
void interrupt_ping_loop(int dummy) {
    continue_ping_loop = 0;
}

/*
 * Function to make a ping request by sending out ICMP packets using a RAW
 * socket in a continuous loop until interrupted by user input. Takes as
 * arguments a socket file descripter, a sockaddr_in struct populated with
 * destination address information (by a call to a forward dns lookup function),
 * the reverse lookup hostname and ip address of the destination, and the
 * hostname provided by the user.
 *
 * It does this by first filling an ICMP packet with an icmp header, a process
 * id and a random message, then calculating and assigning the checksum of the
 * packet. In an infinite, user-interruptible loop, it sends the packet, waits
 * for it to be received, and then parses the response.
 *
 * For each ping sent, the function displays the packet size, pinged domain,
 * time-to-live (ttl), round-trip time (rtt) and message number.
 *
 * After the user interrups the loop, the function displays cumulative ping
 * statistics such as number of packets send and received, packet loss, and
 * total time.
 */
void send_ping(int ping_sockfd, struct sockaddr_in* ping_addr,
               char* rev_host, char* ping_ip, char* ping_dom, int family) {
    int ttl_val = TTL_VAL;
    int icmp_count = 0;
    int msg_received_count = 0;
    int i = 0;

    // IPv4
    ping_icmp_packet outgoing = {0};
    ping_ip_packet incoming = {0};

    // IPv6
    ping_icmp6_packet outgoing6 = {0};
    ping_icmp6_packet incoming6 = {0};

    struct timespec time_start, time_end, tfs, tfe;
    long double rtt_msec = 0, total_msec = 0;
    struct timeval tv_out;
    tv_out.tv_sec = RECV_TIMEOUT;
    tv_out.tv_usec = 0;

    clock_gettime(CLOCK_MONOTONIC, &tfs);

    switch(family) {
        case AF_INET:
            if (setsockopt(ping_sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) {
                printf("Error: setting socket options to TTL failed.\n");
                return;
            }
            break;
        //case AF_INET6:
        //    if (setsockopt(ping_sockfd, IPPROTO_IPV6, IPV6_TCLASS, &ttl_val, sizeof(ttl_val)) != 0) {
        //        printf("Error: setting socket options to TTL failed.\n");
        //        return;
        //    }
        //    break;
    }

    // Setting timeout of receiving setting
    setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out,
               sizeof(tv_out));

    // Send ICMP packet in an infinite loop
    while(continue_ping_loop) {
        switch(family) {
            case AF_INET:
                // Fill the packet
                bzero(&outgoing, sizeof(outgoing));
                outgoing.header.type = ICMP_ECHO;
                outgoing.header.un.echo.id = getpid();

                // Generate a message
                for (; i < sizeof(outgoing.msg) - 1; ++i) {
                    outgoing.msg[i] = i + '0';
                }
                outgoing.msg[i] = 0;

                outgoing.header.un.echo.sequence = icmp_count++;

                // Calculate and set checksum in packet
                outgoing.header.checksum = checksum(&outgoing, sizeof(outgoing));

                usleep(PING_DELAY);

                // Send the packet
                clock_gettime(CLOCK_MONOTONIC, &time_start);
                int err = send(ping_sockfd, &outgoing, sizeof(outgoing), 0);
                if (err < 0) {
                    perror("send: ");
                }

                // Receive a packet
                int retry = 1;
                while(retry) {
                    int recv_code = recv(ping_sockfd, &incoming, sizeof(incoming), 0);

                    if (recv_code < 0) {
                        perror("recv :");
                        break;
                    }

                    if (incoming.icmp_pkt.header.type == 8) {
                        continue;
                    }

                    retry = 0;
                    clock_gettime(CLOCK_MONOTONIC, &time_end);
                    double time_elapsed = ((double)(time_end.tv_nsec -
                                           time_start.tv_nsec))/1000000.0;
                    rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0
                               + time_elapsed;

                    if (!(incoming.icmp_pkt.header.type == 0 &&
                          incoming.icmp_pkt.header.code == 0)) {
                        printf("Error: packet received with ICMP type %d code %d\n",
                                incoming.icmp_pkt.header.type,
                                incoming.icmp_pkt.header.code);
                    }
                    else {
                        // Parse the packet
                        printf("%d bytes from %s (h: %s) (%s) icmp_seq=%d ttl=%d "
                                "rtt = %.0Lf ms\n", PING_PKT_SIZE, rev_host, ping_dom,
                                ping_ip, icmp_count, ttl_val, rtt_msec);

                        msg_received_count++;
                    }
                }
                break;
            case AF_INET6:
                // Fill the packet
                bzero(&outgoing6, sizeof(outgoing6));
                outgoing6.header.type = 128;
                outgoing6.header.id = getpid();

                // Generate a message
                for (; i < sizeof(outgoing6.msg) - 1; ++i) {
                    outgoing6.msg[i] = i + '0';
                }
                outgoing6.msg[i] = 0;

                outgoing6.header.seqno = icmp_count++;

                // Calculate and set checksum in packet
                outgoing6.header.checksum = checksum(&outgoing6, sizeof(outgoing6));

                usleep(PING_DELAY);

                // Send the packet
                clock_gettime(CLOCK_MONOTONIC, &time_start);
                int err6 = send(ping_sockfd, &outgoing6, sizeof(outgoing6), 0);
                if (err6 < 0) {
                    perror("send: ");
                }

                // Receive a packet
                int retry6 = 1;
                while(retry6) {
                    int recv_code = recv(ping_sockfd, &incoming6, sizeof(incoming6), 0);

                    if (recv_code < 0) {
                        perror("recv :");
                        break;
                    }

                    if (incoming6.header.type == 128) {
                        continue;
                    }

                    retry6 = 0;
                    clock_gettime(CLOCK_MONOTONIC, &time_end);
                    double time_elapsed = ((double)(time_end.tv_nsec -
                                           time_start.tv_nsec))/1000000.0;
                    rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0
                               + time_elapsed;

                    //DumpHex(&incoming6, 64);
                    if (!(incoming6.header.type == 129 &&
                          incoming6.header.code == 0)) {
                        printf("Error: packet received with ICMP type %d code %d\n",
                                incoming6.header.type,
                                incoming6.header.code);
                    }
                    else {
                        // Parse the packet
                        printf("%d bytes from %s (h: %s) (%s) icmp_seq=%d ttl=%d "
                                "rtt = %.0Lf ms\n", PING_PKT_SIZE, rev_host, ping_dom,
                                ping_ip, icmp_count, ttl_val, rtt_msec);

                        msg_received_count++;
                    }
                }

                break;
        }

    }

    clock_gettime(CLOCK_MONOTONIC, &tfe);
    double time_elapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec)) / 1000000.0;
    total_msec = (tfe.tv_sec - tfs.tv_sec) * 1000.0 + time_elapsed;

    // Display total ping statistics
    printf("\n%s (%s) Ping Statistics:\n", ping_dom, ping_ip);
    printf("\n%d packets sent, %d packets received, %.0f percent packet loss. "
            "Total time: %.0Lf ms\n\n", icmp_count, msg_received_count,
            ((icmp_count - msg_received_count) / icmp_count) * 100.0,
            total_msec);
}

/*
 * main is the driver program for ping.
 */

int main(int argc, char* argv[]) {

    //int sockfd;
    char* ip_addr;
    int family;
    char* reverse_hostname;
    struct sockaddr_in* addr_con;

    socket_st sock4 = { .fd = -1 };
    socket_st sock6 = { .fd = -1 };
    socket_st* sock;

    // If user did not pass in enough arguments
    if (argc < 2) {
        printf("Error: invalid command line argument. Format $ %s <address> <flags>\n",
                argv[0]);
        return 0;
    }

    // New DNS lookup
    socklen_t connect_len;
    ip_addr = dns_lookup(argv[1], &addr_con, &family, &connect_len);
    if (ip_addr == NULL) {
        printf("Error: DNS lookup failed. Could not resolve hostname.\n");
        return 0;
    }

    // Perform reverse DNS lookup on resulting IP address
    reverse_hostname = reverse_dns_lookup(addr_con, family);

    // Calculate message size
    int msg_size = PING_PKT_SIZE - sizeof(struct icmphdr);

    // Display feedback
    printf("Trinity's PING %s((%s (%s)) %d data bytes\n", argv[1],
           reverse_hostname, ip_addr, msg_size);

    // Open a Raw socket. socket() returns file descriptor or -1 on error.
    //     AF_INET: IPv4 internet protocols
    //     AF_INET6: IPv6 internet protocols
    //     SOCK_RAW: provides raw network protocol access
    //     IPPROTO_ICMP: Internet Control Message Protocol
    int protocol;
    switch(family) {
        case AF_INET:
            protocol = IPPROTO_ICMP;
            sock4.fd = socket(family, SOCK_RAW, protocol);
            sock = &sock4;
            break;
        case AF_INET6:
            //protocol = IPPROTO_IPV6;
            protocol = 58;
            sock6.fd = socket(family, SOCK_RAW, protocol);
            sock = &sock6;
            break;
    }

    if (sock->fd < 0) {
        printf("Error: socket file descriptor not received.\n");
        printf("socket: %s\n", gai_strerror(sock->fd));
        return 0;
    }

    connect(sock->fd, (struct sockaddr*)addr_con, connect_len);

    signal(SIGINT, interrupt_ping_loop); // Catching interrupts

    send_ping(sock->fd, addr_con, reverse_hostname, ip_addr, argv[1], family);

    return 0;
}
