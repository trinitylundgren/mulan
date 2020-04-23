const char* usage_text =
"$ sudo ./mulan [OPTIONS] destination\n"
"\n"
"mulan sends a ping as an ICMP echo request to the specified destination.\n"
"Destination may be a URL, an IPv4 address or an IPv6 address. Peforms a \n"
"forward DNS lookup on the hostname and a reverse DNS lookup on the resulting\n"
"IP address. By default, the protocol used may be either IPv4 or IPv6\n"
"depending on the first address returned for the hostname. Default behavior\n"
"is to ping the provided destination in an infinite loop, reporting round\n"
"trip times (rtt) and any packet loss.\n"
"\n"
"OPTIONS:\n"
"\t-h\t\tShow this message and exit.\n"
"\t-4\t\tUse IPv4 protocol only.\n"
"\t-6\t\tUse IPv6 protocol only.\n"
"\t-c\tCOUNT\tSpecify number of time to ping.\n"
"\t-t\tTTL\tSpecify time to live for ICMP echo request.\n"
"\n"
"The name of this program is a tribute to the Chinese heroine Hua Mulan,\n"
"whose alias when disguised as a male soldier in the eponymous Disney film is\n"
"Ping.\n";


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

#ifndef DEFAULT_TTL
#define DEFAULT_TTL 64
#endif

#ifndef RECV_TIMEOUT
#define RECV_TIMEOUT 1
#endif

#ifndef PING_DELAY
#define PING_DELAY 1000000
#endif

/*
 * Global variable governing infinite ping loop in send_ping; may be manipulated
 * by interrupt handler.
 */
int continue_ping_loop = 1;

/*
 * IPv4 packet and header structs
 *
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
 * IPv6 packet and header structs
 *
 */
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

typedef struct ping_ip6_packet {
    ipv6_hdr ip_header;
    ping_icmp6_packet icmp_pkt;
}ping_ip6_packet;

typedef struct socket_st {
    int fd;
    int socktype;
} socket_st;

/*
 * dns_lookup performs a forward DNS lookup. Take as arguments a hostname, a
 * double pointer to a sockaddr struct, an int family (AF_INET for IPv4 and
 * AF_INET6 for IPv6); returns a string IPv4 or IPv6 address and populates the
 * fields of the passed sockaddr_in or sockaddr_in6 struct.
 *
 * For example:
 *
 *     struct sockaddr_in addr_con;
 *     char* ip_addr = dns_lookup_4("www.google.com", &addr_con,
 *                                  AF_INET, &addlen);
 *     printf("IP Address: %s", ip_addr);
 *
 * Prints:
 *
 *     IP Address: 172.217.0.36
 */
char* dns_lookup(char* hostname, struct sockaddr** addr_con, int* family,
                 socklen_t* addlen, struct addrinfo* hints) {
    struct addrinfo* res;
    socklen_t size = NI_MAXHOST;
    char* ip = malloc(size*sizeof(char));
    int err;

    err = getaddrinfo(hostname, NULL, hints, &res);

    if (err != 0) {
        return NULL;
    }

    *family = res->ai_family;
    *addr_con = (struct sockaddr*)res->ai_addr;
    *addlen = res->ai_addrlen;

    char buf[NI_MAXHOST];
    int len = sizeof(struct sockaddr_in6);
    err = getnameinfo((struct sockaddr*)res->ai_addr, len, buf, sizeof(buf),
                      NULL, 0, NI_NAMEREQD);

    switch(*family) {
        case AF_INET:
            inet_ntop(res->ai_family,
                      &((*((struct sockaddr_in**)addr_con))->sin_addr),
                      ip, size);
            break;
        case AF_INET6:
            inet_ntop(res->ai_family,
                      &((*((struct sockaddr_in6**)addr_con))->sin6_addr),
                      ip, size);
            break;
    }

    return ip;
}

/*
 * reverse_dns_lookup performs a Reverse DNS lookup. Takes as arguments a
 * struct sockaddr pointer pointing to a sockaddr_in or sockaddr_in6 struct
 * populated by getnameinfo in a forward DNS lookup, the corresponding int
 * family (AF_INET for IPv4 and AF_INET6 for IPv6).
 */
char* reverse_dns_lookup(struct sockaddr* addr_con, int family) {
    socklen_t len;
    char buf[NI_MAXHOST];

    // Calculate correct sockaddr size for address family
    int err;

    switch(family){
        case AF_INET:
            len = sizeof(struct sockaddr_in);
            err = getnameinfo(addr_con, len, buf, sizeof(buf),
                              NULL, 0, NI_NAMEREQD);
            break;
        case AF_INET6:
            len = sizeof(struct sockaddr_in6);
            err = getnameinfo(addr_con, len, buf, sizeof(buf),
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
void send_ping(int ping_sockfd, char* rev_host, char* ping_ip, char* ping_dom,
               int family, uint8_t ttl, uint32_t count, int inf_flag) {
    int ttl_val = ttl;
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

    // Set TTL value for IPv4 or IPv6
    switch(family) {
        case AF_INET:
            if (setsockopt(ping_sockfd, SOL_IP, IP_TTL,
                           &ttl_val, sizeof(ttl_val)) != 0) {
                printf("Error: setting socket options to TTL failed.\n");
                return;
            }
            break;
        case AF_INET6:
            if (setsockopt(ping_sockfd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                           &ttl_val, sizeof(ttl_val)) != 0) {
                printf("Error: setting socket options to TTL failed.\n");
                return;
            }
            break;
    }

    // Setting timeout of receiving setting
    setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out,
               sizeof(tv_out));

    // Send ICMP packet in an infinite loop
    while(continue_ping_loop && count > 0) {
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
        // If user provided a finite count, decrement it for each pass of the
        // outer loop
        if (!inf_flag) {
            --count;
        }
    }

    // Calculate time elapsed during ping operations
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

    char ch;
    char* ip_addr;
    int family;
    char* reverse_hostname;
    struct sockaddr* addr_con;
    uint8_t ttl = DEFAULT_TTL;
    uint32_t count;
    int inf_flag = 1;

    socket_st sock4 = { .fd = -1 };
    socket_st sock6 = { .fd = -1 };
    socket_st* sock;

    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;


    // Parse command-line flags
    while((ch = getopt(argc, argv, "h46t:c:")) != EOF) {
        switch(ch) {
            case 'h':
                printf("%s", usage_text);
                return 0;
            case '4':
                if (hints.ai_family == AF_INET6) {
                    printf("Error: only one -4 or -6 option may be specified\n");
                    exit(1);
                }
                hints.ai_family = AF_INET;
                break;
            case '6':
                if (hints.ai_family == AF_INET) {
                    printf("Error: only one -4 or -6 option may be specified\n");
                    exit(1);
                }
                hints.ai_family = AF_INET6;
                break;
            case 't':
                if (atoi(optarg) < 1 || atoi(optarg) > 255) {
                    printf("Error: ttl must be between 1 and 255\n");
                    exit(1);
                }
                ttl = atoi(optarg);
                break;
            case 'c':
                if (atoi(optarg) < 1) {
                    printf("Error: count must be greater than 1\n");
                    exit(1);
                }
                inf_flag = 0;
                count = atoi(optarg);
                break;
        }
    }

    // If user did not pass in enough arguments
    if (argc != optind + 1) {
        printf("Error: invalid command line argument.\n%s",
                usage_text);
        return 0;
    }

    char* hostname = argv[optind];

    // New DNS lookup
    socklen_t connect_len;
    ip_addr = dns_lookup(hostname, &addr_con, &family, &connect_len, &hints);
    if (ip_addr == NULL) {
        printf("Error: DNS lookup failed. Could not resolve hostname.\n");
        return 0;
    }

    // Perform reverse DNS lookup on resulting IP address
    reverse_hostname = reverse_dns_lookup(addr_con, family);

    // Calculate message size
    int msg_size = PING_PKT_SIZE - sizeof(struct icmphdr);

    // Display feedback
    printf("Trinity's PING %s((%s (%s)) %d data bytes\n", hostname,
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
            protocol = IPPROTO_ICMPV6;
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

    send_ping(sock->fd, reverse_hostname, ip_addr, hostname, family, ttl, count,
              inf_flag);

    return 0;
}
