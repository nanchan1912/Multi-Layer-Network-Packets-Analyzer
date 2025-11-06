#ifndef CSHARK_H
#define CSHARK_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

// Constants
#define MAX_PACKETS 10000

#define MAX_FILTER_LEN 256

// Packet storage structure
typedef struct {
    struct pcap_pkthdr header;
    u_char *data;
    int id;
} stored_packet_t;

// Session storage
typedef struct {
    stored_packet_t packets[MAX_PACKETS];
    int count;
} session_t;

// Global variables
extern session_t current_session;
extern volatile sig_atomic_t stop_capture;
extern int packet_counter;
extern int current_datalink_type;

// Function prototypes
void display_packet(const struct pcap_pkthdr *header, const u_char *packet, int id);
void display_packet_detailed(const stored_packet_t *pkt);
void hex_dump(const u_char *data, int length, int max_bytes);
const char* identify_app_protocol(int src_port, int dst_port);
void store_packet(const struct pcap_pkthdr *header, const u_char *packet);
void clear_session(void);

#endif // CSHARK_H
