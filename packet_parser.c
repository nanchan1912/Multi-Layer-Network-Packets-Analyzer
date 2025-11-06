#include "packet_parser.h"
#include "cshark.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if_arp.h>
#include <ctype.h>

// Linux Cooked Capture (SLL) constants
#define DLT_LINUX_SLL 113
#define SLL_HDR_LEN 16

// Helper function to format MAC address
void format_mac(const u_char *mac, char *buf) {
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Helper function to identify application protocol based on ports
const char* identify_app_protocol(int src_port, int dst_port) {
    if (src_port == 80 || dst_port == 80) return "HTTP";
    if (src_port == 443 || dst_port == 443) return "HTTPS/TLS";
    if (src_port == 53 || dst_port == 53) return "DNS";
    if (src_port == 22 || dst_port == 22) return "SSH";
    if (src_port == 21 || dst_port == 21) return "FTP";
    if (src_port == 25 || dst_port == 25) return "SMTP";
    if (src_port == 20) return "FTP-DATA";
    return "Unknown";
}

// Hex dump function
void hex_dump(const u_char *data, int length, int max_bytes) {
    int bytes_to_show = (length < max_bytes) ? length : max_bytes;
    
    for (int i = 0; i < bytes_to_show; i += 16) {
        // Print hex values
        for (int j = 0; j < 16 && (i + j) < bytes_to_show; j++) {
            printf("%02X ", data[i + j]);
        }
        
        // Pad if less than 16 bytes in this line
        for (int j = bytes_to_show - i; j < 16; j++) {
            printf("   ");
        }
        
        // Print ASCII representation
        for (int j = 0; j < 16 && (i + j) < bytes_to_show; j++) {
            char c = data[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("\n");
    }
}

// Parse TCP flags
void parse_tcp_flags(u_char flags, char *buf) {
    buf[0] = '\0';
    int first = 1;
    
    if (flags & TH_FIN) { if (!first) strcat(buf, ","); strcat(buf, "FIN"); first = 0; }
    if (flags & TH_SYN) { if (!first) strcat(buf, ","); strcat(buf, "SYN"); first = 0; }
    if (flags & TH_RST) { if (!first) strcat(buf, ","); strcat(buf, "RST"); first = 0; }
    if (flags & TH_PUSH) { if (!first) strcat(buf, ","); strcat(buf, "PSH"); first = 0; }
    if (flags & TH_ACK) { if (!first) strcat(buf, ","); strcat(buf, "ACK"); first = 0; }
    if (flags & TH_URG) { if (!first) strcat(buf, ","); strcat(buf, "URG"); first = 0; }
}

// Parse IPv4 flags
void parse_ip_flags(u_short flags_offset, char *buf) {
    buf[0] = '\0';
    int first = 1;
    
    u_short flags = ntohs(flags_offset) >> 13;
    
    if (flags & 0x4) { strcat(buf, "DF"); first = 0; }
    if (flags & 0x2) { if (!first) strcat(buf, ","); strcat(buf, "MF"); }
    if (strlen(buf) == 0) strcat(buf, "None");
}

// Main packet parsing function
void parse_and_display_packet(const struct pcap_pkthdr *header, const u_char *packet, int id, int detailed, int datalink_type) {
    char src_mac[20], dst_mac[20];
    u_short ether_type;
    const u_char *l3_data;
    int l2_header_len;
    
    printf("-----------------------------------------\n");
    printf("Packet #%d | Timestamp: %ld.%06ld | Length: %d bytes\n",
           id, header->ts.tv_sec, header->ts.tv_usec, header->len);
    
    // If detailed mode, show full hex dump at the start
    if (detailed) {
        printf("\n=== FULL PACKET HEX DUMP ===\n");
        hex_dump(packet, header->len, header->len);
        printf("\n=== LAYER-BY-LAYER ANALYSIS ===\n");
    }
    
    // Layer 2: Check if Linux Cooked Capture or Ethernet
    if (datalink_type == DLT_LINUX_SLL) {
        // Linux Cooked Capture format (used by 'any' interface)
        // SLL Header: 2 bytes packet type, 2 bytes ARPHRD, 2 bytes addr len, 8 bytes addr, 2 bytes protocol
        if (header->caplen < SLL_HDR_LEN) {
            printf("L2 (SLL): Packet too short\n\n");
            return;
        }
        
        // Extract protocol type (at offset 14-15)
        ether_type = (packet[14] << 8) | packet[15];
        
        // Extract source MAC (8 bytes starting at offset 6, but usually only 6 are used)
        format_mac(packet + 6, src_mac);
        strcpy(dst_mac, "N/A");  // SLL doesn't have destination MAC in header
        
        l2_header_len = SLL_HDR_LEN;
        l3_data = packet + SLL_HDR_LEN;
        
        const char *ether_type_str;
        if (ether_type == ETHERTYPE_IP) ether_type_str = "IPv4";
        else if (ether_type == ETHERTYPE_IPV6) ether_type_str = "IPv6";
        else if (ether_type == ETHERTYPE_ARP) ether_type_str = "ARP";
        else ether_type_str = "Unknown";
        
        printf("L2 (Linux SLL): Src MAC: %s | Protocol: %s (0x%04X)\n",
               src_mac, ether_type_str, ether_type);
    } else {
        // Standard Ethernet frame
        struct ether_header *eth_header = (struct ether_header *)packet;
        format_mac(eth_header->ether_shost, src_mac);
        format_mac(eth_header->ether_dhost, dst_mac);
        
        ether_type = ntohs(eth_header->ether_type);
        const char *ether_type_str;
        
        if (ether_type == ETHERTYPE_IP) ether_type_str = "IPv4";
        else if (ether_type == ETHERTYPE_IPV6) ether_type_str = "IPv6";
        else if (ether_type == ETHERTYPE_ARP) ether_type_str = "ARP";
        else ether_type_str = "Unknown";
        
        printf("L2 (Ethernet): Dst MAC: %s | Src MAC: %s | EtherType: %s (0x%04X)\n",
               dst_mac, src_mac, ether_type_str, ether_type);
        
        l2_header_len = sizeof(struct ether_header);
        l3_data = packet + sizeof(struct ether_header);
    }
    
    // Layer 3: Network layer
    if (ether_type == ETHERTYPE_IP) {
        // IPv4
        struct ip *ip_header = (struct ip *)l3_data;
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
        
        const char *protocol_str;
        if (ip_header->ip_p == IPPROTO_TCP) protocol_str = "TCP";
        else if (ip_header->ip_p == IPPROTO_UDP) protocol_str = "UDP";
        else if (ip_header->ip_p == IPPROTO_ICMP) protocol_str = "ICMP";
        else protocol_str = "Unknown";
        
        char flags_str[32];
        parse_ip_flags(ip_header->ip_off, flags_str);
        
        printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: %s (%d) | TTL: %d\n",
               src_ip, dst_ip, protocol_str, ip_header->ip_p, ip_header->ip_ttl);
        printf("           ID: 0x%04X | Total Length: %d | Header Length: %d bytes | Flags: %s\n",
               ntohs(ip_header->ip_id), ntohs(ip_header->ip_len), ip_header->ip_hl * 4, flags_str);
        
        const u_char *l4_data = l3_data + (ip_header->ip_hl * 4);
        int l4_len = ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4);
        
        // Layer 4: Transport layer
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)l4_data;
            int src_port = ntohs(tcp_header->th_sport);
            int dst_port = ntohs(tcp_header->th_dport);
            
            char flags_buf[64];
            parse_tcp_flags(tcp_header->th_flags, flags_buf);
            
            const char *src_port_name = "";
            const char *dst_port_name = "";
            if (src_port == 80) src_port_name = " (HTTP)";
            else if (src_port == 443) src_port_name = " (HTTPS)";
            else if (src_port == 53) src_port_name = " (DNS)";
            else if (src_port == 22) src_port_name = " (SSH)";
            
            if (dst_port == 80) dst_port_name = " (HTTP)";
            else if (dst_port == 443) dst_port_name = " (HTTPS)";
            else if (dst_port == 53) dst_port_name = " (DNS)";
            else if (dst_port == 22) dst_port_name = " (SSH)";
            
            printf("L4 (TCP): Src Port: %d%s | Dst Port: %d%s | Seq: %u | Ack: %u | Flags: [%s]\n",
                   src_port, src_port_name, dst_port, dst_port_name,
                   ntohl(tcp_header->th_seq), ntohl(tcp_header->th_ack), flags_buf);
            printf("          Window: %d | Checksum: 0x%04X | Header Length: %d bytes\n",
                   ntohs(tcp_header->th_win), ntohs(tcp_header->th_sum), tcp_header->th_off * 4);
            
            // Layer 7: Payload
            int tcp_header_len = tcp_header->th_off * 4;
            int payload_len = l4_len - tcp_header_len;
            
            if (payload_len > 0) {
                const u_char *payload = l4_data + tcp_header_len;
                const char *app_proto = identify_app_protocol(src_port, dst_port);
                
                printf("L7 (Payload): Identified as %s on port %d/%d - %d bytes\n",
                       app_proto, src_port, dst_port, payload_len);
                printf("Data (first 64 bytes):\n");
                hex_dump(payload, payload_len, 64);
            }
            
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)l4_data;
            int src_port = ntohs(udp_header->uh_sport);
            int dst_port = ntohs(udp_header->uh_dport);
            
            const char *src_port_name = "";
            const char *dst_port_name = "";
            if (src_port == 53) src_port_name = " (DNS)";
            if (dst_port == 53) dst_port_name = " (DNS)";
            
            printf("L4 (UDP): Src Port: %d%s | Dst Port: %d%s | Length: %d | Checksum: 0x%04X\n",
                   src_port, src_port_name, dst_port, dst_port_name,
                   ntohs(udp_header->uh_ulen), ntohs(udp_header->uh_sum));
            
            // Layer 7: Payload
            int payload_len = ntohs(udp_header->uh_ulen) - 8;
            if (payload_len > 0) {
                const u_char *payload = l4_data + 8;
                const char *app_proto = identify_app_protocol(src_port, dst_port);
                
                printf("L7 (Payload): Identified as %s on port %d/%d - %d bytes\n",
                       app_proto, src_port, dst_port, payload_len);
                printf("Data (first %d bytes):\n", payload_len < 64 ? payload_len : 64);
                hex_dump(payload, payload_len, 64);
            }
        }
        
    } else if (ether_type == ETHERTYPE_IPV6) {
        // IPv6
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)l3_data;
        char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
        
        const char *next_header_str;
        if (ip6_header->ip6_nxt == IPPROTO_TCP) next_header_str = "TCP";
        else if (ip6_header->ip6_nxt == IPPROTO_UDP) next_header_str = "UDP";
        else if (ip6_header->ip6_nxt == IPPROTO_ICMPV6) next_header_str = "ICMPv6";
        else next_header_str = "Unknown";
        
        u_int32_t flow = ntohl(ip6_header->ip6_flow);
        int traffic_class = (flow >> 20) & 0xFF;
        int flow_label = flow & 0xFFFFF;
        
        printf("L3 (IPv6): Src IP: %s | Dst IP: %s | Next Header: %s (%d) | Hop Limit: %d\n",
               src_ip, dst_ip, next_header_str, ip6_header->ip6_nxt, ip6_header->ip6_hlim);
        printf("           Traffic Class: %d | Flow Label: 0x%05X | Payload Length: %d\n",
               traffic_class, flow_label, ntohs(ip6_header->ip6_plen));
        
        const u_char *l4_data = l3_data + sizeof(struct ip6_hdr);
        int l4_len = ntohs(ip6_header->ip6_plen);
        
        // Layer 4: Transport layer
        if (ip6_header->ip6_nxt == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)l4_data;
            int src_port = ntohs(tcp_header->th_sport);
            int dst_port = ntohs(tcp_header->th_dport);
            
            char flags_buf[64];
            parse_tcp_flags(tcp_header->th_flags, flags_buf);
            
            const char *src_port_name = "";
            const char *dst_port_name = "";
            if (src_port == 80) src_port_name = " (HTTP)";
            else if (src_port == 443) src_port_name = " (HTTPS)";
            else if (src_port == 53) src_port_name = " (DNS)";
            
            if (dst_port == 80) dst_port_name = " (HTTP)";
            else if (dst_port == 443) dst_port_name = " (HTTPS)";
            else if (dst_port == 53) dst_port_name = " (DNS)";
            
            printf("L4 (TCP): Src Port: %d%s | Dst Port: %d%s | Seq: %u | Ack: %u | Flags: [%s]\n",
                   src_port, src_port_name, dst_port, dst_port_name,
                   ntohl(tcp_header->th_seq), ntohl(tcp_header->th_ack), flags_buf);
            printf("          Window: %d | Checksum: 0x%04X | Header Length: %d bytes\n",
                   ntohs(tcp_header->th_win), ntohs(tcp_header->th_sum), tcp_header->th_off * 4);
            
            // Layer 7: Payload
            int tcp_header_len = tcp_header->th_off * 4;
            int payload_len = l4_len - tcp_header_len;
            
            if (payload_len > 0) {
                const u_char *payload = l4_data + tcp_header_len;
                const char *app_proto = identify_app_protocol(src_port, dst_port);
                
                printf("L7 (Payload): Identified as %s on port %d/%d - %d bytes\n",
                       app_proto, src_port, dst_port, payload_len);
                printf("Data (first 64 bytes):\n");
                hex_dump(payload, payload_len, 64);
            }
            
        } else if (ip6_header->ip6_nxt == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)l4_data;
            int src_port = ntohs(udp_header->uh_sport);
            int dst_port = ntohs(udp_header->uh_dport);
            
            const char *src_port_name = "";
            const char *dst_port_name = "";
            if (src_port == 53) src_port_name = " (DNS)";
            if (dst_port == 53) dst_port_name = " (DNS)";
            
            printf("L4 (UDP): Src Port: %d%s | Dst Port: %d%s | Length: %d | Checksum: 0x%04X\n",
                   src_port, src_port_name, dst_port, dst_port_name,
                   ntohs(udp_header->uh_ulen), ntohs(udp_header->uh_sum));
            
            // Layer 7: Payload
            int payload_len = ntohs(udp_header->uh_ulen) - 8;
            if (payload_len > 0) {
                const u_char *payload = l4_data + 8;
                const char *app_proto = identify_app_protocol(src_port, dst_port);
                
                printf("L7 (Payload): Identified as %s on port %d/%d - %d bytes\n",
                       app_proto, src_port, dst_port, payload_len);
                printf("Data (first %d bytes):\n", payload_len < 64 ? payload_len : 64);
                hex_dump(payload, payload_len, 64);
            }
        }
        
    } else if (ether_type == ETHERTYPE_ARP) {
        // ARP
        struct arphdr *arp_header = (struct arphdr *)l3_data;
        
        const char *op_str;
        u_short op = ntohs(arp_header->ar_op);
        if (op == ARPOP_REQUEST) op_str = "Request";
        else if (op == ARPOP_REPLY) op_str = "Reply";
        else op_str = "Unknown";
        
        // Extract ARP packet data
        u_char *arp_data = (u_char *)(l3_data + sizeof(struct arphdr));
        char sender_mac[20], target_mac[20];
        char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
        
        format_mac(arp_data, sender_mac);
        inet_ntop(AF_INET, arp_data + 6, sender_ip, INET_ADDRSTRLEN);
        format_mac(arp_data + 10, target_mac);
        inet_ntop(AF_INET, arp_data + 16, target_ip, INET_ADDRSTRLEN);
        
        printf("\nL3 (ARP): Operation: %s (%d) | Sender IP: %s | Target IP: %s\n",
               op_str, op, sender_ip, target_ip);
        printf("          Sender MAC: %s | Target MAC: %s\n",
               sender_mac, target_mac);
        printf("          HW Type: %d | Proto Type: 0x%04X | HW Len: %d | Proto Len: %d\n",
               ntohs(arp_header->ar_hrd), ntohs(arp_header->ar_pro),
               arp_header->ar_hln, arp_header->ar_pln);
    }
    
    printf("\n");
}
