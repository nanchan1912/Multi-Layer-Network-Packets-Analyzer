#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>

void parse_and_display_packet(const struct pcap_pkthdr *header, const u_char *packet, int id, int detailed, int datalink_type);

#endif // PACKET_PARSER_H
