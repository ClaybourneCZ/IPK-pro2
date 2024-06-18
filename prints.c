/**
 * 
 *  Author: Vaclav Chadim (xchadi09)
 *  FIT VUT Brno
 *  IPK Project 2
 *  ZETA - Network Sniffer
 *  
 *  WSL - Ubuntu 20.04
 * 
*/



#include "prints.h"

// Print all interfaces
void printInterfaces() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;
    pcap_if_t *temp;
    if (pcap_findalldevs(&interfaces, error_buffer) < 0) {
        printf("Error in pcap_findalldevs(): %s", error_buffer);
        exit(EXIT_FAILURE);
    }

    printf("\nAvaiable interfaces on this device: \n\n");
    for (temp = interfaces; temp; temp = temp->next) {
        printf("%s\n", temp->name);
    }
}

// Print help message
void printHelpMsg() {
    printf("\nipk-sniffer\n\n");    
    printf("supported arguments: [-h] [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--ndp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n");
    printf("\t-h                            display help message\n");
    printf("\t-i | --interface [string]     specify an interface\n");
    printf("\t-p [integer]                  set packet port to filter extends TCP and/or UDP argumet/s\n");
    printf("\t--port-source [integer]       set source port extends TCP and/or UDP argumet/s\n");
    printf("\t--port-destination [integer]  set destination port extends TCP and/or UDP argumet/s\n");
    printf("\t-u | --udp                    filter only UDP packets\n");
    printf("\t-t | --tcp                    filter only TCP packets\n");
    printf("\t--icmp4                       display only ICMPv4 packets\n");
    printf("\t--icmp6                       display only ICMPv6 echo request/response\n");
    printf("\t--arp                         display only ARP frames\n");
    printf("\t--ndp                         display display only NDP packets, subset of ICMPv6\n");
    printf("\t--igmp                        display only IGMP packets\n");
    printf("\t--mld                         display only MLD packets, subset of ICMPv6\n");    
    printf("\t-n [integer]                  set packet limit (will display only one if not set)\n");
}

void printIpv6(const struct in6_addr *addr, bool srcOrDest)
{
    char formatted_ipv6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, addr, formatted_ipv6, INET6_ADDRSTRLEN);
    if ( srcOrDest == true) printf("src IP: %s\n", formatted_ipv6);    
    if ( srcOrDest == false) printf("dst IP: %s\n", formatted_ipv6);    
}


void printTime()
{
    struct timeval timeval;
    time_t nowtime;
    struct tm *nowtm;

    gettimeofday(&timeval, NULL);
    nowtime = timeval.tv_sec;
    nowtm = localtime(&nowtime);

    char timestr[64];
    strftime(timestr, sizeof(timestr), "%FT%T", nowtm);
    printf("timestamp: %s.%03ld+01:00\n", timestr, timeval.tv_usec);
}


void printHexAsciiLine(const unsigned char *payload, int len, int offset)
{
    int i;
    int gap;
    const unsigned char *ch;

    // offset 
    printf("0x%04x   ", offset);

    // hex 
    ch = payload;
    for (i = 0; i < len; i++)
    {
        printf("%02x ", *ch);
        ch++;
        // print extra space after 8th byte for visual aid 
        if (i == 7)
            printf(" ");
    }

    // print space to handle line less than 8 bytes 
    if (len < 8)
        printf(" ");

    // fill hex gap with spaces if not full line
    if (len < 16)
    {
        gap = 16 - len;
        for (i = 0; i < gap; i++)
        {
            printf("   ");
        }
    }

    printf("   ");
    //ascii (if printable)
    ch = payload;

    for (i = 0; i < len; i++)
    {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }
    printf("\n");

    return;
}

void printPacket(const unsigned char *buffer, int len)
{

    int len_rem = len;

    // number of bytes per line
    int line_width = 16; 
    int line_len;

    // zero-based offset counter
    int offset = 0;  
    const unsigned char *buff = buffer;

    if (len <= 0)
        return;

    // data fits on one line 
    if (len <= line_width)
    {
        printHexAsciiLine(buff, len, offset);
        return;
    }

    // data spans multiple lines 
    for (;;)
    {
        // compute current line length 
        line_len = line_width % len_rem;
        // compute total remaining 
        len_rem -= line_len;
        // print line 
        printHexAsciiLine(buff, line_len, offset);
        // shift pointer to remaining bytes to print
        buff += line_len;
        // add offset 
        offset += line_width;
        // check if we have line width chars or less 
        if (len_rem <= line_width)
        {
            // print last line and get out 
            printHexAsciiLine(buff, len_rem, offset);
            offset += line_width;
            break;
        }
    }
    printf("\n");
    return;
}

void printEthHdr(const unsigned char *packet, int len)
{
    const struct ether_header *ethernet_header = (struct ether_header *)packet;
    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_header->ether_shost[0], ethernet_header->ether_shost[1], ethernet_header->ether_shost[2], ethernet_header->ether_shost[3], ethernet_header->ether_shost[4], ethernet_header->ether_shost[5]);
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_header->ether_dhost[0], ethernet_header->ether_dhost[1], ethernet_header->ether_dhost[2], ethernet_header->ether_dhost[3], ethernet_header->ether_dhost[4], ethernet_header->ether_dhost[5]);
    printf("frame length: %d bytes\n", len);
}