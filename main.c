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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

// define __USE_MISC is for netinet/ip.h 
// to vscode be able to see what is inside structure
// if not defined, doest throw any errors,
#define __USE_MISC 1 

#include <pcap/pcap.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/ip6.h>
#include <netinet/in.h>

#include <netinet/ip.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/icmp6.h>


#include <net/if.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include <signal.h>

#include "prints.h"
#include "filterBuilder.h"

// Global variables
int header_length;
pcap_t* handle;
int linkhdrlen;
int packets; 

//for comandline arguments
int port = -1;
bool mldSetted = false;
bool ndpSetted = false;
bool icmp6Setted = false;
bool noneFilter = false;

// general variable - descriptor
// global due to signal function
pcap_t* pcap_descriptor;

/**
clear the pcap_descriptor and print stats
*/
void stopCapture() {
    // stats of packets
    struct pcap_stat stats;

    // print the stats (if some exist)
    if (pcap_stats(pcap_descriptor, &stats) >= 0) {
        printf("Packet statistics:\n");
        printf("%d packets received\n", stats.ps_recv);
        printf("%d packets dropped\n", stats.ps_drop);
    }

    // close the pcap descriptor
    pcap_close(pcap_descriptor);
    exit(EXIT_SUCCESS);
}

/**
    Establishes pcap_descriptor with filtering and returnes it.
*/
pcap_t* createPcapHandle(const char *device, const char* filter_expression) {
    // error buffer for pcap_functions
    char errbuf[PCAP_ERRBUF_SIZE];

    // variables for the lookupnet function (we wont use source_ip)
    uint32_t  source_ip, netmask;

    // variable for findalldevs function
    pcap_if_t *devs = NULL;

    // struct for filtering
    struct bpf_program  bpf;

    // If no device is selected, get the first one. This should not get executed.
    if (device != NULL) {
        if (pcap_findalldevs(&devs,errbuf)) {
            printf("pcap_findalldevs(): %s\n", errbuf);
            return NULL;
        }
        //strcpy(device, devs[0].name);
    }

    // Open the device for live capture.
    if ((pcap_descriptor = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf)) == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // get network device source IP address and netmask
    if (pcap_lookupnet(device, &source_ip, &netmask, errbuf) < 0) {
        printf("pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    // convert the filter expression into a  packet filter binary
    // we will get the bpf struct, used for filtering, based on our filter expression
    if (pcap_compile(pcap_descriptor, &bpf, (char *) filter_expression, 0, netmask)) {
        printf("pcap_compile(): %s\n", pcap_geterr(pcap_descriptor));
        return NULL;
    }

    // assign the packet filter to the given libpcap socket
    if (pcap_setfilter(pcap_descriptor, &bpf) < 0) {
        printf("pcap_setfilter(): %s\n", pcap_geterr(pcap_descriptor));
        return NULL;
    }

    return pcap_descriptor;
}

void startCapture(pcap_t* pcap_descriptor, int packet_number, pcap_handler func) {
    // dlt enum (link-layer header type)
    int link_type; 

    // determine the datalink layer type (ethernet / slip)
    if ((link_type = pcap_datalink(pcap_descriptor)) < 0) {
        printf("pcap_datalink(): %s\n", pcap_geterr(pcap_descriptor));
        return;
    }

    // Set the datalink layer header size.
    switch (link_type) {
        case DLT_NULL:
            header_length = 4;
            break;

        case DLT_EN10MB:
            header_length = 14;
            break;

        case DLT_SLIP:
        case DLT_PPP:
            header_length = 24;
            break;

        case DLT_LINUX_SLL:
            header_length = 16;
            break;

        default:
            printf("Unsupported datalink (%d)\n", link_type);
            return;
    }

    // start capturing packet_number
    if (pcap_loop(pcap_descriptor, packet_number, func, 0) < 0) {
        printf("pcap_loop() failed: %s\n", pcap_geterr(pcap_descriptor));
    }
}

/* 
Callback function for pcap_loop(), which process recieved packets.
Function checks if packet is ipv4 or ipv6 and what protocol.
Prints timestamp, data of packet, packet and ipv6 address.
*/
void processPacket(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);


int main (int argc, char*argv[]){

    //usage:
    // ./ipk-sniffer [-i interface | --interface interface] 
    // {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]}
    // [--arp] [--ndp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}

    // interface name (device)
    char interface[256] = "";


    // filter string for pcap_compile and others
    char filter_expression[256] = "";

    // number of packets to sniff
    int num_of_packets = 0;

    // port filter
    char port_number[20] = "port ";

    //calling fucntion for building filter string and setting port, mldSetted, ndpSetted
    filterBuilder(argc, argv, interface, filter_expression, &num_of_packets, port_number, &port, &mldSetted, &ndpSetted, &icmp6Setted);

    if (strcmp(filter_expression, "") == 0) {
        noneFilter = true;
        printf("Protocols not specified, printing all content.\n\n");
    }

    int num = num_of_packets;

    // following  functions from libpcap
    if ((pcap_descriptor = createPcapHandle(interface, filter_expression))) {
        //connect the signals to the ending function
        signal(SIGINT, stopCapture);
        signal(SIGQUIT, stopCapture);
        signal(SIGTERM, stopCapture);
        
        // run the sniffing
        startCapture(pcap_descriptor, num, (pcap_handler) processPacket);

        stopCapture();
    }
    exit(EXIT_SUCCESS);
}

void processPacket(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    //unused
    (void) args;

    // for packet printing, proto checks
    int size = header->len;
    const struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    unsigned short ip_len = (ip_header->ihl) * 4;

    // for type ivp4 / ipv6 / arp
    const struct ether_header *ethernet_header = (struct ether_header *)packet;

    //for apr frames
    struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header) + ip_len);
    
    //for port prints
    const struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_len);
    const struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_len);
    
    // for ipv6 and ipv4 prints
    const struct ip6_hdr *ip6_header;
    struct icmp6_hdr *icmp_hdr;
    struct ip *ip = (struct ip *)(packet + sizeof(struct ether_header));

    printTime();

    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP)// ETHERTYPE is IPV4
    { 

        int protocol = ip_header->protocol;
        
        if (protocol == 1){// ICMPv4 IPV4
            printEthHdr(packet, size);
            printf("src IP: %s\n", inet_ntoa(ip->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
            printf("\n");
            printPacket(packet, size);
        } else if (protocol == 2){ // IGMP
            printEthHdr(packet, size);
            printf("src IP: %s\n", inet_ntoa(ip->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
            printf("\n");
            printPacket(packet, size);
        } else if (protocol == 6) {// TCP IPV4
            printEthHdr(packet, size);
            printf("src IP: %s\n", inet_ntoa(ip->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
            if (port != -1)
            {
                printf("src port: %d\n", ntohs(tcp_header->th_sport));
                printf("dst port: %d\n", ntohs(tcp_header->th_dport));
            }
            printf("\n");
            printPacket(packet, size);
        } else if (protocol == 17) { // UDP IPV4
            printEthHdr(packet, size);
            printf("src IP: %s\n", inet_ntoa(ip->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
            if (port != -1)
            {
                printf("src port: %d\n", ntohs(udp_header->uh_dport));
                printf("dst port: %d\n", ntohs(udp_header->uh_dport));
            }
            printf("\n");
            printPacket(packet, size);
        } else if (noneFilter){
            printEthHdr(packet, size);
            printf("src IP: %s\n", inet_ntoa(ip->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
            printf("\n");
            printPacket(packet, size);
        }
    }
    else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IPV6)// if ETHERTYPE is IPV6
    { 
        
        ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ethhdr));
        int protocol = ip6_header->ip6_nxt;
        
            
        if (protocol == 6) // TCP IPV6
        {
            printEthHdr(packet, size);
            printIpv6(&ip6_header->ip6_src, true);
            printIpv6(&ip6_header->ip6_dst, false);
            if (port != -1)
            {
                printf("src port: %d\n", ntohs(tcp_header->th_sport));
                printf("dst port: %d\n", ntohs(tcp_header->th_dport));
            }
            printf("\n");
            printPacket(packet, size);
        }
        else if (protocol == 17) // UDP IPV6
        { 
            printEthHdr(packet, size);
            printIpv6(&ip6_header->ip6_src, true);
            printIpv6(&ip6_header->ip6_dst, false);
            if (port != -1)
            {
                printf("src port: %d\n", ntohs(udp_header->uh_sport));
                printf("dst port: %d\n", ntohs(udp_header->uh_dport));
            }
            printf("\n");
            printPacket(packet, size);
        }
        else if (protocol == 58) //IPPROTO_ICMPV6
        { 
            
            icmp_hdr = (struct icmp6_hdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr)); 
            
            //ICMPv6 ECHO REPLY and REQUEST
            if (icmp_hdr->icmp6_type == ICMP6_ECHO_REQUEST && icmp6Setted) { //128
                printEthHdr(packet, size);
                printIpv6(&ip6_header->ip6_src, true);
                printIpv6(&ip6_header->ip6_dst, false);
                printf("\n");
                printPacket(packet, size);                                    
            } else if (icmp_hdr->icmp6_type == ICMP6_ECHO_REPLY && icmp6Setted) { //129
                printEthHdr(packet, size);
                printIpv6(&ip6_header->ip6_src, true);
                printIpv6(&ip6_header->ip6_dst, false);
                printf("\n");
                printPacket(packet, size);                
            } 

            //ICMPv6 MLD subsets
            else if (icmp_hdr->icmp6_type == MLD_LISTENER_QUERY && mldSetted) { //130
                printEthHdr(packet, size);
                printIpv6(&ip6_header->ip6_src, true);
                printIpv6(&ip6_header->ip6_dst, false);
                printf("\n");
                printPacket(packet, size);                
            } else if (icmp_hdr->icmp6_type == MLD_LISTENER_REPORT && mldSetted) { //131
                printEthHdr(packet, size);
                printIpv6(&ip6_header->ip6_src, true);
                printIpv6(&ip6_header->ip6_dst, false);
                printf("\n");
                printPacket(packet, size);                
            } else if (icmp_hdr->icmp6_type == MLD_LISTENER_REDUCTION && mldSetted) { //132 could be refering to DONE?
                printEthHdr(packet, size);
                printIpv6(&ip6_header->ip6_src, true);
                printIpv6(&ip6_header->ip6_dst, false);
                printf("\n");
                printPacket(packet, size);
            } else if (icmp_hdr->icmp6_type == 143 && mldSetted) { //Version 2 Multicast Listener Report
                printEthHdr(packet, size);
                printIpv6(&ip6_header->ip6_src, true);
                printIpv6(&ip6_header->ip6_dst, false);
                printf("\n");
                printPacket(packet, size);
            }  
            
            //ICMPv6 NDP subsets
            else if (icmp_hdr->icmp6_type == ND_ROUTER_SOLICIT && ndpSetted) {//133
                printEthHdr(packet, size);
                printIpv6(&ip6_header->ip6_src, true);
                printIpv6(&ip6_header->ip6_dst, false);
                printf("\n");
                printPacket(packet, size);                
            }  else if (icmp_hdr->icmp6_type == ND_ROUTER_ADVERT && ndpSetted) {//134
                printEthHdr(packet, size);
                printIpv6(&ip6_header->ip6_src, true);
                printIpv6(&ip6_header->ip6_dst, false);
                printf("\n");
                printPacket(packet, size);                
            }  else if (icmp_hdr->icmp6_type == ND_NEIGHBOR_SOLICIT && ndpSetted) {//135
                printEthHdr(packet, size);
                printIpv6(&ip6_header->ip6_src, true);
                printIpv6(&ip6_header->ip6_dst, false);
                printf("\n");
                printPacket(packet, size);                
            }  else if (icmp_hdr->icmp6_type == ND_NEIGHBOR_ADVERT && ndpSetted) {//136
                printEthHdr(packet, size);
                printIpv6(&ip6_header->ip6_src, true);
                printIpv6(&ip6_header->ip6_dst, false);
                printf("\n");
                printPacket(packet, size);                
            }  else if (icmp_hdr->icmp6_type == ND_REDIRECT && ndpSetted) {//137
                printEthHdr(packet, size);
                printIpv6(&ip6_header->ip6_src, true);
                printIpv6(&ip6_header->ip6_dst, false);
                printf("\n");
                printPacket(packet, size);                
            } else if (noneFilter){
                printEthHdr(packet, size);
                printf("src IP: %s\n", inet_ntoa(ip->ip_src));
                printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
                printf("\n");
                printPacket(packet, size);
            }
            printf("\n"); 
        } else if (noneFilter){
                printEthHdr(packet, size);
                printf("src IP: %s\n", inet_ntoa(ip->ip_src));
                printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
                printf("\n");
                printPacket(packet, size);
        }
    }
    else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_ARP) // 0x0806 ARP
    { 
        
        char srcIP[16], destIP[16];
        inet_ntop(AF_INET, &(arp->arp_spa), srcIP, sizeof(srcIP));
        inet_ntop(AF_INET, &(arp->arp_tpa), destIP, sizeof(destIP));
        printEthHdr(packet, size);
        printf("src IP: %s\n", srcIP);
        printf("dst IP: %s\n", destIP);
        printf("\n");
        printPacket(packet, size);
    } else if (noneFilter){
    
        printEthHdr(packet, size);
        printf("src IP: %s\n", inet_ntoa(ip->ip_src));
        printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
        printf("\n");
        printPacket(packet, size);
    }
}
