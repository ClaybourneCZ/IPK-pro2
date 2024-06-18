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

#define __USE_MISC 1
#include <pcap/pcap.h>
#include <getopt.h>

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

/* 
Function to print ipv6 address.
*/
void printIpv6(const struct in6_addr *addr, bool srcOrDest);

/* 
Function to print ethernet header.
Prints src MAC, dst MAC and frame length.
*/
void printEthHdr(const unsigned char *packet, int len);

/* 
Function to print packet data in rows: offset   hex   ascii.
*/
void printHexAsciiLine(const unsigned char *payload, int len, int offset);

/* 
Function to print timestamp.
*/
void printPacket(const unsigned char *buffer, int len);

/* 
Function to print timestamp.
*/
void printTime();

/* 
Function to print available interfaces.
*/
void printInterfaces();

/* 
Function to print help message.
*/
void printHelpMsg();