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

/* 
Function to parse argumets to filter_expresion.
Also sets port, mldSetted, ndpSetted for further packet processing.
*/
int filterBuilder(int argcount, char*arg[], char interface[256], char filter_expression [256], int *num_of_packets, char port_number[20], int *port, bool *mldSetted, bool *ndpSetted, bool *icmp6Setted);