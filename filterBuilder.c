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

#include "filterBuilder.h"

int filterBuilder(int argcount, char*arg[], char interface[256], char filter_expression [256], int *num_of_packets, char port_number[20], int *port, bool *mldSetted, bool *ndpSetted, bool *icmp6Setted){
    // boolean for tcp and udp connections
    bool TCPset = false;
    bool UDPset = false;

    // boolean for port dest and source
    bool portSourceSet = false;
    bool portDestSet = false;
    bool portSet = false;


    // boolean for other arguments and their conflicts
    bool icmp4Set = false;
    bool icmp6Set = false;
    bool arpSet = false;

    bool igmpSet = false;
    bool mldSet = false;
    bool ndpSet = false;
    bool numSet = false;

    // bool to check whether the interface was added
    bool interfaceSet = false;

    // check parameters for filter appending
    char checkcmp[256] = ""; 

    // Get the command line options, if any
    for (int i = 0; i < argcount; i++){   

        if( strcmp(arg[i],"-h") == 0){
            printHelpMsg();
            exit(0);
            
        }        
        //interface        
        if( strcmp(arg[i],"-i") == 0 || strcmp(arg[i],"--interface") == 0 ){
            if(argcount <= 2){
                printf("Interface is not specified.\n");
                printInterfaces();
                exit(EXIT_FAILURE);
            }
            
            if(interfaceSet){
                printf("Args are in conflict.\n\nFollow the right usage:");
                printHelpMsg();
                exit(EXIT_FAILURE);  
            }
            strcpy(interface, arg[++i]);

            interfaceSet = true;
            
        }

        //port or port dst port src
        if( strcmp( arg[i], "-p") == 0  ){


            if ( portSet || portDestSet || portSourceSet) {
                printf("Args are in conflict.\n\nFollow the right usage:");
                printHelpMsg();
                exit(EXIT_FAILURE);
            }
            *port = 1;
            portSet = true;
            strcat(port_number, arg[++i]); //example: port 22
            
                       
        }
        if( strcmp(arg[i], "--port-destination") == 0  ){
            
            if( portSet || portDestSet ){
                printf("Args are in conflict.\n\nFollow the right usage:");
                printHelpMsg();
                exit(EXIT_FAILURE);  
            }
            *port = 1;
            portDestSet = true;   
            if( portSourceSet == true) strcat(port_number, " or dst port ");
            if( portSourceSet == false) strcpy(port_number, "dst port ");
            strcat(port_number, arg[++i]); //example: dst port 22
                   
        }
        if( strcmp(arg[i], "--port-source") == 0  ){
            if( portSet || portSourceSet ){
                printf("Args are in conflict.\n\nFollow the right usage:");
                printHelpMsg();
                exit(EXIT_FAILURE);  
            }
            *port = 1;
            portSourceSet = true;  
            if( portDestSet == true) strcat(port_number, " or src port ");
            if( portDestSet == false) strcpy(port_number, "src port ");
            strcat(port_number, arg[++i]); //example: src port 22
                 
        }

        // tcp
        if( strcmp(arg[i], "-t") == 0  ||  strcmp(arg[i], "--tcp") == 0  ){
            if(TCPset ){
                printf("Args are in conflict.\n\nFollow the right usage:");
                printHelpMsg();
                exit(EXIT_FAILURE);  
            }
            TCPset = true;
            if (i == argcount-1){
                strcat(checkcmp, "tcp");
            }            
        }

         // udp
        if(  strcmp(arg[i], "-u") == 0  ||  strcmp(arg[i], "--udp") == 0  ){
            if(UDPset){
                printf("Args are in conflict.\n\nFollow the right usage:");
                printHelpMsg();
                exit(EXIT_FAILURE);  
            }
            UDPset = true;
            if (i == argcount-1){
                strcat(checkcmp, "udp");
            } 
        }        

        // icmp
        if( strcmp(arg[i], "--icmp4") == 0  ){
            if(icmp4Set){
                printf("Args are in conflict.\n\nFollow the right usage:");
                printHelpMsg();
                exit(EXIT_FAILURE);  
            } 
            
            icmp4Set = true;
            if (i == argcount-1){
                strcat(checkcmp, "icmp");
            }
        } 

        // icmp6
        if( strcmp(arg[i], "--icmp6") == 0  ){
            if(icmp6Set){
                printf("Args are in conflict.\n\nFollow the right usage:");
                printHelpMsg();
                exit(EXIT_FAILURE);  
            } 
            icmp6Set = true;
            *icmp6Setted = true;
            if (i == argcount-1){
                strcat(checkcmp, "icmp6");
            }
        }

        // arp
        if( strcmp(arg[i], "--arp") == 0 ){
            if(arpSet){
                printf("Args are in conflict.\n\nFollow the right usage:");
                printHelpMsg();
                exit(EXIT_FAILURE);  
            } 
            arpSet = true;
            if (i == argcount-1){
                strcat(checkcmp, "arp");
            }

        }

        // ndp
        if( strcmp(arg[i], "--ndp") == 0  ){
            if(ndpSet){
                printf("Args are in conflict.\n\nFollow the right usage:");
                printHelpMsg();
                exit(EXIT_FAILURE);  
            } 
            *ndpSetted = true; 
            ndpSet = true; 
            if (i == argcount-1){
                strcat(checkcmp, "ndp");
            }   
        }

        // imgp
        if( strcmp(arg[i], "--igmp") == 0  ){
            if(igmpSet){
                printf("Args are in conflict.\n\nFollow the right usage:");
                printHelpMsg();
                exit(EXIT_FAILURE);  
            }  
            igmpSet = true;
            if (i == argcount-1){
                strcat(checkcmp, "igmp");
            }
        }

        // mld
        if( strcmp(arg[i], "--mld") == 0  ){
            if(mldSet){
                printf("Args are in conflict.\n\nFollow the right usage:");
                printHelpMsg();
                exit(EXIT_FAILURE);  
            }   
            *mldSetted = true;  
            mldSet = true;    
            if (i == argcount-1){
                strcat(checkcmp, "mld");
            }   
            
        }

        // num of packets
        if( strcmp(arg[i], "-n") == 0){
            if(numSet){
                printf("Args are in conflict.\n\nFollow the right usage:");
                printHelpMsg();
                exit(EXIT_FAILURE);  
            } 
            numSet = true;
            *num_of_packets = atoi(arg[++i]);
            
            if (i == argcount-1){

                int j = i;
                j = j-2;
                if( strcmp(arg[j], "--igmp") == 0) strcat(checkcmp, "igmp");
                if( strcmp(arg[j], "--icmp4") == 0) strcat(checkcmp, "icmp");
                if( strcmp(arg[j], "--icmp6") == 0) strcat(checkcmp, "icmp6");
                if( strcmp(arg[j], "--arp") == 0) strcat(checkcmp, "arp");
            }
            
        }
        
    }

    //if none number input set it to 1;
    if (*num_of_packets == 0){
        *num_of_packets = 1;
    }

    //check if the interface was added
    if (!interfaceSet) {
        printf("Interface is not specified.\n");
        printInterfaces();
        exit(EXIT_FAILURE);
    }    

    // here i love and hate C at same time

    // arg isnt last 
    if (icmp4Set && ((strcmp(checkcmp, "icmp") != 0) || portSet  || portSourceSet  || portDestSet ) ){
        strcat(filter_expression, "icmp or ");
        icmp4Set = false;
    }
    if ((( icmp6Set ) && ((( strcmp(checkcmp, "icmp6") != 0) && ( strcmp(checkcmp, "mld") != 0) && ( strcmp(checkcmp, "ndp") != 0) ) || portSet  || portSourceSet  || portDestSet ))){
        strcat(filter_expression, "icmp6 or ");
        if (icmp6Set) icmp6Set = false;
        if (mldSet) mldSet = false;
        if (ndpSet) ndpSet = false;
    }
    if ( mldSet  && ((( strcmp(checkcmp, "icmp6") != 0) && ( strcmp(checkcmp, "mld") != 0) && ( strcmp(checkcmp, "ndp") != 0) ) || portSet  || portSourceSet  || portDestSet )){
        strcat(filter_expression, "icmp6 or ");
        if (icmp6Set) icmp6Set = false;
        if (mldSet) mldSet = false;
        if (ndpSet) ndpSet = false;
    }
    if (ndpSet  && ((( strcmp(checkcmp, "icmp6") != 0) && ( strcmp(checkcmp, "mld") != 0) && ( strcmp(checkcmp, "ndp") != 0) ) || portSet  || portSourceSet  || portDestSet )) {
        strcat(filter_expression, "icmp6 or ");
        if (icmp6Set) icmp6Set = false;
        if (mldSet) mldSet = false;
        if (ndpSet) ndpSet = false;
    }
    if (arpSet && ((strcmp(checkcmp, "arp") != 0) || portSet  || portSourceSet  || portDestSet  )){
        strcat(filter_expression, "arp or ");
        arpSet = false;
    } 
    if (igmpSet && ((strcmp(checkcmp, "igmp") != 0) || portSet  || portSourceSet  || portDestSet )){
        strcat(filter_expression, "igmp or ");
        igmpSet = false;
    }

    // ar is last but port set
    if (icmp4Set && (strcmp(checkcmp, "icmp") == 0) &&( portSet || portSourceSet  || portDestSet ) ) {
        strcat(filter_expression, "icmp");
        icmp4Set = false;
    }
    if ((icmp6Set && (strcmp(checkcmp, "icmp6") == 0) && ( portSet || portSourceSet  || portDestSet ) )  ||
        (mldSet && (strcmp(checkcmp, "mld") == 0))  ||
        (ndpSet && (strcmp(checkcmp, "ndp") == 0))) {
        strcat(filter_expression, "icmp6");
        icmp6Set = false;
        mldSet = false;
        ndpSet = false;
    }
    if (arpSet && (strcmp(checkcmp, "arp") == 0) && ( portSet || portSourceSet  || portDestSet ) ) {
        strcat(filter_expression, "arp");
        arpSet = false;
        printf("sem tu 2 \n");
    }
    if (igmpSet && (strcmp(checkcmp, "igmp") == 0) &&( portSet || portSourceSet  || portDestSet ) ) {
        strcat(filter_expression, "igmp");
        igmpSet = false;
    }

    // arg is last port not set
    if (icmp4Set && (strcmp(checkcmp, "icmp") == 0)) {
        strcat(filter_expression, "icmp");
        icmp4Set = false;
    }
    if ((icmp6Set && (strcmp(checkcmp, "icmp6") == 0))  ||
        (mldSet && (strcmp(checkcmp, "mld") == 0))  ||
        (ndpSet && (strcmp(checkcmp, "ndp") == 0))) {
        strcat(filter_expression, "icmp6");
        icmp6Set = false;
        mldSet = false;
        ndpSet = false;
    }
    if (arpSet && (strcmp(checkcmp, "arp") == 0)) {
        strcat(filter_expression, "arp");
        arpSet = false;
        printf("sem tu 2 \n");
    }
    if (igmpSet && (strcmp(checkcmp, "igmp") == 0)) {
        strcat(filter_expression, "igmp");
        igmpSet = false;
    }
        
    
    // finishing filter expresion, appending port/tcp/udp
    if( TCPset || UDPset || portSet || portSourceSet || portDestSet){

        if(!TCPset && !UDPset && (portSet || portSourceSet || portDestSet)){
            printf("Args are in conflict.\n\nFollow the right usage:");
            printHelpMsg();
            exit(EXIT_FAILURE);  
        }

        if (TCPset && !UDPset && strcmp(port_number, "port ") == 0 && strcmp(checkcmp, "tcp") == 0) strcat(filter_expression, " tcp");
        if (TCPset && !UDPset && strcmp(port_number, "port ") == 0 && strcmp(checkcmp, "tcp") != 0) strcat(filter_expression, " or tcp");
        if (UDPset && !TCPset && strcmp(port_number, "port ") == 0 && strcmp(checkcmp, "udp") == 0) strcat(filter_expression, " udp");
        if (UDPset && !TCPset && strcmp(port_number, "port ") == 0 && strcmp(checkcmp, "udp") == 0) strcat(filter_expression, " or udp");
        if (TCPset && UDPset && strcmp(port_number, "port ") == 0 && (strcmp(checkcmp, "udp") == 0 || strcmp(checkcmp, "tcp") == 0)) strcat(filter_expression, "tcp or udp");
        if (TCPset && UDPset && strcmp(port_number, "port ") == 0 && (strcmp(checkcmp, "udp") != 0 && strcmp(checkcmp, "tcp") != 0)) strcat(filter_expression, " or tcp or udp");


        if (TCPset && !UDPset && strcmp(port_number, "port ") != 0) strcat(filter_expression, "(tcp and ");
        if (UDPset && !TCPset && strcmp(port_number, "port ") != 0) strcat(filter_expression, "(udp and ");
        if (TCPset && UDPset && strcmp(port_number, "port ") != 0) strcat(filter_expression, "((tcp or udp) and ");
        if (strcmp(port_number, "port ") != 0){
            if(portSourceSet && portDestSet ) strcat(filter_expression, "(");
            strcat(filter_expression, port_number); 
            if(portSourceSet && portDestSet ) strcat(filter_expression, ")");
            if (TCPset || UDPset) strcat(filter_expression, ")");
        }

    }

    return 0;
}