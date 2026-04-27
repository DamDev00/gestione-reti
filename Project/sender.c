#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pcap.h>
#include "structure.h"


void extract_params(char** params, short int n);
void print_help();

#define LEN_INT 64
#define LEN_IP_HEADER 20
#define LEN_UDP_HEADER 8
#define LEN_PAYLOAD 32 // bytes

char* interface = NULL;

int main(int argc, char** argv){

    if(argc == 1){
        fprintf(stderr,"Error parameters!\n");
        print_help();
        return (-1);
    }

    extract_params(argv, argc);
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int promisc = 1;

    if(!(handle = pcap_open_live(interface, PCAP_ERRBUF_SIZE, promisc,500, errbuf))){
        fprintf(stderr, "Error handler %s\n", errbuf);
        return -1;
    }

    unsigned char packet[LEN_IP_HEADER+LEN_UDP_HEADER+LEN_PAYLOAD];
    memset(packet, 0, sizeof(packet));

    struct ip_header_ *ip = (struct ip_header_*)packet;

    ip->vl = 0x45; // Versione 4 + IHL=5
    ip->type_service = 0;
    ip->total_length = htons(sizeof(packet));
    ip->identification = htons(1234);
    ip->fo = 0;
    ip->ttl = 64;
    ip->protocol = 17; // UDP
    ip->checksum = 0; 
    ip->src_ip = inet_addr("192.168.1.100");
    ip->dst_ip = inet_addr("192.168.1.101");

    struct udp_header_* udp = (struct udp_header_*)(packet + sizeof(struct ip_header_));
    udp->src_port = htons(1234);
    udp->dst_port = htons(53);
    udp->length = htons(sizeof(struct udp_header_));
    udp->checksum = 0;
    
    if(pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "Error packet: %s\n", pcap_geterr(handle));
        return 1;
    }

    printf("Pacchetto inviato!\n");


    return 0;
}

void extract_params(char** params, short int n){

    for(int i = 0; n > i; i++){
        if(params[i][0] == '-'){
            switch(params[i][1]){
                case 'i': 
                    if(i+1 < n && params[i+1] != NULL){
                        interface = (char*)malloc(sizeof(LEN_INT));
                        if(interface == NULL){
                            fprintf(stderr, "Error malloc on line: %d\n", __LINE__);
                            exit(-1);
                        }
                    }
                    strcpy(interface, params[i+1]);
                    interface[sizeof(params[i+1])] = '\0';
                    if(interface == NULL){
                        fprintf(stderr, "Error params on line %d\n", __LINE__);
                        exit(-1);
                    }
                break; 
            }
        } else continue;
    }

}

void print_help(){
    printf("========================\n");
    printf("Syntax error!\n");
    printf("========================\n");
    printf("Options:\n");
    printf("-i [interface] -f [file address ip]\n");
}
