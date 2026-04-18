#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pcap.h>
#include "structure.h"

#define LEN_IP_HEADER 20
#define LEN_UDP_HEADER 8
#define LEN_PAYLOAD 32 // bytes


uint16_t set_checksum(unsigned char* packet, uint8_t len){

    uint32_t sum = 0;

    for(int i = 0; len > i; i++){
        sum += htons(packet[i]);
        if(sum > 0xffff){
            sum = (sum & 0xffff) + 1;
        }
    }

    return htons(~sum);

}

int main(int argc, char** argv){

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    char* interface = "enp0s3";

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if(!handle){
        fprintf(stderr, "Error handler: %s\n", errbuf);
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
    udp->checksum = set_checksum(packet, LEN_IP_HEADER);
    
    if(pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "Error packet: %s\n", pcap_geterr(handle));
        return 1;
    }

    printf("packet UDP!\n");

    pcap_close(handle);


    return 0;
}
