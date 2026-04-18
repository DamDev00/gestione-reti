#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "structure.h"

#define DEFAULT_SNAPLEN 256

int counter_packets = 0;

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

void print_help();
void process_packet(unsigned char* user, const struct pcap_pkthdr* h, 
    const unsigned char* packet) {
    
    uint8_t protocol = packet[9];
    printf("protocol: %d\n", protocol);

    if(protocol == 17){
        counter_packets++;
        printf("==================\n");
        printf("Packet #%d\n", counter_packets);
        printf("Captured length: %u\n", h->caplen);
        printf("Actual length: %u\n", h->len);
        printf("==================\n\n");
    }
    
}

int main(int argc, char** argv){

    char* interface = "enp0s3";
    pcap_t* handle;
    int promisc = 1;
    int snaplen = DEFAULT_SNAPLEN;
    char errbuf[PCAP_ERRBUF_SIZE];


    if((handle = pcap_open_live(interface, snaplen, promisc, 500, errbuf)) == NULL){
        printf("pcap_open_live: %s\n", errbuf);
        return -1;
    }

    printf("handler ready\n");

    /*struct bpf_program fp;
    char* filter = "udp";

    if(pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1){
        fprintf(stderr, "Error compile: %s\n", pcap_geterr(handle));
        return -1;
    }

    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "error set filter: %s\n", pcap_geterr(handle));
        return -1;
    }*/

    printf("filter on UDP protocol!\n");

    pcap_loop(handle, 0, process_packet, NULL);

    return 0;
}

void print_help(){
    printf("Input parameters invalid!\n");
    printf("========================\n");
    printf("Options: -i [listen interface] [name interface]\n");
    printf("========================\n");
}
