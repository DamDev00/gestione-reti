#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "structure.h"

#define DEFAULT_SNAPLEN 256
#define CAPACITY 5
#define SIZE 10

struct Bucket {
    char ip[16];
    int level;
    time_t timestamp;
    struct Bucket* next;
};

struct Bucket* table[SIZE];

int counter_packets = 0;


void print_help();
void process_packet(unsigned char* user, const struct pcap_pkthdr* h, 
    const unsigned char* packet) {
    
    struct ip_header_* header = (struct ip_header_*) packet;
    int protocol = header->protocol;

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
