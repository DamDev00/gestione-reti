#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <stdbool.h>
#include "structure.h"

#define DEFAULT_SNAPLEN 256
#define CAPACITY 5
#define TTL_IP_IN_BUCKET 3 //seconds
#define SIZE 10

struct Bucket {
    char ip[16];
    int level;
    time_t timestamp;
    struct Bucket* next;
};

struct Bucket* table[SIZE] = {0};

int counter_packets = 0;


void print_help();
uint8_t hash(char* ip);
void process_packet(unsigned char* user, const struct pcap_pkthdr* h, 
    const unsigned char* packet) {
    
    struct ip_header_* header = (struct ip_header_*) packet;

    struct in_addr addr;
    addr.s_addr = header->src_ip;
    char* ip = inet_ntoa(addr);
    int protocol = header->protocol;

    if(protocol == 17){

        uint8_t index = hash(ip);
        
        if(table[index] == 0){

            // bucket vuoto

            struct Bucket* b = (struct Bucket*)malloc(sizeof(struct Bucket));
            if(b == NULL){
                fprintf(stderr, "Error malloc on line %d\n", __LINE__);
                exit(-1);
            }
            strcpy(b->ip, ip);
            b->level = 1;
            b->timestamp = time(NULL);
            b->next = NULL;
            table[index] = b;
        } else {
            struct Bucket* b = table[index];
            bool check = false;
            if(strcmp(b->ip, ip) == 0){

                // ip trovato
                check = true;
                b->level++;
                if(b->level > CAPACITY){
                    // inserisco nella blacklist
                }
            } else {

                // cerco l'ip nel bucket
                b = b->next;
                while(b != NULL){
                    
                    b = b->next;
                }
            }

            if(!check){
                //collisione
               struct Bucket* b = (struct Bucket*)malloc(sizeof(struct Bucket));
                if(b == NULL){
                    fprintf(stderr, "Error malloc on line %d\n", __LINE__);
                    exit(-1);
                } 
                strcpy(b->ip, ip);
                b->level = 1;
                b->timestamp = time(NULL);
                struct Bucket* temp = table[index];
                while(temp != NULL){
                    temp = temp->next;
                }
                temp = b;
            }
            
        }
        
        counter_packets++;
        printf("==================\n");
        printf("Packet #%d\n", counter_packets);
        printf("Captured length: %u\n", h->caplen);
        printf("Actual length: %u\n", h->len);
        printf("ip: %s\n", ip);
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

uint8_t hash(char* ip){
    
    uint8_t sum = 0;
    
    for(char* token = strtok(strdup(ip), "."); token != NULL; token = strtok(NULL, ".")){
        sum += atoi(token);
    }

    return sum % (SIZE - 1);

}

void print_help(){
    printf("Input parameters invalid!\n");
    printf("========================\n");
    printf("Options: -i [listen interface] [name interface]\n");
    printf("========================\n");
}
