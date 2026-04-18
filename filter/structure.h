#include <stdint.h>

#pragma pack(push,1)
struct ip_header_ {
    uint8_t vl; // version + header length
    uint8_t type_service;
    uint16_t total_length; //bytes
    uint16_t identification;
    uint16_t fo; //flags + fragment offset
    uint8_t ttl; //seconds
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
}; // 20 bytes

struct udp_header_ {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length; // udp header + payload length
    uint16_t checksum;
};
#pragma pack(pop)
