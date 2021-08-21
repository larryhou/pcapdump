//
//  protocol.hpp
//  pcapdump
//
//  Created by LARRYHOU on 2021/8/12.
//

#ifndef pcapdump_protocol_hpp
#define pcapdump_protocol_hpp

#include <cstdint>
#include <pcap.h>

namespace pcapdump {
enum ProtoType:unsigned char {
    kProtoHopOpt = 0,
    kProtoDestination = 60,
    kProtoRouting = 43,
    kProtoFragment = 44,
    kProtoAuthencation = 51,
    kProtoSecurity = 50,
    kProtoMobility = 135,
    kProtoTCP = 6,
    kProtoUDP = 17,
    kProtoICMP = 1,
    kProtoICMPv6 = 58,
    kProtoNoNext = 59,
};

enum InternetType:uint16_t {
    kInternetIPv4 = 0x0800,
    kInternetIPv6 = 0x86DD,
};

struct RawBytes {
    const char* data;
    int size;
    
    RawBytes slice(int i) { return RawBytes{data+i, size-i}; }
    RawBytes slice(int i, int n) { return RawBytes{data+i, n}; }
};

struct Ethernet {
    char dst_mac_addr[6];
    char src_mac_addr[6];
    InternetType ether_type;
};

struct Internet {};
struct IPv4: public Internet {
    uint ihl:4;
    uint version:4;
    uint ecn:2;
    uint dscp:6;
    uint16_t length;
    uint16_t identifier;
    uint flags:3;
    uint fragment_offset:13;
    uint ttl:8;
    ProtoType protocol:8;
    uint16_t checksum;
    u_char src_addr[4];
    u_char dst_addr[4];
};

struct IPv6: public Internet {
    uint version:4;
    uint traffic_class:8;
    uint flow_label:12;
    uint16_t payload_length;
    ProtoType next_header:8;
    int hop_limit:8;
    u_char src_addr[16];
    u_char dst_addr[16];
};

struct Transport {};
struct TCP: public Transport {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence;
    uint32_t acknowlegement;
    bool ecn:1;
    int reserved:3;
    uint data_offset:4;
    bool fin:1;
    bool syn:1;
    bool rst:1;
    bool psh:1;
    bool ack:1;
    bool urg:1;
    bool ece:1;
    bool cwr:1;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

struct UDP: public Transport {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

}



#endif /* pcapdump_protocol_hpp */
