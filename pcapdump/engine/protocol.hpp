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

#include "stream.hpp"

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

struct Ethernet {
    char dst_mac_addr[6];
    char src_mac_addr[6];
    InternetType type;
    
    void decode(MemoryStream &stream);
};

struct Internet {};
struct IPv4: public Internet {
    uint version:4;
    uint ihl:4;
    uint dscp:6;
    uint ecn:2;
    uint16_t length;
    uint16_t identifier;
    uint flags:3;
    uint fragment_offset:13;
    uint ttl:8;
    ProtoType protocol:8;
    uint16_t checksum;
    char src_addr[4];
    char dst_addr[4];
    
    void decode(MemoryStream &stream);
};

using IPv4Ptr = std::shared_ptr<IPv4>;

struct IPv6: public Internet {
    uint version:4;
    uint traffic_class:8;
    uint flow_label:12;
    uint16_t payload_length;
    ProtoType next_header:8;
    int hop_limit:8;
    char src_addr[16];
    char dst_addr[16];
    
    void decode(MemoryStream &stream);
};

using IPv6Ptr = std::shared_ptr<IPv6>;

struct Transport {};
struct TCP: public Transport {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence;
    uint32_t acknowlegement;
    uint data_offset:4;
    int reserved:3;
    bool ecn:1;
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
    
    void decode(MemoryStream &stream);
};

using TCPPtr = std::shared_ptr<TCP>;

struct UDP: public Transport {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
    
    void decode(MemoryStream &stream);
};

using UDPPtr = std::shared_ptr<UDP>;

}



#endif /* pcapdump_protocol_hpp */
