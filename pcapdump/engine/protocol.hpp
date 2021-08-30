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
#include <vector>
#include <map>

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
struct TCPOption {
    enum Type: uint8_t {
        kTypeEOL = 0,
        kTypeNOP = 1,
        kTypeMSS = 2,
        kTypeWindowScale = 3,
        kTypeSACKPermitted = 4,
        kTypeSACK = 5,
        kTypeTimestamp = 8,
    };
    
    Type type;
    
    static std::shared_ptr<TCPOption> decode(MemoryStream &stream);
};

struct TCPOptionEOL: public TCPOption {};
struct TCPOptionNOP: public TCPOption {};
struct TCPOptionMSS: public TCPOption { uint16_t mss; };
struct TCPOptionWindowScale: public TCPOption { uint8_t scale; };
struct TCPOptionSACKPermitted: public TCPOption {};
struct TCPOptionSACK: public TCPOption { std::vector<std::pair<uint32_t, uint32_t>> sacks; };
struct TCPOptionTimestamp: public TCPOption { uint32_t mine, echo; };

struct TCP: public Transport {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence;
    uint32_t acknowlegement;
    uint data_offset:4;
    int reserved:3;
    int ecn:1;
    int fin:1;
    int syn:1;
    int rst:1;
    int psh:1;
    int ack:1;
    int urg:1;
    int ece:1;
    int cwr:1;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
    
    std::map<TCPOption::Type,std::shared_ptr<TCPOption>> options;
    
    void decode(MemoryStream &stream);
};

struct UDP: public Transport {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
    
    void decode(MemoryStream &stream);
};

}



#endif /* pcapdump_protocol_hpp */
