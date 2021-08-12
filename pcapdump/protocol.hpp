//
//  protocol.hpp
//  pcapdump
//
//  Created by LARRYHOU on 2021/8/12.
//

#ifndef protocol_hpp
#define protocol_hpp

#include <stdio.h>
#include <cstdint>

enum LayerType {
    kLayerHopOpt = 0,
    kLayerDestination = 60,
    kLayerRouting = 43,
    kLayerFragment = 44,
    kLayerAuthencation = 51,
    kLayerSecurity = 50,
    kLayerMobility = 135,
    kLayerTCP  = 6,
    kLayerUDP  = 17,
    kLayerICMP = 1,
    kLayerICMPv6 = 58,
};

struct Ethernet {
    char dst_mac_addr[6];
    char src_mac_addr[6];
    uint16_t ether_type;
};

struct IPv4 {
    char version:4;
    char ihl:4;
    char dscp:6;
    char ecn:2;
    uint16_t length;
    uint16_t identifier;
    char flags:3;
    uint16_t fragment_offset:13;
    char ttl;
    char protocol;
    uint16_t checksum;
    char src_addr[4];
    char dst_addr[4];
};

struct IPv6 {
    char version:4;
    char traffic_class:8;
    uint16_t flow_label:12;
    uint16_t payload_length;
    char next_header;
    char hop_limit;
    char src_addr[16];
    char dst_addr[16];
};

struct TCP {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence;
    uint32_t acknowledgment;
};

#endif /* protocol_hpp */
