//
//  core.hpp
//  pcapdump
//
//  Created by LARRYHOU on 2021/8/13.
//

#ifndef core_hpp
#define core_hpp

#include "protocol.hpp"
#include <map>

namespace pcapdump {
struct Packet {
    Ethernet *ethernet;
    Internet *internet;
    Transport *transport;
    TCP *tcp;
    UDP *udp;
    
    const struct pcap_pkthdr *header;
    std::map<void*, RawBytes> payload;
};

using PacketObserver = std::function<void(std::shared_ptr<const Packet>)>;

class Client {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
public:
    PacketObserver observer;
    bpf_u_int32 addr;
    bpf_u_int32 mask;
    
public:
    Client(PacketObserver observer): observer(observer) {}
    bool start(const char* device, const char* filter);
    void stop();
};

}

#endif /* core_hpp */
