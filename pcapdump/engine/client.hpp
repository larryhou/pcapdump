//
//  client.hpp
//  pcapdump
//
//  Created by LARRYHOU on 2021/8/13.
//

#ifndef pcapdump_client_hpp
#define pcapdump_client_hpp

#include <map>

#include "protocol.hpp"
#include "stream.hpp"

namespace pcapdump {
struct Packet {
    std::shared_ptr<Ethernet> ethernet;
    std::shared_ptr<Internet> internet;
    std::shared_ptr<Transport> transport;
    std::shared_ptr<TCP> tcp;
    std::shared_ptr<UDP> udp;
    
    const struct pcap_pkthdr *header;
    std::map<void*, RawBytes> payload;
};

using PacketObserver = std::function<void(std::shared_ptr<const Packet>)>;

enum PcapMagic { kPcapMagicNano = 0xA1B23C4D, kPcapMagicMicro = 0xA1B2C3D4 };

class Client {
    char __errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *__handle;
    
public:
    PacketObserver observer;
    bpf_u_int32 addr;
    bpf_u_int32 mask;
    
public:
    Client(PacketObserver observer): observer(observer), __handle(nullptr) {}
    ~Client() { stop(); }
    bool start(const char* device, const char* filter);
    bool start(const char* filename);
    void stop();
    std::shared_ptr<Packet> parse(const struct pcap_pkthdr *header, MemoryStream &stream);
};

}

#endif /* pcapdump_client_hpp */
