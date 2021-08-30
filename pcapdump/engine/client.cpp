//
//  client.cpp
//  pcapdump
//
//  Created by LARRYHOU on 2021/8/13.
//

#include "client.hpp"

using namespace pcapdump;

namespace {
void process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    MemoryStream stream((char *)packet, (size_t)header->len);
    stream.endian = kEndianNetwork;
    
    auto client = (Client *)args;
    auto p = client->parse(header, stream);
    if (p) { client->observer(p); }
}

}

std::shared_ptr<Packet> Client::parse(const struct pcap_pkthdr *header, MemoryStream &stream)
{
    auto p = std::make_shared<Packet>();
    p->header = header;
    auto ethernet = std::make_shared<Ethernet>();
    ethernet->decode(stream);
    p->ethernet = ethernet;
    p->payload[p->ethernet.get()] = stream.slice(header->len-sizeof(Ethernet));
    
    int transport = 0;
    ProtoType protocol;
    switch (p->ethernet->type) {
        case kInternetIPv4:
        {
            auto offset = stream.tell();
            auto ipv4 = std::make_shared<IPv4>();
            ipv4->decode(stream);
            auto hdrlen = ipv4->ihl << 2;
            if (hdrlen < 20) {return nullptr;}
            p->internet = ipv4;
            stream.seek(hdrlen - (stream.tell() - offset));
            transport = ipv4->length - hdrlen;
            p->payload[ipv4.get()] = stream.slice(transport);
            protocol = ipv4->protocol;
        } break;
        
        case kInternetIPv6:
        {
            auto ipv6 = std::make_shared<IPv6>();
            ipv6->decode(stream);
            protocol = ipv6->next_header;
            p->internet = ipv6;
            p->payload[ipv6.get()] = stream.slice(ipv6->payload_length);
            auto offset = stream.tell();
            while (true)
            {
                switch (protocol) {
                    case kProtoHopOpt:
                    case kProtoRouting:
                    case kProtoDestination:
                    case kProtoAuthencation:
                    {
                        protocol = stream.read<ProtoType>();
                        stream.seek(stream.read<char>()-1);
                    } break;
                    
                    case kProtoFragment:
                    {
                        protocol = stream.read<ProtoType>();
                        stream.seek(7);
                    } break;
                        
                    case kProtoSecurity: return nullptr;
                    case kProtoMobility: return nullptr;
                    case kProtoNoNext: return nullptr;
                    
                    default:
                        transport = ipv6->payload_length - (int)(stream.tell() - offset);
                        break;
                }
            }
        } break;
        default: return nullptr;
    }
    
    switch (protocol)
    {
        case kProtoTCP:
        {
            auto offset = stream.tell();
            auto tcp = std::make_shared<TCP>();
            tcp->decode(stream);
            auto hdrlen = tcp->data_offset << 2;
            stream.seek(hdrlen - (stream.tell() - offset));
            p->payload[tcp.get()] = stream.slice(transport-hdrlen);
            p->transport = tcp;
            p->tcp = tcp;
        } break;
        
        case kProtoUDP:
        {
            auto offset = stream.tell();
            auto udp = std::make_shared<UDP>();
            udp->decode(stream);
            p->payload[udp.get()] = stream.slice(transport - (stream.tell() - offset));
            p->transport = udp;
            p->udp = udp;
        } break;
        
        default: return nullptr;
    }
    
    return p;
}

bool Client::start(const char *filename)
{
    MmapFile mf;
    if (!mf.open(filename)) {return false;}
    MemoryStream stream(mf);
    
    auto micro = true;
    auto magic = stream.read<uint32_t>();
    switch (magic)
    {
        case kPcapMagicNano:
        {
            micro = false;
            stream.endian = kEndianLittle;
        } break;
            
        case kPcapMagicMicro:
        {
            micro = true;
            stream.endian = kEndianLittle;
        } break;
            
        default:
        {
            magic = magic >> 24 | magic << 24 | (magic >> 8 & 0x00FF00) | (magic << 8 & 0xFF0000);
            switch (magic)
            {
                case kPcapMagicNano:
                {
                    micro = false;
                    stream.endian = kEndianBig;
                } break;
                    
                case kPcapMagicMicro:
                {
                    micro = true;
                    stream.endian = kEndianBig;
                } break;
                default: return false;
            }
        } break;
    }
    
    auto major = stream.read<uint16_t>();
    auto minor = stream.read<uint16_t>();
    
    stream.read<uint32_t>(); // reserved
    stream.read<uint32_t>(); // reserved
    
    auto snaplen = stream.read<uint32_t>();
    
    auto fcs = stream.read<int>(3);
    auto pad = stream.read<int>(1);
    auto linktype = stream.read<uint32_t>(28);
    
    printf("# version=%d.%d snaplen=%d fcs=0x%x pad=%d linktype=0x%7x\n", major, minor, snaplen, fcs, pad, linktype);
    
    while (!stream.eof())
    {
        struct pcap_pkthdr header;
        header.ts.tv_sec = stream.read<uint32_t>();
        header.ts.tv_usec = stream.read<uint32_t>();
        if (!micro) { header.ts.tv_usec /= 1000; }
        header.caplen = stream.read<uint32_t>();
        header.len = stream.read<uint32_t>();
        auto offset = stream.tell();
        auto endian = stream.endian;
        stream.endian = kEndianNetwork;
        auto packet = parse(&header, stream);
        stream.endian = endian;
        if (packet) { observer(packet); }
        stream.seek(offset + header.caplen, std::ios::beg);
        if (pad) { for (auto i = 0; i < fcs; i++) { stream.read<char>(); } }
    }
    return true;
}

bool Client::start(const char *device, const char *filter)
{
    if (pcap_lookupnet(device, &addr, &mask, __errbuf) == -1)
    {
        fprintf(stderr, "could not find device[%s]: %s", device, __errbuf);
        return false;
    }
    
    __handle = pcap_open_live(device, 2048, 1, 1000, __errbuf);
    if (__handle == NULL)
    {
        fprintf(stderr, "could not open device[%s]: %s", device, __errbuf);
        return false;
    }
    
    if (filter != NULL && strlen(filter))
    {
        struct bpf_program program;
        if (pcap_compile(__handle, &program, filter, 0, addr))
        {
            fprintf(stderr, "could not parse filter[%s]: %s", filter, __errbuf);
            return false;
        }
        
        if (pcap_setfilter(__handle, &program) == -1)
        {
            fprintf(stderr, "could not apply filter[%s]: %s", filter, __errbuf);
            return false;
        }
    }
    
    return pcap_loop(__handle, -1, process, (u_char *)this) == 0;
}

void Client::stop()
{
    if (__handle != NULL) {
        pcap_breakloop(__handle);
        __handle = NULL;
    }
}
