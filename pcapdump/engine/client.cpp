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
    auto ptr = (const char*)packet;
    auto client = (Client *)args;
    auto p = std::make_shared<Packet>();
    p->header = header;
    auto ethernet = (Ethernet *)ptr;
    ethernet->ether_type = (InternetType)ntohs(static_cast<uint16_t>(ethernet->ether_type));
    p->ethernet = ethernet;
    
    ptr += sizeof(Ethernet);
    p->payload[p->ethernet] = RawBytes{ptr, (int)(header->len-sizeof(Ethernet))};
    
    int transport = 0;
    ProtoType protocol;
    switch (p->ethernet->ether_type) {
        case kInternetIPv4:
        {
            auto ipv4 = (IPv4 *)ptr;
            auto part = ipv4->flags;
            ipv4->flags = ipv4->fragment_offset >> 10;
            ipv4->fragment_offset = part << 8 | (ipv4->fragment_offset & 0x300) << 2 | (ipv4->fragment_offset & 0xFF);
            ipv4->length = ntohs(ipv4->length);
            ipv4->identifier = ntohs(ipv4->identifier);
            ipv4->checksum = ntohs(ipv4->checksum);
            auto hdrlen = ipv4->ihl << 2;
            if (hdrlen < 20) {return;}
            p->internet = ipv4;
            ptr += hdrlen;
            transport = ipv4->length - hdrlen;
            p->payload[ipv4] = RawBytes{ptr,transport};
            protocol = ipv4->protocol;
        } break;
        
        case kInternetIPv6:
        {
            auto ipv6 = (IPv6 *)ptr;
            auto part = ipv6->version;
            ipv6->version = ipv6->traffic_class >> 4;
            part = ipv6->traffic_class & 0xF;
            ipv6->traffic_class = part << 4 | (ipv6->flow_label >> 8);
            ipv6->flow_label = part << 8 | (ipv6->flow_label & 0xFF);
            ipv6->payload_length = ntohs(ipv6->payload_length);
            protocol = ipv6->next_header;
            ptr += sizeof(IPv6);
            p->payload[ipv6] = RawBytes{ptr,ipv6->payload_length};
            auto beg = ptr;
            while (true)
            {
                switch (protocol) {
                    case kProtoHopOpt:
                    case kProtoRouting:
                    case kProtoDestination:
                    case kProtoAuthencation:
                    {
                        protocol = *(ProtoType *)ptr++;
                        ptr += *(unsigned char *)ptr+1;
                    } break;
                    
                    case kProtoFragment:
                    {
                        protocol = *(ProtoType *)ptr++;
                        ptr += 7;
                    } break;
                        
                    case kProtoSecurity: return;
                    case kProtoMobility: return;
                    case kProtoNoNext: return;
                    
                    default:
                        transport = ipv6->payload_length - static_cast<int>(ptr-beg);
                        break;
                }
            }
        } break;
        default: return;
    }
    
    switch (protocol)
    {
        case kProtoTCP:
        {
            auto tcp = (TCP *)ptr;
            tcp->src_port = ntohs(tcp->src_port);
            tcp->dst_port = ntohs(tcp->dst_port);
            tcp->sequence = ntohl(tcp->sequence);
            tcp->acknowlegement = ntohl(tcp->acknowlegement);
            tcp->window = ntohs(tcp->window);
            tcp->checksum = ntohs(tcp->checksum);
            tcp->urgent_pointer = ntohs(tcp->urgent_pointer);
            auto hdrlen = tcp->data_offset << 2;
            ptr += hdrlen;
            p->payload[tcp] = RawBytes{ptr, transport-hdrlen};
            p->transport = tcp;
            p->tcp = tcp;
        } break;
            
        case kProtoUDP:
        {
            auto udp = (UDP *)ptr;
            udp->src_port = ntohs(udp->src_port);
            udp->dst_port = ntohs(udp->dst_port);
            udp->length = ntohs(udp->length);
            udp->checksum = ntohs(udp->checksum);
            ptr += sizeof(UDP);
            p->payload[udp] = RawBytes{ptr, static_cast<int>(transport-sizeof(UDP))};
            p->transport = udp;
            p->udp = udp;
        } break;
            
        default: return;
    }
    
    client->observer(p);
}

}

bool Client::start(const char *device, const char *filter)
{
    if (pcap_lookupnet(device, &addr, &mask, errbuf) == -1)
    {
        fprintf(stderr, "could not find device[%s]: %s", device, errbuf);
        return false;
    }
    
    handle = pcap_open_live(device, 2048, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "could not open device[%s]: %s", device, errbuf);
        return false;
    }
    
    if (filter != NULL && strlen(filter))
    {
        struct bpf_program program;
        if (pcap_compile(handle, &program, filter, 0, addr))
        {
            fprintf(stderr, "could not parse filter[%s]: %s", filter, errbuf);
            return false;
        }
        
        if (pcap_setfilter(handle, &program) == -1)
        {
            fprintf(stderr, "could not apply filter[%s]: %s", filter, errbuf);
            return false;
        }
    }
    
    return pcap_loop(handle, -1, process, (u_char *)this) == 0;
}

void Client::stop()
{
    if (handle != NULL) {
        pcap_breakloop(handle);
        handle = NULL;
    }
}
