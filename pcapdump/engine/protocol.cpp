//
//  protocol.cpp
//  pcapdump
//
//  Created by LARRYHOU on 2021/8/27.
//

#include "protocol.hpp"
using namespace pcapdump;

void Ethernet::decode(MemoryStream &stream)
{
    stream.read(dst_mac_addr, sizeof(dst_mac_addr));
    stream.read(src_mac_addr, sizeof(src_mac_addr));
    type = stream.read<InternetType>();
}

void IPv4::decode(MemoryStream &stream)
{
    version = stream.read<uint>(4);
    ihl = stream.read<uint>(4);
    dscp = stream.read<uint>(6);
    ecn = stream.read<uint>(2);
    length = stream.read<uint16_t>();
    identifier = stream.read<uint16_t>();
    flags = stream.read<uint>(3);
    fragment_offset = stream.read<uint>(13);
    ttl = stream.read<uint>(8);
    protocol = stream.read<ProtoType>();
    checksum = stream.read<uint16_t>();
    stream.read(src_addr, sizeof(src_addr));
    stream.read(dst_addr, sizeof(dst_addr));
}

void IPv6::decode(MemoryStream &stream)
{
    version = stream.read<uint>(4);
    traffic_class = stream.read<uint>(8);
    flow_label = stream.read<uint>(12);
    payload_length = stream.read<uint16_t>();
    next_header = stream.read<ProtoType>();
    hop_limit = stream.read<int>(8);
    stream.read(src_addr, sizeof(src_addr));
    stream.read(dst_addr, sizeof(dst_addr));
}

std::shared_ptr<TCPOption> TCPOption::decode(MemoryStream &stream)
{
    std::shared_ptr<TCPOption> option;
    auto type = stream.read<TCPOption::Type>();
    switch (type)
    {
        case kTypeEOL:
            option = std::make_shared<TCPOptionEOL>();
            break;
        case kTypeNOP:
            option = std::make_shared<TCPOptionNOP>();
            break;
            
        case kTypeMSS:
        {
            assert(stream.read<uint8_t>() == 4);
            auto opt = std::make_shared<TCPOptionMSS>();
            opt->mss = stream.read<uint16_t>();
            option = opt;
        } break;
            
        case kTypeWindowScale:
        {
            assert(stream.read<uint8_t>() == 3);
            auto opt = std::make_shared<TCPOptionWindowScale>();
            opt->scale = stream.read<uint8_t>();
            option = opt;
        } break;
            
        case kTypeSACKPermitted:
        {
            assert(stream.read<uint8_t>() == 2);
            option = std::make_shared<TCPOptionSACKPermitted>();
        } break;
            
        case kTypeSACK:
        {
            auto num = stream.read<uint8_t>();
            auto opt = std::make_shared<TCPOptionSACK>();
            for (auto i = 0; i < (num - 2)/8; i++)
            {
                opt->sacks.push_back(std::make_pair(stream.read<uint32_t>(), stream.read<uint32_t>()));
            }
            
            option = opt;
        } break;
            
        case kTypeTimestamp:
        {
            assert(stream.read<uint8_t>() == 10);
            auto opt = std::make_shared<TCPOptionTimestamp>();
            opt->mine = stream.read<uint32_t>();
            opt->echo = stream.read<uint32_t>();
            option = opt;
        } break;
            
        default:
            assert(false);
            break;
    }
    
    if (option) { option->type = type; }
    
    return option;
}

void TCP::decode(MemoryStream &stream)
{
    auto offset = stream.tell();
    src_port = stream.read<uint16_t>();
    dst_port = stream.read<uint16_t>();
    sequence = stream.read<uint32_t>();
    acknowlegement = stream.read<uint32_t>();
    data_offset = stream.read<uint>(4);
    reserved = stream.read<int>(3);
    ecn = stream.read<int>(1) > 0;
    cwr = stream.read<int>(1) > 0;
    ece = stream.read<int>(1) > 0;
    urg = stream.read<int>(1) > 0;
    ack = stream.read<int>(1) > 0;
    psh = stream.read<int>(1) > 0;
    rst = stream.read<int>(1) > 0;
    syn = stream.read<int>(1) > 0;
    fin = stream.read<int>(1) > 0;
    window = stream.read<uint16_t>();
    checksum = stream.read<uint16_t>();
    urgent_pointer = stream.read<uint16_t>();
    
    options.clear();
    auto hdrlen = data_offset << 2;
    if (hdrlen > 20)
    {
        auto end = offset + hdrlen;
        while (stream.tell() < end)
        {
            auto opt = TCPOption::decode(stream);
            options[opt->type] = opt;
            assert(stream.tell() <= end);
            if (opt->type == TCPOption::kTypeEOL) {break;}
        }
    }
}

void UDP::decode(MemoryStream &stream)
{
    src_port = stream.read<uint16_t>();
    dst_port = stream.read<uint16_t>();
    length = stream.read<uint16_t>();
    checksum = stream.read<uint16_t>();
}
