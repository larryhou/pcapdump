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

void TCP::decode(MemoryStream &stream)
{
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
}

void UDP::decode(MemoryStream &stream)
{
    src_port = stream.read<uint16_t>();
    dst_port = stream.read<uint16_t>();
    length = stream.read<uint16_t>();
    checksum = stream.read<uint16_t>();
}
