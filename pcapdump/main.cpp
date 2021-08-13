//
//  main.cpp
//  pcapdump
//
//  Created by LARRYHOU on 2021/8/12.
//

#include <iostream>
#include "core.hpp"

void monitor(std::shared_ptr<const pcapdump::Packet> packet)
{
    auto &payload = packet->payload.at(packet->transport);
    if (packet->tcp)
    {
        auto tcp = packet->tcp;
        printf("tcp seq=%u ack=%u len=%d\n", tcp->sequence, tcp->acknowlegement, payload.size);
    }
}

int main(int argc, const char * argv[])
{
    pcapdump::Client client(monitor);
    return client.start("en1", "tcp and port 443");
}
