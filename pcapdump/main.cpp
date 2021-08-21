//
//  main.cpp
//  pcapdump
//
//  Created by LARRYHOU on 2021/8/12.
//

#include <iostream>
#include <fstream>
#include "engine/client.hpp"
#include <vector>
#include <string>

struct Arguments {
    std::map<std::string,std::string> options;
    std::vector<std::string> others;
};

Arguments parse_arguments(int argc, const char **argv)
{
    Arguments args;
    for (auto i = 0; i < argc; i++)
    {
        auto v = argv[i];
        if (*v == '-')
        {
            while(*v == '-') {v++;}
            assert(argv[i+1][0] != '-');
            args.options[v] = argv[++i];
        }
        else
        {
            args.others.push_back(argv[i]);
        }
    }
    
    return args;
}

std::string human(uint64_t v)
{
    char s[16];
    static const int SCALE = 1024;
    if (v < 1000) { sprintf(s, "%5llu ", v); return s; }
    
    auto m = v;
    auto i = 0, r = 0;
    while (m >= 1000)
    {
        r = m % SCALE;
        m /= SCALE;
        ++i;
    }
    static const char MARK[] = " KMGTP";
    
    sprintf(s, "%5.1f%c", (m + float(r) / SCALE), MARK[i]);
    return s;
}

int tcpsum(Arguments &args)
{
    auto filename = args.options["o"];
    if (filename.empty()) { filename = "tcpsum.csv"; }
    std::fstream fs;
    fs.open(filename, std::ios::out | std::ios::binary);
    
    std::map<uint16_t, uint64_t> stats;
    struct timeval base;
    gettimeofday(&base, NULL);
    struct timeval tick;
    using addr_t = std::pair<uint32_t, uint16_t>;
    std::map<std::pair<uint32_t, uint16_t>, uint32_t> offsets;
    pcapdump::Client client([&](std::shared_ptr<const pcapdump::Packet> packet) {
        if (packet->tcp)
        {
            auto &ts = packet->header->ts;
            auto tcp = packet->tcp;
            auto &payload = packet->payload.at(tcp);
            auto elapse = (ts.tv_sec - base.tv_sec) * 1000000 + (ts.tv_usec - base.tv_usec);
            fs << std::to_string(elapse) << ',';
            fs << std::to_string(tcp->src_port) << ',';
            fs << std::to_string(tcp->dst_port) << ',';
            fs << std::to_string(payload.size) << ',';
            
            std::pair<uint32_t, uint16_t> srcent;
            std::pair<uint32_t, uint16_t> dstent;
            if (packet->ethernet->ether_type == pcapdump::kInternetIPv6)
            {
                srcent.first = *(uint32_t *)(((pcapdump::IPv6 *)packet->internet)->src_addr+12);
                dstent.first = *(uint32_t *)(((pcapdump::IPv6 *)packet->internet)->dst_addr+12);
            }
            else
            {
                srcent.first = *(uint32_t *)((pcapdump::IPv4 *)packet->internet)->src_addr;
                dstent.first = *(uint32_t *)((pcapdump::IPv4 *)packet->internet)->dst_addr;
            }
            srcent.second = tcp->src_port;
            dstent.second = tcp->dst_port;
            
            uint32_t srcoff = 0; {
                auto iter = offsets.find(srcent);
                if (iter == offsets.end()) { offsets[srcent] = srcoff = tcp->sequence; } else {
                    if (iter->second > tcp->sequence) { iter->second = 0; } else { srcoff = iter->second; }
                }
            }
            
            uint32_t dstoff = 0; {
                auto iter = offsets.find(dstent);
                if (iter == offsets.end()) { if (tcp->acknowlegement) { offsets[dstent] = dstoff = tcp->acknowlegement;} } else {
                    if (tcp->acknowlegement && tcp->acknowlegement < iter->second) { iter->second = 0; } else { dstoff = iter->second; }
                }
            }
            
            if (tcp->syn) { fs << 'S'; }
            if (tcp->fin) { fs << 'F'; }
            if (tcp->rst) { fs << 'R'; }
            if (tcp->psh) { fs << 'P'; }
            if (tcp->ack) { fs << 'A'; }
            fs << ',';
            fs << std::to_string(tcp->sequence - srcoff) << ',';
            fs << std::to_string(tcp->acknowlegement - dstoff) << ',';
            fs << std::to_string(tcp->window) << ',';
            fs << std::endl;
            
            stats[tcp->src_port] += payload.size;
            if (tick.tv_sec == 0) { tick = ts; } else {
                if (ts.tv_sec > tick.tv_sec)
                {
                    auto interval = (double)(ts.tv_sec - tick.tv_sec + (ts.tv_usec - tick.tv_usec) * 1e-6);
                    std::cout << ' ' << '\r' << std::flush;
                    for (auto iter = stats.begin(); iter != stats.end(); iter++)
                    {
                        std::cout << iter->first << ':' << human((uint64_t)((double)iter->second/interval)) << "/s  " << std::flush;
                        iter->second = 0;
                    }
                    tick = ts;
                }
            }
        }
    });
    
    return client.start(args.options["i"].c_str(), args.options["f"].c_str());
}

int main(int argc, const char * argv[])
{
    auto command = argv[1];
    auto args = parse_arguments(argc-2, argv+2);
    if (!strcmp(command, "sum")) { return tcpsum(args); }
    return 110;
}
