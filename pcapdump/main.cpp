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
    std::map<char,std::string> options;
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
            assert(strlen(v) == 2);
            args.options[v[1]] = argv[++i];
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
    auto filename = args.options['o'];
    if (filename.empty()) { filename = "tcpsum.csv"; }
    std::fstream fs;
    fs.open(filename, std::ios::out | std::ios::binary);
    
    std::map<uint16_t, uint64_t> stats;
    struct timeval base;
    gettimeofday(&base, NULL);
    struct timeval tick;
    pcapdump::Client client([&](std::shared_ptr<const pcapdump::Packet> packet){
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
            if (tcp->syn) { fs << 'S'; }
            if (tcp->fin) { fs << 'F'; }
            if (tcp->rst) { fs << 'R'; }
            if (tcp->psh) { fs << 'P'; }
            if (tcp->ack) { fs << 'A'; }
            fs << std::endl;
            
            stats[tcp->src_port] += payload.size;
            if (tick.tv_sec == 0) { tick = ts; } else {
                if (ts.tv_sec > tick.tv_sec)
                {
                    auto interval = (double)(ts.tv_sec - tick.tv_sec + (ts.tv_usec - tick.tv_usec) / 1E+6);
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
    
    return client.start(args.options['i'].c_str(), args.options['f'].c_str());
}

int main(int argc, const char * argv[])
{
    auto command = argv[1];
    auto args = parse_arguments(argc-2, argv+2);
    if (!strcmp(command, "sum")) { return tcpsum(args); }
    return 110;
}
