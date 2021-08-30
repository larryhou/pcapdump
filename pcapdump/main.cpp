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

int sum_live(Arguments &args)
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
            auto &payload = packet->payload.at(tcp.get());
            auto elapse = (ts.tv_sec - base.tv_sec) * 1000000 + (ts.tv_usec - base.tv_usec);
            fs << std::to_string(elapse) << ',';
            fs << std::to_string(tcp->src_port) << ',';
            fs << std::to_string(tcp->dst_port) << ',';
            fs << std::to_string(payload.size) << ',';
            
            std::pair<uint32_t, uint16_t> srcent;
            std::pair<uint32_t, uint16_t> dstent;
            if (packet->ethernet->type == pcapdump::kInternetIPv6)
            {
                auto ipv6 = (pcapdump::IPv6 *)packet->internet.get();
                srcent.first = *(uint32_t *)(ipv6->src_addr+12);
                dstent.first = *(uint32_t *)(ipv6->dst_addr+12);
            }
            else
            {
                auto ipv4 = (pcapdump::IPv4 *)packet->internet.get();
                srcent.first = *(uint32_t *)ipv4->src_addr;
                dstent.first = *(uint32_t *)ipv4->dst_addr;
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
    
    return client.start(args.options["i"].c_str(), args.options["f"].c_str())? 0 : 1;
}

int sum_pcap(Arguments &args)
{
    char buf[32];
    auto index = 0;
    std::map<std::pair<uint16_t, uint32_t>, int> locator;
    std::map<uint16_t, struct timeval> timestamps;
    std::map<uint16_t, uint8_t> scales;
    uint64_t basetime;
    pcapdump::Client client([&](std::shared_ptr<const pcapdump::Packet> packet) {
        if (packet->tcp)
        {
            auto tcp = packet->tcp;
            auto &pts = packet->header->ts;
            auto &data = packet->payload.at(tcp.get());
            auto winscale = tcp->options.find(pcapdump::TCPOption::kTypeWindowScale);
            if (winscale != tcp->options.end()) {
                scales[tcp->src_port] = ((pcapdump::TCPOptionWindowScale *)winscale->second.get())->scale;
            }
            if (!basetime) { basetime = pts.tv_sec; }
            sprintf(buf, "%.6f", (pts.tv_sec - basetime) + pts.tv_usec * 1e-6);
            std::cout << '#' << index << ' ';
            std::cout << buf << ' ';
            std::cout << tcp->src_port << " => " << tcp->dst_port << " seq=" << tcp->sequence << " ack=" << tcp->acknowlegement << ' ';
            std::cout << "len=" << data.size << ' ';
            std::cout << "win=" << tcp->window << '*' << (int)scales[tcp->src_port] << ' ';
            
            std::cout << '<';
            if (tcp->syn) { std::cout << "SYN|"; }
            if (tcp->fin) { std::cout << "FIN|"; }
            if (tcp->rst) { std::cout << "RST|"; }
            if (tcp->ack) { std::cout << "ACK|"; }
            if (tcp->psh) { std::cout << "PSH|"; }
            std::cout << '\b' << '>';
            auto entity = std::make_pair(tcp->src_port, tcp->sequence + data.size);
            locator[entity] = index;
            auto match = locator.find(std::make_pair(tcp->dst_port, tcp->acknowlegement));
            if (match != locator.end()) { std::cout << " :" << match->second; }
            std::cout << ' ';
            auto sack = tcp->options.find(pcapdump::TCPOption::kTypeSACK);
            if (sack != tcp->options.end())
            {
                auto opt = (pcapdump::TCPOptionSACK *)sack->second.get();
                std::cout << '<';
                for (auto iter = opt->sacks.begin(); iter != opt->sacks.end(); iter++)
                {
                    std::cout << iter->first << ':' << iter->second << ',';
                }
                std::cout << '\b' << '>';
                std::cout << ' ';
            }
            
            auto time = timestamps.find(tcp->src_port);
            if (time != timestamps.end())
            {
                auto elapse = (pts.tv_sec - time->second.tv_sec) * 1000000 + (pts.tv_usec - time->second.tv_usec);
                std::cout << elapse;
            } else {
                std::cout << '-';
            }
            
            std::cout << std::endl;
            timestamps[tcp->src_port] = pts;
            index++;
        }
    });
    
    return client.start(args.options["f"].c_str())? 0 : 1;
}

int main(int argc, const char * argv[])
{
    /* sleep(1); */
    
    auto command = argv[1];
    auto args = parse_arguments(argc-2, argv+2);
    if (!strcmp(command, "sum")) { return sum_live(args); }
    else if (!strcmp(command, "sumpcap")) { return sum_pcap(args); }
    return 110;
}
