//
//  stream.hpp
//  pcapdump
//
//  Created by LARRYHOU on 2021/8/23.
//

#ifndef pcapdump_stream_hpp
#define pcapdump_stream_hpp

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ios>

namespace pcapdump {
class MmapFile {
    const char *__data;
    size_t __size;
    FILE *__fp;
    
public:
    MmapFile();
    ~MmapFile();
    bool open(const char* name);
    void close();
    const char* data() const { return __data; }
    size_t size() const { return __size; }
};

struct RawBytes {
    const char* data;
    int size;
    
    RawBytes slice(int i) { return RawBytes{data+i, size-i}; }
    RawBytes slice(int i, int n) { return RawBytes{data+i, n}; }
};

enum Endian {
    kEndianLittle = 0,
    kEndianBig = 1,
    kEndianNetwork = 1,
};

class MemoryStream {
    const char *__data;
    size_t __size;
    const char* __cursor;
    int __bitpos;
    
public:
    Endian endian;
    
public:
    MemoryStream(const char* data, size_t size);
    MemoryStream(MmapFile &f): MemoryStream(f.data(), f.size()) {}
    
    template<typename T>
    T read(int bits);
    
    template<typename T>
    T read();
    
    const char* ptr() { return __cursor; }
    bool eof() { return __cursor >= __data + __size; }
    
    size_t tell() { return __cursor - __data; }
    void seek(std::ios::off_type offset, std::ios::seekdir whence = std::ios::cur);
    
    void align() { if (__bitpos) { __bitpos = 0; __cursor++; } }
    void align(int size)
    {
        align();
        auto p = __cursor - __data;
        auto t = (p + size - 1) & ~(size - 1);
        __cursor += p - t;
    }
    
    void read(char *buf, int size)
    {
        memcpy(buf, __cursor, size);
        __cursor += size;
    }
    
    RawBytes slice(size_t size) { return RawBytes{__cursor, (int)size}; }
};

template<typename T>
T MemoryStream::read(int bits)
{
    T v = 0;
    while (bits > 0)
    {
        auto r = 8 - __bitpos;
        auto n = r <= bits ? r : bits;
        auto b = *__cursor;
        auto p = b >> (r - n) & (1 << n) - 1;
        v |= p << (bits - n);
        bits -= n;
        __bitpos += n;
        if (__bitpos == 8)
        {
            __bitpos=0;
            __cursor++;
        }
    }
    return v;
}

template<typename T>
T MemoryStream::read()
{
    if (__bitpos > 0) { align(); }
    
    T v;
    if (!endian)
    {
        v = *(T *)__cursor;
        __cursor += sizeof(T);
    }
    else
    {
        auto p = (char *)&v + sizeof(T);
        for (auto i = 0; i < sizeof(T); i++) { memset(--p, *__cursor++, 1); }
    }
    
    return v;
}

}

#endif /* pcapdump_stream_hpp */
