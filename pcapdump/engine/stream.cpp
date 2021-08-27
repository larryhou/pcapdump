//
//  stream.cpp
//  pcapdump
//
//  Created by LARRYHOU on 2021/8/23.
//

#include "stream.hpp"
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/stat.h>

using namespace pcapdump;

MmapFile::MmapFile(): __fp(nullptr), __data(nullptr), __size(0) { }
MmapFile::~MmapFile() { close(); }

bool MmapFile::open(const char *name)
{
    struct stat s;
    if (stat(name, &s)) {return false;}
    __size = s.st_size;
    
    __fp = fopen(name, "r");
    if (!__fp) { return false; }
    
    __data = (const char*)mmap(nullptr, __size, PROT_READ, MAP_PRIVATE, fileno(__fp), 0);
    if (__data == MAP_FAILED) {
        fclose(__fp);
        return false;
    }
    
    return true;
}

void MmapFile::close()
{
    if ((__data && __data != MAP_FAILED) && __size)
    {
        munmap((void *)__data, __size);
        __data = nullptr;
        __size = 0;
    }
    
    if (__fp)
    {
        fclose(__fp);
        __fp = nullptr;
    }
}

MemoryStream::MemoryStream(const char *data, size_t size): __data(data), __size(size), endian(kEndianLittle), __bitpos(0), __cursor(data) { }

void MemoryStream::seek(std::ios::off_type offset, std::ios::seekdir whence)
{
    switch (whence)
    {
        case std::ios::cur:
            __cursor += offset;
            break;
            
        case std::ios::end:
            __cursor = (__data + __size) + offset;
            break;
            
        default:
            __cursor = __data + offset;
            break;
    }
}
