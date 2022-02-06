#include "xbe_loader.hpp"
#include <FEXCore/Utils/Allocator.h>
#include <sys/mman.h>
#include "xbe.hpp"
#include <string.h>
#define ROUND_UP_4K(size) (((size) + 0xFFF) & (~0xFFF))
XBELoader::XBELoader(std::string &path)
{
    xbe = std::make_unique<XBE>(path);
}
XBELoader::XBELoader(const char *path)
{
    xbe = std::make_unique<XBE>(path);
}
XBELoader::~XBELoader() {}

uint64_t XBELoader::StackSize() const
{
    return xbe->header().pe_stack_commit();
}

uint64_t XBELoader::GetStackPointer()
{
    uint64_t result = reinterpret_cast<uint64_t>(FEXCore::Allocator::mmap(reinterpret_cast<void *>(0x04000000 - StackSize()), StackSize(), PROT_READ | PROT_WRITE, MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    return result + StackSize();
}

uint64_t XBELoader::DefaultRIP() const
{
    return xbe->entry();
}

bool XBELoader::MapMemory(const MapperFn &mapper, const UnmapperFn &unmapper) 
{

    auto header = xbe->header();
    const auto base_addr = header.base();
    auto ptr = xbe->ptr();
    // map header
    {
        auto sizeof_image_header = ROUND_UP_4K(header.sizeof_image_header());
        auto mapped = mapper(
            (void*)base_addr, 
            sizeof_image_header, 
            PROT_READ|PROT_WRITE, 
            MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, 
            -1, 
            0 
        );
        memcpy(mapped, (void*)ptr, sizeof_image_header);
    }
    //map sections
    {
        for ( auto section : xbe->section_headers()) {
            auto vaddr = section.virtual_addr();
            auto vsize = section.virtual_size();
            auto raddr = section.raw_addr();
            auto rsize = section.sizeof_raw();
            auto flags = section.flags();
            u32 prot = PROT_READ;
            prot|= flags.executable ? PROT_EXEC  : 0;
            prot|= flags.writable   ? PROT_WRITE : 0;
            auto mapped = mmap(
                (void*)vaddr,
                ROUND_UP_4K(vsize),
                PROT_READ|PROT_WRITE,
                MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED,
                -1,
                0
            );
            memcpy(mapped, (void*)(ptr + raddr), rsize );
        }
    }
    return true;
}