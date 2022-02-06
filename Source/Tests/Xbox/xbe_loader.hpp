#pragma once
#include <FEXCore/Core/CodeLoader.h>
#include <memory>
class XBE;
class XBELoader final: public FEXCore::CodeLoader {
public:
    XBELoader( std::string &path );
    XBELoader( const char *path );

    ~XBELoader();

    uint64_t StackSize() const final;

    uint64_t GetStackPointer() final;

    uint64_t DefaultRIP() const final;
  
    bool MapMemory(const MapperFn& Mapper, const UnmapperFn& Unmapper) final;

private:
    std::unique_ptr<XBE> xbe;

};