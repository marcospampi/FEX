#include <iostream>
#include <fstream>
#include "xbe.hpp"

XBE::XBE(const char *path)
{
    std::ifstream file(path, std::ios::in);
    if ( !file.is_open() )
        throw std::runtime_error("Cannot open file!");
    file.seekg(0, std::ios::end);
    size_ = file.tellg();
    file.seekg(0, std::ios::beg);

    data_ = new u8[size_];
    file.read((char *)data_, size_);
}

XBE::~XBE() {
    delete[] data_;
}
bool XBE::is_debug() const  {
    return header().is_debug();
}
bool XBE::is_retail() const {
    return header().is_retail();
}
bool XBE::Header::is_retail() const {
    return !is_debug();
}
bool XBE::Header::is_debug() const {
    auto entry = this->entry();
    auto size = this->xbe.size();
    auto base = this->base();
    return ( entry ^ XBE::ENTRY_DEBUG_KEY) < (((base + size) &0xfff) << 1);
}
XBE::Header XBE::header() const
{
    return XBE::Header(data_,*this);
}
XBE::Certificate XBE::certificate() const {
    auto header = this->header();
    auto base = header.base();
    auto certificate_offset = header.certificate_addr() - base;
    return XBE::Certificate(data_ + certificate_offset);
}
std::vector<XBE::SectionHeader> XBE::section_headers() const {
    auto header = this->header();
    auto base = header.base();
    auto num_sections = header.sections();
    auto sections_offset = header.section_headers_addr() - base;
    std::vector<XBE::SectionHeader> sections;

    for ( int i = 0; i < num_sections; ++i ) {
        sections.push_back( XBE::SectionHeader(data_ + sections_offset + XBE::SectionHeader::SIZE * i) );
    }

    return sections;
}
std::vector<XBE::LibraryVersion> XBE::library_versions() const {
    auto header = this->header();
    auto base = header.base();
    auto num_libraries = header.library_versions();
    auto offset = header.library_versions_addr() - base;
    std::vector<XBE::LibraryVersion> sections;

    for ( int i = 0; i < num_libraries; ++i ) {
        sections.push_back( XBE::LibraryVersion(data_ + offset + XBE::LibraryVersion::SIZE * i) );
    }

    return sections;
}
XBE::Tls XBE::tls() const {
    auto header = this->header();
    auto base = header.base();
    auto offset = header.tls_addr() - base;
    return XBE::Tls(data_ + offset);
}



#define DECLARE_ME_LAZY(_class, _type, _method, _offset)   \
    _type _class::_method() const                          \
    {                                                      \
        return *reinterpret_cast<_type *>(data + _offset); \
    }
#define DECLARE_ME_LAZY_ARR(_class, _type, _method, _offset)   \
    _type& _class::_method() const                          \
    {                                                      \
        return *reinterpret_cast<_type *>(data + _offset); \
    }
#define COMMA ,
DECLARE_ME_LAZY(XBE::Header, u32, magic, 0);                       
DECLARE_ME_LAZY_ARR(XBE::Header, const std::array<u8 COMMA 256> , digsig, 4) 
DECLARE_ME_LAZY(XBE::Header, u32, base, 0x104)                          
DECLARE_ME_LAZY(XBE::Header, u32, sizeof_headers, 0x108 )                
DECLARE_ME_LAZY(XBE::Header, u32, sizeof_image, 0x10c)                  
DECLARE_ME_LAZY(XBE::Header, u32, sizeof_image_header, 0x110)           
DECLARE_ME_LAZY(XBE::Header, u32, timedate, 0x114)                      
DECLARE_ME_LAZY(XBE::Header, u32, certificate_addr, 0x118)              
DECLARE_ME_LAZY(XBE::Header, u32, sections, 0x11c)                      
DECLARE_ME_LAZY(XBE::Header, u32, section_headers_addr, 0x120)          
DECLARE_ME_LAZY(XBE::Header, XBE::Header::InitFlags, init_flags, 0x124)
DECLARE_ME_LAZY(XBE::Header, u32, entry, 0x128)

u32 XBE::entry() const { return header().entry() ^ (is_debug() ? XBE::ENTRY_DEBUG_KEY : XBE::ENTRY_RETAIL_KEY); }

DECLARE_ME_LAZY(XBE::Header, u32, tls_addr, 0x12c)
DECLARE_ME_LAZY(XBE::Header, u32, pe_stack_commit, 0x130)
DECLARE_ME_LAZY(XBE::Header, u32, pe_heap_reserve, 0x134)
DECLARE_ME_LAZY(XBE::Header, u32, pe_heap_commit, 0x138)
DECLARE_ME_LAZY(XBE::Header, u32, pe_base_addr, 0x13c)
DECLARE_ME_LAZY(XBE::Header, u32, pe_sizeof_image, 0x140)
DECLARE_ME_LAZY(XBE::Header, u32, pe_checksum, 0x144)
DECLARE_ME_LAZY(XBE::Header, u32, pe_timedate, 0x148)
DECLARE_ME_LAZY(XBE::Header, u32, debug_pathname_addr, 0x14c)
DECLARE_ME_LAZY(XBE::Header, u32, debug_filename_addr, 0x150)
DECLARE_ME_LAZY(XBE::Header, u32, debug_unicode_filename_addr,0x154 )
DECLARE_ME_LAZY(XBE::Header, u32, kernel_image_thunk_addr, 0x158)

//u32 XBE::Header::kernel_image_thunk_addr() const { 
//    std::cout << "going to crash" << std::endl;
//    return (*(reinterpret_cast<u32 *>(data + 0x158))) ^ (is_debug() ? XBE::KERNEL_DEBUG_KEY : XBE::KERNEL_RETAIL_KEY); 
//}

DECLARE_ME_LAZY(XBE::Header, u32, nonkernel_import_dir_addr, 0x15c)
DECLARE_ME_LAZY(XBE::Header, u32, library_versions, 0x160)
DECLARE_ME_LAZY(XBE::Header, u32, library_versions_addr, 0x164)
DECLARE_ME_LAZY(XBE::Header, u32, kernel_library_version_addr, 0x168)
DECLARE_ME_LAZY(XBE::Header, u32, xapi_library_version_addr, 0x16c )
DECLARE_ME_LAZY(XBE::Header, u32, logo_bitmap_addr, 0x170)
DECLARE_ME_LAZY(XBE::Header, u32, logo_bitmap_size, 0x174)


const std::array<u32,366>& XBE::thunk_table() const {
    auto header = this->header();
    auto base = header.base();
    auto thunk = header.kernel_image_thunk_addr() ^ (is_debug() ? XBE::KERNEL_DEBUG_KEY : XBE::KERNEL_RETAIL_KEY);

    return *(reinterpret_cast<std::array<u32,366>*>(data_ + (thunk - base)));
}

DECLARE_ME_LAZY(XBE::Certificate,u32,size, 0)                                                    
DECLARE_ME_LAZY(XBE::Certificate,u32,timedate, 0x4)                                                
DECLARE_ME_LAZY(XBE::Certificate,u32,titleid, 0x8)                                                 
DECLARE_ME_LAZY_ARR(XBE::Certificate,const std::array<u16 COMMA 40>, title_name, 0xc )                 
DECLARE_ME_LAZY_ARR(XBE::Certificate,const std::array<u32 COMMA 10>, alt_title_id, 0x5c )                  
DECLARE_ME_LAZY(XBE::Certificate, u32, allowed_media, 0x9c)                                            
DECLARE_ME_LAZY(XBE::Certificate, u32, game_region, 0xa0)                                              
DECLARE_ME_LAZY(XBE::Certificate, u32, game_ratings, 0xa4)                                             
DECLARE_ME_LAZY(XBE::Certificate, u32, disk_number, 0xa8)                                              
DECLARE_ME_LAZY(XBE::Certificate, u32, version, 0xac)                                                  
DECLARE_ME_LAZY_ARR(XBE::Certificate, const std::array<u8 COMMA 16>, lan_key, 0xb0 )                           
DECLARE_ME_LAZY_ARR(XBE::Certificate, const std::array<u8 COMMA 16>, sig_key, 0xc0 )                           
DECLARE_ME_LAZY_ARR(XBE::Certificate, const std::array<std::array<u8 COMMA 16> COMMA 16>, title_alt_sig_key, 0xd0)

DECLARE_ME_LAZY(XBE::SectionHeader, XBE::SectionHeader::Flags, flags, 0 )
DECLARE_ME_LAZY(XBE::SectionHeader, u32, virtual_addr, 0x4 )                         
DECLARE_ME_LAZY(XBE::SectionHeader, u32, virtual_size, 0x8 )                         
DECLARE_ME_LAZY(XBE::SectionHeader, u32, raw_addr, 0xC )                             
DECLARE_ME_LAZY(XBE::SectionHeader, u32, sizeof_raw, 0x10 )                           
DECLARE_ME_LAZY(XBE::SectionHeader, u32, section_name_addr, 0x14 )                    
DECLARE_ME_LAZY(XBE::SectionHeader, u32, section_reference_count, 0x18 )              
DECLARE_ME_LAZY(XBE::SectionHeader, u32, head_shared_ref_count_addr, 0x1c )           
DECLARE_ME_LAZY(XBE::SectionHeader, u32, tail_shared_ref_count_addr, 0x20 )           
DECLARE_ME_LAZY_ARR(XBE::SectionHeader, const std::array<u8 COMMA 20> ,section_digest, 0x24)
DECLARE_ME_LAZY_ARR(XBE::LibraryVersion, const std::array<char COMMA 8> ,name,0)
DECLARE_ME_LAZY(XBE::LibraryVersion, u16, major_version, 0x8 )
DECLARE_ME_LAZY(XBE::LibraryVersion, u16, minor_version, 0xA )
DECLARE_ME_LAZY(XBE::LibraryVersion, u16, build_version, 0xC )
DECLARE_ME_LAZY(XBE::LibraryVersion, XBE::LibraryVersion::Flags, flags, 0x124)

DECLARE_ME_LAZY(XBE::Tls, u32, data_start_addr, 0x0)
DECLARE_ME_LAZY(XBE::Tls, u32, data_end_addr, 0x04)
DECLARE_ME_LAZY(XBE::Tls, u32, tls_index_addr, 0x08)
DECLARE_ME_LAZY(XBE::Tls, u32, tls_callback_addr, 0x0c)
DECLARE_ME_LAZY(XBE::Tls, u32, sizeof_zero_fill, 0x010)
DECLARE_ME_LAZY(XBE::Tls, u32, characteristics, 0x014)