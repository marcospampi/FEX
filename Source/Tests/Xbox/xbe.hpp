#pragma once
#include <array>
#include <vector>
#include "common.hpp"
class XBE
{
public:
    static constexpr u32 ENTRY_DEBUG_KEY = 0x94859D4B;
    static constexpr u32 ENTRY_RETAIL_KEY = 0xA8FC57AB;
    static constexpr u32 KERNEL_DEBUG_KEY = 0xEFB1F152;
    static constexpr u32 KERNEL_RETAIL_KEY = 0x5B6D40B6;

    class Element 
    {
    protected:
        friend class XBE;
        u8 *data;
        Element(u8 *data): data(data) {}
    public:
        u8* ptr() { return data; }
    };
    class Header: public Element
    {
    private:
        friend class XBE;
        const XBE &xbe;
        Header(u8 *data, const XBE &xbe): Element(data), xbe(xbe) {}
        bool is_debug() const;
        bool is_retail() const;
    public:
        #pragma pack(push, 1)
        struct InitFlags
        {
            u32 mount_utility_drive : 1;  // mount utility drive flag
            u32 format_utility_drive : 1; // format utility drive flag
            u32 limit_64mb : 1;           // limit development kit run time memory to 64mb flag
            u32 dont_setup_harddisk : 1;  // don't setup hard disk flag
            u32 unused : 4;               // unused (or unknown)
            u32 unused_b1 : 8;            // unused (or unknown)
            u32 unused_b2 : 8;            // unused (or unknown)
            u32 unused_b3 : 8;            // unused (or unknown)
        };
        #pragma pack(pop)

        u32 magic() const;                         // magic number [should be "XBEH"]
        const std::array<u8, 256> &digsig() const; // digital signature
        u32 base() const;                          // base address
        u32 sizeof_headers() const;                // size of headers
        u32 sizeof_image() const;                  // size of image
        u32 sizeof_image_header() const;           // size of image header
        u32 timedate() const;                      // timedate stamp
        u32 certificate_addr() const;              // certificate address
        u32 sections() const;                      // number of sections
        u32 section_headers_addr() const;          // section headers address
        InitFlags init_flags() const;
        u32 entry() const;                       // entry point address
        u32 tls_addr() const;                    // thread local storage directory address
        u32 pe_stack_commit() const;             // size of stack commit
        u32 pe_heap_reserve() const;             // size of heap reserve
        u32 pe_heap_commit() const;              // size of heap commit
        u32 pe_base_addr() const;                // original base address
        u32 pe_sizeof_image() const;             // size of original image
        u32 pe_checksum() const;                 // original checksum
        u32 pe_timedate() const;                 // original timedate stamp
        u32 debug_pathname_addr() const;         // debug pathname address
        u32 debug_filename_addr() const;         // debug filename address
        u32 debug_unicode_filename_addr() const; // debug unicode filename address
        u32 kernel_image_thunk_addr() const;     // kernel image thunk address
        u32 nonkernel_import_dir_addr() const;   // non kernel import directory address
        u32 library_versions() const;            // number of library versions
        u32 library_versions_addr() const;       // library versions address
        u32 kernel_library_version_addr() const; // kernel library version address
        u32 xapi_library_version_addr() const;   // xapi library version address
        u32 logo_bitmap_addr() const;            // logo bitmap address
        u32 logo_bitmap_size() const;            // logo bitmap size
    };
    class Certificate: public Element
    {
    private:
        friend class XBE;
        Certificate( u8 *ptr ): Element(ptr) {}
    public:
        u32 size() const;                                                    // size of certificate
        u32 timedate() const;                                                // timedate stamp
        u32 titleid() const;                                                 // title id
        const std::array<u16, 40> &title_name() const;                       // title name (unicode)
        const std::array<u32, 10> &alt_title_id() const;                     // alternate title ids
        u32 allowed_media() const;                                           // allowed media types
        u32 game_region() const;                                             // game region
        u32 game_ratings() const;                                            // game ratings
        u32 disk_number() const;                                             // disk number
        u32 version() const;                                                 // version
        const std::array<u8, 16> &lan_key() const;                           // lan key
        const std::array<u8, 16> &sig_key() const;                           // signature key
        const std::array<std::array<u8, 16>, 16> &title_alt_sig_key() const; // alternate signature keys
    };
    class SectionHeader: public Element
    {
    private:
        friend class XBE;
        SectionHeader( u8 *ptr ): Element(ptr) {}

    public:
        static constexpr auto SIZE = 0x38;
        #pragma pack(push,1)
        struct Flags // flags
        {
            uint writable : 1;      // writable flag
            uint preload : 1;       // preload flag
            uint executable : 1;    // executable flag
            uint inserted_file : 1; // inserted file flag
            uint head_page_ro : 1;  // head page read only flag
            uint tail_page_ro : 1;  // tail page read only flag
        };
        #pragma pack(pop)

        Flags flags() const;
        u32 virtual_addr() const;                         // virtual address
        u32 virtual_size() const;                         // virtual size
        u32 raw_addr() const;                             // file offset to raw data
        u32 sizeof_raw() const;                           // size of raw data
        u32 section_name_addr() const;                    // section name addr
        u32 section_reference_count() const;              // section reference count
        u32 head_shared_ref_count_addr() const;           // head shared page reference count address
        u32 tail_shared_ref_count_addr() const;           // tail shared page reference count address
        const std::array<u8, 20> &section_digest() const; // section digest
    };
    class LibraryVersion: public Element
    {
    private:
        friend class XBE;
        LibraryVersion( u8 *ptr ): Element(ptr) {}

    public:
        static constexpr auto SIZE = 0x128;
        #pragma pack(push,1)
        struct Flags            // flags
        {
            u16 qfe_version : 13; // QFE Version
            u16 approved : 2;     // Approved? (0:no, 1:possibly, 2:yes)
            u16 debug_build : 1;  // Is this a debug build?
        }; 
        #pragma pack(pop)
        const std::array<char,8> &name() const;         // library name
        u16 major_version() const; // major version
        u16 minor_version() const; // minor version
        u16 build_version() const; // build version
        Flags flags() const;
    };
    class Tls: public Element 
    {
    private:
        friend class XBE;
        Tls( u8 *ptr ): Element(ptr) {}

        u8 *data;
    public:
        u32 data_start_addr() const;               // raw start address
        u32 data_end_addr() const;                 // raw end address
        u32 tls_index_addr() const;                // tls index  address
        u32 tls_callback_addr() const;             // tls callback address
        u32 sizeof_zero_fill() const;              // size of zero fill
        u32 characteristics() const;               // characteristics
    };
    bool is_debug() const ;
    bool is_retail() const ;
    u32 entry() const;
    Header header() const;
    Certificate certificate() const;
    const std::array<u32,366>& thunk_table() const;
    std::vector<SectionHeader> section_headers() const;
    std::vector<LibraryVersion> library_versions() const;
    Tls tls() const;

    XBE( const char* path );
    XBE( const std::string &path ): XBE(path.c_str()) {}
    ~XBE();
    const u8 *ptr() const { return data_; }
    u32 size() const { return size_;}
private:
    u8 *data_;
    u32 size_;
};