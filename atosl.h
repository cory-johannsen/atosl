/*
 *  Copyright (c) 2013, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#ifndef ATOSL_
#define ATOSL_

#define MH_MAGIC 0xfeedface
#define MH_MAGIC_64 0xfeedfacf

#define FAT_MAGIC 0xcafebabe
#define FAT_CIGAM 0xbebafeca

#define MH_DYLIB 0x6
#define MH_DSYM 0xa
#define MH_EXECUTE 0x2

#define LC_SEGMENT 0x1
#define LC_SYMTAB 0x2
#define LC_PREPAGE 0xa
#define LC_UUID 0x1b
#define LC_SEGMENT_64 0x19
#define LC_FUNCTION_STARTS 0x26

#define N_STAB 0xe0
#define N_PEXT 0x10
#define N_TYPE 0x0e
#define N_EXT 0x01

#define N_UNDF 0x0
#define N_ABS 0x2
#define N_SECT 0xe
#define N_PBUD 0xc
#define N_INDR 0xa

#define CPU_TYPE_ARM ((cpu_type_t)12)
#define CPU_SUBTYPE_ARM_V6 ((cpu_subtype_t)6)
#define CPU_SUBTYPE_ARM_V7 ((cpu_subtype_t)9)
#define CPU_SUBTYPE_ARM_V7S ((cpu_subtype_t)11)

#define CPU_TYPE_ARM64 ((cpu_type_t)16777228)
#define CPU_SUBTYPE_ARM64_ALL ((cpu_subtype_t)0)

#define CPU_TYPE_I386 ((cpu_type_t)7)
#define CPU_SUBTYPE_X86_ALL ((cpu_subtype_t)3)

#define N_ARM_THUMB_DEF 0x0008

#define NUMOF(x) (sizeof((x))/sizeof((x)[0]))

typedef int cpu_type_t;
typedef int cpu_subtype_t;
typedef int vm_prot_t;

struct fat_header_t {
    uint32_t magic;
    uint32_t nfat_arch;
};

struct fat_arch_t {
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
};

struct mach_header_t {
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
};

struct load_command_t {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct segment_command_t {
    char segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    vm_prot_t maxprot;
    vm_prot_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct segment_command_64_t {
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    vm_prot_t maxprot;
    vm_prot_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct section_t {
    char sectname[16];
    char segname[16];
    uint32_t addr;
    uint32_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
};

struct section_64_t {
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
};

struct symtab_command_t {
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
};

struct linkedit_data_command_t {
    uint32_t dataoff;
    uint32_t datasize;
};

struct nlist_t
{
    union {
        int32_t n_strx;
    } n_un;
    uint8_t n_type;
    uint8_t n_sect;
    uint16_t n_desc;
    uint32_t n_value;
};

/* Various addresses, parsed from the cmdline or the mach-o sections */
typedef struct {
    Dwarf_Addr load_address;
    int use_globals;
    int use_cache;
    const char *dsym_filename;
    cpu_type_t cpu_type;
    cpu_subtype_t cpu_subtype;
    const char *cache_dir;
} symbolication_options_t;

typedef struct {
    char* guid_buffer;
    cpu_type_t cpu_type;
    cpu_subtype_t cpu_subtype;
} guid_load_result_t;

typedef struct {
    char* symbol_buffer;
    cpu_type_t cpu_type;
    cpu_subtype_t cpu_subtype;
} symbolication_result_t;

/**
 * Loads the UUIDs from the specified dSym file and returns them to the caller
 *
 * @param dsym_filename (in) File system name of the dSym data file to process
 * @param guid_result (out) Pointer to an array of guild_load_result_t instances that hold the result of invocation.
 * @param max_guid_result_count (in) The maximum number of results to be populated in the guid_result out array.
 * @param max_guid_buffer_size Maximum size for the GUID buffer contained within each guid_load_result_t struct.  This is required to prevent buffer overflows.
 * @param debug_mode
 *
 * @return The count of items populated in the guid_result out array on success, errno indicating error condition on failure.
 **/
int atosl_load_guids(const char* dsym_filename, guid_load_result_t* guid_result, size_t max_guid_result_count, size_t max_guid_buffer_size, int debug_mode);

/**
* Symbolicates the requested symbol address and stores the result in the given buffer.
* The output of symbolication will be truncated to fit the buffer size if the length exceeds bufferSize.
**/
int atosl_symbolicate(symbolication_options_t *options, Dwarf_Addr symbol_address, symbolication_result_t* symbolication_result, size_t max_symbolication_buffer_size, int debug_mode);

#endif /* ATOSL _*/
