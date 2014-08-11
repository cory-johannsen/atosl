/*
 *  Copyright (c) 2013, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#undef NDEBUG
#include <assert.h>
#include <arpa/inet.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dwarf.h>
#include <libdwarf.h>

#include "atosl.h"
#include "subprograms.h"
#include "common.h"

#define VERSION ATOSL_VERSION

#define DWARF_ASSERT(ret, err) \
    do { \
        if (ret == DW_DLV_ERROR) { \
            fatal("dwarf_errmsg: %s", dwarf_errmsg(err)); \
        } \
    } while (0);

extern char *
cplus_demangle (const char *mangled, int options);

typedef unsigned long Dwarf_Word;

Dwarf_Unsigned
_dwarf_decode_u_leb128(Dwarf_Small * leb128,
    Dwarf_Word * leb128_length);
#define DECODE_LEB128_UWORD(ptr, value)               \
    do {                                              \
        Dwarf_Word uleblen;                           \
        value = _dwarf_decode_u_leb128(ptr,&uleblen); \
        ptr += uleblen;                               \
    } while (0)

static int debug = 0;
static int verbose = 0;

static const char *shortopts = "dvl:o:A:gcC:uVh";
static struct option longopts[] = {
    {"debug", no_argument, NULL, 'd'},
    {"verbose", no_argument, NULL, 'v'},
    {"load-address", required_argument, NULL, 'l'},
    {"dsym", required_argument, NULL, 'o'},
    {"arch", optional_argument, NULL, 'A'},
    {"globals", no_argument, NULL, 'g'},
    {"no-cache", no_argument, NULL, 'c'},
    {"cache-dir", required_argument, NULL, 'C'},
    {"uuid", no_argument, NULL, 'u'},
    {"version", no_argument, NULL, 'V'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

static struct {
    const char *name;
    cpu_type_t type;
    cpu_subtype_t subtype;
} arch_str_to_type[] = {
    {"i386", CPU_TYPE_I386, CPU_SUBTYPE_X86_ALL},
    {"armv6",  CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V6},
    {"armv7",  CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7},
    {"armv7s", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7S},
    {"arm64",  CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL}
};

struct symbol_t {
    const char *name;
    struct nlist_t sym;
    Dwarf_Addr addr;
    int thumb:1;
};

struct function_t {
    const char *name;
    Dwarf_Addr addr;
};

typedef struct {
    /* Symbols from symtab */
    struct symbol_t *symlist;
    uint32_t nsymbols;
    /* Functions from LC_FUNCTION_STARTS */
    struct function_t *funclist;
    uint32_t nfuncs;
    struct dwarf_subprogram_t *subprograms;

    Dwarf_Addr intended_addr;
    Dwarf_Addr linkedit_addr;

    struct fat_arch_t arch;

    uint8_t uuid[UUID_LEN];
} context_t;



static symbolication_options_t default_options = {
    .load_address = LONG_MAX,
    .use_globals = 0,
    .use_cache = 1,
    .cpu_type = CPU_TYPE_ARM,
    .cpu_subtype = CPU_SUBTYPE_ARM_V7S,
};

typedef int dwarf_mach_handle;

struct dwarf_section_t;
struct dwarf_section_t {
    struct section_t mach_section;
    struct dwarf_section_t *next;
};

struct dwarf_section_64_t;
struct dwarf_section_64_t {
    struct section_64_t mach_section;
    struct dwarf_section_64_t *next;
};

typedef struct {
    dwarf_mach_handle handle;
    Dwarf_Small length_size;
    Dwarf_Small pointer_size;
    Dwarf_Endianness endianness;

    Dwarf_Unsigned section_count;
    struct dwarf_section_t *sections;
    struct dwarf_section_64_t *sections_64;
} dwarf_mach_object_access_internals_t;

void print_help(void)
{
    fprintf(stderr, "atosl %s\n", VERSION);
    fprintf(stderr, USAGE "\n");
    fprintf(stderr, "\n");
    fprintf(stderr,
            "  -o, --dsym=FILE\t\tfile to find symbols in\n");
    fprintf(stderr,
            "  -d, --debug\t\t\tenable debug messages\n");
    fprintf(stderr,
            "  -v, --verbose\t\t\tenable verbose messages\n");
    fprintf(stderr,
            "  -l, --load_address=ADDRESS\tspecify application load address\n");
    fprintf(stderr,
            "  -A, --arch=ARCH\t\tspecify architecture\n");
    fprintf(stderr,
            "  -g, --globals\t\t\tlookup symbols using global section\n");
    fprintf(stderr,
            "  -c, --no-cache\t\tdon't cache debugging information\n");
    fprintf(stderr,
			"  -u, --uuid\t\tExtract UUIDs\n");
    fprintf(stderr,
            "  -V, --version\t\t\tget current version\n");
    fprintf(stderr,
            "  -h, --help\t\t\tthis help\n");
    fprintf(stderr, "\n");
}

void dwarf_error_handler(Dwarf_Error err, Dwarf_Ptr ptr)
{
    fatal("dwarf error: %s", dwarf_errmsg(err));
}

char *demangle(const char *sym)
{
    char *demangled = NULL;

    if (verbose)
        fprintf(stderr, "Unmangled name: %s\n", sym);
    if (strncmp(sym, "_Z", 2) == 0)
        demangled = cplus_demangle(sym, 0);
    else if (strncmp(sym, "__Z", 3) == 0)
        demangled = cplus_demangle(sym+1, 0);

    return demangled;
}

int parse_uuid(dwarf_mach_object_access_internals_t *obj, context_t* context, uint32_t cmdsize)
{
    int i;
    int ret;

    ret = _read(obj->handle, context->uuid, UUID_LEN);
    if (ret < 0) {
        fatal_file(ret);
        return EXIT_FAILURE;
    }

    if (verbose) {
        fprintf(stderr, "%10s ", "uuid");
        for (i = 0; i < UUID_LEN; i++) {
            fprintf(stderr, "%.02x", context->uuid[i]);
        }
        fprintf(stderr, "\n");
    }

    return 0;
}

int parse_section(dwarf_mach_object_access_internals_t *obj)
{
    int ret;
    struct dwarf_section_t *s;

    s = malloc(sizeof(*s));
    if (!s) {
        fatal("Failed to allocate memory for DWARF section");
        return ENOMEM;
    }

    memset(s, 0, sizeof(*s));

    ret = _read(obj->handle, &s->mach_section, sizeof(s->mach_section));
    if (ret < 0) {
        fatal_file(ret);
        return EXIT_FAILURE;
    }

    if (verbose) {
        fprintf(stderr, "Section\n");
        fprintf(stderr, "%10s %s\n", "sectname", s->mach_section.sectname);
        fprintf(stderr, "%10s %s\n", "segname", s->mach_section.segname);
        fprintf(stderr, "%10s 0x%.08x\n", "addr", s->mach_section.addr);
        fprintf(stderr, "%10s 0x%.08x\n", "size", s->mach_section.size);
        fprintf(stderr, "%10s %d\n", "offset", s->mach_section.offset);
        /* TODO: what is the second value here? */
        fprintf(stderr, "%10s 2^%d (?)\n", "align", s->mach_section.align);
        fprintf(stderr, "%10s %d\n", "reloff", s->mach_section.reloff);
        fprintf(stderr, "%10s %d\n", "nreloc", s->mach_section.nreloc);
        fprintf(stderr, "%10s 0x%.08x\n", "flags", s->mach_section.flags);
        fprintf(stderr, "%10s %d\n", "reserved1", s->mach_section.reserved1);
        fprintf(stderr, "%10s %d\n", "reserved2", s->mach_section.reserved2);
    }

    struct dwarf_section_t *sec = obj->sections;
    if (!sec)
        obj->sections = s;
    else {
        while (sec) {
            if (sec->next == NULL) {
                sec->next = s;
                break;
            } else {
                sec = sec->next;
            }
        }
    }

    obj->section_count++;

    return 0;
}

int parse_section_64(dwarf_mach_object_access_internals_t *obj)
{
    int ret;
    struct dwarf_section_64_t *s;

    s = malloc(sizeof(*s));
    if (!s) {
        fatal("Failed to allocate memory for DWARF section-64");
        return ENOMEM;
    }

    memset(s, 0, sizeof(*s));

    ret = _read(obj->handle, &s->mach_section, sizeof(s->mach_section));
    if (ret < 0) {
        fatal_file(ret);
        return EXIT_FAILURE;
    }

    if (verbose) {
        fprintf(stderr, "Section\n");
        fprintf(stderr, "%10s %s\n", "sectname", s->mach_section.sectname);
        fprintf(stderr, "%10s %s\n", "segname", s->mach_section.segname);
        fprintf(stderr, "%10s 0x%.8llx\n", "addr", (long long unsigned int) s->mach_section.addr);
        fprintf(stderr, "%10s 0x%.8llx\n", "size", (long long unsigned int) s->mach_section.size);
        fprintf(stderr, "%10s %d\n", "offset", s->mach_section.offset);
        /* TODO: what is the second value here? */
        fprintf(stderr, "%10s 2^%d (?)\n", "align", s->mach_section.align);
        fprintf(stderr, "%10s %d\n", "reloff", s->mach_section.reloff);
        fprintf(stderr, "%10s %d\n", "nreloc", s->mach_section.nreloc);
        fprintf(stderr, "%10s 0x%.08x\n", "flags", s->mach_section.flags);
        fprintf(stderr, "%10s %d\n", "reserved1", s->mach_section.reserved1);
        fprintf(stderr, "%10s %d\n", "reserved2", s->mach_section.reserved2);
        fprintf(stderr, "%10s %d\n", "reserved3", s->mach_section.reserved3);
    }

    struct dwarf_section_64_t *sec = obj->sections_64;
    if (!sec)
        obj->sections_64 = s;
    else {
        while (sec) {
            if (sec->next == NULL) {
                sec->next = s;
                break;
            } else {
                sec = sec->next;
            }
        }
    }

    obj->section_count++;

    return 0;
}


int parse_segment(dwarf_mach_object_access_internals_t *obj, context_t* context, uint32_t cmdsize)
{
    int err;
    int ret;
    struct segment_command_t segment;
    int i;

    ret = _read(obj->handle, &segment, sizeof(segment));
    if (ret < 0) {
        fatal_file(ret);
        return EXIT_FAILURE;
    }

    if (verbose) {
        fprintf(stderr, "Segment: %s\n", segment.segname);
        fprintf(stderr, "\tvmaddr: 0x%.08x\n", segment.vmaddr);
        fprintf(stderr, "\tvmsize: %d\n", segment.vmsize);
        fprintf(stderr, "\tfileoff: 0x%.08x\n", segment.fileoff);
        fprintf(stderr, "\tfilesize: %d\n", segment.filesize);
        fprintf(stderr, "\tmaxprot: %d\n", segment.maxprot);
        fprintf(stderr, "\tinitprot: %d\n", segment.initprot);
        fprintf(stderr, "\tnsects: %d\n", segment.nsects);
        fprintf(stderr, "\tflags: %.08x\n", segment.flags);
    }

    if (strcmp(segment.segname, "__TEXT") == 0) {
        context->intended_addr = segment.vmaddr;
    }

    if (strcmp(segment.segname, "__LINKEDIT") == 0) {
        context->linkedit_addr = segment.fileoff;
    }

    for (i = 0; i < segment.nsects; i++) {
        err = parse_section(obj);
        if (err) {
            fatal("unable to parse section in `%s`", segment.segname);
            return EXIT_FAILURE;
        }
    }

    return 0;
}

int parse_segment_64(dwarf_mach_object_access_internals_t *obj, context_t* context, uint32_t cmdsize)
{
    int err;
    int ret;
    struct segment_command_64_t segment;
    int i;

    ret = _read(obj->handle, &segment, sizeof(segment));
    if (ret < 0) {
        fatal_file(ret);
        return EXIT_FAILURE;
    }

    if (verbose) {
        fprintf(stderr, "Segment: %s\n", segment.segname);
        fprintf(stderr, "\tvmaddr: 0x%.8llx\n", (long long unsigned int) segment.vmaddr);
        fprintf(stderr, "\tvmsize: %llu\n", (long long unsigned int) segment.vmsize);
        fprintf(stderr, "\tfileoff: 0x%.8llx\n", (long long unsigned int) segment.fileoff);
        fprintf(stderr, "\tfilesize: %llu\n", (long long unsigned int) segment.filesize);
        fprintf(stderr, "\tmaxprot: %d\n", segment.maxprot);
        fprintf(stderr, "\tinitprot: %d\n", segment.initprot);
        fprintf(stderr, "\tnsects: %d\n", segment.nsects);
        fprintf(stderr, "\tflags: %.08x\n", segment.flags);
    }

    if (strcmp(segment.segname, "__TEXT") == 0) {
        context->intended_addr = segment.vmaddr;
    }

    if (strcmp(segment.segname, "__LINKEDIT") == 0) {
        context->linkedit_addr = segment.fileoff;
    }

    for (i = 0; i < segment.nsects; i++) {
        err = parse_section_64(obj);
        if (err) {
            fatal("unable to parse section in `%s`", segment.segname);
            return EXIT_FAILURE;
        }
    }

    return 0;
}

int parse_symtab(dwarf_mach_object_access_internals_t *obj, context_t* context, uint32_t cmdsize)
{
    int ret;
    off_t pos;
    int i;
    char *strtable;

    struct symtab_command_t symtab;
    struct symbol_t *current;

    ret = _read(obj->handle, &symtab, sizeof(symtab));
    if (ret < 0) {
        fatal_file(ret);
        return EXIT_FAILURE;
    }

    if (verbose) {
        fprintf(stderr, "Symbol\n");
        fprintf(stderr, "%10s %.08x\n", "symoff", symtab.symoff);
        fprintf(stderr, "%10s %d\n", "nsyms", symtab.nsyms);
        fprintf(stderr, "%10s %.08x\n", "stroff", symtab.stroff);
        fprintf(stderr, "%10s %d\n", "strsize", symtab.strsize);
    }

    strtable = malloc(symtab.strsize);
    if (!strtable) {
        fatal("Failed to allocate memory for strtable.");
        return ENOMEM;
    }

    pos = lseek(obj->handle, 0, SEEK_CUR);
    if (pos < 0) {
        fatal("error seeking: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    ret = lseek(obj->handle, context->arch.offset+symtab.stroff, SEEK_SET);
    if (ret < 0) {
        fatal("error seeking: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    ret = _read(obj->handle, strtable, symtab.strsize);
    if (ret < 0) {
        fatal_file(ret);
        return EXIT_FAILURE;
    }

    ret = lseek(obj->handle, context->arch.offset+symtab.symoff, SEEK_SET);
    if (ret < 0) {
        fatal("error seeking: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    context->nsymbols = symtab.nsyms;
    context->symlist = malloc(sizeof(struct symbol_t) * symtab.nsyms);
    if (!context->symlist) {
        fatal("Failed to allocate memory for context symbol list.");
        return ENOMEM;
    }
    current = context->symlist;

    for (i = 0; i < symtab.nsyms; i++) {
        ret = _read(obj->handle, &current->sym, sizeof(current->sym));
        if (ret < 0) {
            fatal_file(ret);
            return EXIT_FAILURE;
        }

        if (current->sym.n_un.n_strx) {
            current->name = strtable+current->sym.n_un.n_strx;
        }

        current++;
    }

    ret = lseek(obj->handle, pos, SEEK_SET);
    if (ret < 0) {
        fatal("error seeking: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    return 0;
}

int parse_function_starts(dwarf_mach_object_access_internals_t *obj, context_t* context,
                          uint32_t cmdsize)
{
    int ret;
    struct linkedit_data_command_t linkedit;
    uint32_t *linkedit_data;
    off_t orig_pos;
    off_t pos;
    Dwarf_Small *encoded_data;
    Dwarf_Word addr;
    Dwarf_Word offset;
    struct function_t *func;

    ret = _read(obj->handle, &linkedit, sizeof(linkedit));
    if (ret < 0) {
        fatal_file(ret);
        return EXIT_FAILURE;
    }

    if (verbose) {
        fprintf(stderr, "LC_FUNCTION_STARTS\n");
        fprintf(stderr, "%10s %.08x\n", "dataoff", linkedit.dataoff);
        fprintf(stderr, "%10s %d\n", "datasize", linkedit.datasize);
    }

    linkedit_data = malloc(linkedit.datasize);
    if (!linkedit_data) {
        fatal("Failed to allocate memory for linkedit data.");
        return ENOMEM;
    }

    orig_pos = lseek(obj->handle, 0, SEEK_CUR);
    if (orig_pos < 0) {
        fatal("error seeking: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    /* TODO: will the linkedit section always be defined before the
     * function_starts command? */
    if (!context->linkedit_addr) {
        fatal("fixme: linkedit address specified after function section.");
        return EXIT_FAILURE;
    }

    pos = context->arch.offset + linkedit.dataoff;
    ret = lseek(obj->handle, pos, SEEK_SET);
    if (ret < 0) {
        fatal("error seeking: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    ret = _read(obj->handle, linkedit_data, linkedit.datasize);
    if (ret < 0) {
        fatal_file(ret);
        return EXIT_FAILURE;
    }

    encoded_data = (Dwarf_Small *)linkedit_data;
    context->nfuncs = 0;
    do {
        DECODE_LEB128_UWORD(encoded_data, offset);
        context->nfuncs++;
    } while (offset != 0);

    context->funclist = func = malloc(sizeof(*func) * context->nfuncs);
    if (!func) {
        fatal("Failed to allocate memory for context function list.");
        return ENOMEM;
    }

    encoded_data = (Dwarf_Small *)linkedit_data;
    addr = context->intended_addr;
    do {
        DECODE_LEB128_UWORD(encoded_data, offset);
        addr += offset;

        func->addr = addr;
        func++;
    } while (offset != 0);

    ret = lseek(obj->handle, orig_pos, SEEK_SET);
    if (ret < 0) {
        fatal("error seeking: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    return 0;
}

int print_symtab_symbol(symbolication_options_t *options, Dwarf_Addr slide, Dwarf_Addr addr, context_t* context, char* symbol_buffer, size_t max_buffer_size)
{
    struct nlist_t nlist;
    struct symbol_t *current;
    struct function_t *func;
    char *demangled = NULL;
    int found = 0;

    int i;
    int j;

    addr = addr - slide;
    current = context->symlist;

    for (i = 0; i < context->nsymbols; i++) {
        memcpy(&nlist, &current->sym, sizeof(current->sym));

        current->thumb = (nlist.n_desc & N_ARM_THUMB_DEF) ? 1 : 0;
        current->addr = nlist.n_value;

        if (verbose) {
            fprintf(stderr, "\t\tname: %s\n", current->name);
            fprintf(stderr, "\t\tn_un.n_un.n_strx: %d\n", nlist.n_un.n_strx);
            fprintf(stderr, "\t\traw n_type: 0x%x\n", nlist.n_type);
            fprintf(stderr, "\t\tn_type: ");
            if (nlist.n_type & N_STAB)
                fprintf(stderr, "N_STAB ");
            if (nlist.n_type & N_PEXT)
                fprintf(stderr, "N_PEXT ");
            if (nlist.n_type & N_EXT)
                fprintf(stderr, "N_EXT ");
            fprintf(stderr, "\n");

            fprintf(stderr, "\t\tType: ");
            switch (nlist.n_type & N_TYPE) {
                case 0: fprintf(stderr, "U "); break;
                case N_ABS: fprintf(stderr, "A "); break;
                case N_SECT: fprintf(stderr, "S "); break;
                case N_INDR: fprintf(stderr, "I "); break;
            }

            fprintf(stderr, "\n");

            fprintf(stderr, "\t\tn_sect: %d\n", nlist.n_sect);
            fprintf(stderr, "\t\tn_desc: %d\n", nlist.n_desc);
            fprintf(stderr, "\t\tn_value: %.08x\n", nlist.n_value);
            fprintf(stderr, "\t\taddr: %.08x\n", (unsigned int)current->addr);
            fprintf(stderr, "\n");
        }

        current++;
    }

    func = context->funclist;

    for (i = 0; i < context->nfuncs; i++) {
        if (addr < func->addr) {
            if (i < 1) {
                /* Someone is asking about a symbol that comes before the first
                 * one we know about. In that case we don't have a match for
                 * them */
                break;
            }

            struct function_t *prev = (func - 1);
            struct symbol_t *sym = NULL;
            int found_sym = 0;
            const char *name;
            assert(i < context->nsymbols);

            for (j = 0; j < context->nsymbols; j++) {
                sym = context->symlist + j;
                if (sym->addr == (prev->addr & -2)) {
                    found_sym = 1;
                    break;
                }
            }

            if (!found_sym) {
                fatal("unable to find symbol at address %x", sym->addr);
                return EXIT_FAILURE;
            }

            demangled = demangle(sym->name);
            name = demangled ? demangled : sym->name;

            if (name[0] == '_')
                name++;

            //printf("%s%s (in %s) + %d\n",
            //        name,
            //        demangled ? "()" : "",
            //        basename((char *)options-<dsym_filename),
            //        (unsigned int)(addr - sym->addr));
            snprintf(symbol_buffer, max_buffer_size, "%s%s (in %s) + %d\n",
                    name,
                    demangled ? "()" : "",
                    basename((char *)options->dsym_filename),
                    (unsigned int)(addr - sym->addr));
            found = 1;

            if (demangled)
                free(demangled);
            break;
        }

        func++;
    }

    return found ? DW_DLV_OK : DW_DLV_NO_ENTRY;
}

int parse_command(
    dwarf_mach_object_access_internals_t *obj,
    context_t* context,
    struct load_command_t load_command)
{
    int ret = 0;
    int cmdsize;

    switch (load_command.cmd) {
        case LC_UUID:
            ret = parse_uuid(obj, context, load_command.cmdsize);
            break;
        case LC_SEGMENT:
            ret = parse_segment(obj, context, load_command.cmdsize);
            break;
        case LC_SEGMENT_64:
            ret = parse_segment_64(obj, context, load_command.cmdsize);
            break;
        case LC_SYMTAB:
            ret = parse_symtab(obj, context, load_command.cmdsize);
            break;
        case LC_FUNCTION_STARTS:
            ret = parse_function_starts(obj, context, load_command.cmdsize);
            break;
        default:
            if (verbose)
                fprintf(stderr, "Warning: unhandled command: 0x%x\n",
                                load_command.cmd);
            /* Fallthrough */
        case LC_PREPAGE:
            cmdsize = load_command.cmdsize - sizeof(load_command);
            ret = lseek(obj->handle, cmdsize, SEEK_CUR);
            if (ret < 0) {
                fatal("error seeking: %s", strerror(errno));
                return EXIT_FAILURE;
            }
            break;
    }

    return ret;
}

static int dwarf_mach_object_access_internals_init(
        dwarf_mach_handle handle,
        context_t* context,
        void *obj_in,
        int *error)
{
    int ret;
    struct mach_header_t header;
    struct load_command_t load_command;
    int i;

    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;

    obj->handle = handle;
    obj->length_size = 4;
    obj->pointer_size = 4;
    obj->endianness = DW_OBJECT_LSB;
    obj->sections = NULL;
    obj->sections_64 = NULL;

    ret = _read(obj->handle, &header, sizeof(header));
    if (ret < 0) {
        fatal_file(ret);
        return EXIT_FAILURE;
    }

    /* Need to skip a couple bits if we're a 64-bit */
    if (header.cputype == CPU_TYPE_ARM64 && header.cpusubtype == CPU_SUBTYPE_ARM64_ALL) {
      ret = lseek(obj->handle, 4, SEEK_CUR);
      if (ret < 0) {
        fatal_file(ret);
        return EXIT_FAILURE;
      }
    }

    if (verbose) {
        fprintf(stderr, "Mach Header:\n");
        fprintf(stderr, "\tCPU Type: %d\n", header.cputype);
        fprintf(stderr, "\tCPU Subtype: %d\n", header.cpusubtype);
        fprintf(stderr, "\tFiletype: %d\n", header.filetype);
        fprintf(stderr, "\tNumber of Cmds: %d\n", header.ncmds);
        fprintf(stderr, "\tSize of commands: %d\n", header.sizeofcmds);
        fprintf(stderr, "\tFlags: %.08x\n", header.flags);
    }

    switch (header.filetype) {
        case MH_DSYM:
            if (verbose)
                fprintf(stderr, "File type: debug file\n");
            break;
        case MH_DYLIB:
            if (verbose)
                fprintf(stderr, "File type: dynamic library\n");
            break;
        case MH_EXECUTE:
            if (verbose)
                fprintf(stderr, "File type: executable file\n");
            break;
        default:
            fatal("unsupported file type: 0x%x", header.filetype);
            assert(0);
            return EXIT_FAILURE;
    }

    for (i = 0; i < header.ncmds; i++) {
        ret = _read(obj->handle, &load_command, sizeof(load_command));
        if (ret < 0) {
            fatal_file(ret);
            return EXIT_FAILURE;
        }

        if (verbose) {
            fprintf(stderr, "Load Command %d\n", i);
            fprintf(stderr, "%10s %x\n", "cmd", load_command.cmd);
            fprintf(stderr, "%10s %d\n", "cmdsize", load_command.cmdsize);
        }

        ret = parse_command(obj, context, load_command);
        if (ret < 0) {
            fatal("unable to parse command %x", load_command.cmd);
            return EXIT_FAILURE;
        }
    }

    return DW_DLV_OK;
}

static Dwarf_Endianness dwarf_mach_object_access_get_byte_order(void *obj_in)
{
    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;
    return obj->endianness;
}

static Dwarf_Unsigned dwarf_mach_object_access_get_section_count(void *obj_in)
{
    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;
    return obj->section_count;
}

static int dwarf_mach_object_access_get_section_info(
        void *obj_in,
        Dwarf_Half section_index,
        Dwarf_Obj_Access_Section *ret_scn,
        int *error)
{
    // verbose("dwarf_mach_object_access_get_section_info called - obj_in: 0x%x, section_index: %d, ret_scn: 0x%x, error: 0x%x", obj_in, section_index, ret_scn, error);
    int i;
    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;
    // verbose("Successfully cast obj_in to dwarf_mach_object_access_internals_t: 0x%x", obj);

    if (section_index >= obj->section_count) {
        // verbose("dwarf_mach_object_access_get_section_info error: section index exceeds section count.");
        *error = DW_DLE_MDE;
        return DW_DLV_ERROR;
    }

    // verbose("Searching for section %d", section_index);
    if (obj->sections) {
        // if (verbose) {
        //     verbose("Using 32-bit dwarf sections.");
        // }
        struct dwarf_section_t *sec = obj->sections;
        for (i = 0; i < section_index; i++) {
            //verbose("Evaluating section 0x%x at index %d.  section name: %s", sec, i, sec->mach_section.sectname);

            sec = sec->next;
        }

        if(!sec) {
            fatal("No DWARF section located with index %d.", section_index);
            *error = DW_DLE_MDE;
            return DW_DLV_ERROR;
        }
        //if(!sec->mach_section) {
        //    fatal("Invalid DWARF section located with index %d: section does not contain a MACH section data element.", section_index);
        //    *error = DW_DLE_MDE;
        //    return DW_DLV_ERROR;
        //}
        // verbose("Located dwarf section 0x%x at index %d", sec, section_index);

        sec->mach_section.sectname[1] = '.';
        ret_scn->size = sec->mach_section.size;
        ret_scn->addr = sec->mach_section.addr;
        ret_scn->name = sec->mach_section.sectname+1;
        if (strcmp(ret_scn->name, ".debug_pubnames__DWARF") == 0)
            ret_scn->name = ".debug_pubnames";

        ret_scn->link = 0; /* rela section or from symtab to strtab */
        ret_scn->entrysize = 0;
    }
    else if(obj->sections_64) {
        // if (verbose) {
        //     verbose("Using 64-bit dwarf sections.");
        // }
        struct dwarf_section_64_t *sec = obj->sections_64;
        for (i = 0; i < section_index; i++) {
            //verbose("Evaluating section 0x%x at index %d.  section name: %s", sec, i, sec->mach_section.sectname);

            sec = sec->next;
        }

        if(!sec) {
            fatal("No DWARF section located with index %d.", section_index);
            *error = DW_DLE_MDE;
            return DW_DLV_ERROR;
        }
        //if(!sec->mach_section) {
        //    fatal("Invalid DWARF section located with index %d: section does not contain a MACH section data element.", section_index);
        //    *error = DW_DLE_MDE;
        //    return DW_DLV_ERROR;
        //}
        // verbose("Located dwarf section 0x%x at index %d. section name: %s", sec, section_index, sec->mach_section.sectname);;

        sec->mach_section.sectname[1] = '.';
        ret_scn->size = sec->mach_section.size;
        ret_scn->addr = sec->mach_section.addr;
        ret_scn->name = sec->mach_section.sectname+1;
        if (strcmp(ret_scn->name, ".debug_pubnames__DWARF") == 0)
            ret_scn->name = ".debug_pubnames";

        ret_scn->link = 0; /* rela section or from symtab to strtab */
        ret_scn->entrysize = 0;
    }
    else {
        fatal("No dwarf sections defined in DWARF data.");
        *error = DW_DLE_MDE;
        return DW_DLV_ERROR;
    }

    // verbose("dwarf_mach_object_access_get_section_info exiting normally.");
    return DW_DLV_OK;
}

static int dwarf_mach_object_access_load_section(
        void *obj_in,
        Dwarf_Half section_index,
        Dwarf_Small **section_data,
        int *error)
{
    void *addr;
    int i;
    int ret;

    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;

    if (section_index >= obj->section_count) {
        *error = DW_DLE_MDE;
        return DW_DLV_ERROR;
    }

    if (obj->sections) {
        struct dwarf_section_t *sec = obj->sections;
        for (i = 0; i < section_index; i++) {
            sec = sec->next;
        }

        addr = malloc(sec->mach_section.size);
        if (!addr) {
            fatal("Failed to allocate memory for DWARF data.");
            return ENOMEM;
        }

        ret = lseek(obj->handle, sec->mach_section.offset, SEEK_SET);
        if (ret < 0) {
            fatal("error seeking: %s", strerror(errno));
            return EXIT_FAILURE;
        }

        ret = _read(obj->handle, addr, sec->mach_section.size);
        if (ret < 0) {
            fatal_file(ret);
            return EXIT_FAILURE;
        }

        *section_data = addr;
    }
    else if (obj->sections_64) {
        struct dwarf_section_64_t *sec = obj->sections_64;
        for (i = 0; i < section_index; i++) {
            sec = sec->next;
        }

        addr = malloc(sec->mach_section.size);
        if (!addr) {
            fatal("Failed to allocate memory for DWARF data.");
            return ENOMEM;
        }

        ret = lseek(obj->handle, sec->mach_section.offset, SEEK_SET);
        if (ret < 0) {
            fatal("error seeking: %s", strerror(errno));
            return EXIT_FAILURE;
        }

        ret = _read(obj->handle, addr, sec->mach_section.size);
        if (ret < 0) {
            fatal_file(ret);
            return EXIT_FAILURE;
        }

        *section_data = addr;
    }
    else {
        fatal("No dwarf sections defined in DWARF data.");
        *error = DW_DLE_MDE;
        return DW_DLV_ERROR;
    }

    return DW_DLV_OK;
}

static int dwarf_mach_object_relocate_a_section(
        void *obj_in,
        Dwarf_Half section_index,
        Dwarf_Debug dbg,
        int *error)
{
    return DW_DLV_NO_ENTRY;
}

static Dwarf_Small dwarf_mach_object_access_get_length_size(void *obj_in)
{
    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;
    return obj->length_size;
}

static Dwarf_Small dwarf_mach_object_access_get_pointer_size(void *obj_in)
{
    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;
    return obj->pointer_size;
}

static const struct Dwarf_Obj_Access_Methods_s
  dwarf_mach_object_access_methods = {
    dwarf_mach_object_access_get_section_info,
    dwarf_mach_object_access_get_byte_order,
    dwarf_mach_object_access_get_length_size,
    dwarf_mach_object_access_get_pointer_size,
    dwarf_mach_object_access_get_section_count,
    dwarf_mach_object_access_load_section,
    dwarf_mach_object_relocate_a_section
};


int dwarf_mach_object_access_init(
        dwarf_mach_handle handle,
        context_t* context,
        Dwarf_Obj_Access_Interface **ret_obj,
        int *err)
{
    int res = 0;
    dwarf_mach_object_access_internals_t *internals = NULL;
    Dwarf_Obj_Access_Interface *intfc = NULL;

    internals = malloc(sizeof(*internals));
    if (!internals) {
        fatal("Failed to allocate memory for DWARF macho object access internals.");
        return ENOMEM;
    }

    memset(internals, 0, sizeof(*internals));
    res = dwarf_mach_object_access_internals_init(handle, context, internals, err);
    if (res != DW_DLV_OK) {
        fatal("error initializing dwarf internals");
        return res;
    }

    intfc = malloc(sizeof(Dwarf_Obj_Access_Interface));
    if (!intfc) {
        fatal("unable to allocate memory");
        return res;
    }

    intfc->object = internals;
    intfc->methods = &dwarf_mach_object_access_methods;

    *ret_obj = intfc;
    return res;
}

void dwarf_mach_object_access_finish(Dwarf_Obj_Access_Interface *obj)
{
    if (!obj)
        return;

    if (obj->object)
        free(obj->object);
    free(obj);
}

const char *lookup_symbol_name(Dwarf_Addr addr, context_t context)
{
    struct dwarf_subprogram_t *subprogram = context.subprograms;

    while (subprogram) {
        if ((addr >= subprogram->lowpc) &&
            (addr <= subprogram->highpc)) {
            return subprogram->name;
            break;
        }

        subprogram = subprogram->next;
    }

    return "(unknown)";
}

int print_subprogram_symbol(symbolication_options_t *options, context_t context, Dwarf_Addr slide, Dwarf_Addr addr, char* symbol_buffer, size_t max_buffer_size)
{
    struct dwarf_subprogram_t *subprogram = context.subprograms;
    struct dwarf_subprogram_t *prev = NULL;
    struct dwarf_subprogram_t *match = NULL;
    char *demangled = NULL;

    addr -= slide;

    /* Address is before our first symbol */
    if (addr < subprogram->lowpc)
        return -1;

    while (subprogram) {
        if (prev && (addr < subprogram->lowpc)) {
            match = prev;
            break;
        }

        prev = subprogram;
        subprogram = subprogram->next;
    }

    if (match) {
        demangled = demangle(match->name);
        //printf("%s (in %s) + %d\n",
        //       demangled ?: match->name,
        //       basename((char *)options->dsym_filename),
        //       (unsigned int)(addr - match->lowpc));
        snprintf(symbol_buffer, max_buffer_size, "%s (in %s) + %d\n",
               demangled ?: match->name,
               basename((char *)options->dsym_filename),
               (unsigned int)(addr - match->lowpc));
        if (demangled)
            free(demangled);

    }

    return match ? 0 : -1;
}

int print_dwarf_symbol(symbolication_options_t *options, context_t context, Dwarf_Debug dbg, Dwarf_Addr slide, Dwarf_Addr addr, char* symbol_buffer, size_t max_buffer_size)
{
    static Dwarf_Arange *arange_buf = NULL;
    Dwarf_Line *linebuf = NULL;
    Dwarf_Signed linecount = 0;
    Dwarf_Off cu_die_offset = 0;
    Dwarf_Die cu_die = NULL;
    Dwarf_Unsigned segment = 0;
    Dwarf_Unsigned segment_entry_size = 0;
    Dwarf_Addr start = 0;
    Dwarf_Unsigned length = 0;
    Dwarf_Arange arange;
    static Dwarf_Signed count;
    int ret;
    Dwarf_Error err;
    int i;
    int found = 0;

    addr -= slide;

    if (!arange_buf) {
        verbose("arange_buf is undefined, invoking dwarf_get_aranges with params: dbg: 0x%x, &arange_buf: 0x%x, &count: 0x%x, &err: 0x%x", dbg, &arange_buf, &count, &err);
        ret = dwarf_get_aranges(dbg, &arange_buf, &count, &err);
        DWARF_ASSERT(ret, err);
    }
    else {
        verbose("arange_buf is already defined with address 0x%llx, NULLing it out now.", arange_buf);
        arange_buf = NULL;
        ret = dwarf_get_aranges(dbg, &arange_buf, &count, &err);
        DWARF_ASSERT(ret, err);
    }

    verbose("invoking dwarf_get_arange with params: &arange_buf: 0x%x, &count: 0x%x, addr: 0x%x, &arange: 0xlx, &err: 0x%x", &arange_buf, &count, addr, &arange, &err);
    ret = dwarf_get_arange(arange_buf, count, addr, &arange, &err);
    DWARF_ASSERT(ret, err);

    if (ret == DW_DLV_NO_ENTRY)
        return ret;

    verbose("invoking dwarf_get_arange_info_b with params: arange: 0x%x, &segment: 0x%x, &segment_entry_size: 0x%x, &start: 0x%x, &length: 0x%x, &cu_die_offset, &err: 0x%x", arange, &segment, &segment_entry_size, &start, &length, &cu_die_offset, &err);
    ret = dwarf_get_arange_info_b(
            arange,
            &segment,
            &segment_entry_size,
            &start,
            &length,
            &cu_die_offset,
            &err);
    DWARF_ASSERT(ret, err);

    verbose("invoking dwarf_offdie with params: dbg: 0x%x, cu_die_offset: 0x%x, &cu_die, &err: 0x%x", dbg, cu_die_offset, &cu_die, &err);
    ret = dwarf_offdie(dbg, cu_die_offset, &cu_die, &err);
    DWARF_ASSERT(ret, err);

    /* ret = dwarf_print_lines(cu_die, &err, &errcnt); */
    /* DWARF_ASSERT(ret, err); */

    verbose("invoking dwarf_srclines with params: cu_die: 0x%x, &linebuf: 0x%x, &linecount, &err: 0x%x", cu_die, &linebuf, &linecount, &err);
    ret = dwarf_srclines(cu_die, &linebuf, &linecount, &err);
    DWARF_ASSERT(ret, err);

    for (i = 0; i < linecount; i++) {
        Dwarf_Line prevline;
        Dwarf_Line nextline;
        Dwarf_Line line = linebuf[i];

        Dwarf_Addr lineaddr;
        Dwarf_Addr lowaddr;
        Dwarf_Addr highaddr;

        ret = dwarf_lineaddr(line, &lineaddr, &err);
        DWARF_ASSERT(ret, err);

        if (i > 0) {
            prevline = linebuf[i-1];
            ret = dwarf_lineaddr(prevline, &lowaddr, &err);
            DWARF_ASSERT(ret, err);
            lowaddr += 1;
        } else {
            lowaddr = lineaddr;
        }

        if (i < linecount - 1) {
            nextline = linebuf[i+1];
            ret = dwarf_lineaddr(nextline, &highaddr, &err);
            DWARF_ASSERT(ret, err);
            highaddr -= 1;
        } else {
            highaddr = lineaddr;
        }

        if ((addr >= lowaddr) && (addr <= highaddr)) {
            char *filename;
            Dwarf_Unsigned lineno;
            char *diename;
            const char *symbol;
            char *demangled;

            ret = dwarf_linesrc(line, &filename, &err);
            DWARF_ASSERT(ret, err);

            ret = dwarf_lineno(line, &lineno, &err);
            DWARF_ASSERT(ret, err);

            ret = dwarf_diename(cu_die, &diename, &err);
            DWARF_ASSERT(ret, err);

            symbol = lookup_symbol_name(addr, context);
            demangled = demangle(symbol);

            //printf("%s (in %s) (%s:%d)\n",
            //       demangled ? demangled : symbol,
            //       basename((char *)options->dsym_filename),
            //       basename(filename), (int)lineno);
            snprintf(symbol_buffer, max_buffer_size, "%s (in %s) (%s:%d)\n",
                   demangled ? demangled : symbol,
                   basename((char *)options->dsym_filename),
                   basename(filename), (int)lineno);

            found = 1;

            if (demangled)
                free(demangled);

            dwarf_dealloc(dbg, diename, DW_DLA_STRING);
            dwarf_dealloc(dbg, filename, DW_DLA_STRING);

            break;
        }
    }

    dwarf_dealloc(dbg, arange, DW_DLA_ARANGE);
    dwarf_srclines_dealloc(dbg, linebuf, linecount);

    return found ? DW_DLV_OK : DW_DLV_NO_ENTRY;
}

int lipo_to_tempfile(int source_fd, off_t source_pos, int* dest_fd_ref, uint32_t* magic_ref, context_t* context, int debug_mode)
{
    // do the work of lipo... given the arch, copy the data from the source file
    // and update the fd to point to the new file just past the magic.
	uint32_t magic;
    //create tempfile
    const char * TEMPLATE = "/tmp/atosl.thin.XXXXXX";
    int template_len = strlen(TEMPLATE)+1;
    char *thin_output_file = malloc(template_len);
    if (thin_output_file == NULL) {
        fatal("Failed to malloc space for tempfilename");
        return ENOMEM;
    }
    strncpy(thin_output_file, TEMPLATE, template_len);

    if (debug_mode) {
    	debug("lipo_to_tempfile invoked with parameters source_fd: %d, dest_fd_ref 0x%x, magic_ref: 0x%x, context: 0x%x", source_fd, dest_fd_ref, magic_ref, context);

    	debug("Creating temporary file with template name %s", thin_output_file);
    }

    int thin_fd = mkstemp(thin_output_file);
    int ret;

    if (debug_mode) {
    	debug("Obtained file descriptor %d for temporary file %s", thin_fd, thin_output_file);
    }

    //dispose of the file after we close it.
    ret = unlink(thin_output_file);
    if (ret) {
        fatal("Failed to unlink file %s", thin_output_file);
        return EXIT_FAILURE;
    }

    free(thin_output_file);

    if (thin_fd < 0) {
        fatal("Failed to create tempfile");
        return thin_fd;
    }

    struct stat stat_buf;
    ret = fstat(thin_fd, &stat_buf); 
    if (ret) {
        fatal("Failed to stat tmpfile!");
        return EXIT_FAILURE;
    }

    off_t bytes_written = 0;

    size_t map_size = context->arch.size + context->arch.offset;
    if (debug_mode) {
		debug("Mapped memory size is %u (0x%x)", map_size, map_size);
	}

    // Memory map the input file data for the current architecture
    void *input_buffer = mmap(0, map_size, PROT_READ, MAP_FILE|MAP_PRIVATE, source_fd, 0);

    if (input_buffer == MAP_FAILED) {
        fatal("can't mmap file (errno %d)", errno);
        return EXIT_FAILURE;
    }

    // Write the current architecture data from the memory mapped region to the new temporary file
    bytes_written = write(thin_fd, &input_buffer[context->arch.offset], context->arch.size + 2 * sizeof(magic));

    if (debug)
        debug("bytes_written = %u (0x%x), size = %u (0x%x)", bytes_written, bytes_written, context->arch.size, context->arch.size);

    if (bytes_written < context->arch.size) {
    	if (bytes_written < 0) {
    		fatal("failed to write to temporary file.  (errno = %d)", errno);
    	}
    	else {
    		fatal("short write");
    	}
        return EXIT_FAILURE;
    }

    // Unmap the memory mapped file data
    if (munmap(input_buffer,  context->arch.size + context->arch.offset) != 0) {
        fatal("can't unmap input file. (errno = %d)", errno);
        return EXIT_FAILURE;
    }
    else {
    	if (debug) {
    		debug("Successfully unmapped input file.");
    	}
    }

    // Reset the file pointer for the temporary file back to the head of the file
    if (debug) {
        debug("Seeking back to start of thinned file.  address: 0x%x, file descriptor %d.", 0, thin_fd);
    }
    ret = lseek(thin_fd, 0, SEEK_SET);
    if (ret < 0) {
        fatal("unable to seek back to start of thinned file.");
        return EXIT_FAILURE;
    }
    else {
    	if (debug) {
    		debug("Successful seek back to start of thinned file.");
    	}
    }

    // Read the magic value from the new file descriptor
    ret = _read(thin_fd, &magic, sizeof(magic));
	if (ret < 0) {
		fatal_file(thin_fd);
		return EXIT_FAILURE;
	}
	else {
		if (debug_mode) {
			debug("Read architecture-specific magic 0x%x", magic);
		}
	}

    // Store the temporary file descriptor into the out parameter
    *dest_fd_ref = thin_fd;
    *magic_ref = magic;

    return EXIT_SUCCESS;
}

static int convert_numeric_guid(context_t context, uint8_t* guid, size_t guid_element_count, char* guid_buffer, size_t max_buffer_size) {
	int uuid_index;
	char uuid[(2 * guid_element_count) + 1];
	memset(uuid, 0, (2 * guid_element_count) + 1);
	for (uuid_index = 0; uuid_index < guid_element_count; uuid_index ++) {
		sprintf(uuid + (2 * uuid_index * sizeof(char)), "%.2x", context.uuid[uuid_index]);
	}
	return snprintf(guid_buffer, max_buffer_size, "%s", uuid);
}

int load_context_count(int fd, uint32_t* nfat_arch_ref, int debug_mode) {
	int ret;
	uint32_t nfat_arch;

	// Read the count of fat binary architectures in the DWARF data
	ret = _read(fd, &nfat_arch, sizeof(nfat_arch));
	if (ret < 0) {
		fatal_file(fd);
        return EXIT_FAILURE;
    }

	nfat_arch = ntohl(nfat_arch);
	if (debug_mode) {
		debug("dsym file contains %d FAT architectures", nfat_arch);
		debug("Setting nfat_arch_ref at 0x%x to value %d", nfat_arch_ref, nfat_arch);
	}

	*nfat_arch_ref = nfat_arch;

	return ret;
}

int load_contexts(int fd, uint32_t nfat_arch, context_t* contexts, int convert_byte_order, int debug_mode) {
	int ret;
	int i;

	// First, extract the architecture contexts
	for (i = 0; i < nfat_arch; i++) {
		ret = _read(fd, &(contexts[i].arch), sizeof(contexts[i].arch));
		if (ret < 0) {
			fatal("Unable to read arch struct");
            return EXIT_FAILURE;
		}
		if (convert_byte_order) {
			contexts[i].arch.cputype = ntohl(contexts[i].arch.cputype);
			contexts[i].arch.cpusubtype = ntohl(contexts[i].arch.cpusubtype);
			contexts[i].arch.offset = ntohl(contexts[i].arch.offset);
			contexts[i].arch.size = ntohl(contexts[i].arch.size);
		}
		if (debug_mode) {
			debug("Located architecture #%d: cpu type %d (0x%x), subtype %d (0x%x), offset %u (0x%x), and size %u (0x%x)", i,
					contexts[i].arch.cputype, contexts[i].arch.cputype, contexts[i].arch.cpusubtype, contexts[i].arch.cpusubtype, contexts[i].arch.offset, contexts[i].arch.offset, contexts[i].arch.size, contexts[i].arch.size);
		}
	}

	return EXIT_SUCCESS;
}

int load_architecture_binary_data(int fd, int* arch_fd, context_t* context, Dwarf_Obj_Access_Interface *binary_interface, int* derr, int debug_mode) {
	int ret;
	uint32_t magic;

    if (debug_mode) {
        debug("Processing architecture for cpu type %d (0x%x), subtype %d (0x%x), offset %u (0x%x), and size %u (0x%x)",
                context->arch.cputype, context->arch.cputype,
                context->arch.cpusubtype, context->arch.cpusubtype,
                context->arch.offset, context->arch.offset,
                context->arch.size, context->arch.size);
    }

    if (context->arch.cputype != CPU_TYPE_I386 &&
    		context->arch.cputype != CPU_TYPE_ARM &&
    		context->arch.cputype != CPU_TYPE_ARM64) {
    	warning("CPU type %d is not recognized.  Skipping this architecture.", context->arch.cputype);
        errno = EINVAL;
    	return EXIT_FAILURE;
    }

    if (context->arch.cpusubtype != CPU_SUBTYPE_X86_ALL &&
    		context->arch.cpusubtype != CPU_SUBTYPE_ARM_V6 &&
    		context->arch.cpusubtype != CPU_SUBTYPE_ARM_V7 &&
    		context->arch.cpusubtype != CPU_SUBTYPE_ARM_V7S &&
    		context->arch.cpusubtype != CPU_SUBTYPE_ARM64_ALL) {
		warning("CPU subtype %d is not recognized.  Skipping this architecture.", context->arch.cpusubtype);
        errno = EINVAL;
    	return EXIT_FAILURE;
	}

    if (context->arch.size == 0) {
    	warning("Architecture size %d is invalid.  Skipping this architecture.", context->arch.size);
        errno = EINVAL;
    	return EXIT_FAILURE;
    }

    if (context->arch.cputype == CPU_TYPE_ARM64) {
    	if (debug_mode) {
    		debug("Detected 64-bit ARM architecture.");
    	}
    }

    ret = lseek(fd, 0, SEEK_CUR);
    if (ret < 0) {
        return EXIT_SUCCESS;
    }

    if(debug_mode) {
        debug("Current file descriptor position: %d (0x%x)", ret, ret);
        debug("Executing seek to address 0x%x on file descriptor %d...", context->arch.offset, fd);
    }
    ret = lseek(fd, context->arch.offset, SEEK_SET);
    if (ret < 0) {
        fatal("Unable to seek to arch (offset=%x): %s",
              context->arch.offset, strerror(errno));
        return EXIT_FAILURE;
    }
    else {
        if (debug_mode) {
            debug("Seek to offset 0x%x completed successfully on file descriptor %d", context->arch.offset, fd);
            debug("  call to lseek returned 0x%x (%d)", ret, ret);
        }
    }

    ret = _read(fd, &magic, sizeof(magic));
    if (ret < 0) {
        fatal_file(fd);
        return EXIT_FAILURE;
    }
    else {
        if (debug_mode) {
            debug("Read architecture magic 0x%x", magic);
            debug("  call to _read returned 0x%x (%d)", ret, ret);
        }
    }

    if (debug_mode) {
        debug("Attempting to extract architecture-specific DWARF data to temporary file...");
    }
    ret = lipo_to_tempfile(fd, context->arch.offset, arch_fd, &magic, context, debug_mode);
    if (ret) {
        fatal("unable to extract LIPO to temp file");
        return ret;
    }
    else {
        if (debug_mode) {
            debug("Successfully extracted architecture-specific DWARF data to temporary file.  Architecture-specific file descriptor: %d", arch_fd);
        }
    }

    if (magic != MH_MAGIC && magic != MH_MAGIC_64) {
        fatal("Invalid magic for architecture.  Found magic 0x%x, expected MH_MAGIC (0x%x) or MH_MAGIC_64 (0x%x)", magic, MH_MAGIC, MH_MAGIC_64);
        errno = EINVAL;
        return EXIT_FAILURE;
    }
    else {
        if (debug_mode) {
            debug("Magic 0x%x matches MH_MAGIC (0x%x) or MH_MAGIC_64 (0x%x)", magic, MH_MAGIC, MH_MAGIC_64);
        }
    }

    if (debug_mode) {
        debug("Successfully located magic 0x%x for architecture with CPU type %d, subtype %d", magic, context->arch.cputype, context->arch.cpusubtype);
        debug("Initializing MACH dwarf object binary interface from file descriptor %d", arch_fd);
    }

    dwarf_mach_object_access_init(*arch_fd, context, &binary_interface, derr);
    assert(binary_interface);

    if (debug_mode) {
		debug("MACH dwarf object binary interface successfully initialized.");
	}

    return EXIT_SUCCESS;
}

int atosl_load_guids(const char* dsym_filename, guid_load_result_t* guid_result, size_t max_guid_result_count, size_t* result_count, size_t max_guid_buffer_size, int debug_mode) {
    int fd;
    int ret;
    int i;
    Dwarf_Obj_Access_Interface *binary_interface = NULL;
    uint32_t magic;
    int derr = 0;

    if (debug_mode) {
        setbuf(stdout, NULL);
        debug("atosl_load_guids invoked with parameters:");
        debug("    dsym_filename: %s", dsym_filename);
        debug("    guid_result: %x", max_guid_result_count);
        debug("    max_guid_result_count: %d", max_guid_result_count);
        debug("    max_guid_buffer_size: %d", max_guid_buffer_size);
    }

    if (debug_mode) {
        debug("Opening dsym file...");
    }
    fd = open(dsym_filename, O_RDONLY);
    if (fd < 0) {
        fatal("Unable to open dsym file `%s': %s",
              dsym_filename,
              strerror(errno));
        return EXIT_FAILURE;
    }

    if (debug_mode) {
        debug("Dsym file opened with file descriptor %d.  Reading magic from dsym file...", fd);
    }
    ret = _read(fd, &magic, sizeof(magic));
    if (ret < 0) {
        fatal_file(fd);
        return EXIT_FAILURE;
    }
    else {
        if (debug_mode) {
            debug("Read magic value 0x%x from dsym file", magic);
        }
    }

    if (magic == FAT_CIGAM) {
    	if (debug_mode) {
			debug("Magic value 0x%x matches FAT_CIGAM value 0x%x.  Processing as a multi-architecture dSym.", magic, FAT_CIGAM);
		}
        uint32_t nfat_arch;
        context_t* contexts = NULL;

        ret = load_context_count(fd, &nfat_arch, debug_mode);
        if (ret < 0) {
			fatal("Failed to load context count from file descriptor %d", fd);
            return EXIT_FAILURE;
		}
		else {
			if (debug_mode) {
				debug("Loaded context count %d contexts from dsym headers.", nfat_arch);
			}
		}

        contexts = malloc(nfat_arch * sizeof(context_t));
        if (!contexts) {
            fatal("Failed to allocate memory for the DWARF contexts.");
            errno = ENOMEM;
            return EXIT_FAILURE;
        }
		memset(contexts, 0, nfat_arch * sizeof(context_t));

        ret = load_contexts(fd, nfat_arch, contexts, 1, debug_mode);
        if (ret < 0) {
        	fatal("Failed to load contexts from file descriptor %d", fd);
            return EXIT_FAILURE;
        }
        else {
        	if (debug_mode) {
        		debug("Loaded %d contexts from dsym headers.", nfat_arch);
        	}
        }

        if (debug_mode) {
            debug("----------------------------------------");
        }

        // Iterate the fat binary architectures and extract the GUID from each one
        int guid_count = 0;
        for (i = 0; i < nfat_arch; i++) {
        	if (i < max_guid_result_count) {
                if (debug_mode) {
                    debug("Processing FAT architecture %d of %d", i + 1, nfat_arch);
                    debug(" CPU type: %d, subtype: %d", contexts[i].arch.cputype, contexts[i].arch.cpusubtype);
                }
                guid_result[i].cpu_type = contexts[i].arch.cputype; 
                guid_result[i].cpu_subtype = contexts[i].arch.cpusubtype; 
                context_t context = contexts[i];
                int arch_fd;

                ret = load_architecture_binary_data(fd, &arch_fd, &context, binary_interface, &derr, debug_mode);

                char uuid[UUID_STR_LEN];
                memset(uuid, 0, UUID_STR_LEN);
                ret = convert_numeric_guid(context, context.uuid, UUID_LEN, uuid, UUID_STR_LEN);
                if (ret < 0) {
                    fatal("Failed to write GUID to character buffer. (%d) %s", errno, strerror(errno));
                    free(contexts);
                    return EXIT_FAILURE;
                }
                if (debug_mode) {
                    debug("(%d,%d) UUID: %s", context.arch.cputype, context.arch.cpusubtype, uuid);
                }
                snprintf(guid_result[i].guid_buffer, max_guid_buffer_size, "%s", uuid);
                guid_count ++;
            }
            else {
                if (debug_mode) {
                    debug("Skipping FAT architecture %d of %d - dSym contains more architectures than result array can hold (%d)", i + 1, nfat_arch, max_guid_result_count);
                }
            }
            
            if (debug_mode) {
                debug("----------------------------------------");
            }
        }
        *result_count = guid_count;
        free(contexts);
    }
    else {
        if (debug_mode) {
            debug("Magic value 0x%x does not match FAT_CIGAM value 0x%x.  Processing as a single architecture dSym.", magic, FAT_CIGAM);
        }
        if (magic != MH_MAGIC && magic != MH_MAGIC_64) {
            fatal("Invalid magic for architecture.  Found magic 0x%x, expected MH_MAGIC (0x%x) or MH_MAGIC_64 (0x%x)", magic, MH_MAGIC, MH_MAGIC_64);
            return EINVAL;
        }
        if (max_guid_result_count < 1) {
            if (debug_mode) {
                debug("Max GUID result count is less than 1: %d", max_guid_result_count);
            }
            return EINVAL;
        }
        context_t context;
        memset(&context, 0, sizeof(context_t));
        ret = load_contexts(fd, 1, &context, 0, debug_mode);
        if (ret < 0) {
        	fatal("Failed to load contexts from file descriptor %d", fd);
            return ret;
        }
        else {
        	if (debug_mode) {
        		debug("Loaded 1 context from dsym headers.");
        	}
        }

        ret = lseek(fd, sizeof(magic), SEEK_SET);
        if (ret < 0) {
            return EXIT_FAILURE;
        }

        dwarf_mach_object_access_init(fd, &context, &binary_interface, &derr);
        assert(binary_interface);

        char uuid[UUID_STR_LEN];
        memset(uuid, 0, UUID_STR_LEN);
        ret = convert_numeric_guid(context, context.uuid, UUID_LEN, uuid, UUID_STR_LEN);
        if (debug_mode) {
        	debug("(%d,%d) UUID: %s", context.arch.cputype, context.arch.cpusubtype, uuid);
        }
        snprintf(guid_result->guid_buffer, max_guid_buffer_size, "%s", uuid);
        guid_result->cpu_type = context.arch.cputype;
        guid_result->cpu_subtype = context.arch.cpusubtype;
        *result_count = 1;
    }

    return EXIT_SUCCESS;
}


int atosl_symbolicate(symbolication_options_t *options, Dwarf_Addr symbol_address, symbolication_result_t* symbolication_result, size_t max_symbolication_buffer_size, int debug_mode) {
    int fd;
    int ret;
    context_t* symbol_context;
    Dwarf_Debug dbg = NULL;
    Dwarf_Error err;
    int derr = 0;
    int i;
    int found = 0;
    Dwarf_Obj_Access_Interface *binary_interface = NULL;
    Dwarf_Ptr errarg = NULL;
    uint32_t magic;

    if (debug_mode) {
        verbose = 1;
        setbuf(stdout, NULL);
        debug("atosl_symbolicate invoked with parameters:");
        debug("    options: 0x%llx", (long long unsigned int) options);
        debug("        load_address: 0x%llx", options->load_address);
        debug("        use_globals: %d", options->use_globals);
        debug("        use_cache: %d", options->use_cache);
        debug("        dsym_filename: %s", options->dsym_filename);
        debug("        cpu_type: 0x%x", options->cpu_type);
        debug("        cpu_subtype: 0x%x", options->cpu_subtype);
        debug("        cache_dir: %s", options->cache_dir ? options->cache_dir : "NULL");
        debug("    symbol_address: 0x%x", symbol_address);
        debug("    symbolication_result: 0x%x", (long long unsigned int) symbolication_result);
        debug("    max_symbolication_buffer_size: %u", (unsigned int) max_symbolication_buffer_size);
    }


    if (!options->dsym_filename) {
        fatal("No dsym filename specified.");
        errno = ENOENT;
        return EXIT_FAILURE;
    }

    if (debug_mode) {
        debug("opening dsym file...");
    }
    fd = open(options->dsym_filename, O_RDONLY);
    if (fd < 0) {
        fatal("Unable to open dsym file `%s': %s",
              options->dsym_filename,
              strerror(errno));
        return EXIT_FAILURE;
    }

    if (debug_mode) {
        debug("dsym file opened with file descriptor %d.  Reading magic from dsym file...");
    }
    ret = _read(fd, &magic, sizeof(magic));
    if (ret < 0) {
        fatal_file(fd);
        return EXIT_FAILURE;
    }

    if (debug_mode) {
    	debug("Read magic value 0x%x from dsym file.", magic);
    }

    if (magic == FAT_CIGAM) {
    	if (debug_mode) {
			debug("Magic value 0x%x matches FAT_CIGAM value 0x%x.  Processing as a multi-architecture dSym.", magic, FAT_CIGAM);
		}
		uint32_t nfat_arch;
		context_t* contexts = NULL;

		ret = load_context_count(fd, &nfat_arch, debug_mode);
		if (ret < 0) {
			fatal("Failed to load context count from file descriptor %d", fd);
            return EXIT_FAILURE;
		}
		else {
			if (debug_mode) {
				debug("Loaded context count %d contexts from dsym headers.", nfat_arch);
			}
		}

		contexts = malloc(nfat_arch * sizeof(context_t));
        if (!contexts) {
            fatal("Failled to allocate memory for contexts.");
            errno = ENOMEM;
            return EXIT_FAILURE;
        }
		memset(contexts, 0, nfat_arch * sizeof(context_t));

		ret = load_contexts(fd, nfat_arch, contexts, 1, debug_mode);
		if (ret < 0) {
			fatal("Failed to load contexts from file descriptor %d", fd);
            free(contexts);
            return EXIT_FAILURE;
		}
		else {
			if (debug_mode) {
				debug("Loaded %d contexts from dsym headers.", nfat_arch);
			}
		}

		if (debug_mode) {
			debug("----------------------------------------");
		}

        /* Find the architecture that matches the architecture for the request */
        for (i = 0; i < nfat_arch; i++) {
        	int arch_fd;
        	context_t context = contexts[i];

            if ((context.arch.cputype == options->cpu_type) &&
                (context.arch.cpusubtype == options->cpu_subtype)) {
            	found = 1;
            	if (debug_mode) {
                	debug("Requested architecture located at index %d.", i);
                }

                ret = lipo_to_tempfile(fd, context.arch.offset, &arch_fd, &magic, &context, debug_mode);
                if (ret) {
                    fatal("Failed to extract LIPO to temporary file.");
                    free(contexts);
                    return EXIT_FAILURE;
                }
                // Close the source fd and then set it to the architecture-specific fd
                ret = close(fd);
                if (ret < 0) {
                	if (debug_mode) {
                		warning("Failed to close source file descriptor %d: (%d) %s", fd, errno, strerror(errno));
                	}
                    free(contexts);
                    return EXIT_FAILURE;
                }
                fd = arch_fd;
                symbol_context = &context;
                break;
            } else {
                // This architecture is not the requested architecture, skip over it
                if (debug_mode) {
                    debug("Skipping architecture at index %d with cpu type: %d (0x%x) and cpu subtype: %d (0x%x)",
                            i, context.arch.cputype, context.arch.cputype, context.arch.cpusubtype, context.arch.cpusubtype);
                    debug("----------------------------------------");
                }
            }
        }
    } else {
    	// If the dSym is a single-arch DWARF file, it is de-facto "found"
    	if (debug_mode) {
			debug("Magic value 0x%x does not match FAT_CIGAM value 0x%x.  Processing as a single-architecture dSym.", magic, FAT_CIGAM);
		}
    	uint32_t nfat_arch = 1;
        found = 1;
        context_t* contexts;
        off_t position;

        contexts = malloc(sizeof(context_t));
        if (!contexts) {
            fatal("Failed to allocate memory for contexts.");
            errno = ENOMEM;
            return EXIT_FAILURE;
        }
		memset(contexts, 0, sizeof(context_t));

		// get the position of the file descriptor
		ret = lseek(fd, 0, SEEK_CUR);
		if (ret < 0) {
			fatal("Failed to set file descriptor position to precede the MACH header: (%d) %s", errno, strerror(errno));
            free(contexts);
            return EXIT_FAILURE;
		}
		else {
			position = ret;
			if (debug_mode) {
				debug("File descriptor position prior to context load: %d (0x%x)", position, position);
			}
		}

		ret = load_contexts(fd, nfat_arch, contexts, 0, debug_mode);
		if (ret < 0) {
			fatal("Failed to read architecture header.");
            free(contexts);
			return EXIT_FAILURE;
		}
		else {
			symbol_context = contexts;
		}

		// re-position the file descriptor position to before the MACH header so that the binary interface initialization works
		ret = lseek(fd, position, SEEK_SET);
		if (ret < 0) {
			fatal("Failed to set file descriptor position to precede the MACH header: (%d) %s", errno, strerror(errno));
            free(contexts);
            return EXIT_FAILURE;
		}
		else {
			if (debug_mode) {
				debug("Successfully reset the file descriptor position to %d (0x%x)", ret, ret);
			}
		}
    }

    if (!found) {
        fatal("No valid architectures found in dsym file.");
        errno = EINVAL;
        return EXIT_FAILURE;
    }

    if (magic != MH_MAGIC && magic != MH_MAGIC_64) {
        fatal("invalid magic for architecture");
        errno = EINVAL;
        return EXIT_FAILURE;
    }

    if (debug_mode) {
        debug("Successfully located magic 0x%x for architecture with CPU type %d and subtype %d", magic, symbol_context->arch.cputype, symbol_context->arch.cpusubtype);
        debug("Initializing MACH dwarf object binary interface...");
    }
    dwarf_mach_object_access_init(fd, symbol_context, &binary_interface, &derr);
    assert(binary_interface);

    if (options->load_address == LONG_MAX)
        options->load_address = symbol_context->intended_addr;

    if (debug_mode) {
        debug("Initializing dwarf object...");
    }
    ret = dwarf_object_init(binary_interface,
                            dwarf_error_handler,
                            errarg, &dbg, &err);
    DWARF_ASSERT(ret, err);

    /* If there is dwarf info we'll use that to parse, otherwise we'll use the
     * symbol table */
    if (ret == DW_DLV_OK) {
        if (debug_mode) {
            debug("dSym data contains DWARF symbols.  Using the DWARF data to resolve symbols.");
        }
        struct subprograms_options_t opts = {
            .persistent = options->use_cache,
            .cache_dir = options->cache_dir,
        };

        if (debug_mode) {
            debug("Attempting to parse and load DWARF subprogram data...");
        }
        symbol_context->subprograms =
            subprograms_load(dbg,
            		symbol_context->uuid,
                             options->use_globals ? SUBPROGRAMS_GLOBALS :
                                                   SUBPROGRAMS_CUS,
                             &opts);

        if (debug_mode) {
            debug("Building DWARF symbol table. Using params options: 0x%x, dbg: 0x%x, slide: 0x%x, addr: 0x%x, symbol_buffer: 0x%x, max_buffer_size: %d",
            		options, dbg, options->load_address - symbol_context->intended_addr, symbol_address, symbolication_result->symbol_buffer, max_symbolication_buffer_size);
        }
        ret = print_dwarf_symbol(options, *symbol_context, dbg,
                             options->load_address - symbol_context->intended_addr,
                             symbol_address, symbolication_result->symbol_buffer, max_symbolication_buffer_size);
        if (ret != DW_DLV_OK) {
            if (debug_mode) {
                debug("Failed to locate the symbol in the DWARF symbol table.  Attempting to resolve the symbol in the subprogram symbols...");
            }
            derr = print_subprogram_symbol(
                     options, *symbol_context, options->load_address - symbol_context->intended_addr, symbol_address, symbolication_result->symbol_buffer, max_symbolication_buffer_size);
        }

        if ((ret != DW_DLV_OK) && derr) {
            if (debug_mode) {
                debug("Failed to locate the symbol in the DWARF symbol table or the subprogram symbols.  Returning the symbol address as the symbol name.");
            }
            snprintf(symbolication_result->symbol_buffer, max_symbolication_buffer_size, "0x%llx", symbol_address);
        }

        dwarf_mach_object_access_finish(binary_interface);

        ret = dwarf_object_finish(dbg, &err);
        DWARF_ASSERT(ret, err);
    } else {
        if (debug_mode) {
            debug("dSym data does not contain DWARF symbols.  Using symtab lookup to resolve symbols.");
        }
        ret = print_symtab_symbol(options,
                options->load_address - symbol_context->intended_addr,
                symbol_address, symbol_context, symbolication_result->symbol_buffer, max_symbolication_buffer_size);

        if (ret != DW_DLV_OK) {
            if (debug_mode) {
                debug("Unable to locate symbol in the symtab data, returning the symbol address.");
            }
            snprintf(symbolication_result->symbol_buffer, max_symbolication_buffer_size, "0x%llx", symbol_address);
        }
    }
    symbolication_result->cpu_type = symbol_context->arch.cputype;
    symbolication_result->cpu_subtype = symbol_context->arch.cpusubtype;

    close(fd);
    return ret;
}

int main(int argc, char *argv[]) {
    int i;
    int option_index;
    int c;
    int result = 0;
    int uuid_mode = 0;
    cpu_type_t cpu_type = -1;
    cpu_subtype_t cpu_subtype = -1;
    symbolication_options_t options = default_options;
    Dwarf_Addr address;


    while ((c = getopt_long(argc, argv, shortopts, longopts, &option_index))
            >= 0) {
        switch (c) {
            case 'l':
                errno = 0;
                address = strtol(optarg, (char **)NULL, 16);
                if (errno != 0) {
                    fatal("invalid load address: `%s': %s", optarg, strerror(errno));
                    return EXIT_FAILURE;
                }
                options.load_address = address;
                break;
            case 'o':
                options.dsym_filename = optarg;
                break;
            case 'A':
                for (i = 0; i < NUMOF(arch_str_to_type); i++) {
                    if (strcmp(arch_str_to_type[i].name, optarg) == 0) {
                        cpu_type = arch_str_to_type[i].type;
                        cpu_subtype = arch_str_to_type[i].subtype;
                        break;
                    }
                }
                if ((cpu_type < 0) && (cpu_subtype < 0)) {
                    fatal("unsupported architecture `%s'", optarg);
                    return EXIT_FAILURE;
                }
                options.cpu_type = cpu_type;
                options.cpu_subtype = cpu_subtype;
                break;
            case 'd':
                debug = 1;
                break;
            case 'v':
				verbose = 1;
				break;
            case 'g':
                options.use_globals = 1;
                break;
            case 'c':
                options.use_cache = 0;
                break;
            case 'C':
                options.cache_dir = optarg;
                break;
            case 'u':
                uuid_mode = 1;
                break;
            case 'V':
                fprintf(stderr, "atosl %s\n", VERSION);
                exit(EXIT_SUCCESS);
            case '?':
                print_help();
                exit(EXIT_FAILURE);
            case 'h':
                print_help();
                exit(EXIT_SUCCESS);
            default:
                fatal("unhandled option");
                return EXIT_FAILURE;
        }
    }
    if (uuid_mode) {
        guid_load_result_t guid_result[8];
        memset(guid_result, 0, 8 * sizeof(guid_load_result_t));
        for (i = 0; i < 8; i++) {
            guid_result[i].guid_buffer = malloc(1024);
            memset(guid_result[i].guid_buffer, 0, 1024);
        }

        size_t result_count = 0;
        result = atosl_load_guids(options.dsym_filename, guid_result, 8, &result_count, 1024, debug);
        if (result < 0) {
            printf("UUID resolution generated an error code: %d\n", result);
        }
        for (i = 0; i < result_count; i++) {
            // printf("CPU type: %d\n", guid_result[i].cpu_type);
            // printf("CPU subtype: %d\n", guid_result[i].cpu_subtype);
            switch (guid_result[i].cpu_type) {
                case CPU_TYPE_ARM:
                    printf("ARM");
                    break;
                case CPU_TYPE_ARM64:
                    printf("ARM64");
                    break;
                case CPU_TYPE_I386:
                    printf("i386");
                    break;
            }
            switch (guid_result[i].cpu_subtype) {
                case CPU_SUBTYPE_ARM_V6:
                    printf("v6");
                    break;
                case CPU_SUBTYPE_ARM_V7:
                    printf("v7");
                    break;
                case CPU_SUBTYPE_ARM_V7S:
                    printf("v7s");
                    break;
                case CPU_SUBTYPE_ARM64_ALL:
                    printf("(all)");
                    break;
                case CPU_SUBTYPE_X86_ALL:
                    printf("(all)");
                    break;
            }
            printf(" - %s\n", guid_result[i].guid_buffer);
        }
    }
    else {

        if (argc <= optind) {
            fatal_usage("no addresses specified");
            return EXIT_FAILURE;
        }

        for (i = optind; i < argc; i++) {
            Dwarf_Addr addr;
            errno = 0;
            addr = strtol(argv[i], (char **)NULL, 16);
            if (errno != 0) {
                fatal("invalid address: `%s': %s", argv[i], strerror(errno));
                return EXIT_FAILURE;
            }
            symbolication_result_t symbol_result;
            memset(&symbol_result, 0, sizeof(symbolication_result_t));
            symbol_result.symbol_buffer = malloc(256);
            memset(symbol_result.symbol_buffer, 0, 256);
            result = atosl_symbolicate(&options, addr, &symbol_result, 256, debug); 
            if (result == 0) {
                printf("Symbolication generated an error code: %d\n", result);
            }
            printf("%s\n", symbol_result.symbol_buffer);
        }
    }
    return result;
}
/* vim:set ts=4 sw=4 sts=4 expandtab: */
