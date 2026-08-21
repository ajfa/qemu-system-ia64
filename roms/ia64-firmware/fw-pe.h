/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * PE32+ / IA-64 image structures and the PE loader API (pe_loader.c).
 */

#ifndef IA64_FIRMWARE_FW_PE_H
#define IA64_FIRMWARE_FW_PE_H

#include "fw-base.h"
#include "fw-efi-types.h"
#include "fw-platform-layout.h"

#define IMAGE_FILE_MACHINE_EBC    0x0ebc
#define IMAGE_FILE_MACHINE_IA64   0x0200
#define IMAGE_DOS_SIGNATURE       0x5A4D    /* "MZ" */
#define IMAGE_NT_SIGNATURE        0x00004550  /* "PE\0\0" */
#define IMAGE_FILE_RELOCS_STRIPPED 0x0001U
#define IA64_EFI_IMAGE_FALLBACK_BASE         FW_LOW_FREE_BASE
#define IA64_EFI_RUNTIME_IMAGE_FALLBACK_BASE FW_LOW_RUNTIME_IMAGE_BASE
#define IA64_EFI_IMAGE_ALIGN                 0x00010000ULL


typedef struct {
    UINT16  e_magic;
    UINT16  e_cblp;
    UINT16  e_cp;
    UINT16  e_crlc;
    UINT16  e_cparhdr;
    UINT16  e_minalloc;
    UINT16  e_maxalloc;
    UINT16  e_ss;
    UINT16  e_sp;
    UINT16  e_csum;
    UINT16  e_ip;
    UINT16  e_cs;
    UINT16  e_lfarlc;
    UINT16  e_ovno;
    UINT16  e_res[4];
    UINT16  e_oemid;
    UINT16  e_oeminfo;
    UINT16  e_res2[10];
    UINT32  e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    UINT16  Machine;
    UINT16  NumberOfSections;
    UINT32  TimeDateStamp;
    UINT32  PointerToSymbolTable;
    UINT32  NumberOfSymbols;
    UINT16  SizeOfOptionalHeader;
    UINT16  Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    UINT16  Magic;
    UINT8   MajorLinkerVersion;
    UINT8   MinorLinkerVersion;
    UINT32  SizeOfCode;
    UINT32  SizeOfInitializedData;
    UINT32  SizeOfUninitializedData;
    UINT32  AddressOfEntryPoint;
    UINT32  BaseOfCode;
    UINT32  BaseOfData;
    UINT32  ImageBase;
    UINT32  SectionAlignment;
    UINT32  FileAlignment;
    UINT16  MajorOperatingSystemVersion;
    UINT16  MinorOperatingSystemVersion;
    UINT16  MajorImageVersion;
    UINT16  MinorImageVersion;
    UINT16  MajorSubsystemVersion;
    UINT16  MinorSubsystemVersion;
    UINT32  Win32VersionValue;
    UINT32  SizeOfImage;
    UINT32  SizeOfHeaders;
    UINT32  CheckSum;
    UINT16  Subsystem;
    UINT16  DllCharacteristics;
    UINT32  SizeOfStackReserve;
    UINT32  SizeOfStackCommit;
    UINT32  SizeOfHeapReserve;
    UINT32  SizeOfHeapCommit;
    UINT32  LoaderFlags;
    UINT32  NumberOfRvaAndSizes;
} IMAGE_OPTIONAL_HEADER32;

typedef struct {
    UINT16  Magic;                   /* 0x020B for PE32+ */
    UINT8   MajorLinkerVersion;
    UINT8   MinorLinkerVersion;
    UINT32  SizeOfCode;
    UINT32  SizeOfInitializedData;
    UINT32  SizeOfUninitializedData;
    UINT32  AddressOfEntryPoint;     /* RVA of entry point plabel */
    UINT32  BaseOfCode;
    UINT64  ImageBase;
    UINT32  SectionAlignment;
    UINT32  FileAlignment;
    UINT16  MajorOperatingSystemVersion;
    UINT16  MinorOperatingSystemVersion;
    UINT16  MajorImageVersion;
    UINT16  MinorImageVersion;
    UINT16  MajorSubsystemVersion;
    UINT16  MinorSubsystemVersion;
    UINT32  Win32VersionValue;
    UINT32  SizeOfImage;
    UINT32  SizeOfHeaders;
    UINT32  CheckSum;
    UINT16  Subsystem;
    UINT16  DllCharacteristics;
    UINT64  SizeOfStackReserve;
    UINT64  SizeOfStackCommit;
    UINT64  SizeOfHeapReserve;
    UINT64  SizeOfHeapCommit;
    UINT32  LoaderFlags;
    UINT32  NumberOfRvaAndSizes;
} IMAGE_OPTIONAL_HEADER64;

typedef struct {
    UINT8   Name[8];
    UINT32  VirtualSize;
    UINT32  VirtualAddress;
    UINT32  SizeOfRawData;
    UINT32  PointerToRawData;
    UINT32  PointerToRelocations;
    UINT32  PointerToLinenumbers;
    UINT16  NumberOfRelocations;
    UINT16  NumberOfLinenumbers;
    UINT32  Characteristics;
} IMAGE_SECTION_HEADER;

#define IMAGE_REL_BASED_ABSOLUTE       0
#define IMAGE_REL_BASED_HIGHLOW        3
#define IMAGE_REL_BASED_IA64_IMM64     9
#define IMAGE_REL_BASED_DIR64          10

#define IMAGE_SCN_CNT_CODE             0x00000020U
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040U
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080U
#define IMAGE_SCN_MEM_EXECUTE          0x20000000U

#define IA64_BUNDLE_TEMPLATE_MASK      0x1FULL
#define IA64_SLOT_MASK                 0x1FFFFFFFFFFULL

#define IMAGE_SUBSYSTEM_EFI_APPLICATION         10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER      12
#define LOADED_IMAGE_MAX             8

typedef struct {
    BOOLEAN in_use;
    BOOLEAN started;
    BOOLEAN is_ebc;
    EFI_HANDLE handle;
    UINTN (*entry)(EFI_HANDLE, EFI_SYSTEM_TABLE *);
    VOID *device_path;
    VOID *hii_package_list;
    UINT64 *runtime_relocation_log;
    UINTN runtime_relocation_entries;
    EFI_LOADED_IMAGE_PROTOCOL loaded_image;
} EFI_LOADED_IMAGE_RECORD;

extern EFI_LOADED_IMAGE_RECORD mLoadedImages[LOADED_IMAGE_MAX];
UINT64 pe_loaded_image_allocation_size(UINTN ImageSize,
                                       EFI_MEMORY_TYPE CodeType);
void pe_release_loaded_image_memory(VOID *ImageBase, UINTN ImageSize,
                                    EFI_MEMORY_TYPE CodeType);
void pe_image_memory_types(UINT16 Subsystem, EFI_MEMORY_TYPE *CodeType,
                           EFI_MEMORY_TYPE *DataType);

typedef enum {
    PE_RELOCATE_LOAD,
    PE_RELOCATE_RUNTIME,
} PE_RELOCATION_MODE;

extern UINT64 mNextPeImageBase;

typedef struct {
    VOID *base;
    UINTN size;
    UINT16 subsystem;
    UINT16 machine;
    VOID *hii_package_list;
    UINT64 *runtime_relocation_log;
    UINTN runtime_relocation_entries;
} PE_LOADED_IMAGE_RESULT;

void *load_pe_image(uint8_t *image_base, UINTN image_size,
                    PE_LOADED_IMAGE_RESULT *Result);
void pe_discard_loaded_image_result(PE_LOADED_IMAGE_RESULT *Result);
EFI_STATUS pe_relocate_runtime_images(void);
BOOLEAN pe_mark_loaded_image_memory(UINT64 ImageBase,
                                    UINT32 SizeOfImage,
                                    const IMAGE_SECTION_HEADER *Sections,
                                    UINT16 NumberOfSections,
                                    EFI_MEMORY_TYPE CodeType,
                                    EFI_MEMORY_TYPE DataType);
UINT64 pe_choose_image_base(UINT64 preferred_base, UINT64 size,
                            BOOLEAN RuntimeImage, BOOLEAN FixedBase,
                            UINT64 SourceBase, UINT64 SourceSize);
BOOLEAN pe_apply_relocations(UINT64 ImageBase, UINT32 SizeOfImage,
                             UINT32 RelocRva, UINT32 RelocSize,
                             UINT64 Adjust, PE_RELOCATION_MODE Mode,
                             UINT64 *RelocationLog,
                             UINTN RelocationLogEntries);
EFI_STATUS pe_relocate_loaded_runtime_image(UINT64 ImageBase,
                                            UINTN ImageSize,
                                            UINT64 *RelocationLog,
                                            UINTN RelocationLogEntries);
void pe_ia64_store_bundle(UINT64 *bundle, UINT64 template,
                          UINT64 slot0, UINT64 slot1, UINT64 slot2);
UINT64 pe_ia64_movl_set_imm64(UINT64 x_slot, UINT64 imm64);
BOOLEAN pe_read_ia64_imm64_reloc(UINT8 *reloc_addr, UINT64 *Imm64);
BOOLEAN pe_hii_package_list_selftest(VOID);

#endif /* IA64_FIRMWARE_FW_PE_H */
