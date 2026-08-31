/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "ia64-test.h"

#define EFI_MEMORY_RUNTIME 0x8000000000000000ULL
#define IA64_RUNTIME_ALIGNMENT 0x2000ULL
#define IA64_LEGACY_IO_BASE 0x00000ffffc000000ULL
#define VGA_TEXT_FB_BASE 0x00000000000b8000ULL
#define VGA_TEXT_COLUMNS 80U
#define VGA_TEXT_ROWS 25U
#define VBE_DISPI_INDEX_ENABLE 4U

static UINT16 vbe_read(UINT16 Index)
{
    volatile UINT16 *index =
        (volatile UINT16 *)(UINTN)(IA64_LEGACY_IO_BASE + 0x1ceU);
    volatile UINT16 *data =
        (volatile UINT16 *)(UINTN)(IA64_LEGACY_IO_BASE + 0x1d0U);

    *index = Index;
    return *data;
}

static BOOLEAN legacy_text_handoff_is_ready(void)
{
    volatile UINT16 *text =
        (volatile UINT16 *)(UINTN)VGA_TEXT_FB_BASE;

    return vbe_read(VBE_DISPI_INDEX_ENABLE) == 0 &&
           text[0] == 0x0720U &&
           text[VGA_TEXT_COLUMNS * VGA_TEXT_ROWS - 1U] == 0x0720U;
}

static UINT8 sal_guid[16] = IA64_GUID_SAL;
static UINT8 smbios_guid[16] = IA64_GUID_SMBIOS;
static UINT8 debug_image_guid[16] = {
    0x77, 0x2e, 0x15, 0x49, 0xda, 0x1a, 0x64, 0x47,
    0xb7, 0xa2, 0x7a, 0xfe, 0xfe, 0xd9, 0x5e, 0x8b,
};

static UINT32 crc32_bytes(const UINT8 *Data, UINTN Size)
{
    UINT32 crc = 0xffffffffU;
    UINTN index;

    for (index = 0; index < Size; index++) {
        UINTN bit;

        crc ^= Data[index];
        for (bit = 0; bit < 8U; bit++) {
            crc = (crc >> 1) ^
                  ((crc & 1U) != 0 ? 0xedb88320U : 0U);
        }
    }
    return ~crc;
}

static BOOLEAN system_table_crc_is_valid(EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_SYSTEM_TABLE copy;
    UINT32 expected;

    if (SystemTable == NULL ||
        SystemTable->Hdr.HeaderSize < sizeof(EFI_TABLE_HEADER) ||
        SystemTable->Hdr.HeaderSize > sizeof(copy)) {
        return 0;
    }
    ia64_copy(&copy, SystemTable, sizeof(copy));
    expected = copy.Hdr.CRC32;
    copy.Hdr.CRC32 = 0;
    return crc32_bytes((const UINT8 *)&copy, copy.Hdr.HeaderSize) == expected;
}

static EFI_STATUS get_final_memory_map(EFI_BOOT_SERVICES *BootServices,
                                       EFI_MEMORY_DESCRIPTOR **Map,
                                       UINTN *MapSize, UINTN *MapKey,
                                       UINTN *DescriptorSize,
                                       UINT32 *DescriptorVersion)
{
    EFI_STATUS status;
    UINTN attempt;

    *Map = NULL;
    *MapSize = 0;
    for (attempt = 0; attempt < 4U; attempt++) {
        UINTN required = *MapSize;
        EFI_MEMORY_DESCRIPTOR *new_map = NULL;

        status = BootServices->GetMemoryMap(
            &required, *Map, MapKey, DescriptorSize, DescriptorVersion);
        if (status == EFI_SUCCESS) {
            *MapSize = required;
            return EFI_SUCCESS;
        }
        if (status != EFI_BUFFER_TOO_SMALL) {
            return status;
        }
        if (*Map != NULL) {
            (void)BootServices->FreePool(*Map);
            *Map = NULL;
        }
        required += 8U * (*DescriptorSize != 0 ? *DescriptorSize :
                         sizeof(EFI_MEMORY_DESCRIPTOR));
        if (BootServices->AllocatePool(EfiLoaderData, required,
                                       (VOID **)&new_map) != EFI_SUCCESS) {
            return EFI_OUT_OF_RESOURCES;
        }
        *Map = new_map;
        *MapSize = required;
    }
    return EFI_OUT_OF_RESOURCES;
}

static BOOLEAN runtime_map_is_aligned(EFI_MEMORY_DESCRIPTOR *Map,
                                      UINTN MapSize, UINTN DescriptorSize)
{
    UINTN offset;
    UINTN runtime_count = 0;

    if (DescriptorSize < sizeof(EFI_MEMORY_DESCRIPTOR) ||
        MapSize % DescriptorSize != 0) {
        return 0;
    }
    for (offset = 0; offset < MapSize; offset += DescriptorSize) {
        EFI_MEMORY_DESCRIPTOR *descriptor =
            (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Map + offset);
        UINT64 size = descriptor->NumberOfPages * EFI_PAGE_SIZE;

        if ((descriptor->Attribute & EFI_MEMORY_RUNTIME) == 0) {
            continue;
        }
        runtime_count++;
        if ((descriptor->PhysicalStart & (IA64_RUNTIME_ALIGNMENT - 1U)) != 0 ||
            (size & (IA64_RUNTIME_ALIGNMENT - 1U)) != 0) {
            return 0;
        }
    }
    return runtime_count != 0;
}

static BOOLEAN memory_map_contains(EFI_MEMORY_DESCRIPTOR *Map,
                                   UINTN MapSize, UINTN DescriptorSize,
                                   const VOID *Address, UINTN Size,
                                   UINT64 RequiredAttributes)
{
    UINT64 start = (UINT64)(UINTN)Address;
    UINT64 end = start + Size;
    UINTN offset;

    if (Map == NULL || Address == NULL || Size == 0 || end < start ||
        DescriptorSize < sizeof(EFI_MEMORY_DESCRIPTOR) ||
        MapSize % DescriptorSize != 0) {
        return 0;
    }
    for (offset = 0; offset < MapSize; offset += DescriptorSize) {
        EFI_MEMORY_DESCRIPTOR *descriptor =
            (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Map + offset);
        UINT64 pages = descriptor->NumberOfPages;
        UINT64 descriptor_size;
        UINT64 descriptor_end;

        if (pages > (~(UINT64)0) / EFI_PAGE_SIZE) {
            continue;
        }
        descriptor_size = pages * EFI_PAGE_SIZE;
        descriptor_end = descriptor->PhysicalStart + descriptor_size;
        if ((descriptor->Attribute & RequiredAttributes) ==
                RequiredAttributes &&
            descriptor_end >= descriptor->PhysicalStart &&
            start >= descriptor->PhysicalStart && end <= descriptor_end) {
            return 1;
        }
    }
    return 0;
}

static BOOLEAN runtime_procedure_is_mapped(EFI_MEMORY_DESCRIPTOR *Map,
                                           UINTN MapSize,
                                           UINTN DescriptorSize,
                                           const VOID *Procedure)
{
    const UINT64 *descriptor;

    /* IA-64 EFI function pointers address a two-word procedure descriptor. */
    if (!memory_map_contains(Map, MapSize, DescriptorSize, Procedure,
                             2U * sizeof(UINT64), EFI_MEMORY_RUNTIME)) {
        return 0;
    }
    descriptor = (const UINT64 *)Procedure;
    return descriptor[0] != 0 && descriptor[1] != 0 &&
           memory_map_contains(
               Map, MapSize, DescriptorSize,
               (const VOID *)(UINTN)descriptor[0], 1,
               EFI_MEMORY_RUNTIME) &&
           memory_map_contains(
               Map, MapSize, DescriptorSize,
               (const VOID *)(UINTN)descriptor[1], 1,
               EFI_MEMORY_RUNTIME);
}

static BOOLEAN runtime_service_procedures_are_mapped(
    EFI_MEMORY_DESCRIPTOR *Map, UINTN MapSize, UINTN DescriptorSize,
    EFI_RUNTIME_SERVICES *RuntimeServices)
{
#define RUNTIME_PROCEDURE(Field) \
    runtime_procedure_is_mapped( \
        Map, MapSize, DescriptorSize, \
        (const VOID *)(UINTN)RuntimeServices->Field)

    return RuntimeServices != NULL &&
           RUNTIME_PROCEDURE(GetTime) &&
           RUNTIME_PROCEDURE(SetTime) &&
           RUNTIME_PROCEDURE(GetWakeupTime) &&
           RUNTIME_PROCEDURE(SetWakeupTime) &&
           RUNTIME_PROCEDURE(SetVirtualAddressMap) &&
           RUNTIME_PROCEDURE(ConvertPointer) &&
           RUNTIME_PROCEDURE(GetVariable) &&
           RUNTIME_PROCEDURE(GetNextVariableName) &&
           RUNTIME_PROCEDURE(SetVariable) &&
           RUNTIME_PROCEDURE(GetNextHighMonotonicCount) &&
           RUNTIME_PROCEDURE(ResetSystem) &&
           RUNTIME_PROCEDURE(QueryVariableInfo);

#undef RUNTIME_PROCEDURE
}

static BOOLEAN configuration_table_ranges_are_mapped(
    EFI_MEMORY_DESCRIPTOR *Map, UINTN MapSize, UINTN DescriptorSize,
    EFI_CONFIGURATION_TABLE *Tables, UINTN Count)
{
    UINTN index;
    BOOLEAN sal_seen = 0;
    BOOLEAN smbios_seen = 0;
    BOOLEAN debug_seen = 0;

    if (Tables == NULL || Count == 0 ||
        Count > (~(UINTN)0) / sizeof(*Tables) ||
        !memory_map_contains(Map, MapSize, DescriptorSize, Tables,
                             Count * sizeof(*Tables),
                             EFI_MEMORY_RUNTIME)) {
        return 0;
    }
    for (index = 0; index < Count; index++) {
        const VOID *vendor_table =
            (const VOID *)(UINTN)Tables[index].VendorTable;
        UINTN minimum_size = 1;
        BOOLEAN must_be_runtime = 0;

        if (ia64_bytes_equal(Tables[index].VendorGuid, sal_guid, 16)) {
            sal_seen = 1;
            must_be_runtime = 1;
            minimum_size = 8;
        } else if (ia64_bytes_equal(Tables[index].VendorGuid,
                                    smbios_guid, 16)) {
            smbios_seen = 1;
            must_be_runtime = 1;
            minimum_size = 31;
        } else if (ia64_bytes_equal(Tables[index].VendorGuid,
                                    debug_image_guid, 16)) {
            debug_seen = 1;
            must_be_runtime = 1;
            minimum_size = 16;
        }
        if (!memory_map_contains(
                Map, MapSize, DescriptorSize, vendor_table, minimum_size,
                must_be_runtime ? EFI_MEMORY_RUNTIME : 0)) {
            return 0;
        }
    }
    return sal_seen && smbios_seen && debug_seen;
}

EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    IA64_TEST_CONTEXT context = {
        .SystemTable = SystemTable,
        .Suite = "exitbs",
        .Passed = 0,
        .Failed = 0,
        .DirectUart = 0,
    };
    EFI_BOOT_SERVICES *boot_services = SystemTable->BootServices;
    EFI_RUNTIME_SERVICES *runtime_services = SystemTable->RuntimeServices;
    EFI_CONFIGURATION_TABLE *configuration_table =
        SystemTable->ConfigurationTable;
    UINTN configuration_count = SystemTable->NumberOfTableEntries;
    EFI_MEMORY_DESCRIPTOR *map = NULL;
    UINTN map_size = 0;
    UINTN map_key = 0;
    UINTN descriptor_size = 0;
    UINT32 descriptor_version = 0;
    EFI_TIME time;
    EFI_STATUS status;
    VOID *convert_address;
    VOID *original_address;
    BOOLEAN aligned;
    BOOLEAN runtime_pointers_mapped;
    BOOLEAN runtime_functions_mapped;
    BOOLEAN configuration_tables_mapped;

    status = get_final_memory_map(boot_services, &map, &map_size, &map_key,
                                  &descriptor_size, &descriptor_version);
    aligned = status == EFI_SUCCESS && descriptor_version == 1U &&
              runtime_map_is_aligned(map, map_size, descriptor_size);
    if (!aligned) {
        ia64_test_fail(&context, "memory-map", status,
                       "runtime-map-alignment");
        ia64_test_done(&context);
        return EFI_DEVICE_ERROR;
    }

    /*
     * Nothing which can call a Boot Service may occur between the final
     * GetMemoryMap and ExitBootServices.  In particular, defer all
     * structured console output until the application has switched to its
     * direct UART path; OutputString is allowed to invalidate map_key.
     */
    runtime_pointers_mapped =
        runtime_services != NULL &&
        memory_map_contains(
            map, map_size, descriptor_size, runtime_services,
            sizeof(EFI_TABLE_HEADER), EFI_MEMORY_RUNTIME) &&
        runtime_services->Hdr.HeaderSize >= sizeof(EFI_TABLE_HEADER) &&
        runtime_services->Hdr.HeaderSize <= EFI_PAGE_SIZE &&
        memory_map_contains(
            map, map_size, descriptor_size, runtime_services,
            runtime_services->Hdr.HeaderSize, EFI_MEMORY_RUNTIME) &&
        memory_map_contains(
            map, map_size, descriptor_size, SystemTable,
            sizeof(*SystemTable), EFI_MEMORY_RUNTIME);
    runtime_functions_mapped = runtime_pointers_mapped &&
        runtime_service_procedures_are_mapped(
            map, map_size, descriptor_size, runtime_services);
    configuration_tables_mapped = configuration_table_ranges_are_mapped(
        map, map_size, descriptor_size, configuration_table,
        configuration_count);

    status = boot_services->ExitBootServices(ImageHandle, map_key);
    if (status != EFI_SUCCESS) {
        ia64_test_fail(&context, "exit-boot-services", status,
                       "exit-boot-services");
        ia64_test_done(&context);
        return status;
    }

    context.DirectUart = 1;
    ia64_test_pass(&context, "memory-map");
    ia64_test_check(
        &context, "runtime-pointer-ranges", runtime_pointers_mapped,
        EFI_DEVICE_ERROR, "runtime-range-attributes");
    ia64_test_check(
        &context, "runtime-function-ranges", runtime_functions_mapped,
        EFI_DEVICE_ERROR, "runtime-procedure-descriptors");
    ia64_test_check(
        &context, "configuration-table-ranges",
        configuration_tables_mapped,
        EFI_DEVICE_ERROR, "configuration-table-ranges");
    ia64_test_pass(&context, "exit-boot-services");
    ia64_test_check(
        &context, "system-table-handoff",
        SystemTable->BootServices == NULL && SystemTable->ConsoleInHandle ==
            NULL && SystemTable->ConIn == NULL &&
            SystemTable->ConsoleOutHandle == NULL && SystemTable->ConOut ==
            NULL && SystemTable->StandardErrorHandle == NULL &&
            SystemTable->StdErr == NULL &&
            SystemTable->RuntimeServices == runtime_services,
        EFI_DEVICE_ERROR, "boot-fields-not-cleared");
    ia64_test_check(
        &context, "system-table-crc",
        system_table_crc_is_valid(SystemTable),
        EFI_DEVICE_ERROR, "system-table-crc-after-exit");
    ia64_test_check(
        &context, "configuration-tables-preserved",
        configuration_count != 0 &&
            SystemTable->NumberOfTableEntries == configuration_count &&
            SystemTable->ConfigurationTable == configuration_table,
        EFI_DEVICE_ERROR, "configuration-table-changed");
    ia64_test_check(
        &context, "legacy-text-handoff", legacy_text_handoff_is_ready(),
        EFI_DEVICE_ERROR, "vga-not-in-legacy-text-mode");
    convert_address = runtime_services;
    original_address = convert_address;
    status = runtime_services->ConvertPointer(2U, &convert_address);
    ia64_test_check(
        &context, "convert-pointer-reserved-bits",
        status == EFI_INVALID_PARAMETER &&
            convert_address == original_address,
        status, "reserved-debug-disposition-accepted");
    status = runtime_services->GetTime(&time, NULL);
    ia64_test_check(&context, "runtime-get-time",
                    status == EFI_SUCCESS && time.Year >= 1998U,
                    status, "get-time-after-exit");
    ia64_test_done(&context);

    for (;;) {
        __asm__ volatile ("hint @pause" ::: "memory");
    }
}

EFI_STATUS (*efi_entry_descriptor_reference)(EFI_HANDLE, EFI_SYSTEM_TABLE *)
    __attribute__((used)) = efi_main;
