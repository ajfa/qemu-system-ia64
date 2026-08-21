/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Filesystem-layer types shared by firmware.c (FAT/ISO + the common
 * EFI_FILE_PROTOCOL layer) and udf.c (UDF 2.01), plus the UDF API.
 */

#ifndef IA64_FIRMWARE_FW_FS_H
#define IA64_FIRMWARE_FW_FS_H

#include "fw-base.h"
#include "fw-efi-types.h"
#include "fw-boot-shell.h"

typedef struct FW_FAT_VOLUME {
    BOOLEAN valid;
    BOOLEAN installed;
    UINT8 fat_type;
    BOOLEAN is_fat16;
    BOOLEAN is_fat32;
    UINT8   sec_per_cluster;
    UINT16  reserved_secs;
    UINT8   num_fats;
    UINT16  root_entries;
    UINT32  secs_per_fat;
    UINT32  eoc_cluster;
    UINT32  root_cluster;
    UINT32  root_dir_start;
    UINT32  root_dir_sectors;
    UINT32  data_start;
    UINT32  cluster_size;
    UINT32  total_sectors;
    UINT32  cluster_count;
    UINT32  lba_offset;
    BOOLEAN fat_cache_valid;
    UINT32  fat_cache_media_id;
    UINT32  fat_cache_lba;
    UINT8   fat_cache[512];
    EFI_HANDLE handle;
    EFI_BLOCK_IO_PROTOCOL *block_io;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL simple_fs;
    CHAR16 label[12];
} FW_FAT_VOLUME;

typedef enum {
    FW_FS_FAT = 0,
    FW_FS_ISO = 1,
    FW_FS_UDF = 2,
} FW_FS_KIND;

typedef struct {
    BOOLEAN valid;
    UINT32  root_extent;
    UINT32  root_size;
    CHAR16  label[33];
} FW_ISO_VOLUME;

typedef struct {
    UINT32 extent;
    UINT32 size;
    UINT8  flags;
    CHAR16 name[64];
} FW_ISO_ENTRY;

typedef struct {
    BOOLEAN valid;
    BOOLEAN checked;
    UINT32  partition_start;
    UINT32  partition_length;
    UINT16  partition_number;
    UINT16  partition_reference;
    UINT32  logical_block_size;
    UINT32  root_icb;
    UINT16  root_partition_reference;
    CHAR16  label[128];
} FW_UDF_VOLUME;

typedef struct {
    UINT32 icb;
    UINT16 partition_reference;
    UINT8  file_characteristics;
    UINT8  file_type;
    UINT16 icb_flags;
    UINT64 size;
    CHAR16 name[64];
} FW_UDF_ENTRY;

typedef struct {
    UINT32 icb;
    UINT16 partition_reference;
    UINT8  file_type;
    UINT16 icb_flags;
    UINT64 information_length;
    UINT32 allocation_offset;
    UINT32 allocation_length;
} FW_UDF_FILE_META;

typedef struct {
    EFI_FILE_PROTOCOL proto;
    BOOLEAN in_use;
    BOOLEAN is_root;
    BOOLEAN is_dir;
    FW_FS_KIND fs_kind;
    FW_FAT_VOLUME *fat_volume;
    UINT32  first_cluster;
    BOOLEAN fat_cursor_valid;
    UINT32  fat_cursor_cluster;
    UINT32  fat_cursor_index;
    UINT32  extent;
    UINT16  partition_reference;
    UINT64  size;
    UINT64  position;
    CHAR16  name[64];
    CHAR16  path[256];
} FW_FILE;

#define FW_FILE_MAX 16

#define UDF_FILE_TYPE_DIRECTORY                  4U
#define UDF_FID_CHAR_DIRECTORY                   0x02U

extern FW_UDF_VOLUME mUdfVolume;
extern UINT32 mCdromBlocks;

/* firmware.c services the UDF module consumes. */
UINT16 fw_le16(const UINT8 *p);
UINT32 fw_le32(const UINT8 *p);
UINT64 fw_le64(const UINT8 *p);
BOOLEAN fw_bytes_eq(const UINT8 *p, const char *s, UINTN len);
UINT8 fw_ascii_upper(UINT8 c);
BOOLEAN fw_iso_read_sectors(UINT8 *buf, UINT32 lba, UINT32 count);
BOOLEAN atapi_configure_el_torito(void);

BOOLEAN fw_udf_init(void);
BOOLEAN fw_udf_entry_load_meta(FW_UDF_ENTRY *Entry);
EFI_STATUS fw_udf_lookup(FW_FILE *Base, CHAR16 *Path, FW_UDF_ENTRY *Entry);
EFI_STATUS fw_udf_next_dir_entry(FW_FILE *Dir, FW_UDF_ENTRY *Entry);
EFI_STATUS fw_udf_read_file_bytes(UINT16 PartitionReference,
                                  UINT32 Icb, UINT64 Offset,
                                  VOID *Buffer, UINT32 *ReadSize);

#endif /* IA64_FIRMWARE_FW_FS_H */
