/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Boot policy: BootOrder/Boot#### evaluation, BootCurrent maintenance,
 * the disk fallback boot, and the boot-shell console services.
 * Extracted verbatim from firmware.c (Phase 1 of
 * plans/firmware-rework-plan.md).
 */

#include "fw-base.h"
#include "fw-services.h"
#include "fw-boot-shell.h"
#include "fw-storage.h"
#include "fw-fs.h"

/* --- Updated boot path using FAT + Block I/O ----------------------------- */

void fw_boot_option_name(UINT16 Option, CHAR16 Name[9])
{
    static const CHAR16 hex[] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
    };

    Name[0] = 'B';
    Name[1] = 'o';
    Name[2] = 'o';
    Name[3] = 't';
    Name[4] = hex[(Option >> 12) & 0xf];
    Name[5] = hex[(Option >> 8) & 0xf];
    Name[6] = hex[(Option >> 4) & 0xf];
    Name[7] = hex[Option & 0xf];
    Name[8] = 0;
}

UINTN fw_load_option_description_size(const UINT8 *Option,
                                      UINTN OptionSize)
{
    UINTN offset = sizeof(UINT32) + sizeof(UINT16);

    while (offset + sizeof(CHAR16) <= OptionSize) {
        CHAR16 ch;

        fw_copy_mem(&ch, (VOID *)(Option + offset), sizeof(ch));
        offset += sizeof(ch);
        if (ch == 0) {
            return offset - (sizeof(UINT32) + sizeof(UINT16));
        }
    }
    return 0;
}

static EFI_STATUS fw_set_boot_current(UINT16 OptionNumber)
{
    static CHAR16 name[] = {
        'B', 'o', 'o', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 0
    };

    return rs_set_variable(name, (void *)mEfiGlobalVariableGuid,
                           EFI_VARIABLE_BOOTSERVICE_ACCESS |
                           EFI_VARIABLE_RUNTIME_ACCESS,
                           sizeof(OptionNumber), &OptionNumber);
}

static void fw_clear_boot_current(void)
{
    static CHAR16 name[] = {
        'B', 'o', 'o', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 0
    };

    (void)rs_set_variable(name, (void *)mEfiGlobalVariableGuid, 0, 0, NULL);
}

static EFI_STATUS boot_image_from_load_option(UINT16 OptionNumber,
                                              const UINT8 *Option,
                                              UINTN OptionSize)
{
    UINT32 attributes;
    UINT16 file_path_list_length;
    UINTN description_size;
    UINTN file_path_offset;
    UINTN optional_data_offset;
    FW_DEVICE_PATH_NODE *file_path;
    VOID *optional_data;
    VOID *load_options = NULL;
    EFI_HANDLE image = NULL;
    EFI_STATUS st;

    if (Option == NULL ||
        OptionSize < sizeof(UINT32) + sizeof(UINT16) + sizeof(CHAR16)) {
        return EFI_LOAD_ERROR;
    }

    fw_copy_mem(&attributes, (VOID *)Option, sizeof(attributes));
    fw_copy_mem(&file_path_list_length,
                (VOID *)(Option + sizeof(UINT32)),
                sizeof(file_path_list_length));
    if ((attributes & 0x00000001U) == 0) {
        return EFI_NOT_FOUND;
    }

    description_size = fw_load_option_description_size(Option, OptionSize);
    if (description_size == 0) {
        return EFI_LOAD_ERROR;
    }
    file_path_offset = sizeof(UINT32) + sizeof(UINT16) + description_size;
    optional_data_offset = file_path_offset + file_path_list_length;
    if (file_path_list_length < sizeof(FW_DEVICE_PATH_NODE) ||
        optional_data_offset > OptionSize) {
        return EFI_LOAD_ERROR;
    }

    file_path = (FW_DEVICE_PATH_NODE *)(VOID *)(Option + file_path_offset);
    if (fw_device_path_size(file_path) != file_path_list_length) {
        return EFI_LOAD_ERROR;
    }

    uart_puts("Boot Manager:        trying Boot");
    uart_put_hex64(OptionNumber);
    uart_puts("\r\n");

    st = mBootServices.LoadImage(1, mImageHandle, file_path,
                                 NULL, 0, &image);
    if (st != EFI_SUCCESS) {
        return st;
    }

    if (optional_data_offset < OptionSize) {
        optional_data = (VOID *)(Option + optional_data_offset);
        st = fw_copy_loaded_image_load_options(
            image, optional_data, (UINT32)(OptionSize - optional_data_offset),
            &load_options);
        if (st != EFI_SUCCESS) {
            (void)mBootServices.UnloadImage(image);
            return st;
        }
    }

    st = fw_set_boot_current(OptionNumber);
    if (st != EFI_SUCCESS) {
        if (load_options != NULL) {
            (void)fw_release_loaded_image_load_options(image, load_options);
        }
        (void)mBootServices.UnloadImage(image);
        return st;
    }

    (void)mBootServices.SetWatchdogTimer(300, 0, 0, NULL);
    mSalLoaderHandoffPending = 1;
    st = mBootServices.StartImage(image, NULL, NULL);
    mSalLoaderHandoffPending = 0;
    (void)mBootServices.SetWatchdogTimer(0, 0, 0, NULL);

    uart_puts("Boot Manager:        StartImage returned status=0x");
    uart_put_hex64(st);
    uart_puts("\r\n");

    if (!mBootServicesExited) {
        if (st != EFI_SUCCESS) {
            fw_clear_boot_current();
        }
        if (load_options != NULL) {
            (void)fw_release_loaded_image_load_options(image, load_options);
        }
        (void)mBootServices.UnloadImage(image);
    }
    return st;
}

EFI_STATUS fw_boot_image_from_boot_option(UINT16 OptionNumber)
{
    /* Do not retain a large firmware stack frame across StartImage(). */
    static UINT8 option[NVRAM_VAR_DATA_MAX];
    CHAR16 name[9];
    UINTN option_size = sizeof(option);
    UINT32 attributes = 0;
    EFI_STATUS st;

    fw_boot_option_name(OptionNumber, name);
    st = rs_get_variable(name, (void *)mEfiGlobalVariableGuid,
                         &attributes, &option_size, option);
    if (st != EFI_SUCCESS) {
        return st;
    }
    if ((attributes & EFI_VARIABLE_BOOTSERVICE_ACCESS) == 0) {
        return EFI_LOAD_ERROR;
    }
    return boot_image_from_load_option(OptionNumber, option, option_size);
}

/* Keep address-taken buffers in a bounded IA-64 register-stack frame. */
EFI_STATUS __attribute__((noinline)) boot_image_from_boot_order(void)
{
    static CHAR16 boot_order_name[] = {
        'B', 'o', 'o', 't', 'O', 'r', 'd', 'e', 'r', 0
    };
    static CHAR16 boot_next_name[] = {
        'B', 'o', 'o', 't', 'N', 'e', 'x', 't', 0
    };
    UINT16 order[16];
    UINT16 boot_next;
    UINTN order_size = sizeof(order);
    UINTN boot_next_size = sizeof(boot_next);
    UINT32 attributes = 0;
    EFI_STATUS st;
    EFI_STATUS last = EFI_NOT_FOUND;
    UINTN i;

    st = rs_get_variable(boot_next_name, (void *)mEfiGlobalVariableGuid,
                         &attributes, &boot_next_size, &boot_next);
    if (st == EFI_SUCCESS && boot_next_size == sizeof(boot_next) &&
        (attributes & EFI_VARIABLE_BOOTSERVICE_ACCESS) != 0) {
        /* BootNext is a one-shot request and must be consumed before use. */
        (void)rs_set_variable(boot_next_name,
                              (void *)mEfiGlobalVariableGuid, 0, 0, NULL);
        last = fw_boot_image_from_boot_option(boot_next);
        if (last == EFI_SUCCESS || mBootServicesExited) {
            return last;
        }
    }

    st = rs_get_variable(boot_order_name, (void *)mEfiGlobalVariableGuid,
                         &attributes, &order_size, order);
    if (st != EFI_SUCCESS) {
        return st;
    }
    if ((attributes & EFI_VARIABLE_BOOTSERVICE_ACCESS) == 0 ||
        (order_size % sizeof(UINT16)) != 0) {
        return EFI_LOAD_ERROR;
    }

    for (i = 0; i < order_size / sizeof(UINT16); i++) {
        last = fw_boot_image_from_boot_option(order[i]);
        if (last == EFI_SUCCESS || mBootServicesExited) {
            return last;
        }
    }
    return last;
}

EFI_STATUS __attribute__((noinline)) boot_image_from_disk(void)
{
    static CHAR16 boot_path[] = {
        '\\', 'E', 'F', 'I', '\\', 'B', 'O', 'O', 'T', '\\',
        'B', 'O', 'O', 'T', 'I', 'A', '6', '4', '.', 'E', 'F', 'I', 0
    };
    FAT_DIR_ENTRY boot_entry;
    static UINT8 full_path[256];
    VOID *file_buf = NULL;
    UINT32 file_size = 0;
    EFI_HANDLE image = NULL;
    EFI_STATUS st;

    uart_puts("Block I/O: locating \\EFI\\BOOT\\BOOTIA64.EFI...\r\n");
    st = fw_fat_lookup(boot_path, &boot_entry);
    if (st != EFI_SUCCESS) {
        uart_puts("Block I/O: BOOTIA64.EFI not found\r\n");
        return st;
    }
    if (boot_entry.size == 0) {
        uart_puts("Block I/O: BOOTIA64.EFI is empty\r\n");
        return EFI_LOAD_ERROR;
    }

    /*
     * Stage the file in a tracked allocation: it bounds the read to the
     * directory entry's size, and it keeps the staging window out of the
     * conventional memory that LoadImage() places the loaded image in.
     */
    st = bs_allocate_pool(EfiBootServicesData, boot_entry.size, &file_buf);
    if (st != EFI_SUCCESS) {
        uart_puts("Block I/O: BOOTIA64.EFI staging failed\r\n");
        return st;
    }

    st = fw_fat_read_file_entry(&boot_entry, file_buf, &file_size);
    if (st != EFI_SUCCESS || file_size != boot_entry.size) {
        uart_puts("Block I/O: BOOTIA64.EFI read failed\r\n");
        (void)bs_free_pool(file_buf);
        return st != EFI_SUCCESS ? st : EFI_DEVICE_ERROR;
    }

    uart_puts("Block I/O: BOOTIA64.EFI loaded\r\n");

    if (mDefaultFatVolume == NULL || !mDefaultFatVolume->valid) {
        (void)bs_free_pool(file_buf);
        return EFI_NOT_FOUND;
    }
    st = fw_build_file_device_path(
        mDefaultFatVolume->handle,
        (FW_DEVICE_PATH_NODE *)&mBootFullDevicePath.FileHeader,
        full_path, sizeof(full_path));
    if (st != EFI_SUCCESS) {
        (void)bs_free_pool(file_buf);
        return st;
    }
    st = mBootServices.LoadImage(1, mImageHandle, full_path,
                                 file_buf, file_size, &image);
    (void)bs_free_pool(file_buf);
    if (st != EFI_SUCCESS) {
        uart_puts("Block I/O: LoadImage failed\r\n");
        return st;
    }

    /* Generic optical boot: launch with empty load options (OS-agnostic). */
    mSalLoaderHandoffPending = 1;
    st = mBootServices.StartImage(image, NULL, NULL);
    mSalLoaderHandoffPending = 0;
    uart_puts("Block I/O: StartImage returned\r\n");
    if (!mBootServicesExited) {
        (void)mBootServices.UnloadImage(image);
    }
    return st;
}

EFI_STATUS fw_console_read_key(EFI_INPUT_KEY *key)
{
    return mConInProto.ReadKeyStroke(&mConInProto, key);
}

EFI_STATUS fw_console_clear(VOID)
{
    return mConOutProto.ClearScreen(&mConOutProto);
}

BOOLEAN fw_boot_services_exited(VOID)
{
    return mBootServicesExited;
}

EFI_STATUS fw_load_image(BOOLEAN boot_policy, VOID *device_path,
                         EFI_HANDLE *image)
{
    return mBootServices.LoadImage(boot_policy, mImageHandle, device_path,
                                   NULL, 0, image);
}

EFI_STATUS fw_start_image(EFI_HANDLE image)
{
    return mBootServices.StartImage(image, NULL, NULL);
}

EFI_STATUS fw_unload_image(EFI_HANDLE image)
{
    return mBootServices.UnloadImage(image);
}

EFI_STATUS fw_set_watchdog_timeout(UINTN timeout_seconds)
{
    return mBootServices.SetWatchdogTimer(timeout_seconds, 0, 0, NULL);
}

void fw_set_sal_loader_handoff_pending(BOOLEAN pending)
{
    mSalLoaderHandoffPending = pending;
}

UINTN fw_partition_count(VOID)
{
    UINTN count = 0;
    UINTN index;

    for (index = 0; index < FW_ARRAY_SIZE(mPartitions); index++) {
        if (mPartitions[index].in_use) {
            count++;
        }
    }
    return count;
}

UINTN fw_processor_count(VOID)
{
    return fw_guest_processor_count();
}

UINT64 fw_installed_ram_size(VOID)
{
    return fw_guest_ram_size();
}

UINT32 fw_graphics_width(VOID)
{
    return mGraphicsWidth;
}

UINT32 fw_graphics_height(VOID)
{
    return mGraphicsHeight;
}

const CHAR8 *fw_storage_description(BOOLEAN boot_device)
{
    FW_STORAGE_DEVICE *device = boot_device ?
        &mBootStorageDevice : &mDiskStorageDevice;

    if (!storage_device_present(device)) {
        return "none";
    }
    if (device->Kind == FW_STORAGE_SCSI) {
        return storage_is_cd(device) ? "SCSI optical" : "SCSI disk";
    }
    if (device->Kind == FW_STORAGE_AHCI) {
        return storage_is_cd(device) ? "SATA optical" : "SATA disk";
    }
    return storage_is_cd(device) ? "IDE optical" : "IDE disk";
}

void fw_reset_cold(VOID)
{
    rs_reset_system(EFI_RESET_COLD, EFI_SUCCESS, 0, NULL);
}

#include "fw-boot-shell.h"

