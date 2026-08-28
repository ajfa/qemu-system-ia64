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

/* --- Interactive boot menu ------------------------------------------------ */

/*
 * A keyboard-navigable boot manager, in the spirit of the Intel EFI sample's
 * bootmgr: it lists the active Boot#### options in BootOrder order plus the
 * built-in EFI Shell and Boot Maintenance actions, honours the EFI Timeout
 * variable with a visible countdown that auto-boots the highlighted default,
 * and hands a chosen option to the existing boot engine
 * (fw_boot_image_from_boot_option).  Built entirely on SimpleTextOut cursor/
 * attribute control and SimpleTextIn ReadKeyStroke -- no new platform service.
 */

#define FW_MENU_MAX          20U
#define FW_MENU_DESC_MAX     58U

#define FW_MENU_ATTR_NORMAL   0x07U  /* light grey on black           */
#define FW_MENU_ATTR_SELECTED 0x70U  /* black on light grey (reverse) */
#define FW_MENU_ATTR_HEADER   0x0eU  /* yellow on black (emphasis)    */

#define FW_MENU_KIND_BOOT   0U
#define FW_MENU_KIND_SHELL  1U
#define FW_MENU_KIND_MAINT  2U

typedef struct {
    UINT16 Option;
    UINT8  Kind;
    CHAR16 Desc[FW_MENU_DESC_MAX + 1U];
} FW_MENU_ENTRY;

static void fw_boot_maint_run(void);

static void fw_menu_attr(UINTN Attr)
{
    (void)mConOutProto.SetAttribute(&mConOutProto, Attr);
}

static void fw_menu_at(UINTN Col, UINTN Row)
{
    (void)mConOutProto.SetCursorPosition(&mConOutProto, Col, Row);
}

static void fw_menu_put_char16(const CHAR16 *Str)
{
    (void)mConOutProto.OutputString(&mConOutProto, (CHAR16 *)Str);
}

static void fw_menu_put_uint(UINTN Value)
{
    CHAR8 buf[12];
    UINTN i = sizeof(buf) - 1U;

    buf[i] = 0;
    do {
        buf[--i] = (CHAR8)('0' + (Value % 10U));
        Value /= 10U;
    } while (Value != 0U && i > 0U);
    efi_conout_ascii(&buf[i]);
}

static void fw_menu_copy_desc(const UINT8 *Option, UINTN OptionSize,
                              CHAR16 *Dst)
{
    UINTN off = sizeof(UINT32) + sizeof(UINT16);
    UINTN i = 0;

    while (off + sizeof(CHAR16) <= OptionSize && i < FW_MENU_DESC_MAX) {
        CHAR16 ch;

        fw_copy_mem(&ch, (VOID *)(Option + off), sizeof(ch));
        off += sizeof(ch);
        if (ch == 0) {
            break;
        }
        Dst[i++] = ch;
    }
    Dst[i] = 0;
}

static UINT16 fw_menu_read_timeout(void)
{
    static CHAR16 name[] = { 'T', 'i', 'm', 'e', 'o', 'u', 't', 0 };
    UINT16 timeout = 5U;
    UINTN size = sizeof(timeout);
    UINT32 attr = 0;

    if (rs_get_variable(name, (void *)mEfiGlobalVariableGuid,
                        &attr, &size, &timeout) != EFI_SUCCESS ||
        size != sizeof(timeout)) {
        timeout = 5U;
    }
    return timeout;
}

static UINTN fw_menu_build(FW_MENU_ENTRY *Entries)
{
    static CHAR16 order_name[] = {
        'B', 'o', 'o', 't', 'O', 'r', 'd', 'e', 'r', 0
    };
    static const CHAR16 shell_label[] = {
        'E', 'F', 'I', ' ', 'S', 'h', 'e', 'l', 'l', ' ',
        '[', 'B', 'u', 'i', 'l', 't', '-', 'i', 'n', ']', 0
    };
    static const CHAR16 maint_label[] = {
        'B', 'o', 'o', 't', ' ', 'o', 'p', 't', 'i', 'o', 'n', ' ',
        'm', 'a', 'i', 'n', 't', 'e', 'n', 'a', 'n', 'c', 'e', ' ',
        'm', 'e', 'n', 'u', 0
    };
    static UINT8 option[NVRAM_VAR_DATA_MAX];
    UINT16 order[16];
    UINTN order_size = sizeof(order);
    UINT32 attr = 0;
    UINTN n = 0;

    if (rs_get_variable(order_name, (void *)mEfiGlobalVariableGuid,
                        &attr, &order_size, order) == EFI_SUCCESS &&
        (order_size % sizeof(UINT16)) == 0) {
        UINTN i;

        for (i = 0; i < order_size / sizeof(UINT16) &&
                    n < FW_MENU_MAX - 2U; i++) {
            CHAR16 name[9];
            UINTN opt_size = sizeof(option);
            UINT32 opt_attr = 0;
            UINT32 load_attr = 0;

            fw_boot_option_name(order[i], name);
            if (rs_get_variable(name, (void *)mEfiGlobalVariableGuid,
                                &opt_attr, &opt_size, option) != EFI_SUCCESS ||
                opt_size < sizeof(UINT32) + sizeof(UINT16)) {
                continue;
            }
            fw_copy_mem(&load_attr, option, sizeof(load_attr));
            if ((load_attr & 0x00000001U) == 0) {
                continue;  /* LOAD_OPTION_ACTIVE clear: not shown */
            }
            Entries[n].Option = order[i];
            Entries[n].Kind = FW_MENU_KIND_BOOT;
            fw_menu_copy_desc(option, opt_size, Entries[n].Desc);
            if (Entries[n].Desc[0] == 0) {
                fw_copy_mem(Entries[n].Desc, name, sizeof(name));
            }
            n++;
        }
    }

    Entries[n].Kind = FW_MENU_KIND_SHELL;
    fw_copy_mem(Entries[n].Desc, shell_label, sizeof(shell_label));
    n++;
    Entries[n].Kind = FW_MENU_KIND_MAINT;
    fw_copy_mem(Entries[n].Desc, maint_label, sizeof(maint_label));
    n++;
    return n;
}

/* Column at which option rows and the footer text begin. */
#define FW_MENU_COL 4U

/* Clear the screen and draw the standard header plus a prompt line. */
static void fw_menu_frame(const CHAR8 *Prompt)
{
    (void)fw_console_clear();
    fw_menu_attr(FW_MENU_ATTR_HEADER);
    fw_menu_at(0, 0);
    efi_conout_ascii("EFI Boot Manager ver 1.10 [1.00]");
    fw_menu_attr(FW_MENU_ATTR_NORMAL);
    fw_menu_at(0, 2);
    efi_conout_ascii(Prompt);
}

/* The arrow-key help line, drawn at the given row.  The up/down glyphs are
 * written as their Unicode code points; the console's CP437 mapping renders
 * them from the 8x16 font (codes 0x18/0x19). */
static void fw_menu_footer(UINTN Row)
{
    static const CHAR16 up[] = { 0x2191U, 0 };
    static const CHAR16 down[] = { 0x2193U, 0 };

    fw_menu_attr(FW_MENU_ATTR_NORMAL);
    fw_menu_at(FW_MENU_COL, Row);
    efi_conout_ascii("Use ");
    fw_menu_put_char16(up);
    efi_conout_ascii(" and ");
    fw_menu_put_char16(down);
    efi_conout_ascii(" to change option(s). Use Enter to select an option");
}

/* Draw one option row: the description at FW_MENU_COL, reverse if selected. */
static void fw_menu_option_row(UINTN Row, const CHAR16 *Desc, BOOLEAN Selected)
{
    fw_menu_at(FW_MENU_COL, Row);
    fw_menu_attr(Selected ? FW_MENU_ATTR_SELECTED : FW_MENU_ATTR_NORMAL);
    fw_menu_put_char16(Desc);
    fw_menu_attr(FW_MENU_ATTR_NORMAL);
}

static void fw_menu_render(const FW_MENU_ENTRY *Entries, UINTN Count,
                           UINTN Selected, INTN SecondsLeft)
{
    UINTN i;

    fw_menu_frame("Please select a boot option");
    for (i = 0; i < Count; i++) {
        fw_menu_option_row(4 + i, Entries[i].Desc, i == Selected);
    }
    fw_menu_footer(5 + Count);

    fw_menu_at(FW_MENU_COL, 6 + Count);
    if (SecondsLeft >= 0) {
        efi_conout_ascii("Default boot selection will be booted in ");
        fw_menu_put_uint((UINTN)SecondsLeft);
        efi_conout_ascii(" seconds       ");
    } else {
        efi_conout_ascii("                                            "
                         "                    ");
    }
}

static void fw_menu_activate(const FW_MENU_ENTRY *Entry)
{
    (void)fw_console_clear();
    if (Entry->Kind == FW_MENU_KIND_SHELL) {
        fw_boot_shell_run();
    } else if (Entry->Kind == FW_MENU_KIND_MAINT) {
        fw_boot_maint_run();
    } else {
        (void)fw_boot_image_from_boot_option(Entry->Option);
    }
}

void fw_boot_menu_run(void)
{
    static FW_MENU_ENTRY entries[FW_MENU_MAX];
    UINTN count;
    UINTN selected = 0;
    UINT16 timeout;
    INTN seconds_left;
    BOOLEAN counting;
    BOOLEAN dirty = 1;

    count = fw_menu_build(entries);
    if (count == 0) {
        return;
    }
    timeout = fw_menu_read_timeout();
    if (timeout == 0) {
        /* Timeout 0 means boot immediately, without a menu; use the full
         * engine so BootNext and the whole BootOrder are honoured. */
        (void)boot_image_from_boot_order();
        return;
    }
    seconds_left = (timeout == 0xffffU) ? -1 : (INTN)timeout;
    counting = (seconds_left >= 0);

    for (;;) {
        EFI_INPUT_KEY key;
        UINTN sub;
        BOOLEAN got_key = 0;

        if (dirty) {
            fw_menu_render(entries, count, selected,
                           counting ? seconds_left : -1);
            dirty = 0;
        }

        /* Poll ~1 second (100 x 10 ms), reacting to the first key. */
        for (sub = 0; sub < 100U; sub++) {
            if (fw_console_read_key(&key) == EFI_SUCCESS) {
                got_key = 1;
                break;
            }
            (void)bs_stall(10000U);
        }

        if (got_key) {
            counting = 0;   /* any key cancels the countdown */
            dirty = 1;
            if (key.ScanCode == EFI_SCAN_UP) {
                selected = (selected == 0) ? count - 1U : selected - 1U;
            } else if (key.ScanCode == EFI_SCAN_DOWN) {
                selected = (selected + 1U) % count;
            } else if (key.ScanCode == EFI_SCAN_ESC) {
                (void)fw_console_clear();
                return;
            } else if (key.UnicodeChar == '\r' || key.UnicodeChar == '\n') {
                fw_menu_activate(&entries[selected]);
                /* Only reached if the boot failed or an action returned:
                 * rebuild (entries may have changed) and re-render. */
                count = fw_menu_build(entries);
                if (selected >= count) {
                    selected = 0;
                }
            }
        } else if (counting) {
            seconds_left--;
            if (seconds_left <= 0) {
                /* Countdown expired with no interaction: auto-boot the default
                 * via the full BootNext/BootOrder engine.  If it returns, every
                 * option failed -- fall back to showing the menu. */
                (void)fw_console_clear();
                (void)boot_image_from_boot_order();
                count = fw_menu_build(entries);
                if (selected >= count) {
                    selected = 0;
                }
                counting = 0;
            }
            dirty = 1;
        }
    }
}

/* --- Boot maintenance ----------------------------------------------------- */

static void fw_maint_set_timeout(void)
{
    static CHAR16 name[] = { 'T', 'i', 'm', 'e', 'o', 'u', 't', 0 };
    UINT16 current = fw_menu_read_timeout();
    UINT32 value = 0;
    BOOLEAN entered = 0;

    fw_menu_frame("Set auto boot timeout");
    fw_menu_at(FW_MENU_COL, 4);
    efi_conout_ascii("Current TimeOut is : ");
    fw_menu_put_uint(current);
    efi_conout_ascii(" seconds");
    fw_menu_at(FW_MENU_COL, 6);
    efi_conout_ascii("New TimeOut in seconds (<= 65535) is : ");

    for (;;) {
        EFI_INPUT_KEY key;

        if (fw_console_read_key(&key) != EFI_SUCCESS) {
            (void)bs_stall(10000U);
            continue;
        }
        if (key.ScanCode == EFI_SCAN_ESC) {
            return;
        }
        if (key.UnicodeChar == '\r' || key.UnicodeChar == '\n') {
            break;
        }
        if (key.UnicodeChar >= '0' && key.UnicodeChar <= '9' &&
            value < 6553U) {
            CHAR8 echo[2];

            value = value * 10U + (UINT32)(key.UnicodeChar - '0');
            entered = 1;
            echo[0] = (CHAR8)key.UnicodeChar;
            echo[1] = 0;
            efi_conout_ascii(echo);
        }
    }
    if (entered) {
        UINT16 t = (UINT16)value;

        (void)rs_set_variable(name, (void *)mEfiGlobalVariableGuid,
                              EFI_VARIABLE_NON_VOLATILE |
                              EFI_VARIABLE_BOOTSERVICE_ACCESS |
                              EFI_VARIABLE_RUNTIME_ACCESS,
                              sizeof(t), &t);
    }
}

static const UINT32 FW_VAR_NV_BS_RT =
    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
    EFI_VARIABLE_RUNTIME_ACCESS;

static CHAR16 fw_boot_order_name[] = {
    'B', 'o', 'o', 't', 'O', 'r', 'd', 'e', 'r', 0
};

/* Remove one option number from BootOrder, preserving the order of the rest. */
static void fw_menu_bootorder_remove(UINT16 Option)
{
    UINT16 order[128];
    UINT16 kept[128];
    UINTN order_size = sizeof(order);
    UINT32 attr = 0;
    UINTN i;
    UINTN n;
    UINTN m = 0;

    if (rs_get_variable(fw_boot_order_name, (void *)mEfiGlobalVariableGuid,
                        &attr, &order_size, order) != EFI_SUCCESS ||
        (order_size % sizeof(UINT16)) != 0) {
        return;
    }
    n = order_size / sizeof(UINT16);
    for (i = 0; i < n; i++) {
        if (order[i] != Option) {
            kept[m++] = order[i];
        }
    }
    (void)rs_set_variable(fw_boot_order_name, (void *)mEfiGlobalVariableGuid,
                          FW_VAR_NV_BS_RT, m * sizeof(UINT16), kept);
}

/* Append one option number to the end of BootOrder. */
static void fw_menu_bootorder_append(UINT16 Option)
{
    UINT16 order[128];
    UINTN order_size = sizeof(order) - sizeof(UINT16);
    UINT32 attr = 0;
    UINTN n = 0;

    if (rs_get_variable(fw_boot_order_name, (void *)mEfiGlobalVariableGuid,
                        &attr, &order_size, order) == EFI_SUCCESS &&
        (order_size % sizeof(UINT16)) == 0) {
        n = order_size / sizeof(UINT16);
    }
    order[n++] = Option;
    (void)rs_set_variable(fw_boot_order_name, (void *)mEfiGlobalVariableGuid,
                          FW_VAR_NV_BS_RT, n * sizeof(UINT16), order);
}

/* Wait for a key so a status line stays readable. */
static void fw_menu_wait_key(void)
{
    EFI_INPUT_KEY key;

    while (fw_console_read_key(&key) != EFI_SUCCESS) {
        (void)bs_stall(10000U);
    }
}

/* Read a line of CHAR16 into Buf (echoing); Enter ends it, Esc returns 0. */
static UINTN fw_menu_read_line(CHAR16 *Buf, UINTN Cap)
{
    UINTN len = 0;

    if (Cap == 0) {
        return 0;
    }
    Buf[0] = 0;
    for (;;) {
        EFI_INPUT_KEY key;

        if (fw_console_read_key(&key) != EFI_SUCCESS) {
            (void)bs_stall(10000U);
            continue;
        }
        if (key.ScanCode == EFI_SCAN_ESC) {
            Buf[0] = 0;
            return 0;
        }
        if (key.UnicodeChar == '\r' || key.UnicodeChar == '\n') {
            Buf[len] = 0;
            efi_conout_ascii("\r\n");
            return len;
        }
        if ((key.UnicodeChar == 0x08 || key.UnicodeChar == 0x7f) && len > 0) {
            len--;
            efi_conout_ascii("\b \b");
            continue;
        }
        if (key.UnicodeChar >= 0x20 && len + 1U < Cap) {
            CHAR16 echo[2];

            Buf[len++] = key.UnicodeChar;
            echo[0] = key.UnicodeChar;
            echo[1] = 0;
            fw_menu_put_char16(echo);
        }
    }
}

/* Lowest Boot#### number not currently defined. */
static UINT16 fw_menu_free_boot_number(void)
{
    static UINT8 probe[NVRAM_VAR_DATA_MAX];
    UINT32 n;

    for (n = 0; n < 0x10000U; n++) {
        CHAR16 name[9];
        UINTN size = sizeof(probe);
        UINT32 attr = 0;

        fw_boot_option_name((UINT16)n, name);
        if (rs_get_variable(name, (void *)mEfiGlobalVariableGuid,
                            &attr, &size, probe) != EFI_SUCCESS) {
            return (UINT16)n;
        }
    }
    return 0;
}

static void fw_maint_add_entry(void)
{
    static UINT8 node[2U * sizeof(FW_DEVICE_PATH_NODE) + 2U * 128U];
    static UINT8 full_path[256];
    static UINT8 option[NVRAM_VAR_DATA_MAX];
    CHAR16 path[128];
    CHAR16 desc[FW_MENU_DESC_MAX + 1U];
    FW_DEVICE_PATH_NODE *hdr = (FW_DEVICE_PATH_NODE *)node;
    UINTN pathlen;
    UINTN desclen;
    UINTN dp_size;
    UINTN off;
    UINT16 num;
    CHAR16 name[9];
    EFI_STATUS st;

    fw_menu_frame("Add a boot option");

    if (mDefaultFatVolume == NULL || !mDefaultFatVolume->valid) {
        fw_menu_at(FW_MENU_COL, 4);
        efi_conout_ascii("No boot volume is available.  Press a key.");
        fw_menu_wait_key();
        return;
    }

    fw_menu_at(FW_MENU_COL, 4);
    efi_conout_ascii("Loader path (e.g. \\EFI\\redhat\\elilo.efi), "
                     "Esc cancels:");
    fw_menu_at(FW_MENU_COL, 5);
    efi_conout_ascii("> ");
    pathlen = fw_menu_read_line(path, sizeof(path) / sizeof(path[0]));
    if (pathlen == 0) {
        return;
    }

    fw_menu_at(FW_MENU_COL, 7);
    efi_conout_ascii("Description, Esc cancels:");
    fw_menu_at(FW_MENU_COL, 8);
    efi_conout_ascii("> ");
    desclen = fw_menu_read_line(desc, sizeof(desc) / sizeof(desc[0]));
    if (desclen == 0) {
        return;
    }

    /* FILE_PATH media node: {type 4, subtype 4, length} followed by the path. */
    hdr->Type = 0x04U;      /* MEDIA_DEVICE_PATH */
    hdr->SubType = 0x04U;   /* MEDIA_FILEPATH_DP */
    hdr->Length = (UINT16)(sizeof(FW_DEVICE_PATH_NODE) + (pathlen + 1U) * 2U);
    fw_copy_mem(node + sizeof(FW_DEVICE_PATH_NODE), path, (pathlen + 1U) * 2U);
    /* Terminate with an End-Entire node so fw_device_path_size() bounds it. */
    {
        FW_DEVICE_PATH_NODE *end =
            (FW_DEVICE_PATH_NODE *)(VOID *)(node + hdr->Length);

        end->Type = 0x7fU;      /* END_DEVICE_PATH_TYPE */
        end->SubType = 0xffU;   /* END_ENTIRE_DEVICE_PATH_SUBTYPE */
        end->Length = (UINT16)sizeof(FW_DEVICE_PATH_NODE);
    }

    st = fw_build_file_device_path(mDefaultFatVolume->handle, hdr,
                                   full_path, sizeof(full_path));
    if (st != EFI_SUCCESS) {
        fw_menu_at(FW_MENU_COL, 10);
        efi_conout_ascii("Could not build the device path.  Press a key.");
        fw_menu_wait_key();
        return;
    }
    dp_size = fw_device_path_size((FW_DEVICE_PATH_NODE *)(VOID *)full_path);

    /* Serialize the EFI_LOAD_OPTION: Attributes, FilePathListLength,
     * Description (CHAR16), then the file-path device path. */
    off = 0;
    {
        UINT32 active = 0x00000001U;
        UINT16 fpll = (UINT16)dp_size;

        fw_copy_mem(option + off, &active, sizeof(active));
        off += sizeof(active);
        fw_copy_mem(option + off, &fpll, sizeof(fpll));
        off += sizeof(fpll);
    }
    fw_copy_mem(option + off, desc, (desclen + 1U) * 2U);
    off += (desclen + 1U) * 2U;
    fw_copy_mem(option + off, full_path, dp_size);
    off += dp_size;

    num = fw_menu_free_boot_number();
    fw_boot_option_name(num, name);
    st = rs_set_variable(name, (void *)mEfiGlobalVariableGuid,
                         FW_VAR_NV_BS_RT, off, option);
    if (st == EFI_SUCCESS) {
        fw_menu_bootorder_append(num);
    }
    fw_menu_at(FW_MENU_COL, 10);
    efi_conout_ascii(st == EFI_SUCCESS ?
                     "Boot entry created.  Press a key." :
                     "Failed to save the boot entry.  Press a key.");
    fw_menu_wait_key();
}

static void fw_maint_delete_entry(void)
{
    static FW_MENU_ENTRY entries[FW_MENU_MAX];
    UINTN count = fw_menu_build(entries);
    UINTN boot_count = (count >= 2U) ? count - 2U : 0U;
    UINTN selected = 0;
    BOOLEAN dirty = 1;

    for (;;) {
        EFI_INPUT_KEY key;
        UINTN i;

        if (boot_count == 0) {
            (void)fw_console_clear();
            fw_menu_attr(FW_MENU_ATTR_NORMAL);
            fw_menu_at(2, 2);
            efi_conout_ascii("No boot entries to delete.  Press a key.");
            fw_menu_wait_key();
            return;
        }
        if (dirty) {
            fw_menu_frame("Delete boot option(s)");
            for (i = 0; i < boot_count; i++) {
                fw_menu_option_row(4 + i, entries[i].Desc, i == selected);
            }
            fw_menu_footer(5 + boot_count);
            dirty = 0;
        }

        while (fw_console_read_key(&key) != EFI_SUCCESS) {
            (void)bs_stall(10000U);
        }
        if (key.ScanCode == EFI_SCAN_UP) {
            selected = (selected == 0) ? boot_count - 1U : selected - 1U;
            dirty = 1;
        } else if (key.ScanCode == EFI_SCAN_DOWN) {
            selected = (selected + 1U) % boot_count;
            dirty = 1;
        } else if (key.ScanCode == EFI_SCAN_ESC) {
            return;
        } else if (key.UnicodeChar == '\r' || key.UnicodeChar == '\n') {
            CHAR16 name[9];

            fw_boot_option_name(entries[selected].Option, name);
            (void)rs_set_variable(name, (void *)mEfiGlobalVariableGuid,
                                  0, 0, NULL);
            fw_menu_bootorder_remove(entries[selected].Option);
            count = fw_menu_build(entries);
            boot_count = (count >= 2U) ? count - 2U : 0U;
            if (selected >= boot_count && boot_count > 0U) {
                selected = boot_count - 1U;
            }
            dirty = 1;
        }
    }
}

static void fw_boot_maint_run(void)
{
    static const CHAR8 *const items[] = {
        "Add a Boot Option",
        "Delete Boot Option(s)",
        "Set Auto Boot TimeOut",
        "Exit",
    };
    UINTN count = sizeof(items) / sizeof(items[0]);
    UINTN selected = 0;

    for (;;) {
        EFI_INPUT_KEY key;
        UINTN i;

        fw_menu_frame("Boot option maintenance menu");
        for (i = 0; i < count; i++) {
            fw_menu_at(FW_MENU_COL, 4 + i);
            fw_menu_attr(i == selected ? FW_MENU_ATTR_SELECTED :
                         FW_MENU_ATTR_NORMAL);
            efi_conout_ascii(items[i]);
            fw_menu_attr(FW_MENU_ATTR_NORMAL);
        }
        fw_menu_footer(5 + count);

        for (;;) {
            if (fw_console_read_key(&key) == EFI_SUCCESS) {
                break;
            }
            (void)bs_stall(10000U);
        }
        if (key.ScanCode == EFI_SCAN_UP) {
            selected = (selected == 0) ? count - 1U : selected - 1U;
        } else if (key.ScanCode == EFI_SCAN_DOWN) {
            selected = (selected + 1U) % count;
        } else if (key.ScanCode == EFI_SCAN_ESC) {
            return;
        } else if (key.UnicodeChar == '\r' || key.UnicodeChar == '\n') {
            if (selected == 0) {
                fw_maint_add_entry();
            } else if (selected == 1) {
                fw_maint_delete_entry();
            } else if (selected == 2) {
                fw_maint_set_timeout();
            } else {
                return;
            }
        }
    }
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

