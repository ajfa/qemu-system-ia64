/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * EFI protocol/structure typedefs shared by the firmware modules.
 * Receives definitions moved out of firmware.c as units are extracted
 * (Phase 1 of plans/firmware-rework-plan.md).
 */

#ifndef IA64_FIRMWARE_FW_EFI_TYPES_H
#define IA64_FIRMWARE_FW_EFI_TYPES_H

#include "fw-base.h"

/* --- EFI Unicode Collation Protocol ---------------------------------------- */

typedef struct _EFI_UNICODE_COLLATION_PROTOCOL EFI_UNICODE_COLLATION_PROTOCOL;

struct _EFI_UNICODE_COLLATION_PROTOCOL {
    INTN (*StriColl)(EFI_UNICODE_COLLATION_PROTOCOL *This,
                     CHAR16 *String1, CHAR16 *String2);
    BOOLEAN (*MetaiMatch)(EFI_UNICODE_COLLATION_PROTOCOL *This,
                          CHAR16 *String, CHAR16 *Pattern);
    VOID (*StrLwr)(EFI_UNICODE_COLLATION_PROTOCOL *This, CHAR16 *String);
    VOID (*StrUpr)(EFI_UNICODE_COLLATION_PROTOCOL *This, CHAR16 *String);
    VOID (*FatToStr)(EFI_UNICODE_COLLATION_PROTOCOL *This,
                     UINTN FatSize, CHAR8 *Fat, CHAR16 *String);
    BOOLEAN (*StrToFat)(EFI_UNICODE_COLLATION_PROTOCOL *This,
                        CHAR16 *String, UINTN FatSize, CHAR8 *Fat);
    CHAR8 *SupportedLanguages;
};

#endif /* IA64_FIRMWARE_FW_EFI_TYPES_H */
