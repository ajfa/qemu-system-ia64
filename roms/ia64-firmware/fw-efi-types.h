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

typedef struct {
    UINT64                  Signature;
    EFI_PHYSICAL_ADDRESS    EfiSystemTableBase;
    UINT32                  Crc32;
    UINT32                  Reserved;
} EFI_SYSTEM_TABLE_POINTER;

typedef struct {
    UINT16 ScanCode;
    CHAR16 UnicodeChar;
} EFI_INPUT_KEY;

/* --- EFI Simple Text Output Protocol -------------------------------------- */
typedef EFI_STATUS (*EFI_TEXT_RESET)(VOID *This, BOOLEAN ExtendedVerification);
typedef EFI_STATUS (*EFI_TEXT_STRING)(VOID *This, CHAR16 *String);
typedef EFI_STATUS (*EFI_TEXT_TEST_STRING)(VOID *This, CHAR16 *String);
typedef EFI_STATUS (*EFI_TEXT_QUERY_MODE)(VOID *This, UINTN ModeNumber, UINTN *Columns, UINTN *Rows);
typedef EFI_STATUS (*EFI_TEXT_SET_MODE)(VOID *This, UINTN ModeNumber);
typedef EFI_STATUS (*EFI_TEXT_SET_ATTRIBUTE)(VOID *This, UINTN Attribute);
typedef EFI_STATUS (*EFI_TEXT_CLEAR_SCREEN)(VOID *This);
typedef EFI_STATUS (*EFI_TEXT_SET_CURSOR_POSITION)(VOID *This, UINTN Column, UINTN Row);
typedef EFI_STATUS (*EFI_TEXT_ENABLE_CURSOR)(VOID *This, BOOLEAN Enable);

typedef struct {
    UINT32                          MaxMode;
    UINT32                          Mode;
    INT32                           Attribute;
    INT32                           CursorColumn;
    INT32                           CursorRow;
    BOOLEAN                         CursorVisible;
} SIMPLE_TEXT_OUTPUT_MODE;

typedef struct _EFI_SIMPLE_TEXT_OUT_PROTOCOL {
    EFI_TEXT_RESET                  Reset;
    EFI_TEXT_STRING                 OutputString;
    EFI_TEXT_TEST_STRING            TestString;
    EFI_TEXT_QUERY_MODE             QueryMode;
    EFI_TEXT_SET_MODE               SetMode;
    EFI_TEXT_SET_ATTRIBUTE          SetAttribute;
    EFI_TEXT_CLEAR_SCREEN           ClearScreen;
    EFI_TEXT_SET_CURSOR_POSITION    SetCursorPosition;
    EFI_TEXT_ENABLE_CURSOR          EnableCursor;
    SIMPLE_TEXT_OUTPUT_MODE        *Mode;
} EFI_SIMPLE_TEXT_OUT_PROTOCOL;

/* --- EFI Simple Text Input Protocol ---------------------------------------- */

#define EFI_SIMPLE_TEXT_INPUT_PROTOCOL_GUID { 0x387477c1, 0x69c7, 0x11d2, \
    { 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } }

typedef struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
    EFI_STATUS (*Reset)(struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
                        BOOLEAN ExtendedVerification);
    EFI_STATUS (*ReadKeyStroke)(struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
                                 EFI_INPUT_KEY *Key);
    EFI_EVENT   WaitForKey;
} EFI_SIMPLE_TEXT_INPUT_PROTOCOL;

/* --- EFI Simple Text Input Ex Protocol ------------------------------------ */

#define EFI_SHIFT_STATE_VALID    0x80000000U
#define EFI_RIGHT_SHIFT_PRESSED  0x00000001U
#define EFI_LEFT_SHIFT_PRESSED   0x00000002U
#define EFI_RIGHT_CONTROL_PRESSED 0x00000004U
#define EFI_LEFT_CONTROL_PRESSED 0x00000008U
#define EFI_RIGHT_ALT_PRESSED    0x00000010U
#define EFI_LEFT_ALT_PRESSED     0x00000020U
#define EFI_RIGHT_LOGO_PRESSED   0x00000040U
#define EFI_LEFT_LOGO_PRESSED    0x00000080U
#define EFI_MENU_KEY_PRESSED     0x00000100U
#define EFI_TOGGLE_STATE_VALID   0x80U
#define EFI_KEY_STATE_EXPOSED    0x40U
#define EFI_SCROLL_LOCK_ACTIVE   0x01U
#define EFI_NUM_LOCK_ACTIVE      0x02U
#define EFI_CAPS_LOCK_ACTIVE     0x04U

typedef UINT8 EFI_KEY_TOGGLE_STATE;

typedef struct {
    UINT32 KeyShiftState;
    EFI_KEY_TOGGLE_STATE KeyToggleState;
} EFI_KEY_STATE;

typedef struct {
    EFI_INPUT_KEY Key;
    EFI_KEY_STATE KeyState;
} EFI_KEY_DATA;

typedef EFI_STATUS (*EFI_KEY_NOTIFY_FUNCTION)(EFI_KEY_DATA *KeyData);

typedef struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL
    EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL;

struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL {
    EFI_STATUS (*Reset)(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
                        BOOLEAN ExtendedVerification);
    EFI_STATUS (*ReadKeyStrokeEx)(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
                                  EFI_KEY_DATA *KeyData);
    EFI_EVENT   WaitForKeyEx;
    EFI_STATUS (*SetState)(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
                           EFI_KEY_TOGGLE_STATE *KeyToggleState);
    EFI_STATUS (*RegisterKeyNotify)(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
                                    EFI_KEY_DATA *KeyData,
                                    EFI_KEY_NOTIFY_FUNCTION KeyNotificationFunction,
                                    VOID **NotifyHandle);
    EFI_STATUS (*UnregisterKeyNotify)(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
                                      VOID *NotificationHandle);
};




#endif /* IA64_FIRMWARE_FW_EFI_TYPES_H */
