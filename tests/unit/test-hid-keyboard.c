/*
 * QEMU HID keyboard tests
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "hw/input/hid.h"
#include "ui/console.h"

/*
 * hid.c wants the input core; none of these paths run for a directly
 * driven keyboard queue, so stub them out.
 */
int qemu_input_key_value_to_scancode(const KeyValue *value, bool down,
                                     int *codes)
{
    g_assert_not_reached();
}

QemuInputHandlerState *qemu_input_handler_register(
    DeviceState *dev, const QemuInputHandler *handler)
{
    g_assert_not_reached();
}

void qemu_input_handler_activate(QemuInputHandlerState *s)
{
    g_assert_not_reached();
}

void qemu_input_handler_unregister(QemuInputHandlerState *s)
{
    g_assert_not_reached();
}

void kbd_put_ledstate(int ledstate)
{
    g_assert_not_reached();
}

static void queue_keycodes(HIDState *hs, const uint32_t *keycodes,
                           size_t count)
{
    size_t i;

    g_assert_cmpuint(hs->n + count, <=, QUEUE_LENGTH);
    for (i = 0; i < count; i++) {
        hs->kbd.keycodes[(hs->head + hs->n) & QUEUE_MASK] = keycodes[i];
        hs->n++;
    }
}

/*
 * An extended key (E0-prefixed) queues two scancodes; the prefix alone
 * does not change the report.  One poll must still deliver the key.
 */
static void test_extended_key_report(void)
{
    static const uint32_t press[] = { 0xe0, 0x50 };
    static const uint32_t release[] = { 0xe0, 0xd0 };
    HIDState hs = {
        .kind = HID_KEYBOARD,
    };
    uint8_t report[8];

    queue_keycodes(&hs, press, G_N_ELEMENTS(press));
    g_assert_cmpint(hid_keyboard_poll(&hs, report, sizeof(report)), ==, 8);
    g_assert_cmpuint(hs.n, ==, 0);
    g_assert_cmpuint(report[0], ==, 0);
    g_assert_cmpuint(report[2], ==, 0x51);   /* HID usage: DownArrow */

    queue_keycodes(&hs, release, G_N_ELEMENTS(release));
    g_assert_cmpint(hid_keyboard_poll(&hs, report, sizeof(report)), ==, 8);
    g_assert_cmpuint(hs.n, ==, 0);
    g_assert_cmpuint(report[0], ==, 0);
    g_assert_cmpuint(report[2], ==, 0);
}

/*
 * Two queued presses produce two distinct reports; the coalescing loop
 * must not merge them into one.
 */
static void test_distinct_reports_remain_queued(void)
{
    static const uint32_t presses[] = { 0x1e, 0x30 };  /* 'a', 'b' */
    HIDState hs = {
        .kind = HID_KEYBOARD,
    };
    uint8_t report[8];

    queue_keycodes(&hs, presses, G_N_ELEMENTS(presses));
    g_assert_cmpint(hid_keyboard_poll(&hs, report, sizeof(report)), ==, 8);
    g_assert_cmpuint(hs.n, ==, 1);
    g_assert_cmpuint(report[2], ==, 0x04);   /* HID usage: 'a' */
    g_assert_cmpuint(report[3], ==, 0);

    g_assert_cmpint(hid_keyboard_poll(&hs, report, sizeof(report)), ==, 8);
    g_assert_cmpuint(hs.n, ==, 0);
    g_assert_cmpuint(report[2], ==, 0x04);
    g_assert_cmpuint(report[3], ==, 0x05);   /* HID usage: 'b' */
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/hid/keyboard/extended-key-report",
                    test_extended_key_report);
    g_test_add_func("/hid/keyboard/distinct-reports-remain-queued",
                    test_distinct_reports_remain_queued);
    return g_test_run();
}
