/*
 * BlockBackend tests
 *
 * Copyright (c) 2017 Kevin Wolf <kwolf@redhat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "block/block.h"
#include "system/block-backend.h"
#include "qapi/error.h"
#include "qemu/coroutine.h"
#include "qemu/main-loop.h"

static void test_drain_aio_error_flush_cb(void *opaque, int ret)
{
    bool *completed = opaque;

    g_assert(ret == -ENOMEDIUM);
    *completed = true;
}

static void test_drain_aio_error(void)
{
    BlockBackend *blk = blk_new(qemu_get_aio_context(),
                                BLK_PERM_ALL, BLK_PERM_ALL);
    BlockAIOCB *acb;
    bool completed = false;

    acb = blk_aio_flush(blk, test_drain_aio_error_flush_cb, &completed);
    g_assert(acb != NULL);
    g_assert(completed == false);

    blk_drain(blk);
    g_assert(completed == true);

    blk_unref(blk);
}

static void test_drain_all_aio_error(void)
{
    BlockBackend *blk = blk_new(qemu_get_aio_context(),
                                BLK_PERM_ALL, BLK_PERM_ALL);
    BlockAIOCB *acb;
    bool completed = false;

    acb = blk_aio_flush(blk, test_drain_aio_error_flush_cb, &completed);
    g_assert(acb != NULL);
    g_assert(completed == false);

    blk_drain_all();
    g_assert(completed == true);

    blk_unref(blk);
}

typedef struct TestRemovableMediaMixed {
    BlockBackend *blk;
    bool done;
} TestRemovableMediaMixed;

static void coroutine_fn test_removable_media_mixed_co(void *opaque)
{
    TestRemovableMediaMixed *data = opaque;

    /*
     * SCSI request completion may resume a host adapter from a block I/O
     * coroutine, which can issue these removable-media operations directly.
     */
    blk_lock_medium(data->blk, true);
    blk_eject(data->blk, false);
    data->done = true;
}

static void test_removable_media_mixed(void)
{
    TestRemovableMediaMixed data = {
        .blk = blk_new(qemu_get_aio_context(), BLK_PERM_ALL, BLK_PERM_ALL),
    };
    Coroutine *co;

    blk_lock_medium(data.blk, false);
    blk_eject(data.blk, false);

    co = qemu_coroutine_create(test_removable_media_mixed_co, &data);
    qemu_coroutine_enter(co);
    g_assert_true(data.done);

    blk_unref(data.blk);
}

int main(int argc, char **argv)
{
    bdrv_init();
    qemu_init_main_loop(&error_abort);

    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/block-backend/drain_aio_error", test_drain_aio_error);
    g_test_add_func("/block-backend/drain_all_aio_error",
                    test_drain_all_aio_error);
    g_test_add_func("/block-backend/removable_media_mixed",
                    test_removable_media_mixed);

    return g_test_run();
}
