/*
 * Apple S5L8940 Power Manager (PMGR) Emulation for iPhone 4S (n94)
 *
 * Copyright (c) 2026 Un1box / n94 Emulation Project
 *
 * Written strictly from scratch for S5L8940 PMGR at 0x0F100000 (size 0x7000).
 * Matches "pmgr,s5l8940x" DeviceTree node.
 */

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "hw/core/irq.h"
#include "qemu/log.h"
#include "qemu/timer.h"

#define TYPE_S5L8940_PMGR "s5l8940-pmgr"
OBJECT_DECLARE_SIMPLE_TYPE(S5L8940PMGRState, S5L8940_PMGR)

#define S5L8940_PMGR_WORDS (0x7000 / 4)
/* n94 device-clocks-min/max are 56/128; driver register = 0x1000 + id*4. */
#define N94_DEVICE_CLOCK_FIRST (0x1000 + 56 * 4)
#define N94_DEVICE_CLOCK_END   (0x1000 + 128 * 4)

struct S5L8940PMGRState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;

    uint32_t clock_gates[128];
    uint32_t power_gates[128];
    uint32_t wdt_ctrl;
    uint32_t wdt_count;

    uint32_t storage[S5L8940_PMGR_WORDS];
};

static uint64_t s5l8940_pmgr_read(void *opaque, hwaddr offset, unsigned size)
{
    S5L8940PMGRState *s = opaque;
    uint32_t val = 0;
    uint32_t word_idx = (offset / 4) % S5L8940_PMGR_WORDS;

    if (offset >= N94_DEVICE_CLOCK_FIRST && offset < N94_DEVICE_CLOCK_END) {
        return s->storage[word_idx];
    }

    switch (offset) {
    case 0x300:
        /* Stock n94 _initPMGRState reads +0x300 at 0x80d96230 and uses
         * its low nibble as the occupied PERF_STATE prefix. A blanket 0xf
         * leaves one of 16 slots and provokes "out of PERF_STATE registers".
         * Keep a distinct writable register, including a meaningful zero.
         * TODO(n94): verify full PERF_STATE control bits and hardware reset.
         */
        val = s->storage[word_idx];
        break;
    case 0x00 ... 0x1fc: { /* Clock Gates */
        int idx = (offset / 4) % 128;
        val = s->clock_gates[idx];
        break;
    }
    case 0x3020: /* WDT Control */
        val = s->wdt_ctrl;
        break;
    case 0x3024: /* WDT Counter */
        val = s->wdt_count;
        break;
    case 0x5000 ... 0x51fc: { /* Power Gates */
        int idx = ((offset - 0x5000) / 4) % 128;
        val = s->power_gates[idx];
        break;
    }
    default:
        val = s->storage[word_idx];
        if (val == 0) {
            /* Apple PMGR default: domains initialized to active power state 0xF */
            val = 0x0000000f;
        }
        break;
    }

    return val;
}

static void s5l8940_pmgr_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    S5L8940PMGRState *s = opaque;
    uint32_t word_idx = (offset / 4) % S5L8940_PMGR_WORDS;
    if (offset >= N94_DEVICE_CLOCK_FIRST && offset < N94_DEVICE_CLOCK_END) {
        /* 13G37 0x80d96bae waits until low target and high actual nibble
         * agree. Complete the virtual domain transition synchronously.
         * Preserve other control bits and meaningful OFF=0 writes.
         * TODO(n94): power-domain dependencies and transition latency.
         */
        s->storage[word_idx] = (value & ~0xf0U) | ((value & 0xf) << 4);
        return;
    }
    s->storage[word_idx] = (uint32_t)value;

    switch (offset) {
    case 0x00 ... 0x1fc: {
        int idx = (offset / 4) % 128;
        /*
         * When Apple kernel sets gate target, bits 0..3 reflect actual state.
         * Setting actual state equal to target ensures clock-wait loops terminate immediately.
         */
        s->clock_gates[idx] = (uint32_t)value | 0x0f;
        break;
    }
    case 0x3020:
        s->wdt_ctrl = (uint32_t)value;
        break;
    case 0x3024:
        s->wdt_count = (uint32_t)value;
        break;
    case 0x5000 ... 0x51fc: {
        int idx = ((offset - 0x5000) / 4) % 128;
        s->power_gates[idx] = (uint32_t)value | 0x0f;
        break;
    }
    default:
        break;
    }
}

static const MemoryRegionOps s5l8940_pmgr_ops = {
    .read = s5l8940_pmgr_read,
    .write = s5l8940_pmgr_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static void s5l8940_pmgr_init(Object *obj)
{
    S5L8940PMGRState *s = S5L8940_PMGR(obj);
    SysBusDevice *dev = SYS_BUS_DEVICE(obj);

    for (int i = 0; i < 128; i++) {
        s->clock_gates[i] = 0x0000000f;
        s->power_gates[i] = 0x0000000f;
    }
    for (int i = 0; i < S5L8940_PMGR_WORDS; i++) {
        s->storage[i] = 0x0000000f;
    }
    /* Diagnostic boot owns no preallocated performance-state slots. */
    s->storage[0x300 / 4] = 0;
    for (unsigned offset = N94_DEVICE_CLOCK_FIRST;
         offset < N94_DEVICE_CLOCK_END; offset += 4) {
        s->storage[offset / 4] = 0xff; /* diagnostic active target/current */
    }

    memory_region_init_io(&s->iomem, obj, &s5l8940_pmgr_ops, s, "s5l8940-pmgr", 0x7000);
    sysbus_init_mmio(dev, &s->iomem);
}

static const TypeInfo s5l8940_pmgr_info = {
    .name          = TYPE_S5L8940_PMGR,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(S5L8940PMGRState),
    .instance_init = s5l8940_pmgr_init,
};

static void s5l8940_pmgr_register_types(void)
{
    type_register_static(&s5l8940_pmgr_info);
}

type_init(s5l8940_pmgr_register_types)
