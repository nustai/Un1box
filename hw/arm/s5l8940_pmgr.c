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
#include "qemu/host-utils.h"

#define TYPE_S5L8940_PMGR "s5l8940-pmgr"
OBJECT_DECLARE_SIMPLE_TYPE(S5L8940PMGRState, S5L8940_PMGR)

#define S5L8940_PMGR_WORDS (0x7000 / 4)

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

    /* Stock n94 _mach_absolute_time at 0x800c8be0 reads HI/LO/HI
     * at +0x28/+0x20/+0x28. The DT identifies this PMGR as device_type=timer.
     * Keep it on QEMU virtual time so it stops when the guest is paused.
     * 24 MHz matches the fixed/timebase frequency supplied by our boot image.
     */
    if (offset == 0x20 || offset == 0x28) {
        uint64_t ticks = muldiv64(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                                 24000000, NANOSECONDS_PER_SECOND);
        return offset == 0x20 ? (uint32_t)ticks : (uint32_t)(ticks >> 32);
    }

    switch (offset) {
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
    if (offset == 0x20 || offset == 0x28) {
        return; /* free-running counter, not a clock-gate backing register */
    }
    uint32_t word_idx = (offset / 4) % S5L8940_PMGR_WORDS;
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
