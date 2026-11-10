/*
 * Apple S5L8940 Interrupt Controller (AIC) Emulation for iPhone 4S (n94)
 *
 * Copyright (c) 2026 Un1box / n94 Emulation Project
 *
 * Written strictly from scratch for S5L8940 AIC at 0x0F200000 (size 0x10000).
 * Compatible with "aic,1" specification from DeviceTree.n94ap.RELEASE.
 * Dual-core SMP routing: target-destinations [0x87, 0x01, 0x8b, 0x02]
 */

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "hw/core/irq.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "qemu/host-utils.h"

#define TYPE_S5L8940_AIC "s5l8940-aic"
OBJECT_DECLARE_SIMPLE_TYPE(S5L8940AICState, S5L8940_AIC)

/* n94 ipid-mask is six words. The stock driver requires exactly
 * ceil(INFO.num_irqs / 32) words (13G37 0x80f09736..0x80f09754).
 * TODO(n94): establish exact implemented IRQ count within this 192-bit capacity.
 */
#define S5L8940_AIC_NUM_IRQS 192
#define S5L8940_AIC_BANKS (S5L8940_AIC_NUM_IRQS / 32)
#define S5L8940_AIC_REG_WORDS (0x10000 / 4)

struct S5L8940AICState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;

    /* 4 IRQ output lines:
     * irq_out[0] = CPU0 IRQ, fiq_out[0] = CPU0 FIQ
     * irq_out[1] = CPU1 IRQ, fiq_out[1] = CPU1 FIQ
     */
    qemu_irq irq_out[2];
    qemu_irq fiq_out[2];
    qemu_irq doorbell_out;

    uint32_t enabled[S5L8940_AIC_BANKS];
    uint32_t pending[S5L8940_AIC_BANKS];
    uint32_t type[S5L8940_AIC_BANKS]; /* TODO(n94): verify IRQ/FIQ routing ABI. */
    uint32_t target[S5L8940_AIC_BANKS];
    uint32_t target_destinations[4]; /* DeviceTree: [0x87, 0x01, 0x8b, 0x02] */
    uint32_t priority[S5L8940_AIC_NUM_IRQS];

    /* Full register backing store to handle all vendor control and status registers */
    uint32_t storage[S5L8940_AIC_REG_WORDS];
    unsigned diagnostic_accesses;
    QEMUTimer *timer0;
    bool timer0_enabled;
    bool timer0_pending;
    uint32_t timer0_count;
};

static void s5l8940_aic_update(S5L8940AICState *s)
{
    for (int cpu = 0; cpu < 2; cpu++) {
        bool has_irq = false;
        bool has_fiq = false;
        uint32_t cpu_mask = (1U << cpu);

        for (int i = 0; i < S5L8940_AIC_BANKS; i++) {
            uint32_t active = s->pending[i] & s->enabled[i];
            uint32_t cpu_active = 0;

            for (int bit = 0; bit < 32; bit++) {
                int irq_idx = i * 32 + bit;
                /*
                 * Target routing per DeviceTree target-destinations:
                 * Priority upper 16 bits or bank-level target mask.
                 * Bit 0 routes to CPU0, Bit 1 routes to CPU1.
                 * TODO(n94): AIC target-destinations hardware register behavior
                 */
                uint32_t dest = s->priority[irq_idx] >> 16;
                if (!dest) {
                    dest = s->target[i];
                }
                if (!dest) {
                    dest = 0x01; /* Default to primary core CPU0 */
                }

                if (dest & cpu_mask) {
                    if (active & (1U << bit)) {
                        cpu_active |= (1U << bit);
                    }
                }
            }

            has_fiq |= (cpu_active & s->type[i]) != 0;
            has_irq |= (cpu_active & ~s->type[i]) != 0;
        }

        qemu_set_irq(s->irq_out[cpu], has_irq);
        qemu_set_irq(s->fiq_out[cpu], has_fiq || (cpu == 0 && s->timer0_pending));
    }
}

/* TODO(n94): verify control/ack semantics and timer clock on physical A5.
 * 13G37 programs +2014 with a relative tick count via 0x800c8c20,
 * and initialization writes 1 to +2010 and +2018. FIQ routing and 24 MHz
 * are diagnostic hypotheses, not a claim of complete timer hardware. */
static void n94_timer0_expired(void *opaque)
{
    S5L8940AICState *s = opaque;
    if (s->timer0_enabled) {
        s->timer0_pending = true;
        s5l8940_aic_update(s);
    }
}

static void n94_timer0_schedule(S5L8940AICState *s)
{
    timer_del(s->timer0);
    if (s->timer0_enabled) {
        uint64_t ns = muldiv64(s->timer0_count, NANOSECONDS_PER_SECOND, 24000000);
        timer_mod_ns(s->timer0, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + MAX(ns, 1));
    }
}

static void s5l8940_aic_set_irq(void *opaque, int irq, int level)
{
    S5L8940AICState *s = opaque;
    if (irq < 0 || irq >= S5L8940_AIC_NUM_IRQS) {
        return;
    }

    int idx = irq / 32;
    uint32_t mask = 1U << (irq % 32);

    if (level) {
        s->pending[idx] |= mask;
    } else {
        s->pending[idx] &= ~mask;
    }

    s5l8940_aic_update(s);
}

static uint64_t s5l8940_aic_read(void *opaque, hwaddr offset, unsigned size)
{
    S5L8940AICState *s = opaque;
    uint32_t val = 0;
    uint32_t word_idx = (offset / 4) % S5L8940_AIC_REG_WORDS;
    if (offset != 0x20 && offset != 0x28 && s->diagnostic_accesses++ < 2048) {
        qemu_log_mask(LOG_UNIMP, "n94 AIC read +0x%" HWADDR_PRIx "\n", offset);
    }

    /* Stock 13G37 mach_absolute_time reads HI/LO/HI at +0x28/+0x20/+0x28.
     * QMP gva2gpa of its global clock pointer confirms physical 0x3f200000.
     * TODO(n94): independently calibrate frequency; 24 MHz matches boot DT.
     */
    if (offset == 0x20 || offset == 0x28) {
        uint64_t ticks = muldiv64(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                                 24000000, NANOSECONDS_PER_SECOND);
        return offset == 0x20 ? (uint32_t)ticks : (uint32_t)(ticks >> 32);
    }
    if (offset == 0x2010) {
        return s->timer0_enabled;
    }
    if (offset == 0x2014) {
        return s->timer0_count;
    }
    if (offset == 0x2018) {
        return s->timer0_pending;
    }

    switch (offset) {
    case 0x00: /* CPU WhoAmI (returns 0 for primary core) */
        val = 0;
        break;
    case 0x04:
        /* Stock AppleInterruptController::start reads INFO at +4 twice:
         * bits 16..20 = CPUs minus one; bits 0..9 = IRQ capacity.
         * Returning zero caused the observed ipid-mask length 24 != 0 panic.
         */
        val = (1U << 16) | S5L8940_AIC_NUM_IRQS;
        break;
    case 0x08 ... 0x10: /* TODO(n94): remaining legacy register interpretations */
        val = s->type[(offset - 0x04) / 4];
        break;
    case 0x80: /* Target / affinity register 0 (DeviceTree target-destinations: 0x87 -> CPU0) */
        val = s->target_destinations[0];
        break;
    case 0x84: /* Target / affinity register 1 (DeviceTree target-destinations: 0x8b -> CPU1) */
        val = s->target_destinations[2];
        break;
    case 0x88 ... 0x8c: /* AIC_INT_PENDING */
        val = s->pending[(offset - 0x80) / 4];
        break;
    case 0x100 ... 0x10c: /* AIC_INT_ENABLE[0..3] */
        val = s->enabled[(offset - 0x100) / 4];
        break;
    case 0x140 ... 0x33c: /* AIC_INT_PRIORITY[0..127] */
        val = s->priority[(offset - 0x140) / 4];
        break;
    default:
        val = s->storage[word_idx];
        break;
    }

    return val;
}

static void s5l8940_aic_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    S5L8940AICState *s = opaque;
    if (offset != 0x20 && offset != 0x28 && s->diagnostic_accesses++ < 2048) {
        qemu_log_mask(LOG_UNIMP, "n94 AIC write +0x%" HWADDR_PRIx " = 0x%08x\n", offset, (uint32_t)value);
    }
    if (offset == 0x20 || offset == 0x28) {
        return; /* free-running counter */
    }
    if (offset == 0x2010) {
        s->timer0_enabled = value & 1;
        n94_timer0_schedule(s);
        return;
    }
    if (offset == 0x2014) {
        s->timer0_count = value;
        s->timer0_pending = false;
        n94_timer0_schedule(s);
        s5l8940_aic_update(s);
        return;
    }
    if (offset == 0x2018) {
        if (value & 1) {
            s->timer0_pending = false;
            s5l8940_aic_update(s);
        }
        return;
    }
    uint32_t word_idx = (offset / 4) % S5L8940_AIC_REG_WORDS;
    s->storage[word_idx] = (uint32_t)value;

    switch (offset) {
    case 0x04:
        return; /* read-only INFO */
    case 0x08 ... 0x10: /* TODO(n94): remaining legacy register interpretations */
        s->type[(offset - 0x04) / 4] = (uint32_t)value;
        break;
    case 0x80:
        s->target_destinations[0] = (uint32_t)value;
        break;
    case 0x84:
        s->target_destinations[2] = (uint32_t)value;
        break;
    case 0x100 ... 0x10c: /* AIC_INT_ENABLE */
        s->enabled[(offset - 0x100) / 4] |= (uint32_t)value;
        break;
    case 0x110 ... 0x11c: /* AIC_INT_DISABLE */
        s->enabled[(offset - 0x110) / 4] &= ~(uint32_t)value;
        break;
    case 0x120 ... 0x12c: /* AIC_INT_SW_SET */
        s->pending[(offset - 0x120) / 4] |= (uint32_t)value;
        break;
    case 0x130 ... 0x13c: /* AIC_INT_SW_CLR / ACK */
        s->pending[(offset - 0x130) / 4] &= ~(uint32_t)value;
        break;
    case 0x140 ... 0x33c: /* AIC_INT_PRIORITY */
        s->priority[(offset - 0x140) / 4] = (uint32_t)value;
        break;
    case 0x5000 ... 0x50ff:
        /* DIPI registers (including 0x5030: DIPI 3 doorbell to IOP) */
        s->storage[word_idx] = (uint32_t)value;
        if (offset == 0x5030 && s->doorbell_out) {
            qemu_irq_pulse(s->doorbell_out);
        }
        break;
    default:
        break;
    }

    s5l8940_aic_update(s);
}

static const MemoryRegionOps s5l8940_aic_ops = {
    .read = s5l8940_aic_read,
    .write = s5l8940_aic_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static void s5l8940_aic_init(Object *obj)
{
    S5L8940AICState *s = S5L8940_AIC(obj);
    SysBusDevice *dev = SYS_BUS_DEVICE(obj);

    memory_region_init_io(&s->iomem, obj, &s5l8940_aic_ops, s, "s5l8940-aic", 0x10000);
    s->timer0 = timer_new_ns(QEMU_CLOCK_VIRTUAL, n94_timer0_expired, s);
    sysbus_init_mmio(dev, &s->iomem);

    /* 4 IRQ output lines:
     * Output 0: CPU0 IRQ
     * Output 1: CPU0 FIQ
     * Output 2: CPU1 IRQ
     * Output 3: CPU1 FIQ
     */
    sysbus_init_irq(dev, &s->irq_out[0]);
    sysbus_init_irq(dev, &s->fiq_out[0]);
    sysbus_init_irq(dev, &s->irq_out[1]);
    sysbus_init_irq(dev, &s->fiq_out[1]);
    sysbus_init_irq(dev, &s->doorbell_out);

    /* DeviceTree target-destinations: [0x87, 0x01, 0x8b, 0x02]
     * Pairs of (routing_register_offset, cpu_bitmask):
     * - CPU0: register 0x87, bitmask 0x01
     * - CPU1: register 0x8b, bitmask 0x02
     */
    s->target_destinations[0] = 0x87;
    s->target_destinations[1] = 0x01;
    s->target_destinations[2] = 0x8b;
    s->target_destinations[3] = 0x02;

    s->target[0] = 0x01; /* Bank 0 (IRQs 0..31): CPU0 */
    s->target[1] = 0x01; /* Bank 1 (IRQs 32..63): CPU0 */
    s->target[2] = 0x03; /* Bank 2 (IRQs 64..95): both CPU0 and CPU1 */
    s->target[3] = 0x03; /* Bank 3 (IRQs 96..127): both CPU0 and CPU1 */

    qdev_init_gpio_in(DEVICE(obj), s5l8940_aic_set_irq, S5L8940_AIC_NUM_IRQS);
}

static void s5l8940_aic_reset(DeviceState *dev)
{
    S5L8940AICState *s = S5L8940_AIC(dev);
    timer_del(s->timer0);
    s->timer0_count = 0;
    s->timer0_enabled = false;
    s->timer0_pending = false;
    memset(s->enabled, 0, sizeof(s->enabled));
    memset(s->pending, 0, sizeof(s->pending));
    s5l8940_aic_update(s);
}

static void s5l8940_aic_class_init(ObjectClass *klass, const void *data)
{
    device_class_set_legacy_reset(DEVICE_CLASS(klass), s5l8940_aic_reset);
}

static const TypeInfo s5l8940_aic_info = {
    .name          = TYPE_S5L8940_AIC,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(S5L8940AICState),
    .instance_init = s5l8940_aic_init,
    .class_init = s5l8940_aic_class_init,
};

static void s5l8940_aic_register_types(void)
{
    type_register_static(&s5l8940_aic_info);
}

type_init(s5l8940_aic_register_types)
