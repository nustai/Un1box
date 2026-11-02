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

#define TYPE_S5L8940_AIC "s5l8940-aic"
OBJECT_DECLARE_SIMPLE_TYPE(S5L8940AICState, S5L8940_AIC)

#define S5L8940_AIC_NUM_IRQS 128
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

    uint32_t enabled[4];
    uint32_t pending[4];
    uint32_t type[4];     /* 0 = IRQ, 1 = FIQ */
    uint32_t target[4];   /* Target CPU bitmask for 4 banks of 32 IRQs */
    uint32_t target_destinations[4]; /* DeviceTree: [0x87, 0x01, 0x8b, 0x02] */
    uint32_t priority[S5L8940_AIC_NUM_IRQS];

    /* Full register backing store to handle all vendor control and status registers */
    uint32_t storage[S5L8940_AIC_REG_WORDS];
};

static void s5l8940_aic_update(S5L8940AICState *s)
{
    for (int cpu = 0; cpu < 2; cpu++) {
        bool has_irq = false;
        bool has_fiq = false;
        uint32_t cpu_mask = (1U << cpu);

        for (int i = 0; i < 4; i++) {
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
        qemu_set_irq(s->fiq_out[cpu], has_fiq);
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

    switch (offset) {
    case 0x00: /* CPU WhoAmI (returns 0 for primary core) */
        val = 0;
        break;
    case 0x04 ... 0x10: /* AIC_INT_TYPE[0..3] */
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
    uint32_t word_idx = (offset / 4) % S5L8940_AIC_REG_WORDS;
    s->storage[word_idx] = (uint32_t)value;

    switch (offset) {
    case 0x04 ... 0x10: /* AIC_INT_TYPE */
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

static const TypeInfo s5l8940_aic_info = {
    .name          = TYPE_S5L8940_AIC,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(S5L8940AICState),
    .instance_init = s5l8940_aic_init,
};

static void s5l8940_aic_register_types(void)
{
    type_register_static(&s5l8940_aic_info);
}

type_init(s5l8940_aic_register_types)
