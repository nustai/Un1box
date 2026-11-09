/*
 * Apple S5L8940 Flash Memory Interface (FMI) Controller
 *
 * Copyright (c) 2026 Un1box / n94 Emulation Project
 *
 * Written strictly from scratch for Apple S5L8940 (iPhone4,1 / n94 / N94AP).
 * Diagnostic register subset matching DeviceTree /arm-io/flash-controller0.
 *
 * TODO(n94): implement NAND geometry, command FIFO, ECC engine, and DMA channels.
 * Register retention supports driver probing and power management transitions
 * (AppleIOPFMI::setPowerState) without guest data aborts.
 */

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "qemu/log.h"

#define TYPE_N94_FMI "n94-fmi"
OBJECT_DECLARE_SIMPLE_TYPE(N94FMIState, N94_FMI)

#define N94_FMI_NUM_BANKS 6
#define N94_FMI_BANK_SIZE 0x1000

struct N94FMIState {
    SysBusDevice parent_obj;
    MemoryRegion iomem[N94_FMI_NUM_BANKS];
    qemu_irq irq[2];
    uint32_t regs[N94_FMI_NUM_BANKS][N94_FMI_BANK_SIZE / 4];
};

static uint64_t n94_fmi_read(void *opaque, hwaddr offset, unsigned size)
{
    uint32_t *bank_regs = opaque;
    unsigned idx = offset / 4;
    if (idx < (N94_FMI_BANK_SIZE / 4)) {
        return bank_regs[idx];
    }
    qemu_log_mask(LOG_GUEST_ERROR, "n94-fmi: out-of-bounds read +0x%" HWADDR_PRIx "\n", offset);
    return 0;
}

static void n94_fmi_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    uint32_t *bank_regs = opaque;
    unsigned idx = offset / 4;
    if (idx < (N94_FMI_BANK_SIZE / 4)) {
        bank_regs[idx] = (uint32_t)value;
        return;
    }
    qemu_log_mask(LOG_GUEST_ERROR, "n94-fmi: out-of-bounds write +0x%" HWADDR_PRIx "\n", offset);
}

static const MemoryRegionOps n94_fmi_ops = {
    .read = n94_fmi_read,
    .write = n94_fmi_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
        .unaligned = false,
    },
};

static void n94_fmi_reset(DeviceState *dev)
{
    N94FMIState *s = N94_FMI(dev);
    memset(s->regs, 0, sizeof(s->regs));
    /* Status register default: channel ready */
    for (int i = 0; i < N94_FMI_NUM_BANKS; i++) {
        s->regs[i][0] = 0x00000001;
    }
}

static void n94_fmi_init(Object *obj)
{
    N94FMIState *s = N94_FMI(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    for (int i = 0; i < N94_FMI_NUM_BANKS; i++) {
        char name[32];
        snprintf(name, sizeof(name), "n94-fmi.bank%d", i);
        memory_region_init_io(&s->iomem[i], obj, &n94_fmi_ops, s->regs[i], name, N94_FMI_BANK_SIZE);
        sysbus_init_mmio(sbd, &s->iomem[i]);
    }

    sysbus_init_irq(sbd, &s->irq[0]);
    sysbus_init_irq(sbd, &s->irq[1]);
}

static void n94_fmi_class_init(ObjectClass *klass, const void *data)
{
    device_class_set_legacy_reset(DEVICE_CLASS(klass), n94_fmi_reset);
}

static const TypeInfo n94_fmi_info = {
    .name          = TYPE_N94_FMI,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(N94FMIState),
    .instance_init = n94_fmi_init,
    .class_init    = n94_fmi_class_init,
};

static void n94_fmi_register(void)
{
    type_register_static(&n94_fmi_info);
}

type_init(n94_fmi_register)
