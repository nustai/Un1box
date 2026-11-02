/*
 * Apple S5L8940 SoC (Apple A5) Emulation for iPhone 4S (n94)
 *
 * Copyright (c) 2026 Un1box / n94 Emulation Project
 *
 * Written strictly from scratch for Apple S5L8940 (iPhone4,1 / n94 / N94AP).
 * MMIO layout and peripherals derived from DeviceTree.n94ap.RELEASE (13G37).
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/core/sysbus.h"
#include "hw/core/irq.h"
#include "hw/core/qdev-properties.h"
#include "system/address-spaces.h"
#include "system/system.h"
#include "hw/arm/boot.h"
#include "hw/arm/s5l8940_soc.h"
#include "target/arm/cpu.h"

static void s5l8940_soc_init(Object *obj)
{
    S5L8940State *s = S5L8940_SOC(obj);

    /* Initialize dual Cortex-A9 CPU cores with explicit names */
    object_initialize_child(obj, "cpu[0]", &s->cpu[0], ARM_CPU_TYPE_NAME("cortex-a9"));
    object_initialize_child(obj, "cpu[1]", &s->cpu[1], ARM_CPU_TYPE_NAME("cortex-a9"));

    /* AIC Interrupt Controller */
    s->aic = qdev_new("s5l8940-aic");
    /* PMGR Power Manager */
    s->pmgr = qdev_new("s5l8940-pmgr");
    /* UART1 Debug Console */
    s->uart1 = qdev_new("n94-uart");
    /* Display CLCD (640x960 Retina) */
    s->clcd = qdev_new("n94-display");
}

static void s5l8940_soc_realize(DeviceState *dev, Error **errp)
{
    S5L8940State *s = S5L8940_SOC(dev);
    MemoryRegion *sysmem = get_system_memory();

    /* Realize CPU cores (Cortex-A9 is ARMv7-A without EL3) */
    for (int i = 0; i < 2; i++) {
        object_property_set_bool(OBJECT(&s->cpu[i]), "reset-hivecs", true, &error_fatal);
        if (!qdev_realize(DEVICE(&s->cpu[i]), NULL, errp)) {
            return;
        }
        s->cpu_irq[i] = qdev_get_gpio_in(DEVICE(&s->cpu[i]), ARM_CPU_IRQ);
        s->cpu_fiq[i] = qdev_get_gpio_in(DEVICE(&s->cpu[i]), ARM_CPU_FIQ);
    }

    /* 1. Realize and map AIC */
    sysbus_realize_and_unref(SYS_BUS_DEVICE(s->aic), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(s->aic), 0, S5L8940_AIC_BASE);

    /* Connect AIC outputs to CPU0 and CPU1 IRQ/FIQ:
     * Line 0 -> CPU0 IRQ
     * Line 1 -> CPU0 FIQ
     * Line 2 -> CPU1 IRQ
     * Line 3 -> CPU1 FIQ
     */
    sysbus_connect_irq(SYS_BUS_DEVICE(s->aic), 0, s->cpu_irq[0]);
    sysbus_connect_irq(SYS_BUS_DEVICE(s->aic), 1, s->cpu_fiq[0]);
    sysbus_connect_irq(SYS_BUS_DEVICE(s->aic), 2, s->cpu_irq[1]);
    sysbus_connect_irq(SYS_BUS_DEVICE(s->aic), 3, s->cpu_fiq[1]);

    /* 2. Realize and map PMGR */
    sysbus_realize_and_unref(SYS_BUS_DEVICE(s->pmgr), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(s->pmgr), 0, S5L8940_PMGR_BASE);

    /* 3. Realize and map UART1 (Serial debug console) */
    if (serial_hd(0)) {
        qdev_prop_set_chr(s->uart1, "chardev", serial_hd(0));
    }
    sysbus_realize_and_unref(SYS_BUS_DEVICE(s->uart1), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(s->uart1), 0, S5L8940_UART1_DEBUG_BASE);
    /* DeviceTree specifies interrupt 0x16 for UART1 */
    sysbus_connect_irq(SYS_BUS_DEVICE(s->uart1), 0, qdev_get_gpio_in(s->aic, 0x16));

    /* 4. Realize and map Display (640x960 Retina) and subregions */
    sysbus_realize_and_unref(SYS_BUS_DEVICE(s->clcd), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(s->clcd), 0, S5L8940_CLCD_BASE);
    sysbus_mmio_map(SYS_BUS_DEVICE(s->clcd), 1, S5L8940_CLCD_SUB_BASE_1);
    sysbus_mmio_map(SYS_BUS_DEVICE(s->clcd), 2, S5L8940_CLCD_SUB_BASE_2);

    /* DeviceTree specifies interrupts 0x2b, 0x2a for CLCD in that order:
     * Line 0 -> IRQ 0x2b (VBLANK)
     * Line 1 -> IRQ 0x2a (FIFO/DMA)
     */
    sysbus_connect_irq(SYS_BUS_DEVICE(s->clcd), 0, qdev_get_gpio_in(s->aic, 0x2b));
    sysbus_connect_irq(SYS_BUS_DEVICE(s->clcd), 1, qdev_get_gpio_in(s->aic, 0x2a));

    /* 5. Map IO regions (0x3fb00000 and 0x3fc00000) */
    memory_region_init_ram(&s->io_mem_0, OBJECT(s), "s5l8940.io0", S5L8940_IO_SIZE_0, &error_fatal);
    memory_region_add_subregion(sysmem, S5L8940_IO_BASE_0, &s->io_mem_0);

    memory_region_init_ram(&s->io_mem_1, OBJECT(s), "s5l8940.io1", S5L8940_IO_SIZE_1, &error_fatal);
    memory_region_add_subregion(sysmem, S5L8940_IO_BASE_1, &s->io_mem_1);
}

static void s5l8940_soc_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = s5l8940_soc_realize;
}

static const TypeInfo s5l8940_soc_info = {
    .name          = TYPE_S5L8940_SOC,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(S5L8940State),
    .instance_init = s5l8940_soc_init,
    .class_init    = s5l8940_soc_class_init,
};

static void s5l8940_soc_register_types(void)
{
    type_register_static(&s5l8940_soc_info);
}

type_init(s5l8940_soc_register_types)
