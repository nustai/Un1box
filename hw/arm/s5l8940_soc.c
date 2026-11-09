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
#include "hw/arm/s5l8940_iop.h"
#include "hw/arm/s5l8940_spi.h"
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
    s->gpio = qdev_new("s5l8940-gpio");
    s->pl310 = qdev_new("s5l8940-pl310");
    s->cdma = qdev_new("s5l8940-cdma");
    object_property_add_child(obj, "cdma", OBJECT(s->cdma));
    /* UART0 is marked boot-console in the stock n94 DeviceTree. */
    s->uart0 = qdev_new("n94-uart");
    /* UART1 is a separate peripheral, not the selected boot console. */
    s->uart1 = qdev_new("n94-uart");
    /* Display CLCD (640x960 Retina) */
    s->clcd = qdev_new("n94-display");
    /* IOP Storage Controller */
    s->iop = qdev_new("s5l8940-iop");
    object_property_add_child(obj, "iop", OBJECT(s->iop));
    /* SPI1 Multitouch Controller */
    s->spi1 = qdev_new("s5l8940-spi");
    object_property_add_child(obj, "spi1", OBJECT(s->spi1));
}

static void s5l8940_soc_release_cpu1(void *opaque, int n, int level)
{
    S5L8940State *s = opaque;
    if (level) {
        CPUState *cs1 = CPU(&s->cpu[1]);
        if (cs1->halted) {
            uint32_t active_thread = 0;
            cpu_physical_memory_read(0x803fe020, &active_thread, sizeof(active_thread));
            if (!active_thread) {
                return;
            }
            ARMCPU *cpu1 = &s->cpu[1];
            CPUARMState *env1 = &cpu1->env;
            if (s->bootargs_pa) {
                env1->regs[0] = s->bootargs_pa;
            } else if (!env1->regs[0]) {
                env1->regs[0] = 0x80005000;
            }
            if (!env1->regs[1]) {
                env1->regs[1] = 0x803fe000; /* Apple A5 CPU1 cpu_data_t physical address */
            }
            if (!env1->regs[13]) {
                env1->regs[13] = 0x80200000; /* Secondary initial stack */
            }
            if (!env1->regs[15]) {
                env1->regs[15] = 0x800c7000; /* Secondary core startup vector in start.s */
            }
            cpsr_write(env1, 0x000000D3, 0xffffffff, CPSRWriteRaw);
            env1->cp15.vbar_el[1] = 0x80000000;
            cs1->halted = 0;
            qemu_cpu_kick(cs1);
        }
    }
}

static void s5l8940_soc_realize(DeviceState *dev, Error **errp)
{
    S5L8940State *s = S5L8940_SOC(dev);
    MemoryRegion *sysmem = get_system_memory();

    /* Realize CPU cores (Cortex-A9 is ARMv7-A without EL3) */
    for (int i = 0; i < 2; i++) {
        object_property_set_bool(OBJECT(&s->cpu[i]), "reset-hivecs", true, &error_fatal);
        object_property_set_int(OBJECT(&s->cpu[i]), "mp-affinity", i, &error_fatal);
        object_property_set_bool(OBJECT(&s->cpu[i]), "start-powered-off", i != 0, &error_fatal);
        if (!qdev_realize(DEVICE(&s->cpu[i]), NULL, errp)) {
            return;
        }
        s->cpu_irq[i] = qdev_get_gpio_in(DEVICE(&s->cpu[i]), ARM_CPU_IRQ);
        s->cpu_fiq[i] = qdev_get_gpio_in(DEVICE(&s->cpu[i]), ARM_CPU_FIQ);
    }

    qdev_init_gpio_in(dev, s5l8940_soc_release_cpu1, 1);

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
    /* Connect PMGR CPU1 release output to SoC secondary core wake line */
    sysbus_connect_irq(SYS_BUS_DEVICE(s->pmgr), 0, qdev_get_gpio_in(dev, 0));

    /* 3. USB Subsystem: control, OTG PHY, device controller, and EHCI/OHCI hosts */
    DeviceState *usb_control = qdev_new("n94-usb-control");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(usb_control), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(usb_control), 0, S5L8940_USB_COMPLEX_BASE);

    DeviceState *otgphy = qdev_new("n94-otgphyctrl");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(otgphy), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(otgphy), 0, S5L8940_OTGPHYCTRL_BASE);

    DeviceState *usb_device = qdev_new("n94-usb-device");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(usb_device), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(usb_device), 0, S5L8940_USB_DEV_BASE);
    sysbus_connect_irq(SYS_BUS_DEVICE(usb_device), 0, qdev_get_gpio_in(s->aic, 0x0b));

    DeviceState *usb_ehci = qdev_new("n94-usb-host");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(usb_ehci), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(usb_ehci), 0, S5L8940_USB_EHCI_BASE0);
    sysbus_mmio_map(SYS_BUS_DEVICE(usb_ehci), 1, S5L8940_USB_EHCI_BASE1);
    sysbus_connect_irq(SYS_BUS_DEVICE(usb_ehci), 0, qdev_get_gpio_in(s->aic, 0x0c));

    DeviceState *usb_ohci0 = qdev_new("n94-usb-host");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(usb_ohci0), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(usb_ohci0), 0, S5L8940_USB_OHCI0_BASE);
    sysbus_connect_irq(SYS_BUS_DEVICE(usb_ohci0), 0, qdev_get_gpio_in(s->aic, 0x0d));

    DeviceState *usb_ohci1 = qdev_new("n94-usb-host");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(usb_ohci1), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(usb_ohci1), 0, S5L8940_USB_OHCI1_BASE);
    sysbus_connect_irq(SYS_BUS_DEVICE(usb_ohci1), 0, qdev_get_gpio_in(s->aic, 0x0e));

    /* 4. Flash Memory Interface (FMI) controller: 6 MMIO banks */
    DeviceState *fmi = qdev_new("n94-fmi");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(fmi), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(fmi), 0, S5L8940_FMI_BASE_0);
    sysbus_mmio_map(SYS_BUS_DEVICE(fmi), 1, S5L8940_FMI_BASE_1);
    sysbus_mmio_map(SYS_BUS_DEVICE(fmi), 2, S5L8940_FMI_BASE_2);
    sysbus_mmio_map(SYS_BUS_DEVICE(fmi), 3, S5L8940_FMI_BASE_3);
    sysbus_mmio_map(SYS_BUS_DEVICE(fmi), 4, S5L8940_FMI_BASE_4);
    sysbus_mmio_map(SYS_BUS_DEVICE(fmi), 5, S5L8940_FMI_BASE_5);
    sysbus_connect_irq(SYS_BUS_DEVICE(fmi), 0, qdev_get_gpio_in(s->aic, 0x21));
    sysbus_connect_irq(SYS_BUS_DEVICE(fmi), 1, qdev_get_gpio_in(s->aic, 0x22));

    DeviceState *sgx_control = qdev_new("n94-sgx-control");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(sgx_control), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(sgx_control), 0, 0x3f10b000);

    /* n94 DeviceTree dwi reg 0x0f700000 under arm-io. */
    DeviceState *dwi = qdev_new("n94-dwi");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dwi), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dwi), 0, 0x3f700000);

    /* Diagnostic only: n94 scaler0 registers, without image processing. */
    DeviceState *scaler = qdev_new("n94-scaler");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(scaler), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(scaler), 0, 0x38300000);

    /* The n94 DT exposes a second independent scaler at 0x38400000. */
    DeviceState *scaler1 = qdev_new("n94-scaler");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(scaler1), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(scaler1), 0, 0x38400000);

    DeviceState *mipi = qdev_new("n94-mipi");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(mipi), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(mipi), 0, 0x39500000);
    sysbus_mmio_map(SYS_BUS_DEVICE(mipi), 1, 0x3f110000);

    /* Both n94 DT DART resources; mapping behavior is not implemented. */
    DeviceState *dart_rt = qdev_new("n94-dart-diagnostic");
    DeviceState *dart_nrt = qdev_new("n94-dart-diagnostic");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dart_rt), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dart_rt), 0, 0x3a400000);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dart_nrt), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dart_nrt), 0, 0x38b00000);

    sysbus_realize_and_unref(SYS_BUS_DEVICE(s->gpio), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(s->gpio), 0, S5L8940_GPIO_BASE);
    sysbus_connect_irq(SYS_BUS_DEVICE(s->gpio), 0, qdev_get_gpio_in(s->aic, 0x77));

    DeviceState *i2s_switch = qdev_new("n94-i2s-switch");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(i2s_switch), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(i2s_switch), 0, 0x3fa01000);

    sysbus_realize_and_unref(SYS_BUS_DEVICE(s->pl310), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(s->pl310), 0, S5L8940_PL310_BASE);
    sysbus_mmio_map(SYS_BUS_DEVICE(s->pl310), 1, S5L8940_CIF_BASE);

    sysbus_realize_and_unref(SYS_BUS_DEVICE(s->cdma), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(s->cdma), 0, S5L8940_CDMA_BASE);
    sysbus_mmio_map(SYS_BUS_DEVICE(s->cdma), 1, S5L8940_CDMA_CRYPTO_BASE);
    for (unsigned i = 0; i < 44; i++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(s->cdma), i,
                           qdev_get_gpio_in(s->aic, 0x33 + i));
    }

    /* 5. Realize the boot console (UART0) and the separate UART1. */
    sysbus_realize_and_unref(SYS_BUS_DEVICE(s->uart0), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(s->uart0), 0, S5L8940_UART0_BASE);
    sysbus_connect_irq(SYS_BUS_DEVICE(s->uart0), 0, qdev_get_gpio_in(s->aic, 0x15));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(s->uart1), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(s->uart1), 0, S5L8940_UART1_DEBUG_BASE);
    /* DeviceTree specifies interrupt 0x16 for UART1 */
    sysbus_connect_irq(SYS_BUS_DEVICE(s->uart1), 0, qdev_get_gpio_in(s->aic, 0x16));

    /* 6. Realize and map Display (640x960 Retina) and subregions */
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

    /* 7. Map IO regions (0x3fb00000 and 0x3fc00000) */
    memory_region_init_ram(&s->io_mem_0, OBJECT(s), "s5l8940.io0", S5L8940_IO_SIZE_0, &error_fatal);
    memory_region_add_subregion(sysmem, S5L8940_IO_BASE_0, &s->io_mem_0);

    memory_region_init_ram(&s->io_mem_1, OBJECT(s), "s5l8940.io1", S5L8940_IO_SIZE_1, &error_fatal);
    memory_region_add_subregion(sysmem, S5L8940_IO_BASE_1, &s->io_mem_1);

    /* 8. S5L8940 IOP Storage Controller */
    sysbus_realize_and_unref(SYS_BUS_DEVICE(s->iop), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(s->iop), 0, S5L8940_IOP_BASE);
    sysbus_connect_irq(SYS_BUS_DEVICE(s->iop), 0, qdev_get_gpio_in(s->aic, 0x02));

    /* 9. S5L8940 SPI1 Multitouch Controller */
    sysbus_realize_and_unref(SYS_BUS_DEVICE(s->spi1), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(s->spi1), 0, S5L8940_SPI1_BASE);
    sysbus_connect_irq(SYS_BUS_DEVICE(s->spi1), 0, qdev_get_gpio_in(s->aic, 0x1d));
    sysbus_connect_irq(SYS_BUS_DEVICE(s->spi1), 1, qdev_get_gpio_in(s->gpio, 21));
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
