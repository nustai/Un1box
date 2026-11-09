/*
 * Apple S5L8940 SoC (Apple A5) Header for iPhone 4S (n94)
 *
 * Copyright (c) 2026 Un1box / n94 Emulation Project
 *
 * Written strictly from scratch for Apple S5L8940 (iPhone4,1 / n94 / N94AP).
 * Verified against DeviceTree.n94ap.RELEASE from iOS 9.3.6 (13G37).
 */

#ifndef HW_ARM_S5L8940_SOC_H
#define HW_ARM_S5L8940_SOC_H

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "hw/core/irq.h"
#include "target/arm/cpu.h"
#include "hw/arm/boot.h"

#define TYPE_S5L8940_SOC "s5l8940-soc"
OBJECT_DECLARE_SIMPLE_TYPE(S5L8940State, S5L8940_SOC)

/* Apple DT /arm-io/ranges = { child: 0, parent: 0x30000000, size: 0x10000000 }.
 * Peripheral reg entries are bus-relative; map them into root physical memory.
 * The arm-io node's own reg (0x3fb00000, 0x3fc00000) is already root-relative.
 * TODO(n94): register semantics still require hardware/guest-driver verification.
 */
#define S5L8940_ARM_IO_BASE        0x30000000U
#define S5L8940_IO_BASE_0          0x3fb00000
#define S5L8940_IO_SIZE_0          0x1000
#define S5L8940_IO_BASE_1          0x3fc00000
#define S5L8940_IO_SIZE_1          0x1000

#define S5L8940_AIC_BASE           (S5L8940_ARM_IO_BASE + 0x0f200000U)
#define S5L8940_AIC_SIZE           0x10000

#define S5L8940_GPIO_BASE          (S5L8940_ARM_IO_BASE + 0x0fa00000U)
#define S5L8940_GPIO_SIZE          0x1000

#define S5L8940_PL310_BASE         (S5L8940_ARM_IO_BASE + 0x0e000000U)
#define S5L8940_CIF_BASE           (S5L8940_ARM_IO_BASE + 0x0fd00000U)
#define S5L8940_CDMA_BASE          (S5L8940_ARM_IO_BASE + 0x07000000U)
#define S5L8940_CDMA_CRYPTO_BASE   (S5L8940_ARM_IO_BASE + 0x07800000U)

#define S5L8940_PMGR_BASE          (S5L8940_ARM_IO_BASE + 0x0f100000U)
#define S5L8940_PMGR_SIZE          0x7000
#define S5L8940_WDT_BASE           (S5L8940_ARM_IO_BASE + 0x0f103020U)
#define S5L8940_WDT_SIZE           0x10

#define S5L8940_UART0_BASE         (S5L8940_ARM_IO_BASE + 0x02500000U)
#define S5L8940_UART1_DEBUG_BASE   (S5L8940_ARM_IO_BASE + 0x02600000U)
#define S5L8940_UART3_BT_BASE      (S5L8940_ARM_IO_BASE + 0x02800000U)
#define S5L8940_UART5_GG_BASE      (S5L8940_ARM_IO_BASE + 0x02a00000U)
#define S5L8940_UART_SIZE          0x1000

#define S5L8940_CLCD_BASE          (S5L8940_ARM_IO_BASE + 0x0a100000U)
#define S5L8940_CLCD_SIZE          0x7000
#define S5L8940_CLCD_SUB_BASE_1    (S5L8940_ARM_IO_BASE + 0x09200000U)
#define S5L8940_CLCD_SUB_SIZE_1    0x2000
#define S5L8940_CLCD_SUB_BASE_2    (S5L8940_ARM_IO_BASE + 0x09300000U)
#define S5L8940_CLCD_SUB_SIZE_2    0x1000

#define S5L8940_MIPI_DSIM_BASE     (S5L8940_ARM_IO_BASE + 0x09500000U)
#define S5L8940_MIPI_DSIM_SIZE     0x1000

#define S5L8940_SGX_BASE           (S5L8940_ARM_IO_BASE + 0x05100000U)
#define S5L8940_SGX_SIZE           0x18000
#define S5L8940_SGX_MMU_BASE       (S5L8940_ARM_IO_BASE + 0x0f10b000U)
#define S5L8940_SGX_MMU_SIZE       0x1000

#define S5L8940_FMI_BASE_0         (S5L8940_ARM_IO_BASE + 0x01200000U)
#define S5L8940_FMI_BASE_1         (S5L8940_ARM_IO_BASE + 0x01240000U)
#define S5L8940_FMI_BASE_2         (S5L8940_ARM_IO_BASE + 0x01280000U)
#define S5L8940_FMI_BASE_3         (S5L8940_ARM_IO_BASE + 0x01300000U)
#define S5L8940_FMI_BASE_4         (S5L8940_ARM_IO_BASE + 0x01340000U)
#define S5L8940_FMI_BASE_5         (S5L8940_ARM_IO_BASE + 0x01380000U)
#define S5L8940_FMI_BANK_SIZE      0x1000

#define S5L8940_OTGPHYCTRL_BASE    (S5L8940_ARM_IO_BASE + 0x06000000U)
#define S5L8940_OTGPHYCTRL_SIZE    0x1000

#define S5L8940_USB_COMPLEX_BASE   (S5L8940_ARM_IO_BASE + 0x0f108000U)
#define S5L8940_USB_COMPLEX_SIZE   0x1000

#define S5L8940_USB_DEV_BASE       (S5L8940_ARM_IO_BASE + 0x06100000U)
#define S5L8940_USB_DEV_SIZE       0x10000

#define S5L8940_USB_EHCI_BASE0     (S5L8940_ARM_IO_BASE + 0x06400000U)
#define S5L8940_USB_EHCI_BASE1     (S5L8940_ARM_IO_BASE + 0x06700000U)

#define S5L8940_USB_OHCI0_BASE     (S5L8940_ARM_IO_BASE + 0x06500000U)
#define S5L8940_USB_OHCI1_BASE     (S5L8940_ARM_IO_BASE + 0x06600000U)

#define S5L8940_RAM_BASE           0x80000000
#define S5L8940_RAM_SIZE           (512 * 1024 * 1024) /* 512 MB LPDDR2 */

#define S5L8940_IOP_BASE           (S5L8940_ARM_IO_BASE + 0x0f300000U)
#define S5L8940_IOP_SIZE           0x1000

#define S5L8940_SPI1_BASE          (S5L8940_ARM_IO_BASE + 0x02100000U)
#define S5L8940_SPI1_SIZE          0x1000

/* Screen geometry: iPhone 4S strictly 640x960 Retina (326 ppi) */
#define N94_SCREEN_WIDTH           640
#define N94_SCREEN_HEIGHT          960
#define N94_SCREEN_BPP             32

struct S5L8940State {
    SysBusDevice parent_obj;

    MemoryRegion sram;
    MemoryRegion io_mem_0;
    MemoryRegion io_mem_1;

    /* Cores */
    ARMCPU cpu[2]; /* Dual-core Cortex-A9 MPCore structs embedded directly */
    qemu_irq cpu_irq[2];
    qemu_irq cpu_fiq[2];

    /* Submodules */
    DeviceState *aic;
    DeviceState *pmgr;
    DeviceState *gpio; /* Partial n94 port bank; interrupt groups TODO. */
    DeviceState *pl310; /* Coherent maintenance; diagnostic geometry and CIF. */
    DeviceState *cdma; /* Plain scatter/gather subset, AES TODO. */
    DeviceState *uart0; /* DeviceTree boot-console */
    DeviceState *uart1; /* Debug console */
    DeviceState *clcd;  /* Display controller */
    DeviceState *iop;   /* S5L8940 IOP storage controller */
    DeviceState *spi1;  /* Multitouch SPI controller */

    /* Boot arguments and DTB buffer */
    uint32_t ram_size;
    uint32_t bootargs_pa;
    void *devicetree_blob;
    size_t devicetree_size;
};

/* Display the validated bootloader-provided framebuffer until guest takeover. */
void n94_display_set_boot_framebuffer(DeviceState *dev, uint32_t address);

#endif /* HW_ARM_S5L8940_SOC_H */
