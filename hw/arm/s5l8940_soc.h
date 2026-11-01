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

/* S5L8940 MMIO Memory Map (strictly verified from DeviceTree.n94ap) */
#define S5L8940_IO_BASE_0          0x3fb00000
#define S5L8940_IO_SIZE_0          0x1000
#define S5L8940_IO_BASE_1          0x3fc00000
#define S5L8940_IO_SIZE_1          0x1000

#define S5L8940_AIC_BASE           0x0f200000
#define S5L8940_AIC_SIZE           0x10000

#define S5L8940_GPIO_BASE          0x0fa00000
#define S5L8940_GPIO_SIZE          0x1000

#define S5L8940_PMGR_BASE          0x0f100000
#define S5L8940_PMGR_SIZE          0x7000
#define S5L8940_WDT_BASE           0x0f103020
#define S5L8940_WDT_SIZE           0x10

#define S5L8940_UART0_BASE         0x02500000
#define S5L8940_UART1_DEBUG_BASE   0x02600000
#define S5L8940_UART3_BT_BASE      0x02800000
#define S5L8940_UART5_GG_BASE      0x02a00000
#define S5L8940_UART_SIZE          0x1000

#define S5L8940_CLCD_BASE          0x0a100000
#define S5L8940_CLCD_SIZE          0x7000
#define S5L8940_CLCD_SUB_BASE_1    0x09200000
#define S5L8940_CLCD_SUB_SIZE_1    0x2000
#define S5L8940_CLCD_SUB_BASE_2    0x09300000
#define S5L8940_CLCD_SUB_SIZE_2    0x1000

#define S5L8940_MIPI_DSIM_BASE     0x09500000
#define S5L8940_MIPI_DSIM_SIZE     0x1000

#define S5L8940_SGX_BASE           0x05100000
#define S5L8940_SGX_SIZE           0x18000
#define S5L8940_SGX_MMU_BASE       0x0f10b000
#define S5L8940_SGX_MMU_SIZE       0x1000

#define S5L8940_FMI_BASE           0x01200000
#define S5L8940_FMI_SIZE           0x1000

#define S5L8940_USB_COMPLEX_BASE   0x0f108000
#define S5L8940_USB_COMPLEX_SIZE   0x1000

#define S5L8940_RAM_BASE           0x80000000
#define S5L8940_RAM_SIZE           (512 * 1024 * 1024) /* 512 MB LPDDR2 */

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
    DeviceState *uart1; /* Debug console */
    DeviceState *clcd;  /* Display controller */

    /* Boot arguments and DTB buffer */
    uint32_t ram_size;
    void *devicetree_blob;
    size_t devicetree_size;
};

#endif /* HW_ARM_S5L8940_SOC_H */
