/*
 * Apple S5L8940 IOP (I/O Processor) Header for iPhone 4S (n94)
 *
 * Copyright (c) 2026 Un1box / n94 Emulation Project
 *
 * Written strictly from scratch for Apple S5L8940 (iPhone4,1 / n94 / N94AP).
 * Matches DeviceTree /arm-io/iop (reg 0x0f300000:0x1000, AIC IRQ 0x02).
 */

#ifndef HW_ARM_S5L8940_IOP_H
#define HW_ARM_S5L8940_IOP_H

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"

#define TYPE_S5L8940_IOP "s5l8940-iop"
OBJECT_DECLARE_SIMPLE_TYPE(S5L8940IOPState, S5L8940_IOP)

/* Trigger doorbell handling from AP or platform function */
void s5l8940_iop_ring_doorbell(DeviceState *dev);

#endif /* HW_ARM_S5L8940_IOP_H */
