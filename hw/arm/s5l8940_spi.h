/*
 * Apple S5L8940 SPI Controller & Multitouch for iPhone 4S (n94)
 *
 * Copyright (c) 2026 Un1box / n94 Emulation Project
 *
 * Written strictly from scratch for Apple S5L8940 (iPhone4,1 / n94 / N94AP).
 * Matches DeviceTree /arm-io/spi1 (reg 0x02100000:0x1000, AIC IRQ 0x1d)
 * and child node multi-touch (GPIO IRQ 0x15).
 */

#ifndef HW_ARM_S5L8940_SPI_H
#define HW_ARM_S5L8940_SPI_H

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"

#define TYPE_S5L8940_SPI "s5l8940-spi"
OBJECT_DECLARE_SIMPLE_TYPE(S5L8940SPIState, S5L8940_SPI)

#define S5L8940_TOUCH_PHASE_DOWN 1
#define S5L8940_TOUCH_PHASE_MOVE 2
#define S5L8940_TOUCH_PHASE_UP   3

/* Inject normalized touch coordinates (0.0 .. 1.0) into the digitizer */
void s5l8940_spi_inject_touch(DeviceState *dev, float norm_x, float norm_y, int phase);

/* Trigger the standard iOS unlock gesture: swipe (0.20, 0.92) -> (0.85, 0.92) */
void s5l8940_spi_trigger_unlock(DeviceState *dev);

#endif /* HW_ARM_S5L8940_SPI_H */
