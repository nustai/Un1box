#ifndef HW_ARM_S5L8940_PERIPHERALS_H
#define HW_ARM_S5L8940_PERIPHERALS_H

#include "hw/core/qdev.h"

#define TYPE_S5L8940_I2C "s5l8940.i2c"
#define TYPE_S5L8940_D1881 "s5l8940.d1881"
bool s5l8940_d1881_guest_shutdown_confirmed(void);

#endif
