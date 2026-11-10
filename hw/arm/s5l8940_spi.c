/*
 * Apple S5L8940 SPI Controller & Multitouch Emulation for iPhone 4S (n94)
 *
 * Copyright (c) 2026 Un1box / n94 Emulation Project
 *
 * Written strictly from scratch for Apple S5L8940 (iPhone4,1 / n94 / N94AP).
 * Matches DeviceTree /arm-io/spi1 (reg 0x02100000:0x1000, AIC IRQ 0x1d)
 * and child node multi-touch (GPIO IRQ 0x15).
 */

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "hw/core/irq.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "hw/arm/s5l8940_spi.h"

#define S5L8940_SPI_REG_SIZE     0x1000
#define S5L8940_SPI_REG_WORDS    (S5L8940_SPI_REG_SIZE / 4)

/* SPI Controller Register Offsets */
#define SPI_REG_CTRL             0x00
#define SPI_REG_SETUP            0x04
#define SPI_REG_STATUS           0x08
#define SPI_REG_PIN              0x0C
#define SPI_REG_TX_DATA          0x10
#define SPI_REG_RX_DATA          0x20
#define SPI_REG_CLK_DIV          0x24

/* Status bits */
#define SPI_STATUS_TX_EMPTY      (1U << 0)
#define SPI_STATUS_TX_READY      (1U << 1)
#define SPI_STATUS_RX_READY      (1U << 2)
#define SPI_STATUS_COMPLETE      (1U << 3)

/* Touch Frame (Apple Z2 Multitouch Protocol) */
#define MT_CMD_READ_FRAME        0xEB
#define MT_CMD_GET_VERSION       0xD0
#define MT_CMD_READ_REPORT       0x82

#define MT_MAX_RX_FIFO           1024

struct S5L8940SPIState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    qemu_irq irq;         /* AIC IRQ 0x1d (Line 0) */
    qemu_irq touch_irq;   /* GPIO IRQ 0x15 (Line 1) */

    uint32_t regs[S5L8940_SPI_REG_WORDS];

    /* RX FIFO */
    uint8_t rx_fifo[MT_MAX_RX_FIFO];
    uint32_t rx_head;
    uint32_t rx_tail;
    uint32_t rx_count;

    /* Current command state */
    uint8_t cur_cmd;
    uint8_t frame_seq;

    /* Automated unlock gesture */
    QEMUTimer *unlock_timer;
    int unlock_step;
};

static void s5l8940_spi_rx_push(S5L8940SPIState *s, uint8_t byte)
{
    if (s->rx_count < MT_MAX_RX_FIFO) {
        s->rx_fifo[s->rx_head] = byte;
        s->rx_head = (s->rx_head + 1) % MT_MAX_RX_FIFO;
        s->rx_count++;
    }
}

static uint8_t s5l8940_spi_rx_pop(S5L8940SPIState *s)
{
    if (s->rx_count == 0) {
        return 0xFF;
    }
    uint8_t val = s->rx_fifo[s->rx_tail];
    s->rx_tail = (s->rx_tail + 1) % MT_MAX_RX_FIFO;
    s->rx_count--;
    return val;
}

static void s5l8940_spi_rx_clear(S5L8940SPIState *s)
{
    s->rx_head = 0;
    s->rx_tail = 0;
    s->rx_count = 0;
}

static void s5l8940_spi_update_irq(S5L8940SPIState *s)
{
    uint32_t status = SPI_STATUS_TX_EMPTY | SPI_STATUS_TX_READY | SPI_STATUS_COMPLETE;
    if (s->rx_count > 0) {
        status |= SPI_STATUS_RX_READY;
    }
    s->regs[SPI_REG_STATUS / 4] = status;

    /* Pulse AIC IRQ when transfer completes or data is ready */
    qemu_irq_pulse(s->irq);
}

void s5l8940_spi_inject_touch(DeviceState *dev, float norm_x, float norm_y, int phase)
{
    S5L8940SPIState *s = S5L8940_SPI(dev);

    /* Clamp coordinates */
    if (norm_x < 0.0f) norm_x = 0.0f;
    if (norm_x > 1.0f) norm_x = 1.0f;
    if (norm_y < 0.0f) norm_y = 0.0f;
    if (norm_y > 1.0f) norm_y = 1.0f;

    int16_t x = (int16_t)(norm_x * 640.0f);
    int16_t y = (int16_t)(norm_y * 960.0f);

    /* Construct Apple Z2 frame:
     * [0..1] Length = 47 bytes (0x002F)
     * [2] Marker = 0xAA
     * [3..26] Header (24 bytes)
     * [27..44] Contact 0 (18 bytes)
     * [45..46] Checksum (16-bit sum)
     */
    uint8_t frame[47];
    memset(frame, 0, sizeof(frame));

    frame[0] = 0x2F; /* Length low */
    frame[1] = 0x00; /* Length high */
    frame[2] = 0xAA; /* Sync/status */

    /* Header */
    frame[3] = 0x02; /* Type */
    frame[4] = ++s->frame_seq;
    frame[5] = 24;   /* Header len */
    uint32_t ts = (uint32_t)(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / 1000000);
    stl_le_p(&frame[7], ts);

    if (phase != S5L8940_TOUCH_PHASE_UP) {
        frame[15] = 1;  /* numFingers = 1 */
        frame[16] = 18; /* fingerDataLen = 18 */

        /* Finger 0 */
        frame[27] = 1;     /* Finger ID */
        frame[28] = phase; /* Event: 1=down, 2=move, 3=up */
        stw_le_p(&frame[31], x);
        stw_le_p(&frame[33], y);
        stw_le_p(&frame[35], 0); /* velX */
        stw_le_p(&frame[37], 0); /* velY */
        stw_le_p(&frame[39], 10); /* radius */
        stw_le_p(&frame[41], 10);
        stw_le_p(&frame[43], 100); /* pressure */
    } else {
        frame[15] = 0; /* numFingers = 0 for touch up release */
        frame[16] = 0;
    }

    /* Compute 16-bit checksum of payload */
    uint16_t sum = 0;
    for (size_t i = 2; i < 45; i++) {
        sum += frame[i];
    }
    stw_be_p(&frame[45], sum);

    /* Push into RX FIFO */
    s5l8940_spi_rx_clear(s);
    for (size_t i = 0; i < sizeof(frame); i++) {
        s5l8940_spi_rx_push(s, frame[i]);
    }

    /* Assert GPIO IRQ line 1 (GPIO 21) to notify AppleMultitouchSPI */
    qemu_irq_pulse(s->touch_irq);
    s5l8940_spi_update_irq(s);
}

static void s5l8940_spi_unlock_timer_cb(void *opaque)
{
    S5L8940SPIState *s = opaque;
    s->unlock_step++;

    if (s->unlock_step <= 15) {
        /* Move gesture across 15 steps from 0.20 to 0.85 horizontally at y=0.92 */
        float x = 0.20f + 0.65f * ((float)s->unlock_step / 15.0f);
        int phase = (s->unlock_step == 1) ? S5L8940_TOUCH_PHASE_DOWN : S5L8940_TOUCH_PHASE_MOVE;
        s5l8940_spi_inject_touch(DEVICE(s), x, 0.92f, phase);

        /* Schedule next step in 40 ms */
        timer_mod(s->unlock_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 40);
    } else if (s->unlock_step == 16) {
        /* Release (ACTION_UP) at final destination */
        s5l8940_spi_inject_touch(DEVICE(s), 0.85f, 0.92f, S5L8940_TOUCH_PHASE_UP);
        /* Periodic retrigger every 3 seconds to guarantee SpringBoard unlock once active */
        s->unlock_step = 0;
        timer_mod(s->unlock_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 3000);
    }
}

void s5l8940_spi_trigger_unlock(DeviceState *dev)
{
    S5L8940SPIState *s = S5L8940_SPI(dev);
    s->unlock_step = 0;
    timer_mod(s->unlock_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 10);
}

static uint64_t s5l8940_spi_read(void *opaque, hwaddr offset, unsigned size)
{
    S5L8940SPIState *s = opaque;
    uint32_t idx = offset / 4;

    switch (offset) {
    case SPI_REG_STATUS:
        return s->regs[idx] | SPI_STATUS_TX_EMPTY | SPI_STATUS_TX_READY | SPI_STATUS_COMPLETE;
    case SPI_REG_RX_DATA: {
        uint32_t byte = s5l8940_spi_rx_pop(s);
        if (s->rx_count == 0) {
            s->regs[SPI_REG_STATUS / 4] &= ~SPI_STATUS_RX_READY;
        }
        return byte;
    }
    default:
        if (idx < S5L8940_SPI_REG_WORDS) {
            return s->regs[idx];
        }
        return 0;
    }
}

static void s5l8940_spi_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    S5L8940SPIState *s = opaque;
    uint32_t idx = offset / 4;
    if (idx < S5L8940_SPI_REG_WORDS) {
        s->regs[idx] = (uint32_t)value;
    }

    switch (offset) {
    case SPI_REG_CTRL:
        if (value & 0x02) { /* RX FIFO reset */
            s5l8940_spi_rx_clear(s);
        }
        break;
    case SPI_REG_TX_DATA: {
        uint8_t cmd = (uint8_t)value;
        s->cur_cmd = cmd;
        if (cmd == MT_CMD_GET_VERSION) {
            /* Reply with Apple Z2 controller version */
            s5l8940_spi_rx_clear(s);
            s5l8940_spi_rx_push(s, 0xAA);
            s5l8940_spi_rx_push(s, 0x10);
            s5l8940_spi_rx_push(s, 0x00);
            s5l8940_spi_rx_push(s, 0x47);
            s5l8940_spi_update_irq(s);

            /* Arm automated unlock timer to fire swipe gesture once SpringBoard UI is up */
            if (s->unlock_step == 0) {
                timer_mod(s->unlock_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 4000);
            }
        } else if (cmd == MT_CMD_READ_FRAME && s->rx_count == 0) {
            /* Return empty frame if no touch pending */
            s5l8940_spi_rx_push(s, 0xAA);
            s5l8940_spi_rx_push(s, 0x00);
            s5l8940_spi_rx_push(s, 0x02);
            s5l8940_spi_rx_push(s, 0x00);
            s5l8940_spi_rx_push(s, 0x02);
            s5l8940_spi_update_irq(s);
        }
        break;
    }
    default:
        break;
    }
}

static const MemoryRegionOps s5l8940_spi_ops = {
    .read = s5l8940_spi_read,
    .write = s5l8940_spi_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
        .unaligned = false,
    },
};

static void s5l8940_spi_reset(DeviceState *dev)
{
    S5L8940SPIState *s = S5L8940_SPI(dev);
    memset(s->regs, 0, sizeof(s->regs));
    s->regs[SPI_REG_STATUS / 4] = SPI_STATUS_TX_EMPTY | SPI_STATUS_TX_READY | SPI_STATUS_COMPLETE;
    s5l8940_spi_rx_clear(s);
    s->cur_cmd = 0;
    s->frame_seq = 0;
    s->unlock_step = 0;

    if (s->unlock_timer) {
        timer_del(s->unlock_timer);
    }
}

static void s5l8940_spi_init(Object *obj)
{
    S5L8940SPIState *s = S5L8940_SPI(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    memory_region_init_io(&s->iomem, obj, &s5l8940_spi_ops, s,
                          "s5l8940-spi", S5L8940_SPI_REG_SIZE);
    sysbus_init_mmio(sbd, &s->iomem);

    /* Output 0: AIC IRQ 0x1d (Line 0) */
    sysbus_init_irq(sbd, &s->irq);
    /* Output 1: GPIO Touch IRQ 0x15 (Line 1) */
    sysbus_init_irq(sbd, &s->touch_irq);

    s->unlock_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, s5l8940_spi_unlock_timer_cb, s);
}

static void s5l8940_spi_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    device_class_set_legacy_reset(dc, s5l8940_spi_reset);
}

static const TypeInfo s5l8940_spi_info = {
    .name          = TYPE_S5L8940_SPI,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(S5L8940SPIState),
    .instance_init = s5l8940_spi_init,
    .class_init    = s5l8940_spi_class_init,
};

static void s5l8940_spi_register_types(void)
{
    type_register_static(&s5l8940_spi_info);
}

type_init(s5l8940_spi_register_types)
