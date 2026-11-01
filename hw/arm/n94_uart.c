/*
 * Apple S5L8940 UART Emulation for iPhone 4S (n94)
 *
 * Copyright (c) 2026 Un1box / n94 Emulation Project
 *
 * Written strictly from scratch for S5L8940 UART at 0x02600000 (UART1 Debug).
 * Matches "uart-1,samsung" DeviceTree node.
 */

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "hw/core/irq.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/qdev-properties-system.h"
#include "chardev/char-fe.h"
#include "qemu/log.h"

#define TYPE_N94_UART "n94-uart"
OBJECT_DECLARE_SIMPLE_TYPE(N94UARTState, N94_UART)

#define N94_UTRSTAT_TX_EMPTY        0x04
#define N94_UTRSTAT_TX_BUF_EMPTY    0x02
#define N94_UTRSTAT_RX_READY        0x01

#define N94_UART_WORDS (0x1000 / 4)

struct N94UARTState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    CharFrontend chr;
    qemu_irq irq;

    uint32_t ulcon;
    uint32_t ucon;
    uint32_t ufcon;
    uint32_t umcon;
    uint32_t ubrdiv;
    uint32_t ufracval;
    uint32_t uintm;

    uint32_t storage[N94_UART_WORDS];
};

static uint64_t n94_uart_read(void *opaque, hwaddr offset, unsigned size)
{
    N94UARTState *s = opaque;
    uint32_t val = 0;
    uint32_t word_idx = (offset / 4) % N94_UART_WORDS;

    switch (offset) {
    case 0x00: /* ULCON */
        val = s->ulcon;
        break;
    case 0x04: /* UCON */
        val = s->ucon;
        break;
    case 0x08: /* UFCON */
        val = s->ufcon;
        break;
    case 0x0c: /* UMCON */
        val = s->umcon;
        break;
    case 0x10: /* UTRSTAT - Always report TX buffer and shifter ready */
        val = N94_UTRSTAT_TX_EMPTY | N94_UTRSTAT_TX_BUF_EMPTY;
        break;
    case 0x14: /* UERSTAT */
        val = 0;
        break;
    case 0x18: /* UFSTAT */
        val = 0;
        break;
    case 0x1c: /* UMSTAT */
        val = 0x01; /* Clear to send */
        break;
    case 0x24: /* URXH (RX Buffer) */
        val = 0;
        break;
    case 0x28: /* UBRDIV */
        val = s->ubrdiv;
        break;
    case 0x2c: /* UFRACVAL */
        val = s->ufracval;
        break;
    case 0x38: /* UINTM */
        val = s->uintm;
        break;
    default:
        val = s->storage[word_idx];
        break;
    }

    return val;
}

static void n94_uart_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    N94UARTState *s = opaque;
    uint32_t word_idx = (offset / 4) % N94_UART_WORDS;
    s->storage[word_idx] = (uint32_t)value;

    switch (offset) {
    case 0x00:
        s->ulcon = (uint32_t)value;
        break;
    case 0x04:
        s->ucon = (uint32_t)value;
        break;
    case 0x08:
        s->ufcon = (uint32_t)value;
        break;
    case 0x0c:
        s->umcon = (uint32_t)value;
        break;
    case 0x20: { /* UTXH - Character transmission */
        unsigned char ch = (unsigned char)value;
        if (qemu_chr_fe_backend_connected(&s->chr)) {
            qemu_chr_fe_write_all(&s->chr, &ch, 1);
        } else {
            fputc(ch, stderr);
            fflush(stderr);
        }
        /* Pulse TX interrupt if TX interrupt is unmasked */
        if (!(s->uintm & 0x02)) {
            qemu_irq_pulse(s->irq);
        }
        break;
    }
    case 0x28:
        s->ubrdiv = (uint32_t)value;
        break;
    case 0x2c:
        s->ufracval = (uint32_t)value;
        break;
    case 0x38:
        s->uintm = (uint32_t)value;
        break;
    default:
        break;
    }
}

static const MemoryRegionOps n94_uart_ops = {
    .read = n94_uart_read,
    .write = n94_uart_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static void n94_uart_init(Object *obj)
{
    N94UARTState *s = N94_UART(obj);
    SysBusDevice *dev = SYS_BUS_DEVICE(obj);

    memory_region_init_io(&s->iomem, obj, &n94_uart_ops, s, "n94-uart", 0x1000);
    sysbus_init_mmio(dev, &s->iomem);
    sysbus_init_irq(dev, &s->irq);
}

static const Property n94_uart_properties[] = {
    DEFINE_PROP_CHR("chardev", N94UARTState, chr),
};

static void n94_uart_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    device_class_set_props(dc, n94_uart_properties);
}

static const TypeInfo n94_uart_info = {
    .name          = TYPE_N94_UART,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(N94UARTState),
    .instance_init = n94_uart_init,
    .class_init    = n94_uart_class_init,
};

static void n94_uart_register_types(void)
{
    type_register_static(&n94_uart_info);
}

type_init(n94_uart_register_types)
