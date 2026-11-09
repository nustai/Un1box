/*
 * Apple S5L8940 USB Controllers and PHY for iPhone 4S (n94)
 *
 * Copyright (c) 2026 Un1box / n94 Emulation Project
 *
 * Written strictly from scratch for Apple S5L8940 (iPhone4,1 / n94 / N94AP).
 * Diagnostic register subsets matching DeviceTree nodes:
 *   /arm-io/otgphyctrl
 *   /arm-io/usb-complex
 *   /arm-io/usb-complex/usb-device
 *   /arm-io/usb-complex/usb-ehci
 *   /arm-io/usb-complex/usb-ohci0
 *   /arm-io/usb-complex/usb-ohci1
 *
 * TODO(n94): implement USB packet processing, endpoint state machines, and host transfers.
 * Register retention supports driver initialization, clock gating, and power management.
 */

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "qemu/log.h"

/* -----------------------------------------------------------------------
 * USB Complex Control (0x3f108000, size 0x1000)
 * ----------------------------------------------------------------------- */
#define TYPE_N94_USB_CONTROL "n94-usb-control"
OBJECT_DECLARE_SIMPLE_TYPE(N94USBControl, N94_USB_CONTROL)

struct N94USBControl {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t regs[0x1000 / 4];
};

static uint64_t usb_control_read(void *opaque, hwaddr offset, unsigned size)
{
    N94USBControl *s = opaque;
    unsigned idx = offset / 4;
    if (idx < (0x1000 / 4)) {
        return s->regs[idx];
    }
    qemu_log_mask(LOG_GUEST_ERROR, "n94-usb-control: out-of-bounds read +0x%" HWADDR_PRIx "\n", offset);
    return 0;
}

static void usb_control_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    N94USBControl *s = opaque;
    unsigned idx = offset / 4;
    if (idx < (0x1000 / 4)) {
        s->regs[idx] = (uint32_t)value;
        return;
    }
    qemu_log_mask(LOG_GUEST_ERROR, "n94-usb-control: out-of-bounds write +0x%" HWADDR_PRIx "\n", offset);
}

static const MemoryRegionOps usb_control_ops = {
    .read = usb_control_read,
    .write = usb_control_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4, .unaligned = false },
};

static void usb_control_reset(DeviceState *dev)
{
    N94USBControl *s = N94_USB_CONTROL(dev);
    memset(s->regs, 0, sizeof(s->regs));
}

static void usb_control_init(Object *obj)
{
    N94USBControl *s = N94_USB_CONTROL(obj);
    memory_region_init_io(&s->iomem, obj, &usb_control_ops, s, "n94-usb-control", 0x1000);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->iomem);
}

static void usb_control_class_init(ObjectClass *klass, const void *data)
{
    device_class_set_legacy_reset(DEVICE_CLASS(klass), usb_control_reset);
}

static const TypeInfo usb_control_info = {
    .name          = TYPE_N94_USB_CONTROL,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(N94USBControl),
    .instance_init = usb_control_init,
    .class_init    = usb_control_class_init,
};

/* -----------------------------------------------------------------------
 * OTG PHY Control (0x36000000, size 0x1000)
 * ----------------------------------------------------------------------- */
#define TYPE_N94_OTGPHYCTRL "n94-otgphyctrl"
OBJECT_DECLARE_SIMPLE_TYPE(N94OTGPHYCtrl, N94_OTGPHYCTRL)

struct N94OTGPHYCtrl {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t regs[0x1000 / 4];
};

static uint64_t otgphy_read(void *opaque, hwaddr offset, unsigned size)
{
    N94OTGPHYCtrl *s = opaque;
    unsigned idx = offset / 4;
    if (idx < (0x1000 / 4)) {
        return s->regs[idx];
    }
    qemu_log_mask(LOG_GUEST_ERROR, "n94-otgphyctrl: out-of-bounds read +0x%" HWADDR_PRIx "\n", offset);
    return 0;
}

static void otgphy_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    N94OTGPHYCtrl *s = opaque;
    unsigned idx = offset / 4;
    if (idx < (0x1000 / 4)) {
        s->regs[idx] = (uint32_t)value;
        return;
    }
    qemu_log_mask(LOG_GUEST_ERROR, "n94-otgphyctrl: out-of-bounds write +0x%" HWADDR_PRIx "\n", offset);
}

static const MemoryRegionOps otgphy_ops = {
    .read = otgphy_read,
    .write = otgphy_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4, .unaligned = false },
};

static void otgphy_reset(DeviceState *dev)
{
    N94OTGPHYCtrl *s = N94_OTGPHYCTRL(dev);
    memset(s->regs, 0, sizeof(s->regs));
    /* Status default: PHY PLL locked and ready */
    s->regs[0] = 0x00000001;
}

static void otgphy_init(Object *obj)
{
    N94OTGPHYCtrl *s = N94_OTGPHYCTRL(obj);
    memory_region_init_io(&s->iomem, obj, &otgphy_ops, s, "n94-otgphyctrl", 0x1000);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->iomem);
}

static void otgphy_class_init(ObjectClass *klass, const void *data)
{
    device_class_set_legacy_reset(DEVICE_CLASS(klass), otgphy_reset);
}

static const TypeInfo otgphy_info = {
    .name          = TYPE_N94_OTGPHYCTRL,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(N94OTGPHYCtrl),
    .instance_init = otgphy_init,
    .class_init    = otgphy_class_init,
};

/* -----------------------------------------------------------------------
 * USB Device Controller (0x36100000, size 0x10000, IRQ 0xb)
 * ----------------------------------------------------------------------- */
#define TYPE_N94_USB_DEVICE "n94-usb-device"
OBJECT_DECLARE_SIMPLE_TYPE(N94USBDeviceState, N94_USB_DEVICE)

struct N94USBDeviceState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    qemu_irq irq;
    uint32_t regs[0x10000 / 4];
};

static uint64_t usb_dev_read(void *opaque, hwaddr offset, unsigned size)
{
    N94USBDeviceState *s = opaque;
    unsigned idx = offset / 4;
    if (idx < (0x10000 / 4)) {
        return s->regs[idx];
    }
    qemu_log_mask(LOG_GUEST_ERROR, "n94-usb-device: out-of-bounds read +0x%" HWADDR_PRIx "\n", offset);
    return 0;
}

static void usb_dev_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    N94USBDeviceState *s = opaque;
    unsigned idx = offset / 4;
    if (idx < (0x10000 / 4)) {
        s->regs[idx] = (uint32_t)value;
        return;
    }
    qemu_log_mask(LOG_GUEST_ERROR, "n94-usb-device: out-of-bounds write +0x%" HWADDR_PRIx "\n", offset);
}

static const MemoryRegionOps usb_dev_ops = {
    .read = usb_dev_read,
    .write = usb_dev_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4, .unaligned = false },
};

static void usb_dev_reset(DeviceState *dev)
{
    N94USBDeviceState *s = N94_USB_DEVICE(dev);
    memset(s->regs, 0, sizeof(s->regs));
}

static void usb_dev_init(Object *obj)
{
    N94USBDeviceState *s = N94_USB_DEVICE(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);
    memory_region_init_io(&s->iomem, obj, &usb_dev_ops, s, "n94-usb-device", 0x10000);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
}

static void usb_dev_class_init(ObjectClass *klass, const void *data)
{
    device_class_set_legacy_reset(DEVICE_CLASS(klass), usb_dev_reset);
}

static const TypeInfo usb_dev_info = {
    .name          = TYPE_N94_USB_DEVICE,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(N94USBDeviceState),
    .instance_init = usb_dev_init,
    .class_init    = usb_dev_class_init,
};

/* -----------------------------------------------------------------------
 * USB Host (EHCI / OHCI) Diagnostic Storage
 * ----------------------------------------------------------------------- */
#define TYPE_N94_USB_HOST "n94-usb-host"
OBJECT_DECLARE_SIMPLE_TYPE(N94USBHostState, N94_USB_HOST)

struct N94USBHostState {
    SysBusDevice parent_obj;
    MemoryRegion iomem[2];
    qemu_irq irq;
    uint32_t regs[2][0x10000 / 4];
};

static uint64_t usb_host_read(void *opaque, hwaddr offset, unsigned size)
{
    uint32_t *regs = opaque;
    unsigned idx = offset / 4;
    if (idx < (0x10000 / 4)) {
        return regs[idx];
    }
    return 0;
}

static void usb_host_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    uint32_t *regs = opaque;
    unsigned idx = offset / 4;
    if (idx < (0x10000 / 4)) {
        regs[idx] = (uint32_t)value;
    }
}

static const MemoryRegionOps usb_host_ops = {
    .read = usb_host_read,
    .write = usb_host_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4, .unaligned = false },
};

static void usb_host_reset(DeviceState *dev)
{
    N94USBHostState *s = N94_USB_HOST(dev);
    memset(s->regs, 0, sizeof(s->regs));
    /* EHCI capability register defaults: CAPLENGTH = 0x20, HCIVERSION = 0x0100 */
    s->regs[0][0] = 0x01000020;
}

static void usb_host_init(Object *obj)
{
    N94USBHostState *s = N94_USB_HOST(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    memory_region_init_io(&s->iomem[0], obj, &usb_host_ops, s->regs[0], "n94-usb-host.0", 0x10000);
    sysbus_init_mmio(sbd, &s->iomem[0]);

    memory_region_init_io(&s->iomem[1], obj, &usb_host_ops, s->regs[1], "n94-usb-host.1", 0x10000);
    sysbus_init_mmio(sbd, &s->iomem[1]);

    sysbus_init_irq(sbd, &s->irq);
}

static void usb_host_class_init(ObjectClass *klass, const void *data)
{
    device_class_set_legacy_reset(DEVICE_CLASS(klass), usb_host_reset);
}

static const TypeInfo usb_host_info = {
    .name          = TYPE_N94_USB_HOST,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(N94USBHostState),
    .instance_init = usb_host_init,
    .class_init    = usb_host_class_init,
};

static void n94_usb_register_types(void)
{
    type_register_static(&usb_control_info);
    type_register_static(&otgphy_info);
    type_register_static(&usb_dev_info);
    type_register_static(&usb_host_info);
}

type_init(n94_usb_register_types)
