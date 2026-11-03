/* n94 USB complex control register, diagnostic subset from stock 13G37.
 * TODO(n94): implement PHY, power transitions, USB host/device and IRQs.
 * Offset zero is read-modify-written by the bundled driver at 0x80d2747a.
 * Bit meanings and reset value are unverified; zero is a diagnostic default.
 */
#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "qemu/log.h"

#define TYPE_N94_USB_CONTROL "n94-usb-control"
OBJECT_DECLARE_SIMPLE_TYPE(N94USBControl, N94_USB_CONTROL)
struct N94USBControl {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t control;
};

static uint64_t usb_read(void *opaque, hwaddr offset, unsigned size)
{
    N94USBControl *s = opaque;
    if (offset == 0) {
        return s->control;
    }
    qemu_log_mask(LOG_UNIMP, "n94 USB control unimplemented read +0x%" HWADDR_PRIx "\n", offset);
    return 0;
}

static void usb_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    N94USBControl *s = opaque;
    if (offset == 0) {
        s->control = value;
        qemu_log_mask(LOG_UNIMP, "n94 USB control diagnostic write 0x%08x\n", s->control);
        return;
    }
    qemu_log_mask(LOG_UNIMP, "n94 USB control unimplemented write +0x%" HWADDR_PRIx "\n", offset);
}

static const MemoryRegionOps usb_ops = {
    .read = usb_read, .write = usb_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, .unaligned = false },
};

static void usb_reset(DeviceState *dev)
{
    N94_USB_CONTROL(dev)->control = 0;
}

static void usb_init(Object *obj)
{
    N94USBControl *s = N94_USB_CONTROL(obj);
    memory_region_init_io(&s->iomem, obj, &usb_ops, s, "n94-usb-control", 0x1000);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->iomem);
}

static void usb_class_init(ObjectClass *klass, const void *data)
{
    device_class_set_legacy_reset(DEVICE_CLASS(klass), usb_reset);
}
static const TypeInfo usb_info = {
    .name = TYPE_N94_USB_CONTROL, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(N94USBControl), .instance_init = usb_init,
    .class_init = usb_class_init,
};
static void usb_register(void) { type_register_static(&usb_info); }
type_init(usb_register)
