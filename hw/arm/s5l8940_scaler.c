/* n94 SCALER diagnostic register subset, from the 13G37 driver startup.
 * TODO(n94): implement SCALER transactions, pixel processing and interrupt 0x09.
 * Retaining startup configuration does not emulate a working display scaler. */
#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "qemu/log.h"

#define TYPE_N94_SCALER "n94-scaler"
OBJECT_DECLARE_SIMPLE_TYPE(N94SCALER, N94_SCALER)
struct N94SCALER {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t regs[0x1000 / 4];
};
static uint64_t scaler_read(void *opaque, hwaddr offset, unsigned size)
{
    N94SCALER *s = opaque;
    qemu_log_mask(LOG_UNIMP, "n94 SCALER diagnostic read +0x%" HWADDR_PRIx "\n", offset);
    return s->regs[offset / 4];
}
static void scaler_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    N94SCALER *s = opaque;
    qemu_log_mask(LOG_UNIMP, "n94 SCALER diagnostic write +0x%" HWADDR_PRIx " = 0x%08x\n", offset, (uint32_t)value);
    s->regs[offset / 4] = value;
}
static const MemoryRegionOps scaler_ops = {
    .read = scaler_read, .write = scaler_write, .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, .unaligned = false },
};
static void scaler_reset(DeviceState *dev)
{
    memset(N94_SCALER(dev)->regs, 0, sizeof(N94_SCALER(dev)->regs));
}
static void scaler_init(Object *obj)
{
    N94SCALER *s = N94_SCALER(obj);
    memory_region_init_io(&s->iomem, obj, &scaler_ops, s, "n94-scaler", 0x1000);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->iomem);
}
static void scaler_class_init(ObjectClass *klass, const void *data)
{
    device_class_set_legacy_reset(DEVICE_CLASS(klass), scaler_reset);
}
static const TypeInfo scaler_info = {
    .name = TYPE_N94_SCALER, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(N94SCALER), .instance_init = scaler_init,
    .class_init = scaler_class_init,
};
static void scaler_register(void) { type_register_static(&scaler_info); }
type_init(scaler_register)
