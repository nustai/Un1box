/* n94 DART register storage for startup diagnostics, not an IOMMU.
 * TODO(n94): implement page tables, address translation, faults and IRQs.
 * MMIO retention must not be interpreted as functional guest DMA mapping. */
#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "qemu/log.h"
#define TYPE_N94_DART "n94-dart-diagnostic"
OBJECT_DECLARE_SIMPLE_TYPE(N94DART, N94_DART)
struct N94DART {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t regs[0x2000 / 4];
};
static uint64_t dart_read(void *opaque, hwaddr offset, unsigned size)
{
    N94DART *s = opaque;
    qemu_log_mask(LOG_UNIMP, "n94 DART diagnostic read +0x%" HWADDR_PRIx "\n", offset);
    return s->regs[offset / 4];
}
static void dart_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    N94DART *s = opaque;
    qemu_log_mask(LOG_UNIMP, "n94 DART diagnostic write +0x%" HWADDR_PRIx " = 0x%08x\n", offset, (uint32_t)value);
    s->regs[offset / 4] = value;
}
static const MemoryRegionOps dart_ops = {
    .read = dart_read, .write = dart_write, .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, .unaligned = false },
};
static void dart_reset(DeviceState *dev)
{
    memset(N94_DART(dev)->regs, 0, sizeof(N94_DART(dev)->regs));
}
static void dart_init(Object *obj)
{
    N94DART *s = N94_DART(obj);
    memory_region_init_io(&s->iomem, obj, &dart_ops, s, "n94-dart-diagnostic", 0x2000);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->iomem);
}
static void dart_class_init(ObjectClass *klass, const void *data)
{
    device_class_set_legacy_reset(DEVICE_CLASS(klass), dart_reset);
}
static const TypeInfo dart_info = {
    .name = TYPE_N94_DART, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(N94DART), .instance_init = dart_init,
    .class_init = dart_class_init,
};
static void dart_register(void) { type_register_static(&dart_info); }
type_init(dart_register)
