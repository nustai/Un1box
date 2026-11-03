/* n94 DWI diagnostic register subset, from the 13G37 driver startup.
 * TODO(n94): implement DWI transactions, PMIC responses and interrupt 0x06.
 * Retaining startup configuration does not emulate a connected PMIC. */
#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "qemu/log.h"

#define TYPE_N94_DWI "n94-dwi"
OBJECT_DECLARE_SIMPLE_TYPE(N94DWI, N94_DWI)
struct N94DWI {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t regs[0x1000 / 4];
};
static uint64_t dwi_read(void *opaque, hwaddr offset, unsigned size)
{
    N94DWI *s = opaque;
    qemu_log_mask(LOG_UNIMP, "n94 DWI diagnostic read +0x%" HWADDR_PRIx "\n", offset);
    return s->regs[offset / 4];
}
static void dwi_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    N94DWI *s = opaque;
    qemu_log_mask(LOG_UNIMP, "n94 DWI diagnostic write +0x%" HWADDR_PRIx " = 0x%08x\n", offset, (uint32_t)value);
    s->regs[offset / 4] = value;
}
static const MemoryRegionOps dwi_ops = {
    .read = dwi_read, .write = dwi_write, .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, .unaligned = false },
};
static void dwi_reset(DeviceState *dev)
{
    memset(N94_DWI(dev)->regs, 0, sizeof(N94_DWI(dev)->regs));
}
static void dwi_init(Object *obj)
{
    N94DWI *s = N94_DWI(obj);
    memory_region_init_io(&s->iomem, obj, &dwi_ops, s, "n94-dwi", 0x1000);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->iomem);
}
static void dwi_class_init(ObjectClass *klass, const void *data)
{
    device_class_set_legacy_reset(DEVICE_CLASS(klass), dwi_reset);
}
static const TypeInfo dwi_info = {
    .name = TYPE_N94_DWI, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(N94DWI), .instance_init = dwi_init,
    .class_init = dwi_class_init,
};
static void dwi_register(void) { type_register_static(&dwi_info); }
type_init(dwi_register)
