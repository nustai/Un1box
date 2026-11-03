/* n94 MIPI-DSI diagnostic register storage, DT reg 0x09500000/0x0f110000.
 * TODO(n94): implement DSI transactions, PHY, interrupts and panel protocol.
 * Register retention alone is not a working display pipeline. */
#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "qemu/log.h"

#define TYPE_N94_MIPI "n94-mipi"
OBJECT_DECLARE_SIMPLE_TYPE(N94MIPI, N94_MIPI)
struct N94MIPI {
    SysBusDevice parent_obj;
    MemoryRegion controller, phy;
    uint32_t controller_regs[0x1000 / 4];
    uint32_t phy_regs[0x1000 / 4];
};
static uint64_t controller_read(void *opaque, hwaddr offset, unsigned size)
{
    N94MIPI *s = opaque;
    qemu_log_mask(LOG_UNIMP, "n94 MIPI diagnostic read +0x%" HWADDR_PRIx "\n", offset);
    return s->controller_regs[offset / 4];
}
static void controller_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    N94MIPI *s = opaque;
    qemu_log_mask(LOG_UNIMP, "n94 MIPI diagnostic write +0x%" HWADDR_PRIx " = 0x%08x\n", offset, (uint32_t)value);
    s->controller_regs[offset / 4] = value;
}
static uint64_t phy_read(void *opaque, hwaddr offset, unsigned size)
{
    N94MIPI *s = opaque;
    qemu_log_mask(LOG_UNIMP, "n94 MIPI PHY diagnostic read +0x%" HWADDR_PRIx "\n", offset);
    return s->phy_regs[offset / 4];
}
static void phy_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    N94MIPI *s = opaque;
    qemu_log_mask(LOG_UNIMP, "n94 MIPI PHY diagnostic write +0x%" HWADDR_PRIx " = 0x%08x\n", offset, (uint32_t)value);
    s->phy_regs[offset / 4] = value;
}
static const MemoryRegionOps controller_ops = {
    .read = controller_read, .write = controller_write, .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, .unaligned = false },
};
static const MemoryRegionOps phy_ops = {
    .read = phy_read, .write = phy_write, .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, .unaligned = false },
};
static void mipi_reset(DeviceState *dev)
{
    N94MIPI *s = N94_MIPI(dev);
    memset(s->controller_regs, 0, sizeof(s->controller_regs));
    memset(s->phy_regs, 0, sizeof(s->phy_regs));
}
static void mipi_init(Object *obj)
{
    N94MIPI *s = N94_MIPI(obj);
    memory_region_init_io(&s->controller, obj, &controller_ops, s, "n94-mipi", 0x1000);
    memory_region_init_io(&s->phy, obj, &phy_ops, s, "n94-mipi-phy", 0x1000);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->controller);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->phy);
}
static void mipi_class_init(ObjectClass *klass, const void *data)
{
    device_class_set_legacy_reset(DEVICE_CLASS(klass), mipi_reset);
}
static const TypeInfo mipi_info = {
    .name = TYPE_N94_MIPI, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(N94MIPI), .instance_init = mipi_init,
    .class_init = mipi_class_init,
};
static void mipi_register(void) { type_register_static(&mipi_info); }
type_init(mipi_register)
