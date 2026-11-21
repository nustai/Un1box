/* n94 MIPI-DSI slow adaptive clocking, DT reg[1] at 0x0f110000. */
#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "qemu/log.h"

#define TYPE_N94_MIPI "n94-mipi-sac"
#define SAC_READY (1u << 8)
OBJECT_DECLARE_SIMPLE_TYPE(N94MIPI, N94_MIPI)
struct N94MIPI {
    SysBusDevice parent_obj;
    MemoryRegion sac;
    uint32_t sac_regs[0x1000 / 4];
};

static uint64_t sac_read(void *opaque, hwaddr offset, unsigned size)
{
    N94MIPI *s = opaque;
    uint32_t value = s->sac_regs[offset / 4];

    /* No physical clock transition to wait for in the emulator. */
    return offset == 0 ? value | SAC_READY : value;
}

static void sac_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    N94MIPI *s = opaque;
    qemu_log_mask(LOG_UNIMP, "n94 MIPI SAC write +0x%" HWADDR_PRIx " = 0x%08x\n",
                  offset, (uint32_t)value);
    s->sac_regs[offset / 4] = value;
}
static const MemoryRegionOps sac_ops = {
    .read = sac_read, .write = sac_write, .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, .unaligned = false },
};
static void mipi_reset(DeviceState *dev)
{
    N94MIPI *s = N94_MIPI(dev);
    memset(s->sac_regs, 0, sizeof(s->sac_regs));
}
static void mipi_init(Object *obj)
{
    N94MIPI *s = N94_MIPI(obj);
    memory_region_init_io(&s->sac, obj, &sac_ops, s, "n94-mipi-sac", 0x1000);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->sac);
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
