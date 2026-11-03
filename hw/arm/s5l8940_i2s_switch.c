/* n94 i2s-switch: diagnostic backing for the 16 words written by
 * AppleAE2Audio at 0x80fc7404. TODO(n94): implement routing, audio and
 * hardware reset/bit semantics; preserving words alone does not produce sound. */
#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "qemu/log.h"

#define TYPE_N94_I2S_SWITCH "n94-i2s-switch"
OBJECT_DECLARE_SIMPLE_TYPE(N94I2SSwitch, N94_I2S_SWITCH)
struct N94I2SSwitch {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t words[16];
};
static uint64_t switch_read(void *opaque, hwaddr offset, unsigned size)
{
    N94I2SSwitch *s = opaque;
    if (offset < sizeof(s->words)) {
        return s->words[offset / 4];
    }
    qemu_log_mask(LOG_UNIMP, "n94 i2s-switch read +0x%" HWADDR_PRIx "\n", offset);
    return 0;
}
static void switch_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    N94I2SSwitch *s = opaque;
    if (offset < sizeof(s->words)) {
        s->words[offset / 4] = value;
        qemu_log_mask(LOG_UNIMP, "n94 i2s-switch diagnostic write +0x%" HWADDR_PRIx "\n", offset);
        return;
    }
    qemu_log_mask(LOG_UNIMP, "n94 i2s-switch unsupported write +0x%" HWADDR_PRIx "\n", offset);
}
static const MemoryRegionOps switch_ops = {
    .read = switch_read, .write = switch_write, .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, .unaligned = false },
};
static void switch_reset(DeviceState *dev)
{
    memset(N94_I2S_SWITCH(dev)->words, 0, sizeof(N94_I2S_SWITCH(dev)->words));
}
static void switch_init(Object *obj)
{
    N94I2SSwitch *s = N94_I2S_SWITCH(obj);
    memory_region_init_io(&s->iomem, obj, &switch_ops, s, "n94-i2s-switch", 0x1000);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->iomem);
}
static void switch_class_init(ObjectClass *klass, const void *data)
{
    device_class_set_legacy_reset(DEVICE_CLASS(klass), switch_reset);
}
static const TypeInfo switch_info = {
    .name = TYPE_N94_I2S_SWITCH, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(N94I2SSwitch), .instance_init = switch_init,
    .class_init = switch_class_init,
};
static void switch_register(void) { type_register_static(&switch_info); }
type_init(switch_register)
