/* n94 S5L8940 PL310 handoff model, authored from the stock 13G37 driver.
 * DT /arm-io/pl310 reg: (0x0e000000,0x1000),(0x0fd00000,0x2000).
 * Root translation adds 0x30000000. No other board model is used.
 * Generic maintenance offsets agree with ARM DDI 0246A, section 3.
 * TODO(n94): confirm cache ID/type geometry and bootloader reset snapshot.
 * cache-type=0 is a diagnostic geometry, NOT measured A5 hardware data.
 * QEMU memory is coherent: cache maintenance completes synchronously; this
 * device does not simulate timing, cache lines, or PL310 errata.
 */
#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "hw/core/qdev-properties.h"
#include "qemu/log.h"

#define TYPE_S5L8940_PL310 "s5l8940-pl310"
OBJECT_DECLARE_SIMPLE_TYPE(S5L8940PL310State, S5L8940_PL310)

struct S5L8940PL310State {
    SysBusDevice parent_obj;
    MemoryRegion cache;
    MemoryRegion cif;
    uint32_t cache_type;
    uint32_t cache_id;
    uint32_t registers[0x1000 / 4];
    uint32_t cif_words[0x2000 / 4];
};

static bool n94_cache_maintenance(hwaddr offset)
{
    switch (offset) {
    case 0x730: case 0x770: case 0x77c:
    case 0x7b0: case 0x7b8: case 0x7bc:
    case 0x7f0: case 0x7f8: case 0x7fc:
        return true;
    default:
        return false;
    }
}

static bool n94_cache_config(hwaddr offset)
{
    switch (offset) {
    /* Accessed by AppleS5L8940XPL310 at 0x80d97498..0x80d97608. */
    case 0x100: case 0x104: case 0x108: case 0x10c:
    case 0x900: case 0x904: case 0x908: case 0x90c:
    case 0xf40: case 0xf60: case 0xf80:
        return true;
    default:
        return false;
    }
}

static uint64_t n94_pl310_read(void *opaque, hwaddr offset, unsigned size)
{
    S5L8940PL310State *s = opaque;
    if (offset == 0) {
        return s->cache_id;
    }
    if (offset == 4) {
        return s->cache_type;
    }
    if (n94_cache_maintenance(offset)) {
        return 0; /* no outstanding cache-line operation in coherent QEMU */
    }
    if (n94_cache_config(offset)) {
        return s->registers[offset / 4];
    }
    qemu_log_mask(LOG_UNIMP, "n94 PL310 unsupported read +0x%" HWADDR_PRIx "\n", offset);
    return 0;
}

static void n94_pl310_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    S5L8940PL310State *s = opaque;
    if (offset == 0 || offset == 4 || n94_cache_maintenance(offset)) {
        return;
    }
    if (n94_cache_config(offset)) {
        s->registers[offset / 4] = offset == 0x100 ? value & 1 : value;
        return;
    }
    qemu_log_mask(LOG_UNIMP, "n94 PL310 unsupported write +0x%" HWADDR_PRIx "\n", offset);
}

static uint64_t n94_cif_read(void *opaque, hwaddr offset, unsigned size)
{
    S5L8940PL310State *s = opaque;
    /* TODO(n94): CIF commands/status/idle transitions. Bounded diagnostic
     * backing alone does not implement a functioning cache interface.
     */
    qemu_log_mask(LOG_UNIMP, "n94 CIF diagnostic read +0x%" HWADDR_PRIx "\n", offset);
    return s->cif_words[offset / 4];
}

static void n94_cif_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    S5L8940PL310State *s = opaque;
    qemu_log_mask(LOG_UNIMP, "n94 CIF diagnostic write +0x%" HWADDR_PRIx "\n", offset);
    s->cif_words[offset / 4] = value;
}

static const MemoryRegionOps n94_pl310_ops = {
    .read = n94_pl310_read, .write = n94_pl310_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, .unaligned = false },
};
static const MemoryRegionOps n94_cif_ops = {
    .read = n94_cif_read, .write = n94_cif_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, .unaligned = false },
};

static void n94_pl310_reset(DeviceState *dev)
{
    S5L8940PL310State *s = S5L8940_PL310(dev);
    memset(s->registers, 0, sizeof(s->registers));
    memset(s->cif_words, 0, sizeof(s->cif_words));
}

static void n94_pl310_init(Object *obj)
{
    S5L8940PL310State *s = S5L8940_PL310(obj);
    memory_region_init_io(&s->cache, obj, &n94_pl310_ops, s, "n94-pl310", 0x1000);
    memory_region_init_io(&s->cif, obj, &n94_cif_ops, s, "n94-cif", 0x2000);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->cache);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->cif);
}

static const Property n94_pl310_properties[] = {
    DEFINE_PROP_UINT32("cache-type", S5L8940PL310State, cache_type, 0),
    DEFINE_PROP_UINT32("cache-id", S5L8940PL310State, cache_id, 0),
};
static void n94_pl310_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    device_class_set_props(dc, n94_pl310_properties);
    device_class_set_legacy_reset(dc, n94_pl310_reset);
}
static const TypeInfo n94_pl310_info = {
    .name = TYPE_S5L8940_PL310, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(S5L8940PL310State), .instance_init = n94_pl310_init,
    .class_init = n94_pl310_class_init,
};
static void n94_pl310_register_types(void)
{
    type_register_static(&n94_pl310_info);
}
type_init(n94_pl310_register_types)
