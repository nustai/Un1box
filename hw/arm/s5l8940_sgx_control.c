/* Diagnostic backing for n94 SGX secondary control resource only.
 * TODO(n94): establish register semantics and implement SGX543 GPU execution.
 * This storage does not render or claim graphics acceleration. */
#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "qemu/log.h"
#define TYPE_N94_SGX_CONTROL "n94-sgx-control"
OBJECT_DECLARE_SIMPLE_TYPE(N94SGXControl, N94_SGX_CONTROL)
struct N94SGXControl {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t words[0x1000 / 4];
};
static uint64_t sgx_control_read(void *opaque, hwaddr offset, unsigned size)
{
    N94SGXControl *s = opaque;
    qemu_log_mask(LOG_UNIMP, "n94 SGX control diagnostic read +0x%" HWADDR_PRIx "\n", offset);
    return s->words[offset / 4];
}
static void sgx_control_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    N94SGXControl *s = opaque;
    qemu_log_mask(LOG_UNIMP, "n94 SGX control diagnostic write +0x%" HWADDR_PRIx " = 0x%08x\n", offset, (uint32_t)value);
    s->words[offset / 4] = value;
}
static const MemoryRegionOps ops = {
    .read = sgx_control_read, .write = sgx_control_write, .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, .unaligned = false },
};
static void sgx_control_reset(DeviceState *dev)
{
    memset(N94_SGX_CONTROL(dev)->words, 0, sizeof(N94_SGX_CONTROL(dev)->words));
}
static void sgx_control_init(Object *obj)
{
    N94SGXControl *s = N94_SGX_CONTROL(obj);
    memory_region_init_io(&s->iomem, obj, &ops, s, "n94-sgx-control", 0x1000);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->iomem);
}
static void sgx_control_class_init(ObjectClass *klass, const void *data)
{
    device_class_set_legacy_reset(DEVICE_CLASS(klass), sgx_control_reset);
}
static const TypeInfo sgx_control_info = {
    .name = TYPE_N94_SGX_CONTROL, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(N94SGXControl), .instance_init = sgx_control_init,
    .class_init = sgx_control_class_init,
};
static void sgx_control_register(void) { type_register_static(&sgx_control_info); }
type_init(sgx_control_register)
