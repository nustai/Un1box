/* Diagnostic S5L8940 GPIO register bank, strictly for the n94 13G37 DT.
 * DT reg: arm-io + 0x0fa00000, size 0x1000; #gpio-ports=28,
 * #interrupt-groups=8, parent AIC interrupt=0x77.
 * Stock driver at 0x8109efdc reads one 32-bit word per port at 4-byte stride.
 * TODO(n94): verify hardware reset values, pin bitfields, external input,
 * GPIO interrupt groups/acknowledgement and parent IRQ delivery. This partial
 * bank only preserves port words; it does not claim functioning GPIO devices.
 */
#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "hw/core/irq.h"
#include "qemu/log.h"

#define TYPE_S5L8940_GPIO "s5l8940-gpio"
OBJECT_DECLARE_SIMPLE_TYPE(S5L8940GPIOState, S5L8940_GPIO)
#define N94_GPIO_PORTS 28

struct S5L8940GPIOState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    qemu_irq parent_irq;
    uint32_t ports[N94_GPIO_PORTS];
    uint32_t levels;
};

static void s5l8940_gpio_set_irq(void *opaque, int line, int level)
{
    S5L8940GPIOState *s = opaque;
    if (line >= 0 && line < 32) {
        if (level) {
            s->levels |= (1U << line);
        } else {
            s->levels &= ~(1U << line);
        }
        qemu_set_irq(s->parent_irq, s->levels != 0);
    }
}

static uint64_t s5l8940_gpio_read(void *opaque, hwaddr offset, unsigned size)
{
    S5L8940GPIOState *s = opaque;
    if (offset < sizeof(s->ports)) {
        return s->ports[offset / 4];
    }
    qemu_log_mask(LOG_UNIMP, "n94 GPIO unimplemented read at 0x%" HWADDR_PRIx "\n", offset);
    return 0;
}

static void s5l8940_gpio_write(void *opaque, hwaddr offset, uint64_t value,
                              unsigned size)
{
    S5L8940GPIOState *s = opaque;
    if (offset < sizeof(s->ports)) {
        s->ports[offset / 4] = value;
        return;
    }
    qemu_log_mask(LOG_UNIMP, "n94 GPIO unimplemented write at 0x%" HWADDR_PRIx "\n", offset);
}

static const MemoryRegionOps s5l8940_gpio_ops = {
    .read = s5l8940_gpio_read,
    .write = s5l8940_gpio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, .unaligned = false },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void s5l8940_gpio_reset(DeviceState *dev)
{
    S5L8940GPIOState *s = S5L8940_GPIO(dev);
    memset(s->ports, 0, sizeof(s->ports));
    s->levels = 0;
    qemu_set_irq(s->parent_irq, 0);
}

static void s5l8940_gpio_init(Object *obj)
{
    S5L8940GPIOState *s = S5L8940_GPIO(obj);
    memory_region_init_io(&s->iomem, obj, &s5l8940_gpio_ops, s,
                          "n94-gpio", 0x1000);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->iomem);
    sysbus_init_irq(SYS_BUS_DEVICE(obj), &s->parent_irq);
    qdev_init_gpio_in(DEVICE(obj), s5l8940_gpio_set_irq, 32);
}

static void s5l8940_gpio_class_init(ObjectClass *klass, const void *data)
{
    device_class_set_legacy_reset(DEVICE_CLASS(klass), s5l8940_gpio_reset);
}

static const TypeInfo s5l8940_gpio_info = {
    .name = TYPE_S5L8940_GPIO,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(S5L8940GPIOState),
    .instance_init = s5l8940_gpio_init,
    .class_init = s5l8940_gpio_class_init,
};

static void s5l8940_gpio_register_types(void)
{
    type_register_static(&s5l8940_gpio_info);
}
type_init(s5l8940_gpio_register_types)
