/* n94 CDMA v3, derived from its 13G37 AppleCDMA driver and DeviceTree.
 * reg=(0x07000000,0x2d000),(0x07800000,0x9000) on arm-io +0x30000000.
 * Channel windows have stride 0x1000, IDs 1..44; IRQs 0x33..0x5e.
 * Plain FIFO scatter/gather subset only. TODO(n94): verify descriptor flag
 * and status interpretations on hardware; peripheral request handshakes,
 * asynchronous scheduling, AES and extended descriptor modes are unfinished.
 */
#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "hw/core/irq.h"
#include "qemu/bswap.h"
#include "qemu/log.h"
#include "system/address-spaces.h"
#include "system/dma.h"

#define TYPE_S5L8940_CDMA "s5l8940-cdma"
OBJECT_DECLARE_SIMPLE_TYPE(S5L8940CDMAState, S5L8940_CDMA)
#define N94_CDMA_CHANNELS 44
#define CDMA_IDLE 0x20000U
#define CDMA_ERROR 0x40000U
#define CDMA_END 0x80000U
#define CDMA_DESC_IRQ 0x100000U
#define CDMA_EVENTS (CDMA_END | CDMA_DESC_IRQ)
#define CDMA_LIMIT (16U << 20)

typedef struct N94CDMAChannel {
    uint32_t regs[16];
    uint32_t status;
} N94CDMAChannel;

struct S5L8940CDMAState {
    SysBusDevice parent_obj;
    MemoryRegion channels;
    MemoryRegion crypto;
    qemu_irq irq[N94_CDMA_CHANNELS];
    N94CDMAChannel channel[N94_CDMA_CHANNELS + 1];
    uint32_t enabled[2];
    uint32_t crypto_words[0x9000 / 4];
    bool crypto_configured;
};

static void n94_cdma_update(S5L8940CDMAState *s)
{
    for (unsigned id = 1; id <= N94_CDMA_CHANNELS; id++) {
        bool enabled = s->enabled[id / 32] & (1U << (id % 32));
        qemu_set_irq(s->irq[id - 1], enabled &&
                     (s->channel[id].status & CDMA_EVENTS));
    }
}

static bool n94_cdma_ram(uint32_t address, uint32_t size)
{
    return address >= 0x80000000U &&
           (uint64_t)address + size <= 0xa0000000ULL;
}

static void n94_cdma_error(S5L8940CDMAState *s, unsigned id, const char *why)
{
    s->channel[id].status = CDMA_IDLE | CDMA_ERROR | CDMA_END;
    qemu_log_mask(LOG_GUEST_ERROR, "n94 CDMA channel %u: %s\n", id, why);
    n94_cdma_update(s);
}

static void n94_cdma_run(S5L8940CDMAState *s, unsigned id)
{
    N94CDMAChannel *ch = &s->channel[id];
    uint32_t descriptor = ch->regs[0x14 / 4];
    uint32_t endpoint = ch->regs[8 / 4];
    uint32_t config = ch->regs[4 / 4];
    unsigned width_code = (config >> 2) & 3;
    unsigned width = 1U << width_code;
    bool output = config & 2;
    uint32_t total = 0;

    if (s->crypto_configured || width_code == 3 || (endpoint & (width - 1)) ||
        (endpoint >= 0x37000000U && endpoint < 0x3702d000U) ||
        (endpoint >= 0x37800000U && endpoint < 0x37809000U)) {
        n94_cdma_error(s, id, "unsupported crypto/width or recursive endpoint");
        return;
    }
    if (!address_space_access_valid(&address_space_memory, endpoint, width,
                                    output, MEMTXATTRS_UNSPECIFIED)) {
        n94_cdma_error(s, id, "unmapped or unwritable FIFO endpoint");
        return;
    }
    ch->status = 0x10000; /* diagnostic running state */
    for (unsigned step = 0; step < 128; step++) {
        uint8_t raw[32];
        uint32_t next, flags, buffer, length;
        if ((descriptor & 31) || !n94_cdma_ram(descriptor, sizeof(raw)) ||
            dma_memory_read(&address_space_memory, descriptor, raw, sizeof(raw),
                            MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
            n94_cdma_error(s, id, "invalid descriptor address");
            return;
        }
        next = ldl_le_p(raw);
        flags = ldl_le_p(raw + 4);
        buffer = ldl_le_p(raw + 8);
        length = ldl_le_p(raw + 12);
        if (!(flags & 15)) {
            ch->status = (ch->status & CDMA_EVENTS) | CDMA_IDLE;
            n94_cdma_update(s);
            return;
        }
        if ((flags & 15) != 3 || (length % width) ||
            length > CDMA_LIMIT - total || !n94_cdma_ram(buffer, length)) {
            n94_cdma_error(s, id, "unsupported command or invalid buffer/length");
            return;
        }
        for (uint32_t offset = 0; offset < length; offset += width) {
            uint8_t bytes[4];
            uint32_t source = output ? buffer + offset : endpoint;
            uint32_t target = output ? endpoint : buffer + offset;
            if (dma_memory_read(&address_space_memory, source, bytes, width,
                                MEMTXATTRS_UNSPECIFIED) != MEMTX_OK ||
                dma_memory_write(&address_space_memory, target, bytes, width,
                                 MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
                n94_cdma_error(s, id, "DMA memory transaction rejected");
                return;
            }
            ch->regs[0x10 / 4] = buffer + offset + width;
            ch->regs[0x0c / 4] += width;
        }
        total += length;
        ch->regs[0x14 / 4] = next;
        ch->regs[0x20 / 4] = next;
        ch->regs[0x18 / 4] = 0;
        ch->status = (ch->status & CDMA_EVENTS) | CDMA_IDLE;
        if (flags & 0x100) {
            ch->status |= CDMA_DESC_IRQ;
        }
        if (flags & 0x200) {
            ch->status |= CDMA_END;
            n94_cdma_update(s);
            return;
        }
        descriptor = next;
    }
    n94_cdma_error(s, id, "descriptor chain exceeds 128 entries");
}

static uint64_t n94_cdma_read(void *opaque, hwaddr offset, unsigned size)
{
    S5L8940CDMAState *s = opaque;
    unsigned id = offset >> 12;
    unsigned reg = offset & 0xfff;
    if (!id && reg < 16) {
        /* Readback is diagnostic; set/clear writes are visible in 13G37. */
        return s->enabled[(reg / 4) & 1];
    }
    if (id >= 1 && id <= N94_CDMA_CHANNELS && reg < 0x40) {
        return reg ? s->channel[id].regs[reg / 4] : s->channel[id].status;
    }
    qemu_log_mask(LOG_UNIMP, "n94 CDMA unsupported read +0x%" HWADDR_PRIx "\n", offset);
    return 0;
}

static void n94_cdma_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    S5L8940CDMAState *s = opaque;
    unsigned id = offset >> 12;
    unsigned reg = offset & 0xfff;
    if (!id && reg < 16) {
        unsigned bank = (reg / 4) & 1;
        if (reg < 8) {
            s->enabled[bank] |= value;
        } else {
            s->enabled[bank] &= ~value;
        }
        n94_cdma_update(s);
        return;
    }
    if (id >= 1 && id <= N94_CDMA_CHANNELS && reg < 0x40) {
        N94CDMAChannel *ch = &s->channel[id];
        if (reg) {
            ch->regs[reg / 4] = value;
            return;
        }
        /* Inferred from stop/reset at 0x80c90468 and submit at 0x80c8ff7a.
         * TODO(n94): full status/W1C semantics and partial/cancelled transfers.
         */
        if (value & 2) {
            memset(ch, 0, sizeof(*ch));
            ch->status = CDMA_IDLE;
        } else {
            ch->status &= ~(value & CDMA_EVENTS);
            if (value & 0x18) {
                ch->status &= ~CDMA_EVENTS;
            }
            if (value & 4) {
                ch->status |= 0x200000; /* pause acknowledgement */
            }
            if (value & 1) {
                n94_cdma_run(s, id);
            }
        }
        n94_cdma_update(s);
        return;
    }
    qemu_log_mask(LOG_UNIMP, "n94 CDMA unsupported write +0x%" HWADDR_PRIx "\n", offset);
}

static uint64_t n94_cdma_crypto_read(void *opaque, hwaddr offset, unsigned size)
{
    S5L8940CDMAState *s = opaque;
    qemu_log_mask(LOG_UNIMP, "n94 CDMA crypto unsupported read +0x%" HWADDR_PRIx "\n", offset);
    return s->crypto_words[offset / 4];
}

static void n94_cdma_crypto_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    S5L8940CDMAState *s = opaque;
    qemu_log_mask(LOG_UNIMP, "n94 CDMA crypto unsupported write +0x%" HWADDR_PRIx "\n", offset);
    s->crypto_words[offset / 4] = value;
    s->crypto_configured |= value != 0; /* conservative rejection until reset */
}

static const MemoryRegionOps n94_cdma_ops = {
    .read = n94_cdma_read, .write = n94_cdma_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, .unaligned = false },
};
static const MemoryRegionOps n94_cdma_crypto_ops = {
    .read = n94_cdma_crypto_read, .write = n94_cdma_crypto_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, .unaligned = false },
};

static void n94_cdma_reset(DeviceState *dev)
{
    S5L8940CDMAState *s = S5L8940_CDMA(dev);
    memset(s->channel, 0, sizeof(s->channel));
    memset(s->enabled, 0, sizeof(s->enabled));
    memset(s->crypto_words, 0, sizeof(s->crypto_words));
    s->crypto_configured = false;
    for (unsigned id = 1; id <= N94_CDMA_CHANNELS; id++) {
        s->channel[id].status = CDMA_IDLE;
    }
    n94_cdma_update(s);
}

static void n94_cdma_init(Object *obj)
{
    S5L8940CDMAState *s = S5L8940_CDMA(obj);
    memory_region_init_io(&s->channels, obj, &n94_cdma_ops, s, "n94-cdma", 0x2d000);
    memory_region_init_io(&s->crypto, obj, &n94_cdma_crypto_ops, s, "n94-cdma-crypto", 0x9000);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->channels);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->crypto);
    for (unsigned i = 0; i < N94_CDMA_CHANNELS; i++) {
        sysbus_init_irq(SYS_BUS_DEVICE(obj), &s->irq[i]);
    }
}
static void n94_cdma_class_init(ObjectClass *klass, const void *data)
{
    device_class_set_legacy_reset(DEVICE_CLASS(klass), n94_cdma_reset);
}
static const TypeInfo n94_cdma_info = {
    .name = TYPE_S5L8940_CDMA, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(S5L8940CDMAState), .instance_init = n94_cdma_init,
    .class_init = n94_cdma_class_init,
};
static void n94_cdma_register_types(void)
{
    type_register_static(&n94_cdma_info);
}
type_init(n94_cdma_register_types)
