/*
 * Apple S5L8940 IOP (I/O Processor) Emulation for iPhone 4S (n94)
 *
 * Copyright (c) 2026 Un1box / n94 Emulation Project
 *
 * Written strictly from scratch for Apple S5L8940 (iPhone4,1 / n94 / N94AP).
 * Matches DeviceTree /arm-io/iop (reg 0x0f300000:0x1000, AIC IRQ 0x02).
 */

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "hw/core/qdev-properties.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "system/address-spaces.h"
#include "hw/arm/s5l8940_soc.h"
#include "hw/arm/s5l8940_iop.h"

#define S5L8940_IOP_REG_SIZE     0x1000
#define S5L8940_IOP_REG_WORDS    (S5L8940_IOP_REG_SIZE / 4)

/* AP-side Control Block Registers (MMIO 0x3F300000) */
#define IOP_REG_CTRL             0x00
#define IOP_REG_FW_BASE          0x04
#define IOP_REG_FW_SIZE          0x08
#define IOP_REG_CACHE_CFG        0x34

#define IOP_CTRL_STOP            0x00
#define IOP_CTRL_RUN             0x01
#define IOP_CTRL_STOPPED         0x02
#define IOP_CTRL_HALT            0x10

/* EmbeddedIOP Firmware Layout */
#define FW_CONFIG_MAGIC          0x636e6667  /* 'cnfg' */
#define FW_CONFIG_DEFAULT_OFFSET 0x13000

#define IOP_MAX_ENDPOINTS        8
#define RING_CONTROL             0
#define RING_MESSAGE             1
#define RING_SDIO                3
#define RING_FMI0                5
#define RING_FMI1                6

#define FMI_OP_SET_CONFIG        1
#define FMI_OP_RESET_EVERYTHING  2
#define FMI_OP_ERASE_SINGLE      3
#define FMI_OP_READ_SINGLE       4
#define FMI_OP_READ_RAW          5
#define FMI_OP_WRITE_SINGLE      6
#define FMI_OP_READ_MULTI        8
#define FMI_OP_WRITE_MULTI       9
#define FMI_OP_ERASE_MULTI       12

#define FMI_STATUS_OK            1
#define FMI_STATUS_BLANK         2
#define FMI_STATUS_PARAM         0x80000004
#define FMI_ID_BYTES             5
#define FMI_META_BYTES           10

/* Default: Hynix SLC 4K NAND ID (0xAD 0xD5 0x14 0xB6 0x44) */
#define FMI_DEFAULT_NAND_ID      0xb614d5ad

struct S5L8940IOPState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    qemu_irq irq;

    uint32_t regs[S5L8940_IOP_REG_WORDS];
    bool running;
    uint32_t fw_base;
    uint32_t fw_size;
    uint32_t fw_config;

    /* NAND geometry and storage backend */
    uint32_t nand_id;
    char *nand_path;
    char *nand_overlay_path;
    FILE *raw_file;
    uint32_t bytes_per_page[2];
    uint32_t bytes_per_spare[2];
    uint32_t pages_per_block[2];

    QEMUTimer *doorbell_timer;
};

/*
 * Address translation for IOP memory window:
 * In S5L8940 IOP address space, host DRAM (0x80000000..0xA0000000)
 * is mapped at 0xC0000000..0xE0000000.
 */
static inline hwaddr s5l8940_iop_pa(hwaddr addr)
{
    if (addr >= 0xc0000000U && addr < 0xe0000000U) {
        return addr - 0x40000000U;
    }
    return addr;
}

static inline uint32_t iop_ldl(hwaddr addr)
{
    return address_space_ldl_le(&address_space_memory, s5l8940_iop_pa(addr),
                                MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline void iop_stl(hwaddr addr, uint32_t val)
{
    address_space_stl_le(&address_space_memory, s5l8940_iop_pa(addr), val,
                         MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline void iop_read(hwaddr addr, void *buf, hwaddr len)
{
    address_space_read(&address_space_memory, s5l8940_iop_pa(addr),
                       MEMTXATTRS_UNSPECIFIED, buf, len);
}

static inline void iop_write(hwaddr addr, const void *buf, hwaddr len)
{
    address_space_write(&address_space_memory, s5l8940_iop_pa(addr),
                        MEMTXATTRS_UNSPECIFIED, buf, len);
}

static void s5l8940_iop_raise_irq(S5L8940IOPState *s)
{
    qemu_irq_pulse(s->irq);
}

/* Locate 'cnfg' structure in guest IOP firmware */
static uint32_t s5l8940_iop_find_config(S5L8940IOPState *s)
{
    if (s->fw_config) {
        return s->fw_config;
    }
    /* Fast check default known offset */
    if (iop_ldl(s->fw_base + FW_CONFIG_DEFAULT_OFFSET) == FW_CONFIG_MAGIC) {
        s->fw_config = s->fw_base + FW_CONFIG_DEFAULT_OFFSET;
        return s->fw_config;
    }
    /* Full scan within firmware image */
    uint32_t limit = s->fw_size ? MIN(s->fw_size, 0x40000U) : 0x40000U;
    for (uint32_t off = 0x1000; off < limit; off += 4) {
        if (iop_ldl(s->fw_base + off) == FW_CONFIG_MAGIC) {
            s->fw_config = s->fw_base + off;
            return s->fw_config;
        }
    }
    return 0;
}

/* Read physical NAND page from raw file or zero-fill */
static uint32_t s5l8940_iop_read_page(S5L8940IOPState *s, int bus, uint32_t ce,
                                      uint32_t page, uint8_t *data, uint8_t *meta)
{
    uint32_t bpp = s->bytes_per_page[bus ? 1 : 0];
    if (bpp == 0) {
        bpp = 4096;
    }
    memset(data, 0, bpp);
    memset(meta, 0xff, FMI_META_BYTES);

    if (s->raw_file) {
        int64_t offset = (int64_t)page * bpp;
        if (fseeko(s->raw_file, offset, SEEK_SET) == 0) {
            size_t read_bytes = fread(data, 1, bpp, s->raw_file);
            if (read_bytes > 0) {
                return FMI_STATUS_OK;
            }
        }
    }
    return FMI_STATUS_BLANK;
}

/* Process pending ring items across control and FMI channels */
static void s5l8940_iop_process_rings(S5L8940IOPState *s)
{
    if (!s->running) {
        return;
    }
    uint32_t cfg = s5l8940_iop_find_config(s);
    if (!cfg) {
        return;
    }

    bool handled_any = false;

    /* 1. Control Ring (Handle 0: cfg + 0x10) */
    hwaddr ctrl_ring = iop_ldl(cfg + 0x10);
    uint32_t ctrl_count = iop_ldl(cfg + 0x14);
    if (ctrl_ring && ctrl_count > 0 && ctrl_count <= 256) {
        for (uint32_t i = 0; i < ctrl_count; i++) {
            hwaddr entry = ctrl_ring + i * 16;
            uint32_t w0 = iop_ldl(entry);
            /* AP -> IOP: ownership bit 0 is 0 */
            if ((w0 & ~3U) && !(w0 & 1U)) {
                hwaddr item = w0 & ~3U;
                uint32_t opcode = iop_ldl(item);
                (void)opcode;
                /* 'nop ' (0x6e6f7020) or 'nop_' (0x6e6f705f) ping */
                iop_stl(item + 4, 0); /* status = 0 (kIOReturnSuccess) */
                /* Return ownership to AP (bit 0 = 1) */
                iop_stl(entry, item | 1U);
                handled_any = true;
            }
        }
    }

    /* 2. FMI Rings (FMI0 Handle 5: cfg + 0x38, FMI1 Handle 6: cfg + 0x40) */
    static const int fmi_handles[2] = { RING_FMI0, RING_FMI1 };
    for (int bus = 0; bus < 2; bus++) {
        int h = fmi_handles[bus];
        hwaddr fmi_ring = iop_ldl(cfg + 0x10 + h * 8);
        uint32_t fmi_count = iop_ldl(cfg + 0x14 + h * 8);
        if (!fmi_ring || fmi_count == 0 || fmi_count > 256) {
            continue;
        }

        for (uint32_t i = 0; i < fmi_count; i++) {
            hwaddr entry = fmi_ring + i * 16;
            uint32_t w0 = iop_ldl(entry);
            if ((w0 & ~3U) && !(w0 & 1U)) {
                hwaddr item = w0 & ~3U;
                uint32_t opcode = iop_ldl(item);
                uint32_t status = FMI_STATUS_OK;

                switch (opcode) {
                case FMI_OP_SET_CONFIG:
                    s->bytes_per_page[bus] = iop_ldl(item + 0x24);
                    s->bytes_per_spare[bus] = iop_ldl(item + 0x28);
                    s->pages_per_block[bus] = iop_ldl(item + 0x1c);
                    if (s->bytes_per_page[bus] == 0) {
                        s->bytes_per_page[bus] = 4096;
                    }
                    status = FMI_STATUS_OK;
                    break;

                case FMI_OP_RESET_EVERYTHING: {
                    hwaddr id_buf = iop_ldl(item + 0x10);
                    if (id_buf) {
                        uint8_t ids[16 * FMI_ID_BYTES] = { 0 };
                        /* Write NAND ID into CE 0 */
                        stl_le_p(&ids[0], s->nand_id);
                        ids[4] = 0x44;
                        iop_write(id_buf, ids, sizeof(ids));
                    }
                    status = FMI_STATUS_OK;
                    break;
                }

                case FMI_OP_READ_SINGLE: {
                    uint32_t ce = iop_ldl(item + 0x10);
                    uint32_t page = iop_ldl(item + 0x14);
                    hwaddr data_buf = iop_ldl(item + 0x18);
                    hwaddr meta_buf = iop_ldl(item + 0x1c);
                    uint32_t bpp = s->bytes_per_page[bus];
                    if (bpp == 0) {
                        bpp = 4096;
                    }
                    g_autofree uint8_t *page_data = g_malloc0(bpp);
                    uint8_t meta_data[FMI_META_BYTES];
                    status = s5l8940_iop_read_page(s, bus, ce, page, page_data, meta_data);
                    if (data_buf) {
                        iop_write(data_buf, page_data, bpp);
                    }
                    if (meta_buf) {
                        iop_write(meta_buf, meta_data, FMI_META_BYTES);
                    }
                    break;
                }

                case FMI_OP_READ_MULTI: {
                    uint32_t n = iop_ldl(item + 0x10);
                    hwaddr ces = iop_ldl(item + 0x14);
                    hwaddr pages = iop_ldl(item + 0x18);
                    hwaddr data_desc = iop_ldl(item + 0x1c);
                    uint32_t bpp = s->bytes_per_page[bus];
                    if (bpp == 0) {
                        bpp = 4096;
                    }

                    if (ces && pages && data_desc && n > 0 && n <= 128) {
                        g_autofree uint8_t *page_data = g_malloc0(bpp);
                        uint8_t meta_data[FMI_META_BYTES];
                        for (uint32_t j = 0; j < n; j++) {
                            uint32_t ce = iop_ldl(ces + j * 4);
                            uint32_t pg = iop_ldl(pages + j * 4);
                            hwaddr dst_seg = iop_ldl(data_desc + j * 8);
                            s5l8940_iop_read_page(s, bus, ce, pg, page_data, meta_data);
                            if (dst_seg) {
                                iop_write(dst_seg, page_data, bpp);
                            }
                        }
                    }
                    /* Mark pages completed */
                    iop_stl(item + 0x60, n);
                    iop_stl(item + 0x64, FMI_STATUS_OK);
                    status = FMI_STATUS_OK;
                    break;
                }

                case FMI_OP_ERASE_SINGLE:
                case FMI_OP_ERASE_MULTI:
                case FMI_OP_WRITE_SINGLE:
                case FMI_OP_WRITE_MULTI:
                default:
                    status = FMI_STATUS_OK;
                    break;
                }

                /* Write status to command result word */
                iop_stl(item + 0x20, status);
                /* Return ownership to AP */
                iop_stl(entry, item | 1U);
                handled_any = true;
            }
        }
    }

    if (handled_any) {
        s5l8940_iop_raise_irq(s);
    }
}

static void s5l8940_iop_doorbell_in(void *opaque, int n, int level)
{
    S5L8940IOPState *s = opaque;
    if (level && s->running) {
        s5l8940_iop_process_rings(s);
    }
}

void s5l8940_iop_ring_doorbell(DeviceState *dev)
{
    S5L8940IOPState *s = S5L8940_IOP(dev);
    s5l8940_iop_process_rings(s);
}

static void s5l8940_iop_doorbell_timer_cb(void *opaque)
{
    S5L8940IOPState *s = opaque;
    if (s->running) {
        s5l8940_iop_process_rings(s);
        timer_mod(s->doorbell_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1);
    }
}

static uint64_t s5l8940_iop_read(void *opaque, hwaddr offset, unsigned size)
{
    S5L8940IOPState *s = opaque;
    uint32_t idx = offset / 4;

    switch (offset) {
    case IOP_REG_CTRL:
        return s->running ? 0 : IOP_CTRL_STOPPED;
    case IOP_REG_FW_BASE:
        return s->fw_base;
    case IOP_REG_FW_SIZE:
        return s->fw_size;
    case IOP_REG_CACHE_CFG:
        return s->regs[idx];
    default:
        if (idx < S5L8940_IOP_REG_WORDS) {
            return s->regs[idx];
        }
        return 0;
    }
}

static void s5l8940_iop_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    S5L8940IOPState *s = opaque;
    uint32_t idx = offset / 4;
    if (idx < S5L8940_IOP_REG_WORDS) {
        s->regs[idx] = (uint32_t)value;
    }

    switch (offset) {
    case IOP_REG_CTRL:
        if (value == IOP_CTRL_RUN) {
            s->running = true;
            s->fw_config = 0;
            s5l8940_iop_process_rings(s);
            timer_mod(s->doorbell_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1);
        } else if (value == IOP_CTRL_STOP || value == IOP_CTRL_HALT) {
            s->running = false;
            timer_del(s->doorbell_timer);
        }
        break;
    case IOP_REG_FW_BASE:
        s->fw_base = (uint32_t)value;
        s->fw_config = 0;
        break;
    case IOP_REG_FW_SIZE:
        s->fw_size = (uint32_t)value;
        break;
    default:
        break;
    }
}

static const MemoryRegionOps s5l8940_iop_ops = {
    .read = s5l8940_iop_read,
    .write = s5l8940_iop_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
        .unaligned = false,
    },
};

static void s5l8940_iop_reset(DeviceState *dev)
{
    S5L8940IOPState *s = S5L8940_IOP(dev);
    memset(s->regs, 0, sizeof(s->regs));
    s->running = false;
    s->fw_base = 0;
    s->fw_size = 0;
    s->fw_config = 0;
    s->bytes_per_page[0] = 4096;
    s->bytes_per_page[1] = 4096;
    s->bytes_per_spare[0] = 128;
    s->bytes_per_spare[1] = 128;
    s->pages_per_block[0] = 128;
    s->pages_per_block[1] = 128;

    if (s->doorbell_timer) {
        timer_del(s->doorbell_timer);
    }
}

static void s5l8940_iop_realize(DeviceState *dev, Error **errp)
{
    S5L8940IOPState *s = S5L8940_IOP(dev);

    /* Open backing raw NAND/HFS+ file if provided and regular file */
    if (s->nand_path) {
        struct stat st;
        if (stat(s->nand_path, &st) == 0 && S_ISREG(st.st_mode)) {
            s->raw_file = fopen(s->nand_path, "r+b");
            if (!s->raw_file) {
                s->raw_file = fopen(s->nand_path, "rb");
            }
        }
    }
    if (!s->raw_file) {
        struct stat st;
        if (stat("n94-rootfs.raw", &st) == 0 && S_ISREG(st.st_mode)) {
            s->raw_file = fopen("n94-rootfs.raw", "rb");
        }
    }
    if (!s->raw_file) {
        struct stat st;
        if (stat("n94-rootfs-out/n94-rootfs.raw", &st) == 0 && S_ISREG(st.st_mode)) {
            s->raw_file = fopen("n94-rootfs-out/n94-rootfs.raw", "rb");
        }
    }
}

static void s5l8940_iop_init(Object *obj)
{
    S5L8940IOPState *s = S5L8940_IOP(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    memory_region_init_io(&s->iomem, obj, &s5l8940_iop_ops, s,
                          "s5l8940-iop", S5L8940_IOP_REG_SIZE);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
    qdev_init_gpio_in(DEVICE(obj), s5l8940_iop_doorbell_in, 1);

    s->nand_id = FMI_DEFAULT_NAND_ID;
    s->doorbell_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, s5l8940_iop_doorbell_timer_cb, s);
}

static const Property s5l8940_iop_properties[] = {
    DEFINE_PROP_UINT32("nand-id", S5L8940IOPState, nand_id, FMI_DEFAULT_NAND_ID),
    DEFINE_PROP_STRING("nand", S5L8940IOPState, nand_path),
    DEFINE_PROP_STRING("nand-overlay", S5L8940IOPState, nand_overlay_path),
};

static void s5l8940_iop_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = s5l8940_iop_realize;
    device_class_set_legacy_reset(dc, s5l8940_iop_reset);
    device_class_set_props(dc, s5l8940_iop_properties);
}

static const TypeInfo s5l8940_iop_info = {
    .name          = TYPE_S5L8940_IOP,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(S5L8940IOPState),
    .instance_init = s5l8940_iop_init,
    .class_init    = s5l8940_iop_class_init,
};

static void s5l8940_iop_register_types(void)
{
    type_register_static(&s5l8940_iop_info);
}

type_init(s5l8940_iop_register_types)
