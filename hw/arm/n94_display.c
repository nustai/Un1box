/*
 * Apple S5L8940 Display Controller (CLCD) for iPhone 4S (n94)
 *
 * Copyright (c) 2026 Un1box / n94 Emulation Project
 *
 * Strictly 640x960 Retina (326 ppi). Absolute prohibition on 1024x768 (iPad).
 * MMIO derived from DeviceTree.n94ap.RELEASE ("clcd,s5l8940x"):
 * Base 0: 0x0A100000 (size 0x7000) - Main CLCD control and timing
 * Base 1: 0x09200000 (size 0x2000) - CLCD timing generator
 * Base 2: 0x09300000 (size 0x1000) - CLCD auxiliary registers
 * Interrupts: 0x2b (DisplayPipe), 0x2a (CLCD)
 */

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "hw/core/irq.h"
#include "hw/arm/s5l8940_soc.h"
#include "ui/console.h"
#include "ui/surface.h"
#include "qemu/timer.h"
#include "qemu/log.h"
#include "exec/cpu-common.h"

#define TYPE_N94_DISPLAY "n94-display"
OBJECT_DECLARE_SIMPLE_TYPE(N94DisplayState, N94_DISPLAY)

/* iPhone 4S Physical Panel Specifications */
#define N94_DISPLAY_WIDTH       640
#define N94_DISPLAY_HEIGHT      960
#define N94_DISPLAY_STRIDE      (N94_DISPLAY_WIDTH * 4)

#define N94_CLCD_WORDS          (0x7000 / 4)
#define N94_CLCD_SUB1_WORDS     (0x2000 / 4)
#define N94_CLCD_SUB2_WORDS     (0x1000 / 4)
#define CLCD_IRQ_ENABLE         0x08
#define CLCD_ENVID              0x50
#define CLCD_SIZE               0x60
#define CLCD_IRQ_MASK           0x64
#define CLCD_IRQ_STATUS         0x68
#define CLCD_IRQ_FRAME          0x04
#define PIPE_LAYER_ENABLE       0x1038
#define PIPE_LAYER_BASE(layer)  (0x4000 + (layer) * 0x1000)
#define PIPE_LAYER_FORMAT       0x40
#define PIPE_LAYER_ADDRESS      0x44
#define PIPE_LAYER_PITCH        0x48
#define PIPE_LAYER_SIZE         0x60

struct N94DisplayState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    MemoryRegion iomem_sub1;
    MemoryRegion iomem_sub2;

    QemuConsole *con;
    qemu_irq vblank_irq[2];
    QEMUTimer *vblank_timer;

    uint32_t fb_base;
    uint32_t boot_fb_base;
    uint32_t ctrl;
    uint32_t status;
    bool enabled;

    uint32_t storage[N94_CLCD_WORDS];
    uint32_t storage_sub1[N94_CLCD_SUB1_WORDS];
    uint32_t storage_sub2[N94_CLCD_SUB2_WORDS];
    uint8_t seen_main[N94_CLCD_WORDS];
    uint8_t seen_sub1[N94_CLCD_SUB1_WORDS];
    uint8_t seen_sub2[N94_CLCD_SUB2_WORDS];

    uint32_t pkt_left;
    uint32_t pkt_off;
    uint32_t swap_id;
    bool swap_pending;
};

/* Log up to four reads and writes per register without flooding the trace. */
static void n94_display_trace(uint8_t *seen, hwaddr offset, bool write, uint32_t value,
                              const char *region)
{
    uint8_t *entry = &seen[offset / 4];
    unsigned count = write ? (*entry >> 4) : (*entry & 0xf);
    if (count < 4) {
        *entry += write ? 0x10 : 1;
        qemu_log_mask(LOG_UNIMP, "n94 CLCD %s %s #%u +0x%" HWADDR_PRIx " = 0x%08x\n",
                      region, write ? "write" : "read", count + 1, offset, value);
    }
}

static void n94_display_update(void *opaque)
{
    N94DisplayState *s = opaque;
    DisplaySurface *surface = qemu_console_surface(s->con);
    uint32_t fb = s->fb_base;
    uint32_t pitch = N94_DISPLAY_STRIDE;

    if (!fb) {
        /* N94 uses the A4 DisplayPipe layout. Prefer the upper UI layer
         * when it can supply a full linear ARGB frame. */
        for (int layer = 1; layer >= 0; layer--) {
            uint32_t *regs = &s->storage[PIPE_LAYER_BASE(layer) / 4];
            uint32_t address = regs[PIPE_LAYER_ADDRESS / 4] & ~0x3fu;
            uint32_t stride = regs[PIPE_LAYER_PITCH / 4] & ~0x3fu;
            uint64_t end = (uint64_t)address +
                           (N94_DISPLAY_HEIGHT - 1) * (uint64_t)stride +
                           N94_DISPLAY_STRIDE;

            if ((s->storage[PIPE_LAYER_ENABLE / 4] & (1u << (8 + layer))) &&
                (regs[PIPE_LAYER_FORMAT / 4] & 0x701) == 1 &&
                stride >= N94_DISPLAY_STRIDE && address >= S5L8940_RAM_BASE &&
                end <= (uint64_t)S5L8940_RAM_BASE + S5L8940_RAM_SIZE) {
                fb = address;
                pitch = stride;
                break;
            }
        }
    }
    if (fb < S5L8940_RAM_BASE ||
        (uint64_t)fb + (N94_DISPLAY_HEIGHT - 1) * (uint64_t)pitch +
        N94_DISPLAY_STRIDE > (uint64_t)S5L8940_RAM_BASE + S5L8940_RAM_SIZE) {
        return;
    }

    uint8_t *dest = surface_data(surface);
    if (dest) {
        /* Read directly from guest physical memory into console surface buffer */
        for (unsigned y = 0; y < N94_DISPLAY_HEIGHT; y++) {
            cpu_physical_memory_read(fb + y * pitch,
                                     dest + y * surface_stride(surface), N94_DISPLAY_STRIDE);
        }
        dpy_gfx_update_full(s->con);
    }
}

static void n94_pipe_fifo_write_word(N94DisplayState *s, uint32_t val)
{
    if (s->pkt_left == 0) {
        s->pkt_left = val >> 16;
        s->pkt_off = val & 0xffff;
    } else {
        if (s->pkt_off < 0x7000) {
            s->storage[s->pkt_off / 4] = val;
        }
        s->pkt_off += 4;
        s->pkt_left--;
    }
}

static void n94_pipe_fifo_write(N94DisplayState *s, uint32_t val)
{
    if ((val & 0x80000000) && s->pkt_left == 0) {
        s->swap_id = val & 0xffff;
        s->swap_pending = true;
        return;
    }
    n94_pipe_fifo_write_word(s, val);
}

static void n94_clcd_update_irq(N94DisplayState *s)
{
    const uint32_t *regs = s->storage_sub1;

    qemu_set_irq(s->vblank_irq[1],
                 (regs[CLCD_IRQ_ENABLE / 4] & 1) &&
                 (regs[CLCD_IRQ_STATUS / 4] & regs[CLCD_IRQ_MASK / 4]));
}

static void n94_vblank_tick(void *opaque)
{
    N94DisplayState *s = opaque;

    /* S5L8940 CLCD / AppleDisplayPipe:
     * DPCIRQ (+0x102c):
     * Bit 0: VBL / frame done (DP_IRQ_VBL, 0x001)
     * Bit 1: VBLANK completion (0x002)
     * Bit 8: Swap completed (DP_IRQ_SWAP_DONE, 0x100)
     */
    if (s->swap_pending) {
        s->storage[0x1048 / 4] = (s->storage[0x1048 / 4] & ~0xffff) | s->swap_id;
        s->storage[0x102c / 4] |= 0x103; /* VBL (0x1) + VBLANK (0x2) + SWAP_DONE (0x100) */
        s->swap_pending = false;
    } else {
        s->storage[0x102c / 4] |= 0x03; /* VBL (0x1) + VBLANK (0x2) */
    }

    /* Level IRQ line 0 (0x2b) asserts for unmasked DisplayPipe events. */
    if (s->storage[0x102c / 4] & s->storage[0x1028 / 4]) {
        qemu_irq_raise(s->vblank_irq[0]);
    }

    if (s->storage_sub1[CLCD_ENVID / 4] & 1) {
        s->storage_sub1[CLCD_IRQ_STATUS / 4] |= CLCD_IRQ_FRAME;
        n94_clcd_update_irq(s);
    }

    /* Re-arm for 60 Hz (~16.6 ms) */
    timer_mod(s->vblank_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + (NANOSECONDS_PER_SECOND / 60));
}

/* MMIO Region 0: 0x0A100000:0x7000 (Main Control) */
static uint64_t n94_display_read(void *opaque, hwaddr offset, unsigned size)
{
    N94DisplayState *s = opaque;
    uint32_t val = 0;
    uint32_t word_idx = (offset / 4) % N94_CLCD_WORDS;

    /* TODO(n94): offsets 0x00..0x20 below are diagnostic interface
     * assumptions, not verified S5L8940 CLCD register semantics. Stock
     * 13G37 startup instead accessed offsets including 0x1028 and 0x205c;
     * do not interpret this fallback as a functional hardware driver. */
    switch (offset) {
    case 0x00: /* CLCD Control / Enable */
        val = s->ctrl;
        break;
    case 0x04: /* Status / VBLANK */
        val = s->status | 0x01;
        break;
    case 0x10: /* Framebuffer Base PA */
        val = (s->fb_base != 0) ? s->fb_base : s->boot_fb_base;
        break;
    case 0x14: /* Width strictly 640 */
        val = N94_DISPLAY_WIDTH;
        break;
    case 0x18: /* Height strictly 960 */
        val = N94_DISPLAY_HEIGHT;
        break;
    case 0x1c: /* Stride (640 * 4 = 2560 = 0xA00) */
        val = N94_DISPLAY_STRIDE;
        break;
    case 0x20: /* Pixel format: 32-bit ARGB */
        val = 0x01;
        break;
    case 0x101c: /* DP_FLAGS: return 0 (idle) */
        val = 0;
        break;
    case 0x1044: /* DP_FIFO_COUNT: polled to 0 */
        val = 0;
        break;
    case 0x1048: /* DP_SWAP_DONE: low 16 bits completed swap ID */
        val = s->storage[0x1048 / 4];
        break;
    default:
        val = s->storage[word_idx];
        break;
    }

    n94_display_trace(s->seen_main, offset, false, val, "main");
    return val;
}

static void n94_display_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    N94DisplayState *s = opaque;
    uint32_t word_idx = (offset / 4) % N94_CLCD_WORDS;
    n94_display_trace(s->seen_main, offset, true, (uint32_t)value, "main");
    /* The stock driver reads DPCIRQ at +0x102c, accumulates its bits,
     * then writes those bits back to clear them (W1C).
     * Level IRQ line 0 (0x2b) deasserts when all unmasked bits are cleared. */
    if (offset == 0x103c) {
        n94_pipe_fifo_write(s, (uint32_t)value);
        return;
    }
    if (offset == 0x102c) {
        s->storage[word_idx] &= ~(uint32_t)value;
        if (!(s->storage[0x102c / 4] & s->storage[0x1028 / 4])) {
            qemu_irq_lower(s->vblank_irq[0]);
        }
        return;
    }
    if (offset == 0x1028) {
        s->storage[word_idx] = (uint32_t)value;
        if (s->storage[0x102c / 4] & s->storage[0x1028 / 4]) {
            qemu_irq_raise(s->vblank_irq[0]);
        } else {
            qemu_irq_lower(s->vblank_irq[0]);
        }
        return;
    }
    s->storage[word_idx] = (uint32_t)value;

    switch (offset) {
    case 0x00:
        s->ctrl = (uint32_t)value;
        s->enabled = (s->ctrl & 0x01) != 0;
        break;
    case 0x10:
        s->fb_base = (uint32_t)value;
        break;
    default:
        break;
    }
}

void n94_display_set_boot_framebuffer(DeviceState *dev, uint32_t address)
{
    N94DisplayState *s = N94_DISPLAY(dev);
    uint32_t *ui0 = &s->storage[PIPE_LAYER_BASE(0) / 4];

    s->boot_fb_base = address;
    s->fb_base = 0;

    if (address) {
        /* Use the related S5L8930 model's boot timing defaults until
         * panel-specific porch values are available. Size is N94's. */
        s->storage_sub1[0x00 / 4] = 0x4;
        s->storage_sub1[0x04 / 4] = 0x3;
        s->storage_sub1[0x14 / 4] = 0x81110001;
        s->storage_sub1[0x18 / 4] = 0x20408;
        s->storage_sub1[0x58 / 4] = 9 << 16 | 9 << 8 | 11;
        s->storage_sub1[0x5c / 4] = 132 << 16 | 132 << 8 | 134;
        s->storage_sub1[CLCD_ENVID / 4] = 1;
        s->storage_sub1[CLCD_SIZE / 4] =
            ((N94_DISPLAY_WIDTH - 1) << 16) | (N94_DISPLAY_HEIGHT - 1);
        s->storage[0x1030 / 4] = N94_DISPLAY_WIDTH << 16 | N94_DISPLAY_HEIGHT;
    }

    /* Model the iBoot handoff as a single enabled UI0 layer. */
    s->storage[PIPE_LAYER_ENABLE / 4] = address ? 0x100 : 0;
    s->storage[0x205c / 4] = 0x00000001;
    s->storage[0x2060 / 4] = 0x00000001;
    s->storage[0x2064 / 4] = 0x00000001;
    ui0[PIPE_LAYER_FORMAT / 4] = 1;
    ui0[PIPE_LAYER_ADDRESS / 4] = address;
    ui0[PIPE_LAYER_PITCH / 4] = N94_DISPLAY_STRIDE | 2;
    ui0[PIPE_LAYER_SIZE / 4] = N94_DISPLAY_WIDTH << 16 | N94_DISPLAY_HEIGHT;
}

/* MMIO Region 1: 0x09200000:0x2000 (CLCD timing generator) */
static uint64_t n94_display_sub1_read(void *opaque, hwaddr offset, unsigned size)
{
    N94DisplayState *s = opaque;
    uint32_t word_idx = (offset / 4) % N94_CLCD_SUB1_WORDS;
    uint32_t value = s->storage_sub1[word_idx];
    if (offset == CLCD_ENVID) {
        /* The ready-down bit follows ENVID independently of stored writes. */
        value = (value & ~2u) | ((value & 1) ? 0 : 2);
    }
    n94_display_trace(s->seen_sub1, offset, false, value, "sub1");
    return value;
}

static void n94_display_sub1_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    N94DisplayState *s = opaque;
    uint32_t word_idx = (offset / 4) % N94_CLCD_SUB1_WORDS;
    n94_display_trace(s->seen_sub1, offset, true, (uint32_t)value, "sub1");
    if (offset == CLCD_IRQ_STATUS) {
        s->storage_sub1[word_idx] &= ~(uint32_t)value;
    } else {
        s->storage_sub1[word_idx] = (uint32_t)value;
    }
    n94_clcd_update_irq(s);
}

/* MMIO Region 2: 0x09300000:0x1000 (CLCD auxiliary registers) */
static uint64_t n94_display_sub2_read(void *opaque, hwaddr offset, unsigned size)
{
    N94DisplayState *s = opaque;
    uint32_t word_idx = (offset / 4) % N94_CLCD_SUB2_WORDS;
    uint32_t value = s->storage_sub2[word_idx];
    n94_display_trace(s->seen_sub2, offset, false, value, "sub2");
    return value;
}

static void n94_display_sub2_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    N94DisplayState *s = opaque;
    uint32_t word_idx = (offset / 4) % N94_CLCD_SUB2_WORDS;
    n94_display_trace(s->seen_sub2, offset, true, (uint32_t)value, "sub2");
    s->storage_sub2[word_idx] = (uint32_t)value;
}

static const MemoryRegionOps n94_display_ops = {
    .read = n94_display_read,
    .write = n94_display_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static const MemoryRegionOps n94_display_sub1_ops = {
    .read = n94_display_sub1_read,
    .write = n94_display_sub1_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static const MemoryRegionOps n94_display_sub2_ops = {
    .read = n94_display_sub2_read,
    .write = n94_display_sub2_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static const GraphicHwOps n94_display_gfx_ops = {
    .gfx_update = n94_display_update,
};

static void n94_display_init(Object *obj)
{
    N94DisplayState *s = N94_DISPLAY(obj);
    SysBusDevice *dev = SYS_BUS_DEVICE(obj);

    /* Main CLCD MMIO (0x0A100000:0x7000) */
    memory_region_init_io(&s->iomem, obj, &n94_display_ops, s, "n94-clcd", 0x7000);
    sysbus_init_mmio(dev, &s->iomem);

    /* Subregion 1 (0x09200000:0x2000) */
    memory_region_init_io(&s->iomem_sub1, obj, &n94_display_sub1_ops, s, "n94-clcd-sub1", 0x2000);
    sysbus_init_mmio(dev, &s->iomem_sub1);

    /* Subregion 2 (0x09300000:0x1000) */
    memory_region_init_io(&s->iomem_sub2, obj, &n94_display_sub2_ops, s, "n94-clcd-sub2", 0x1000);
    sysbus_init_mmio(dev, &s->iomem_sub2);

    /* 2 IRQ lines matching DeviceTree interrupts ['0x2b', '0x2a'] */
    sysbus_init_irq(dev, &s->vblank_irq[0]);
    sysbus_init_irq(dev, &s->vblank_irq[1]);

    s->vblank_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, n94_vblank_tick, s);
    timer_mod(s->vblank_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + (NANOSECONDS_PER_SECOND / 60));
}

static void n94_display_realize(DeviceState *dev, Error **errp)
{
    N94DisplayState *s = N94_DISPLAY(dev);
    s->con = graphic_console_init(dev, 0, &n94_display_gfx_ops, s);
    qemu_console_resize(s->con, N94_DISPLAY_WIDTH, N94_DISPLAY_HEIGHT);
}

static void n94_display_reset(DeviceState *dev)
{
    N94DisplayState *s = N94_DISPLAY(dev);
    /* TODO(n94): verify reset values against S5L8940 hardware. */
    s->fb_base = 0;
    s->ctrl = 0;
    s->status = 0;
    s->enabled = false;
    s->pkt_left = 0;
    s->pkt_off = 0;
    s->swap_id = 0;
    s->swap_pending = false;
    memset(s->storage, 0, sizeof(s->storage));
    memset(s->storage_sub1, 0, sizeof(s->storage_sub1));
    memset(s->storage_sub2, 0, sizeof(s->storage_sub2));
    memset(s->seen_main, 0, sizeof(s->seen_main));
    memset(s->seen_sub1, 0, sizeof(s->seen_sub1));
    memset(s->seen_sub2, 0, sizeof(s->seen_sub2));
    qemu_irq_lower(s->vblank_irq[0]);
    qemu_irq_lower(s->vblank_irq[1]);
    if (s->boot_fb_base) {
        n94_display_set_boot_framebuffer(dev, s->boot_fb_base);
    }
}

static void n94_display_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = n94_display_realize;
    device_class_set_legacy_reset(dc, n94_display_reset);
}

static const TypeInfo n94_display_info = {
    .name          = TYPE_N94_DISPLAY,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(N94DisplayState),
    .instance_init = n94_display_init,
    .class_init    = n94_display_class_init,
};

static void n94_display_register_types(void)
{
    type_register_static(&n94_display_info);
}

type_init(n94_display_register_types)
