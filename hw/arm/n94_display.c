/*
 * Apple S5L8940 Display Controller (CLCD) for iPhone 4S (n94)
 *
 * Copyright (c) 2026 Un1box / n94 Emulation Project
 *
 * Strictly 640x960 Retina (326 ppi). Absolute prohibition on 1024x768 (iPad).
 * MMIO derived from DeviceTree.n94ap.RELEASE ("clcd,s5l8940x"):
 * Base 0: 0x0A100000 (size 0x7000) - Main CLCD control and timing
 * Base 1: 0x09200000 (size 0x2000) - Overlay / Window 0
 * Base 2: 0x09300000 (size 0x1000) - Overlay / Window 1
 * Interrupts: 0x2b (Line 0, VBLANK), 0x2a (Line 1, FIFO/DMA)
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
#define N94_DISPLAY_BPP         32
#define N94_DISPLAY_STRIDE      (N94_DISPLAY_WIDTH * 4)
#define N94_DISPLAY_FB_SIZE     (N94_DISPLAY_STRIDE * N94_DISPLAY_HEIGHT) /* 2,457,600 bytes */

#define N94_CLCD_WORDS          (0x7000 / 4)
#define N94_CLCD_SUB1_WORDS     (0x2000 / 4)
#define N94_CLCD_SUB2_WORDS     (0x1000 / 4)

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
    bool guest_configured;

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
    if (!fb || fb < 0x80000000 || fb >= 0xa0000000) {
        fb = s->storage[0x5048 / 4];
    }
    if (!fb || fb < 0x80000000 || fb >= 0xa0000000) {
        fb = s->storage[0x4048 / 4];
    }
    if (!fb || fb < 0x80000000 || fb >= 0xa0000000) {
        fb = s->storage[0x5044 / 4];
    }
    if (!fb || fb < 0x80000000 || fb >= 0xa0000000) {
        fb = s->storage[0x4044 / 4];
    }
    if (!fb || fb < 0x80000000 || fb >= 0xa0000000) {
        fb = s->boot_fb_base;
    }
    if (!fb) {
        return;
    }

    uint8_t *dest = surface_data(surface);
    if (dest) {
        /* Read directly from guest physical memory into console surface buffer */
        for (unsigned y = 0; y < N94_DISPLAY_HEIGHT; y++) {
            cpu_physical_memory_read(fb + y * N94_DISPLAY_STRIDE,
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
            if (s->pkt_off >= 0x4000 && s->pkt_off < 0x6000) {
                uint32_t base = val & ~0x3f;
                if (base >= 0x80000000 && base < 0xa0000000) {
                    s->fb_base = base;
                    s->guest_configured = true;
                    if (s->storage[0x1028 / 4] == 0) {
                        s->storage[0x1028 / 4] = 0x0001fa43;
                    }
                }
            }
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

    /* Level IRQ line 0 (0x2b) asserts if any active status bit is enabled,
     * but only after guest driver has initialized and configured the hardware. */
    if (s->guest_configured && (s->storage[0x102c / 4] & s->storage[0x1028 / 4])) {
        qemu_irq_raise(s->vblank_irq[0]);
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
    case 0x1038: /* DPCENAB */
        val = s->storage[word_idx] ? s->storage[word_idx] : 0x00000201;
        break;
    case 0x4040: /* DPU1SRCFMT */
        val = s->storage[word_idx];
        break;
    case 0x4044: /* DPU1SRCSIZE */
        val = s->storage[word_idx] ? s->storage[word_idx] : ((640 << 16) | 960);
        break;
    case 0x4048: /* DPU1SRCBASE */
        val = s->storage[word_idx] ? s->storage[word_idx] : s->boot_fb_base;
        s->guest_configured = true;
        if (s->storage[0x1028 / 4] == 0) {
            s->storage[0x1028 / 4] = 0x0001fa43;
        }
        break;
    case 0x404c: /* DPU1SRCPITCH */
        val = s->storage[word_idx] ? s->storage[word_idx] : N94_DISPLAY_STRIDE;
        break;
    case 0x4060: /* DPU1 Crop start */
        val = s->storage[word_idx];
        break;
    case 0x4070: /* DPU1 Crop end */
        val = s->storage[word_idx] ? s->storage[word_idx] : ((640 << 16) | 960);
        break;
    case 0x5048: /* DPU0SRCBASE */
        val = s->storage[word_idx] ? s->storage[word_idx] : s->boot_fb_base;
        s->guest_configured = true;
        if (s->storage[0x1028 / 4] == 0) {
            s->storage[0x1028 / 4] = 0x0001fa43;
        }
        break;
    case 0x5040: /* DPU0SRCFMT */
        val = s->storage[word_idx];
        break;
    case 0x5044: /* DPU0SRCSIZE */
        val = s->storage[word_idx] ? s->storage[word_idx] : ((640 << 16) | 960);
        break;
    case 0x504c: /* DPU0SRCPITCH */
        val = s->storage[word_idx] ? s->storage[word_idx] : N94_DISPLAY_STRIDE;
        break;
    case 0x5060: /* Crop start */
        val = s->storage[word_idx];
        break;
    case 0x5070: /* Crop end */
        val = s->storage[word_idx] ? s->storage[word_idx] : ((640 << 16) | 960);
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
        if (value != 0) {
            s->guest_configured = true;
        }
        if (s->guest_configured && (s->storage[0x102c / 4] & s->storage[0x1028 / 4])) {
            qemu_irq_raise(s->vblank_irq[0]);
        } else {
            qemu_irq_lower(s->vblank_irq[0]);
        }
        return;
    }
    s->storage[word_idx] = (uint32_t)value;

    switch (offset) {
    case 0x00:
        s->guest_configured = true;
        s->ctrl = (uint32_t)value;
        s->enabled = (s->ctrl & 0x01) != 0;
        break;
    case 0x10:
        s->fb_base = (uint32_t)value;
        break;
    case 0x5048: /* DPU0SRCBASE */
    case 0x4048: /* DPU1SRCBASE */
        {
            uint32_t base = (uint32_t)(value & ~0x3f);
            if (base >= 0x80000000 && base < 0xa0000000) {
                s->fb_base = base;
                s->guest_configured = true;
                if (s->storage[0x1028 / 4] == 0) {
                    s->storage[0x1028 / 4] = 0x0001fa43;
                }
            }
        }
        break;
    default:
        if (value >= 0x80000000 && value < 0xa0000000 && (value & 0xfff) == 0) {
            s->fb_base = (uint32_t)value;
            s->guest_configured = true;
        }
        break;
    }
}

void n94_display_set_boot_framebuffer(DeviceState *dev, uint32_t address)
{
    N94DisplayState *s = N94_DISPLAY(dev);
    s->boot_fb_base = address;
    s->fb_base = address;
    s->guest_configured = false;

    /* S5L8940 CLCD / AppleDisplayPipe default bootloader (iBoot) hardware state:
     * DPCIRQ (+0x102c): initial status 0.
     * DPCENAB (+0x1038): LCD enabled (bit 0) and DPU0 enabled (bit 9, 0x200).
     */
    s->storage[0x1038 / 4] = 0x00000201;
    s->storage[0x205c / 4] = 0x00000001;
    s->storage[0x2060 / 4] = 0x00000001;
    s->storage[0x2064 / 4] = 0x00000001;
    s->storage[0x5040 / 4] = 0x00000000;
    s->storage[0x5044 / 4] = (640 << 16) | 960;
    s->storage[0x5048 / 4] = address;
    s->storage[0x504c / 4] = N94_DISPLAY_STRIDE;
    s->storage[0x5060 / 4] = 0x00000000;
    s->storage[0x5070 / 4] = (640 << 16) | 960;
    s->storage[0x4040 / 4] = 0x00000000;
    s->storage[0x4044 / 4] = (640 << 16) | 960;
    s->storage[0x4048 / 4] = address;
    s->storage[0x404c / 4] = N94_DISPLAY_STRIDE;
    s->storage[0x4060 / 4] = 0x00000000;
    s->storage[0x4070 / 4] = (640 << 16) | 960;
}

/* MMIO Region 1: 0x09200000:0x2000 (Overlay 0 / Subregion 1) */
static uint64_t n94_display_sub1_read(void *opaque, hwaddr offset, unsigned size)
{
    N94DisplayState *s = opaque;
    uint32_t word_idx = (offset / 4) % N94_CLCD_SUB1_WORDS;
    uint32_t value = s->storage_sub1[word_idx];
    n94_display_trace(s->seen_sub1, offset, false, value, "sub1");
    return value;
}

static void n94_display_sub1_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    N94DisplayState *s = opaque;
    uint32_t word_idx = (offset / 4) % N94_CLCD_SUB1_WORDS;
    n94_display_trace(s->seen_sub1, offset, true, (uint32_t)value, "sub1");
    s->storage_sub1[word_idx] = (uint32_t)value;

    /* If overlay / window 0 points to a new surface in guest RAM */
    if (value >= 0x80000000 && value < 0xa0000000 && (value & 0xfff) == 0) {
        s->fb_base = (uint32_t)value;
        s->guest_configured = true;
    }
}

/* MMIO Region 2: 0x09300000:0x1000 (Overlay 1 / Subregion 2) */
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

    /* If overlay / window 1 points to a new surface in guest RAM */
    if (value >= 0x80000000 && value < 0xa0000000 && (value & 0xfff) == 0) {
        s->fb_base = (uint32_t)value;
        s->guest_configured = true;
    }
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
    s->guest_configured = false;
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
