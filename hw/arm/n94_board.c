/*
 * Apple iPhone 4S (n94 / N94AP) Machine Emulation
 *
 * Copyright (c) 2026 Un1box / n94 Emulation Project
 *
 * Written strictly from scratch for iPhone 4S (n94, S5L8940, Cortex-A9 MPCore).
 * Absolute prohibition on n90 (iPhone 4) or iPad code/parameters.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/core/boards.h"
#include "hw/core/sysbus.h"
#include "hw/core/qdev-properties.h"
#include "system/address-spaces.h"
#include "system/reset.h"
#include "exec/cpu-common.h"
#include "hw/core/loader.h"
#include "qemu/error-report.h"
#include "target/arm/cpu.h"
#include "hw/arm/boot.h"
#include "system/system.h"
#include "hw/arm/machines-qom.h"
#include "hw/arm/s5l8940_soc.h"

#define TYPE_N94_MACHINE MACHINE_TYPE_NAME("n94")
#define TYPE_IPHONE4S_MACHINE MACHINE_TYPE_NAME("iPhone-4S")
OBJECT_DECLARE_SIMPLE_TYPE(N94MachineState, N94_MACHINE)

#define N94_KBOOT_MAGIC "N94KBOOT"
#define K48_KBOOT_MAGIC "K48KBOOT"
#define KBOOT_TRAILER_LEN 24
#define S5L8940_IBOOT_BASE 0x9ff00000U
#define N94_BOOTARGS_PA (S5L8940_RAM_BASE + 0x00700000U)
#define N94_DEVICETREE_PA (S5L8940_RAM_BASE + 0x00800000U)
#define N94_FB_BASE (S5L8940_RAM_BASE + 0x0FD00000U)

/* Apple ARM struct boot_args passed in R0 to kernel entry */
struct n94_boot_args {
    uint16_t Revision;
    uint16_t Version;
    uint32_t virtBase;
    uint32_t physBase;
    uint32_t memSize;
    uint32_t topOfKernelData;
    struct {
        uint32_t v_baseAddr;
        uint32_t v_display;
        uint32_t v_rowBytes;
        uint32_t v_width;
        uint32_t v_height;
        uint32_t v_depth;
    } video;
    uint32_t machineType;
    uint32_t deviceTreeP;
    uint32_t deviceTreeLength;
    char cmdline[256];
    /* Extended XNU arm32 / iOS 9.3.6 (xnu-3248) fields */
    uint32_t bootFlags;
    uint32_t memSizeActual;
    uint64_t kernEntry;
    uint64_t kernPhys;
    char kernelVersion[256];
    char memoryPanicLog[2048];
    uint64_t panicData;
};

struct N94MachineState {
    MachineState parent_obj;
    S5L8940State soc;
    MemoryRegion ram;

    /* Boot targets */
    uint32_t kernel_entry;
    uint32_t bootargs_pa;

    /* Configurable properties matching Un1box Portable invocation */
    char *kboot_path;
    char *iboot_path;
    char *nor_path;
    char *nand_path;
    char *nand_overlay_path;
    bool baseband;
};

/* Mach-O 32-bit loader for iOS xnu kernelcache */
static uint32_t n94_load_macho(const char *filename)
{
    FILE *f = fopen(filename, "rb");
    if (!f) {
        error_report("n94_load_macho: cannot open kernelcache %s", filename);
        return 0;
    }

    struct n94_mach_header {
        uint32_t magic;
        uint32_t cputype;
        uint32_t cpusubtype;
        uint32_t filetype;
        uint32_t ncmds;
        uint32_t sizeofcmds;
        uint32_t flags;
    } header;

    if (fread(&header, sizeof(header), 1, f) != 1) {
        error_report("n94_load_macho: failed to read Mach-O header");
        fclose(f);
        return 0;
    }

    if (header.magic != 0xfeedface || header.cputype != 12 /* ARM */) {
        error_report("n94_load_macho: invalid Mach-O (magic=0x%08x, cputype=%d)",
                     header.magic, header.cputype);
        fclose(f);
        return 0;
    }

    uint8_t *cmd_buf = g_malloc(header.sizeofcmds);
    if (fread(cmd_buf, 1, header.sizeofcmds, f) != header.sizeofcmds) {
        error_report("n94_load_macho: failed to read load commands");
        g_free(cmd_buf);
        fclose(f);
        return 0;
    }

    uint32_t entry_point = 0;
    uint32_t offset = 0;

    for (uint32_t i = 0; i < header.ncmds && offset < header.sizeofcmds; i++) {
        uint32_t cmd = *(uint32_t *)(cmd_buf + offset);
        uint32_t cmdsize = *(uint32_t *)(cmd_buf + offset + 4);

        if (cmd == 0x1 /* LC_SEGMENT */) {
            uint32_t vmaddr = *(uint32_t *)(cmd_buf + offset + 24);
            uint32_t vmsize = *(uint32_t *)(cmd_buf + offset + 28);
            uint32_t fileoff = *(uint32_t *)(cmd_buf + offset + 32);
            uint32_t filesize = *(uint32_t *)(cmd_buf + offset + 36);

            if (filesize > 0) {
                fseek(f, fileoff, SEEK_SET);
                uint8_t *seg_buf = g_malloc(filesize);
                if (fread(seg_buf, 1, filesize, f) == filesize) {
                    cpu_physical_memory_write(vmaddr, seg_buf, filesize);
                }
                g_free(seg_buf);
            }
            if (vmsize > filesize) {
                uint32_t bss = vmsize - filesize;
                uint8_t *zero_buf = g_malloc0(bss);
                cpu_physical_memory_write(vmaddr + filesize, zero_buf, bss);
                g_free(zero_buf);
            }
        } else if (cmd == 0x5 /* LC_UNIXTHREAD */) {
            /* ARM register state: PC is register 15 (offset 16 + 15 * 4 = 76) */
            entry_point = *(uint32_t *)(cmd_buf + offset + 76);
        }

        offset += cmdsize;
    }

    g_free(cmd_buf);
    fclose(f);
    return entry_point;
}

static void n94_reset(void *opaque)
{
    N94MachineState *s = opaque;
    ARMCPU *cpu0 = &s->soc.cpu[0];
    CPUARMState *env = &cpu0->env;

    /* 1. Reset PC to entry point */
    if (s->kernel_entry) {
        env->regs[15] = s->kernel_entry;
    }

    /* 2. SP = RAM + 0x100000 */
    env->regs[13] = S5L8940_RAM_BASE + 0x00100000;

    /* 3. R0 = bootargs physical address as expected by Apple _start */
    env->regs[0] = s->bootargs_pa ? s->bootargs_pa : N94_BOOTARGS_PA;

    /* 4. CPSR = 0x000000D3 (Supervisor mode, IRQ/FIQ disabled, ARM state) */
    cpsr_write(env, 0x000000D3, 0xffffffff, CPSRWriteRaw);

    /* 5. VBAR = 0x80000000 (Vector Base Address Register) */
    env->cp15.vbar_el[1] = S5L8940_RAM_BASE;
}

static void n94_init(MachineState *machine)
{
    N94MachineState *s = N94_MACHINE(machine);
    MemoryRegion *sysmem = get_system_memory();

    /* 1. Allocate 512 MB LPDDR2 RAM */
    if (machine->ram_size != S5L8940_RAM_SIZE) {
        machine->ram_size = S5L8940_RAM_SIZE;
    }
    memory_region_init_ram(&s->ram, OBJECT(machine), "n94.ram", S5L8940_RAM_SIZE, &error_fatal);
    memory_region_add_subregion(sysmem, S5L8940_RAM_BASE, &s->ram);

    /* 2. Initialize S5L8940 SoC */
    object_initialize_child(OBJECT(machine), "soc", &s->soc, TYPE_S5L8940_SOC);

    /* Connect UART1 serial console to chardev */
    if (serial_hd(0)) {
        qdev_prop_set_chr(DEVICE(s->soc.uart1), "chardev", serial_hd(0));
    }

    /* Realize SoC */
    sysbus_realize(SYS_BUS_DEVICE(&s->soc), &error_fatal);

    /* 3. Boot path selection: kboot bundle, iBoot binary, or direct kernelcache */
    if (s->kboot_path) {
        FILE *kf = fopen(s->kboot_path, "rb");
        if (kf) {
            fseek(kf, 0, SEEK_END);
            long ksize = ftell(kf);
            if (ksize >= KBOOT_TRAILER_LEN) {
                fseek(kf, ksize - KBOOT_TRAILER_LEN, SEEK_SET);
                uint8_t trailer[KBOOT_TRAILER_LEN];
                if (fread(trailer, 1, KBOOT_TRAILER_LEN, kf) == KBOOT_TRAILER_LEN) {
                    if (memcmp(trailer, N94_KBOOT_MAGIC, 8) != 0 &&
                        memcmp(trailer, K48_KBOOT_MAGIC, 8) != 0) {
                        error_report("n94: invalid kboot magic");
                        fclose(kf);
                        return;
                    }
                    uint32_t load_pa = *(uint32_t *)(trailer + 8);
                    uint32_t entry_pa = *(uint32_t *)(trailer + 12);
                    uint32_t bootargs_pa = *(uint32_t *)(trailer + 16);
                    uint32_t image_len = *(uint32_t *)(trailer + 20);

                    fseek(kf, 0, SEEK_SET);
                    uint8_t *kbuf = g_malloc(image_len);
                    if (fread(kbuf, 1, image_len, kf) == image_len) {
                        cpu_physical_memory_write(load_pa, kbuf, image_len);
                        s->kernel_entry = entry_pa;
                        s->bootargs_pa = bootargs_pa;
                    }
                    g_free(kbuf);
                }
            }
            fclose(kf);
        }
    } else if (s->iboot_path) {
        /* iBoot stage into link address */
        load_image_targphys(s->iboot_path, S5L8940_IBOOT_BASE, 0x1000000, &error_fatal);
        s->kernel_entry = S5L8940_IBOOT_BASE;
        s->bootargs_pa = 0;
    } else if (machine->kernel_filename) {
        /* Direct kernelcache + DeviceTree loading */
        s->kernel_entry = n94_load_macho(machine->kernel_filename);

        uint32_t dt_len = 0x80000;
        if (machine->dtb) {
            ssize_t loaded = load_image_targphys(machine->dtb, N94_DEVICETREE_PA, 0x100000, &error_fatal);
            if (loaded > 0) {
                dt_len = (uint32_t)loaded;
            }
        }

        /* Populate struct n94_boot_args in guest RAM */
        struct n94_boot_args ba;
        memset(&ba, 0, sizeof(ba));
        ba.Revision = 1;
        ba.Version = 2;
        ba.virtBase = S5L8940_RAM_BASE;
        ba.physBase = S5L8940_RAM_BASE;
        ba.memSize = S5L8940_RAM_SIZE;
        ba.topOfKernelData = S5L8940_RAM_BASE + 0x02000000U;
        ba.video.v_baseAddr = N94_FB_BASE;
        ba.video.v_display = 1;
        ba.video.v_rowBytes = 640 * 4;
        ba.video.v_width = 640;
        ba.video.v_height = 960;
        ba.video.v_depth = 32;
        ba.machineType = 0x8940;
        ba.deviceTreeP = N94_DEVICETREE_PA;
        ba.deviceTreeLength = dt_len;
        snprintf(ba.cmdline, sizeof(ba.cmdline), "-v serial=3 debug=0x14e");
        ba.bootFlags = 0;
        ba.memSizeActual = S5L8940_RAM_SIZE;
        ba.kernEntry = s->kernel_entry;
        ba.kernPhys = S5L8940_RAM_BASE;
        snprintf(ba.kernelVersion, sizeof(ba.kernelVersion), "Darwin Kernel Version 15.6.0: Wed Jun 22 23:36:13 PDT 2016; root:xnu-3248.61.1~1/RELEASE_ARM_S5L8940X");
        memset(ba.memoryPanicLog, 0, sizeof(ba.memoryPanicLog));
        ba.panicData = 0;

        cpu_physical_memory_write(N94_BOOTARGS_PA, &ba, sizeof(ba));
        s->bootargs_pa = N94_BOOTARGS_PA;
    }

    qemu_register_reset(n94_reset, s);
}

static char *n94_get_kboot(Object *obj, Error **errp)
{
    return g_strdup(N94_MACHINE(obj)->kboot_path);
}

static void n94_set_kboot(Object *obj, const char *value, Error **errp)
{
    N94MachineState *s = N94_MACHINE(obj);
    g_free(s->kboot_path);
    s->kboot_path = g_strdup(value);
}

static char *n94_get_iboot(Object *obj, Error **errp)
{
    return g_strdup(N94_MACHINE(obj)->iboot_path);
}

static void n94_set_iboot(Object *obj, const char *value, Error **errp)
{
    N94MachineState *s = N94_MACHINE(obj);
    g_free(s->iboot_path);
    s->iboot_path = g_strdup(value);
}

static char *n94_get_nor(Object *obj, Error **errp)
{
    return g_strdup(N94_MACHINE(obj)->nor_path);
}

static void n94_set_nor(Object *obj, const char *value, Error **errp)
{
    N94MachineState *s = N94_MACHINE(obj);
    g_free(s->nor_path);
    s->nor_path = g_strdup(value);
}

static bool n94_get_baseband(Object *obj, Error **errp)
{
    return N94_MACHINE(obj)->baseband;
}

static void n94_set_baseband(Object *obj, bool value, Error **errp)
{
    N94_MACHINE(obj)->baseband = value;
}

static void n94_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "Apple iPhone 4S (n94 / N94AP / S5L8940 / iOS 9.3.6)";
    mc->init = n94_init;
    mc->max_cpus = 2;
    mc->default_cpus = 2;
    mc->min_cpus = 1;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-a9");
    mc->default_ram_size = S5L8940_RAM_SIZE;
    mc->default_ram_id = "n94.ram";

    object_class_property_add_str(oc, "kboot", n94_get_kboot, n94_set_kboot);
    object_class_property_add_str(oc, "iboot", n94_get_iboot, n94_set_iboot);
    object_class_property_add_str(oc, "nor-rw", n94_get_nor, n94_set_nor);
    object_class_property_add_bool(oc, "baseband", n94_get_baseband, n94_set_baseband);
}

static const TypeInfo n94_machines_info[] = {
    {
        .name          = TYPE_N94_MACHINE,
        .parent        = TYPE_MACHINE,
        .interfaces    = arm_machine_interfaces,
        .instance_size = sizeof(N94MachineState),
        .class_init    = n94_class_init,
    },
    {
        .name          = TYPE_IPHONE4S_MACHINE,
        .parent        = TYPE_MACHINE,
        .interfaces    = arm_machine_interfaces,
        .instance_size = sizeof(N94MachineState),
        .class_init    = n94_class_init,
    },
};

static void n94_register_types(void)
{
    for (size_t i = 0; i < ARRAY_SIZE(n94_machines_info); i++) {
        type_register_static(&n94_machines_info[i]);
    }
}

type_init(n94_register_types)
