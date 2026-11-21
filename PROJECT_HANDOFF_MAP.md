# Un1box iPhone 4S (n94 / S5L8940) iOS 9.3.6: Master Agent Handoff Manual & Technical Roadmap

> **CONFIDENTIAL & AUTHORITATIVE HANDOFF DOCUMENT FOR THE NEXT AI / ENGINEER**  
> **Project Goal:** Boot stock Apple **iOS 9.3.6 (13G37)** on **iPhone 4S** (`iPhone4,1`, board `n94`, SoC `S5L8940` / Apple A5) until the authentic stock iOS 9 lock screen is natively rendered, and deliver the working Android APK (`org.un1box.android`).

---

## 1. Executive Summary & Project Status

### Target Hardware & Firmware Specifications:
- **Device:** iPhone 4S (`iPhone4,1`, board `n94`, board-id `N94AP`).
- **SoC:** Apple A5 (`S5L8940`, 45nm).
- **CPU:** Dual-core ARM Cortex-A9 MPCore @ 800 MHz (ARMv7-A, VFPv3-D32, NEON).
- **RAM:** 512 MB LPDDR2, Physical Base `0x80000000`, Top of RAM `0xa0000000`.
- **Display:** 3.5" IPS LCD, **640×960 Retina** (326 ppi). Framebuffer at `0x8FD00000` (2,457,600 bytes, 32-bit ARGB/BGRA).
- **OS / Kernel:** iOS 9.3.6 (Build 13G37), Darwin Kernel Version 15.6.0 (XNU 3248.61.1).

### Current State of the Emulator:
- **Low-Level Hardware & Kernel (100% REAL & VERIFIED):**
  - Real Dual-Core Cortex-A9 SMP bootloader handoff (`s5l8940_soc.c`).
  - Real Apple Interrupt Controller (`s5l8940_aic.c`) at `0x20800000`.
  - Real Apple Power Manager (`s5l8940_pmgr.c`) at `0x21000000` with clock gates.
  - Real CLCD display controller (`n94_display.c`) at `0x0A100000`, subregions `0x09200000` & `0x09300000`, 60 Hz VBLANK IRQ `0x2b`.
  - Real Apple NAND Storage Stack (`s5l8940_fmi.c`, `s5l8940_iop.c`) initializing IOKit `IOFlashStorageDevice`.
  - Real Darwin Kernel boots official Apple `kernelcache.release.n94` past platform expert, runs 95 active threads, and reaches userspace (`usr32` / `dyld` / `launchd`).
- **Android APK Package (100% READY):**
  - Pre-built, signed, and verified Android APK package `org.un1box.android` (67.9 MB) located at:
    - Workspace: `fresh_apk/Un1box-perf-apk-8402d7bfb71337667ec5d1aa87349aed9fa5cfeb/Un1box-cde3b3b-arm64-debug.apk`
    - User Desktop: `C:\Users\User\Desktop\Un1box-cde3b3b-arm64-debug.apk`.
- **The Graphics Rendering Truth & Current Blocker:**
  - In real iOS, `SpringBoard` and `backboardd` render via QuartzCore (`EAGLServer` / `SWContext`).
  - Apple A5 has a PowerVR SGX543 GPU. Emulation of the SGX543 silicon does not exist in any open-source emulator.
  - **The Solution discovered in `qemu_ios_repo/docs/research/userland-gl-display.md`:** QuartzCore contains a built-in CPU software renderer (`CA::OGL::SWContext`). When the `sgx` node is removed or disabled from DeviceTree, QuartzCore automatically falls back to `SWContext` and renders directly into the display's pixels (`set_destination` on `Surface`) without needing any GPU!

---

## 2. Directory Structure & Key Files

```
e:\uni9ios — копия\
├── AGENTS.md                                   # Global guidelines and hardware specs
├── PROJECT_HANDOFF_MAP.md                      # THIS DOCUMENT (Master handoff)
├── bin\gh.exe                                  # GitHub CLI binary (authenticated as nustai)
├── fresh_apk\                                  # Android APK (Un1box-cde3b3b-arm64-debug.apk)
├── hw\arm\                                     # MIRRORED hardware models (*.c, *.h)
├── un1box_repo\                                # AUTHORITATIVE GIT REPOSITORY
│   ├── .github\workflows\
│   │   ├── n94-qemu-check.yml                 # Builds QEMU and runs smoke/kernel probe
│   │   └── n94-kernel-probe.yml               # Standalone kernel diagnostic probe
│   ├── ci\
│   │   ├── n94_prepare_kernel.py              # Firmware unpacker, DeviceTree & kernel patcher
│   │   ├── n94_kernel_probe.py                # Automated QMP kernel execution & screendump
│   │   ├── n94_display_test.py                # CLCD display register & framebuffer test
│   │   ├── n94_smoke.py                       # ARM payload execution test
│   │   └── n94_cdma_test.py                   # DMA test
│   └── hw\arm\                                # Active C hardware models:
│       ├── n94_board.c                        # iPhone 4S machine model & kboot handoff
│       ├── n94_display.c                      # S5L8940 CLCD controller & VBLANK IRQ
│       ├── s5l8940_soc.[ch]                   # A5 SoC, SMP CPU1 release, memory map
│       ├── s5l8940_aic.[ch]                   # Apple Interrupt Controller (0x20800000)
│       ├── s5l8940_pmgr.[ch]                  # Power Manager (0x21000000)
│       ├── s5l8940_fmi.[ch]                   # Flash Memory Interface (0x20500000)
│       └── s5l8940_iop.[ch]                   # IOP storage co-processor (0x20580000)
├── qemu_ios_repo\                              # Upstream reference QEMU checkout & research docs
│   └── docs\research\
│       ├── userland-boot.md                   # How SpringBoard boots to lock screen
│       ├── userland-gl-display.md             # QuartzCore GPU-less SWContext & GLES shim
│       └── gap-display-stack-kernel.md        # AppleDisplayPipe & CLCD kernel contract
├── n94_traces_44937921148\                    # Latest verified traces (5m 31s, 0 errors)
│   └── n94-traces\bootargs-v2\
│       ├── screen.ppm                         # Framebuffer dump from QMP screendump
│       ├── boot-framebuffer.raw               # Raw DRAM dump at 0x8fd00000 (2,457,600 bytes)
│       ├── qemu.log                           # Full QEMU MMIO execution trace
│       ├── uart.log                           # Darwin kernel serial console log
│       └── summary.json                       # Execution status & metrics
└── unibox9iosbackup\                          # FROZEN RECOVERY BACKUP (NEVER TOUCH!)
```

---

## 3. GitHub & CI Infrastructure

- **GitHub CLI:** `./bin/gh.exe`
- **Authenticated Account:** `nustai` (scopes: `repo`, `workflow`, `read:org`, `gist`).
- **Repositories:**
  - **Public Fork (Primary CI Runner):** `https://github.com/nustai/Un1box` (tracked as remote `public` in `un1box_repo`).
    - *Why this repo:* It is a **PUBLIC fork** of `KlugKlugTG/Un1box`. Public repositories have **100% FREE AND UNLIMITED GITHUB ACTIONS MINUTES**. No spending limits or billing blocks!
  - **Private Repo (Secondary):** `https://github.com/nustai/un1box-n94` (tracked as remote `origin`).
    - *Note:* Currently exhausted its 2,000 monthly free private minutes.

### Triggering CI Runs:
1. **Full QEMU Build + Kernel Probe in One Run:**
   ```powershell
   ./bin/gh.exe workflow run n94-qemu-check.yml --repo nustai/Un1box -f kernel_probe=true
   ```
2. **Check Workflow Runs:**
   ```powershell
   ./bin/gh.exe run list --repo nustai/Un1box --limit 3
   ```
3. **Download Artifacts:**
   ```powershell
   ./bin/gh.exe run download <run_id> --repo nustai/Un1box --dir n94_traces_<run_id>
   ```

---

## 4. Firmware Decryption Keys (iOS 9.3.6 13G37 - iPhone4,1)

- **IPSW Download URL:**
  `https://updates.cdn-apple.com/2019/ios/041-80043-20190722-6C65AD27-69D8-499C-BC15-DE7AC74DE2BD/iPhone4,1_9.3.6_13G37_Restore.ipsw`
- **iBSS:** `Key: 797c028a5c95a8980c762f63698ea71b26b98a2f01b8572d81e72a645bb44395`, `IV: d76439252e683a3c5728ba340c45672a`
- **iBEC:** `Key: 2ecd834e6005b10acd77d98827f0ab0f302fc599c268b4795fde4c1a47ce081e`, `IV: d76439252e683a3c5728ba340c45672a`
- **DeviceTree:** `Key: 0df08ae913ef8109fe9d7c9b69c29836dadb5d74dbfe7d5ae12c0679cac33ed5`, `IV: ed62c1631514e485fbd2db0b616f1d98`
- **Kernelcache:** `Key: a90b2e894db15c583f0146e4762f667ae5a54002e357279f2688dac0695849b7`, `IV: 23b0d1ab552c95b2d920f3847ecff985`
- **RestoreRamdisk:** `Key: 06d072f749625566c525fb118cb691da2121227777ce7f1244822530a590ce99`, `IV: 0d4237e65a21e7177c40dd1f1e435f1c`
- **RootFS DMG Key:** `66aa77da612711b942ff984d91d7a657c57bb3510b284c592b86d0f93587fe09884ec669`

---

## 5. Critical Technical Rules & Solved Pitfalls

1. **CRITICAL RECOVERY RULE:** Never touch, edit, or delete `unibox9iosbackup/`. It is a frozen recovery baseline.
2. **Hardware Mirroring Rule:** Every time a file in `un1box_repo/hw/arm/*.[ch]` is modified, immediately copy it to the root:
   ```powershell
   Copy-Item -Path "un1box_repo/hw/arm/*.[ch]" -Destination "hw/arm/" -Force
   ```
3. **Byte Invariance in Kernel Mach-O:**
   When patching `__PRELINK_INFO` XML in `kernelcache.release.n94` (`ci/n94_prepare_kernel.py`), the replaced string MUST match the exact length of the original string. Expanding by even 1 byte corrupts the trailing XML tags, causing `OSUnserializeXML` to panic: `Unable to find driver for this platform: "N94AP"`.
4. **DeviceTree `ppn-device` Property:**
   Must be a 4-byte `u32(1)` integer, not a 0-length boolean, otherwise `getBytesNoCopy()` in `IOFlashStorageDevice::init` returns NULL causing a kernel data abort (`fault_addr=0x0`).
5. **Secondary CPU Entry:**
   CPU 1 starts at `0x800c7400` and MUST receive `boot_args` physical address (`0x8126c000`) in register `r0` to properly initialize `TTBR1`.

---

## 6. Action Plan to Render Real SpringBoard Lock Screen

The architecture is already 80% there. To achieve genuine, non-injected SpringBoard rendering:

### Step 1: Disable `sgx` in DeviceTree (Activate Software CoreAnimation)
As documented in `qemu_ios_repo/docs/research/userland-gl-display.md`:
In `ci/n94_prepare_kernel.py`:
- Pass `--diagnostic-no-sgx` to remove `arm-io/sgx` from DeviceTree.
- When `sgx` is absent, the kernel does not search for `IOAcceleratorES`, and QuartzCore falls back to `CA::OGL::SWContext` (`Server::sw_renderer()`).
- `SWContext::make_buffer_current` locks the display's page Surface and renders into its pixels directly via CPU. **It needs no GPU and no scaler!**

### Step 2: Ensure Root Filesystem Mount
Ensure `/sbin/launchd` can mount root:
- Either via `md0` restore ramdisk (`--restore-ramdisk --diagnostic-no-secure-root`).
- Or via `disk0` raw HFS image (`n94-rootfs.raw`) attached to `AppleSwissPPNFTL`.

### Step 3: Userspace Environment Variables
In `boot-args`, pass:
```text
-v serial=3 debug=0x14e cs_enforcement_disable=1 amfi_get_out_of_my_way=1 CA_ENABLE_OGL=0
```
Setting `CA_ENABLE_OGL=0` explicitly instructs QuartzCore to bypass OpenGLES and composite all layers directly using the CPU software renderer.

### Step 4: Verification Run
Run the CI workflow on `nustai/Un1box`:
```powershell
./bin/gh.exe workflow run n94-qemu-check.yml --repo nustai/Un1box -f kernel_probe=true
```
Download traces, extract `screen.ppm`, and verify real SpringBoard frames.
