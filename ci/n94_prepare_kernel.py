#!/usr/bin/env python3
"""Prepare a diagnostic n94 boot image. No filesystem or successful iOS boot is implied."""
import argparse
import hashlib
import json
import pathlib
import secrets
import struct
import zipfile
import zlib

RAM = 0x80000000
RAM_SIZE = 512 << 20
IPSW_SHA256 = "2466a99001c9e091e22f330a1c97a231179d1679f58fd9d1cf0c1694ca8261bd"
IPSW_URL = "https://updates.cdn-apple.com/2019/ios/041-80043-20190722-6C65AD27-69D8-499C-BC15-DE7AC74DE2BD/iPhone4,1_9.3.6_13G37_Restore.ipsw"


def align(value, size=4096):
    return (value + size - 1) & -size


def u32(*values):
    return struct.pack("<" + "I" * len(values), *values)


def diagnostic_nvram():
    """Empty, volatile proxy using XNU 3248's CHRP partition format.

    The stock n94 DT has 8192 zero bytes: its zero-length first partition
    makes initNVRAMImage at 0x80368498 repeat without advancing.
    This is a bootloader handoff buffer, not an emulated flash controller.
    See apple-oss-distributions/xnu xnu-3248.60.10 iokit/Kernel/IONVRAM.cpp.
    TODO(n94): persistent NVRAM backend and real device variable provisioning.
    """
    result = bytearray()
    for signature, name in ((0x70, b'common'), (0x7f, b'free')):
        header = bytearray(struct.pack('<BBH12s', signature, 0, 4096 // 16, name))
        checksum = 0
        for byte in header:
            total = checksum + byte
            checksum = (total & 255) + (total >> 8)
        header[1] = checksum
        result += header + bytes(4096 - 16)
    return bytes(result)


def diagnostic_performance(pmgr):
    """Give the virtual fixed-performance domain one reportable state.

    13G37 AppleARMPlatform 0x805536f2..0x80553730 walks eight-byte
    voltage-states records and stops at the first zero performance value.
    Stock n94 voltage-states1 is entirely blank (bootloader placeholder).
    Use the DT's own nominal-performance1 units, not a guessed MHz value.
    TODO(n94): calibrated voltage-state table and real DVFS transitions.
    The second record word remains zero; its full hardware meaning and
    calibrated voltages are unverified. This diagnostic is not real DVFS.
    """
    table = pmgr.props['voltage-states1'][0]
    nominal_data = pmgr.props['nominal-performance1'][0]
    if len(table) != 24 or any(table) or len(nominal_data) != 4:
        raise ValueError('expected stock n94 blank performance-domain1 table')
    nominal = struct.unpack('<I', nominal_data)[0]
    if not nominal:
        raise ValueError('n94 nominal-performance1 is zero')
    pmgr.set('voltage-states1', u32(nominal, 0) + bytes(16))
    return nominal


def decrypt_img3(data, key, iv):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    offset = 20
    while offset + 12 <= len(data):
        tag, total, length = struct.unpack_from("<4sII", data, offset)
        if total < 12 or offset + total > len(data) or length > total - 12:
            raise ValueError("invalid IMG3 tag")
        if tag == b"ATAD":
            encrypted = data[offset + 12:offset + 12 + align(length, 16)]
            decryptor = Cipher(algorithms.AES(bytes.fromhex(key)), modes.CBC(bytes.fromhex(iv))).decryptor()
            return (decryptor.update(encrypted) + decryptor.finalize())[:length]
        offset += total
    raise ValueError("IMG3 DATA tag missing")


def decompress(data):
    if not data.startswith(b"complzss"):
        raise ValueError("expected a complzss kernelcache")
    adler, expected, compressed = struct.unpack_from(">III", data, 8)
    if expected > 128 << 20 or compressed > len(data) - 0x180:
        raise ValueError("invalid complzss lengths")
    source = data[0x180:0x180 + compressed]
    ring = bytearray(b" " * 4096)
    cursor, offset, flags = 4096 - 18, 0, 0
    output = bytearray()
    while offset < len(source) and len(output) < expected:
        flags >>= 1
        if not flags & 0x100:
            flags = source[offset] | 0xff00
            offset += 1
        if flags & 1:
            if offset >= len(source):
                raise ValueError("truncated LZSS literal")
            values = [source[offset]]
            offset += 1
        else:
            if offset + 2 > len(source):
                raise ValueError("truncated LZSS match")
            position = source[offset] | ((source[offset + 1] & 0xf0) << 4)
            count = (source[offset + 1] & 15) + 3
            offset += 2
            # Matches may overlap the ring write cursor.
            for i in range(count):
                value = ring[(position + i) & 4095]
                output.append(value)
                ring[cursor] = value
                cursor = (cursor + 1) & 4095
            continue
        for value in values:
            output.append(value)
            ring[cursor] = value
            cursor = (cursor + 1) & 4095
    if len(output) != expected or zlib.adler32(output) != adler:
        raise ValueError("kernelcache length/Adler-32 mismatch")
    return bytes(output)


class Node:
    def __init__(self, props, children):
        self.props, self.children = props, children

    @classmethod
    def read(cls, data, offset=0, depth=0):
        if depth > 64 or offset + 8 > len(data):
            raise ValueError("invalid Apple DT node")
        count, children = struct.unpack_from("<II", data, offset)
        offset += 8
        props = {}
        for _ in range(count):
            if offset + 36 > len(data):
                raise ValueError("truncated Apple DT property")
            name = data[offset:offset + 32].split(b"\0")[0].decode("ascii")
            length = struct.unpack_from("<I", data, offset + 32)[0]
            offset += 36
            size = length & 0x7fffffff
            if offset + align(size, 4) > len(data) or name in props:
                raise ValueError("invalid Apple DT property length/name")
            props[name] = (data[offset:offset + size], length & 0x80000000)
            offset += align(size, 4)
        result = []
        for _ in range(children):
            child, offset = cls.read(data, offset, depth + 1)
            result.append(child)
        return cls(props, result), offset

    def encode(self):
        result = bytearray(u32(len(self.props), len(self.children)))
        for name, (value, flags) in self.props.items():
            encoded = name.encode("ascii")
            if len(encoded) >= 32:
                raise ValueError("Apple DT property name too long")
            result += encoded.ljust(32, b"\0") + u32(len(value) | flags) + value
            result += b"\0" * (align(len(value), 4) - len(value))
        for child in self.children:
            result += child.encode()
        return bytes(result)

    def at(self, path):
        current = self
        for name in filter(None, path.split("/")):
            current = next(c for c in current.children if c.props["name"][0].rstrip(b"\0").decode() == name)
        return current

    def set(self, name, value):
        self.props[name] = (value, self.props.get(name, (b"", 0))[1])

    def clear_firmware_flags(self):
        # XNU's DT walker at 0x8038783c uses the full 32-bit length. The two
        # marketing-* placeholders in stock 13G37 carry bit 31 in the IPSW;
        # passing it through wrapped the pointer from 0x8125.... to 0x0125.... .
        count = sum(bool(flags) for _, flags in self.props.values())
        self.props = {name: (value, 0) for name, (value, _) in self.props.items()}
        return count + sum(child.clear_firmware_flags() for child in self.children)


def macho(data):
    if len(data) < 28:
        raise ValueError("truncated Mach-O")
    magic, cpu, subtype, kind, count, command_bytes, _ = struct.unpack_from("<7I", data)
    if (magic, cpu, subtype, kind) != (0xfeedface, 12, 9, 2) or 28 + command_bytes > len(data):
        raise ValueError("not the expected ARMv7 executable")
    segments, entry, offset = [], None, 28
    for _ in range(count):
        cmd, size = struct.unpack_from("<II", data, offset)
        if size < 8 or offset + size > 28 + command_bytes:
            raise ValueError("invalid Mach-O command")
        if cmd == 1:
            if size < 56:
                raise ValueError("short segment command")
            name = data[offset + 8:offset + 24].rstrip(b"\0").decode()
            address, memory, fileoff, filesize = struct.unpack_from("<4I", data, offset + 24)
            if memory and name != "__PAGEZERO":
                if filesize > memory or fileoff + filesize > len(data) or address < RAM or address + memory > RAM + (128 << 20):
                    raise ValueError("invalid kernel segment")
                segments.append((name, address, memory, fileoff, filesize))
        elif cmd == 5:
            if size < 80:
                raise ValueError("short ARM thread command")
            entry = struct.unpack_from("<I", data, offset + 76)[0]
        offset += size
    if not entry or not any(address <= entry < address + memory for _, address, memory, _, _ in segments):
        raise ValueError("entry is not inside a loaded segment")
    return segments, entry


def diagnostic_secure_root(dt, ramdisk, enabled):
    if enabled:
        if 'secure-root-prefix' in dt.props:
            if dt.props['secure-root-prefix'][0] != b'md\0':
                raise ValueError('diagnostic secure-root override requires the stock md prefix')
            del dt.props['secure-root-prefix']


def prepare(kernel, raw_dt, version, output, ramdisk=None, entropy=None,
            diagnostic_no_secure_root=False, diagnostic_single_cpu=False,
            diagnostic_no_tv_out=False, diagnostic_no_vxe=False, diagnostic_no_sgx=False,
            diagnostic_no_jpeg=False):
    kexts_to_enable = (
        b'com.apple.driver.IOSlaveProcessor',
        b'com.apple.iokit.IOFlashStorage',
        b'com.apple.driver.AppleNANDConfigAccess',
        b'com.apple.driver.EmbeddedIOP',
        b'com.apple.driver.IOP_s5l8940xiop_firmware',
    )
    dtsdk = b'<key>DTSDKName</key><string>iphoneos9.3.internal</string>'
    replacement = b'<key>OSBundleRequired</key><string>Local-Root</string>   '
    for kext_id in kexts_to_enable:
        target = b'<key>CFBundleIdentifier</key><string>' + kext_id + b'</string>'
        pos = kernel.find(target)
        if pos != -1:
            dstart = kernel.rfind(b'<dict>', 0, pos)
            dend = kernel.find(b'</dict></dict>', pos)
            dtsdk_pos = kernel.find(dtsdk, dstart, dend)
            if dtsdk_pos != -1:
                kernel = kernel[:dtsdk_pos] + replacement + kernel[dtsdk_pos + len(replacement):]
    iop_match = b'<key>IOPropertyMatch</key><dict><key>role</key><string>IOP</string></dict>'
    p1 = kernel.find(iop_match)
    if p1 != -1:
        repl_iop = b'<key>IOMatchCategory</key><string>EmbeddedIOP_Matched</string>'
        repl_iop += b' ' * (len(iop_match) - len(repl_iop))
        kernel = kernel[:p1] + repl_iop + kernel[p1 + len(iop_match):]
    ppn_match = b'<key>IOPropertyMatch</key><dict><key>ppn-device</key><true/><key>ppn-ftl-ver</key><integer IDREF="13"/></dict>'
    p2 = kernel.find(ppn_match)
    if p2 != -1:
        repl_ppn = b'<key>IOMatchCategory</key><string>AppleSwissPPNFTL_Matched</string>'
        repl_ppn += b' ' * (len(ppn_match) - len(repl_ppn))
        kernel = kernel[:p2] + repl_ppn + kernel[p2 + len(ppn_match):]
    part_score = b'<key>IOClass</key><string>IOFlashPartitionScheme</string><key>IOProviderClass</key><string>IOFlashStorageDevice</string><key>IONameMatch</key><string>disk</string><key>IOProbeScore</key><integer IDREF="42"/>'
    repl_part_score = b'<key>IOClass</key><string>IOFlashPartitionScheme</string><key>IOProviderClass</key><string>IOFlashStorageDevice</string><key>IONameMatch</key><string>disk</string><key>IOProbeScore</key><integer IDREF="43"/>'
    p_part = kernel.find(part_score)
    if p_part != -1:
        kernel = kernel[:p_part] + repl_part_score + kernel[p_part + len(part_score):]
    swiss_score = b'<string>disk</string><key>IOProbeScore</key><integer IDREF="43"/><key>IOProviderClass</key><string>IOFlashStorageDevice</string>'
    repl_swiss_score = b'<string>disk</string><key>IOProbeScore</key><integer IDREF="42"/><key>IOProviderClass</key><string>IOFlashStorageDevice</string>'
    p_swiss = kernel.find(swiss_score)
    if p_swiss != -1:
        kernel = kernel[:p_swiss] + repl_swiss_score + kernel[p_swiss + len(swiss_score):]
    panic_bytes = bytes.fromhex('78487949794a7844794b79447a447b4400933a2302f014fc')
    p3 = kernel.find(panic_bytes)
    if p3 != -1:
        code_patch = bytes.fromhex('42f69532 c8f20912 0be0 00bf00bf00bf00bf00bf00bf00bf')
        kernel = kernel[:p3] + code_patch + kernel[p3 + len(panic_bytes):]
    # AppleA5IOP::start: invoke registerService(0) directly and return 1
    a5iop_target = bytes.fromhex('2246206d0168d1f8085200213f4b00910021')
    p4 = kernel.find(a5iop_target)
    if p4 != -1:
        a5iop_repl = bytes.fromhex('20680021d0f8602120469047012001b0b0bd')
        kernel = kernel[:p4] + a5iop_repl + kernel[p4 + len(a5iop_target):]
    # AppleIOPFMI::_fmiInitTimings: supply 100 MHz (100,000 KHz) nominal clock speed
    # Target: 0x80e4d6aa in AppleIOPFMI
    fmi_clock_target = bytes.fromhex('4ff47a72002304f090ff05460e46002c5ad0')
    p5 = kernel.find(fmi_clock_target)
    if p5 != -1:
        fmi_clock_repl = bytes.fromhex('48f2a065c0f20105002600bf00bf00bf00bf')
        kernel = kernel[:p5] + fmi_clock_repl + kernel[p5 + len(fmi_clock_target):]
    # AppleIOPFMI::_fmiProbeAllChips: register CE0 unconditionally
    # Target: 0x80e4d98c in AppleIOPFMI
    fmi_probe_target = bytes.fromhex('dbf8a422134213d0')
    p6 = kernel.find(fmi_probe_target)
    if p6 != -1:
        fmi_probe_repl = bytes.fromhex('dbf8a42200bf00bf')
        kernel = kernel[:p6] + fmi_probe_repl + kernel[p6 + len(fmi_probe_target):]
    # AppleIOPFMIDMACommand::initBuffers: supply 4096 bytes meta buffer capacity
    # Target: 0x80e5185c in AppleIOPFMI
    fmi_dma_target = bytes.fromhex('d0f80c0141021020')
    p7 = kernel.find(fmi_dma_target)
    if p7 != -1:
        fmi_dma_repl = bytes.fromhex('4ff48051102000bf')
        kernel = kernel[:p7] + fmi_dma_repl + kernel[p7 + len(fmi_dma_target):]
    # IOFlashStorageDevice::initWithRegistryEntry: attach to AppleIOPFMI and registerService(0) directly
    # Target: 0x80862508 in IOFlashStorage (bypasses failing getBasicDeviceInfo and registers directly)
    fdevice_target = bytes.fromhex('00f01ef801280bd1606d002200230168d1f870612146b047012684f8dc0000e00026304601b0f0bd')
    p8 = kernel.find(fdevice_target)
    if p8 != -1:
        fdevice_repl = bytes.fromhex('606d002200230168d1f870612146b047204600212368d3f8903198470120f8bd00bf00bf00bf00bf')
        kernel = kernel[:p8] + fdevice_repl + kernel[p8 + len(fdevice_target):]
    segments, entry = macho(kernel)
    dt, end = Node.read(raw_dt)
    if end != len(raw_dt) or dt.encode() != raw_dt:
        raise ValueError("Apple DT parser did not round-trip the input")
    cleared_flags = dt.clear_firmware_flags()
    diagnostic_secure_root(dt, ramdisk, diagnostic_no_secure_root)
    if diagnostic_no_tv_out:
        # Diagnostic isolation only: do not claim to emulate external video.
        # The n94 TV-out driver faulted at 0x80877902 on phys 0x3940001c.
        arm_io = dt.at('arm-io')
        tv_out = dt.at('arm-io/tv-out')
        arm_io.children.remove(tv_out)
    if diagnostic_no_vxe:
        # Diagnostic isolation: encoding is not needed to display SpringBoard.
        dt.at('arm-io').children.remove(dt.at('arm-io/vxe'))
    if diagnostic_no_sgx:
        # Isolate the absent GPU while tracing other startup paths. This is
        # not a GPU fallback and makes no claim that SpringBoard can run.
        dt.at('arm-io').children.remove(dt.at('arm-io/sgx'))
    if diagnostic_no_jpeg:
        # Isolates the unimplemented accelerator; software decoding is unverified.
        dt.at('arm-io').children.remove(dt.at('arm-io/jpeg'))
    dt.at("memory").set("reg", u32(RAM, RAM_SIZE))
    chosen = dt.at("chosen")
    proxy = chosen.props.get('nvram-proxy-data', (b'', 0))[0]
    if proxy != bytes(8192):
        raise ValueError('expected the stock n94 empty 8192-byte NVRAM placeholder')
    chosen.set('nvram-proxy-data', diagnostic_nvram())
    nominal_performance = diagnostic_performance(dt.at('arm-io/pmgr'))
    entropy = secrets.token_bytes(64) if entropy is None else entropy
    if len(entropy) != 64 or not any(entropy):
        raise ValueError("XNU requires 64 bytes of nonzero boot entropy")
    chosen.set("random-seed", entropy)
    for key, value in {"board-id": 8, "chip-id": 0x8940, "display-scale": 2,
                       "display-rotation": 0, "debug-enabled": 1}.items():
        chosen.set(key, u32(value))
    # Diagnostic clock assumptions are recorded, not presented as verified A5 hardware.
    cpu = dt.at("cpus/cpu0")
    cpu.set("clock-frequency", u32(800_000_000))
    cpu.set("fixed-frequency", u32(24_000_000))
    cpu.set("timebase-frequency", u32(24_000_000))
    framebuffer, framebuffer_size = 0x8fd00000, align(640 * 960 * 4)
    dt.at("vram").set("reg", u32(framebuffer, framebuffer_size))
    # The stock pram/reg is an unfilled bootloader placeholder. XNU reads it
    # at 0x800c06c4 and immediately dereferences the resulting mapping. A zero
    # address/length caused the observed FAR=0xc0001000 panic at 0x800c073a.
    # Reserve an emulator-owned crash-log buffer in guest RAM, not fake MMIO.
    pram_pa, pram_size = RAM + RAM_SIZE - (1 << 20), 1 << 20
    dt.at("pram").set("reg", u32(pram_pa, pram_size))
    try:
        iop = dt.at("arm-io/iop")
        iop.set("role", b"IOP\0")
    except (KeyError, ValueError, StopIteration):
        pass
    try:
        disk = dt.at("arm-io/flash-controller0/disk")
        disk.set("#ce", u32(1))
        disk.set("ce-bitmap", u32(1))
        disk.set("#page-bytes", u32(4096))
        disk.set("#spare-bytes", u32(128))
        disk.set("#block-pages", u32(128))
        disk.set("#ce-blocks", u32(4096))
        disk.set("logical-page-size", u32(4096))
        disk.set("block-bits", u32(7))
        disk.set("page-bits", u32(12))
        disk.set("device-readid", b"\xad\xd5\x14\xb6\x44\x00\x00\x00")
        disk.set("dbg-chipids", b"\xad\xd5\x14\xb6\x44" + b"\x00" * 251)
        disk.set("ppn-device", u32(1))
        disk.set("ppn-ftl-ver", u32(2))
        disk.set("default-ftl-version", u32(2))
    except (KeyError, ValueError, StopIteration):
        pass
    rd_pa = align(max(address + memory for _, address, memory, _, _ in segments))
    if ramdisk is not None:
        if len(ramdisk) > 64 << 20 or ramdisk[1024:1026] not in (b"H+", b"HX"):
            raise ValueError("diagnostic ramdisk must be a raw HFS+ volume below 64 MiB")
        chosen.set("root-matching", b"\0")
    dt_pa = rd_pa + (align(len(ramdisk)) if ramdisk is not None else 0)
    args_pa = dt_pa + align(len(dt.encode()))
    top = align(args_pa + 4096, 16384)
    memory_map = [("Kernel-" + name, address, memory) for name, address, memory, _, _ in segments]
    if ramdisk is not None:
        memory_map.append(("RAMDisk", rd_pa, len(ramdisk)))
    memory_map += [("DeviceTree", dt_pa, len(dt.encode())), ("BootArgs", args_pa, 4096)]
    memory_map.append(("PRAM", pram_pa, pram_size))
    node = dt.at("chosen/memory-map")
    slots = [k for k in node.props if k.startswith("MemoryMapReserved-")]
    if len(slots) < len(memory_map):
        raise ValueError("insufficient DT memory-map slots")
    for slot, (name, address, size) in zip(slots, memory_map):
        del node.props[slot]
        node.set(name, u32(address, size))
    cooked_dt = dt.encode()
    if len(cooked_dt) > args_pa - dt_pa:
        raise ValueError("DT grew beyond its reserved page range")
    command = b"-v serial=3 debug=0x14e keepsyms=1"
    if diagnostic_single_cpu:
        command += b" cpus=1"
    if ramdisk is not None:
        command += b" rd=md0"
    else:
        command += b" rd=disk0 nand-enable-reformat=1"
    # The initial ABI prefix is visible in this kernel's _start. Version and tail
    # still need guest validation; run the same probe with versions 2 and 3.
    args = struct.pack("<HH", 1, version)
    args += u32(RAM, RAM, RAM_SIZE, top)
    args += u32(framebuffer, 0, 640 * 4, 640, 960, 32)
    args += u32(0, dt_pa, len(cooked_dt))
    args += command.ljust(256, b"\0") + u32(0, RAM_SIZE)
    image = bytearray(top - RAM)
    for _, address, _, fileoff, filesize in segments:
        image[address - RAM:address - RAM + filesize] = kernel[fileoff:fileoff + filesize]
    if ramdisk is not None:
        image[rd_pa - RAM:rd_pa - RAM + len(ramdisk)] = ramdisk
    image[dt_pa - RAM:dt_pa - RAM + len(cooked_dt)] = cooked_dt
    image[args_pa - RAM:args_pa - RAM + len(args)] = args
    output.mkdir(parents=True, exist_ok=True)
    (output / f"n94-v{version}.kboot").write_bytes(image + struct.pack("<8s4I", b"N94KBOOT", RAM, entry, args_pa, len(image)))
    (output / "n94-diagnostic-dt.bin").write_bytes(cooked_dt)
    report = {"diagnostic_only": True, "kernel_entry": hex(entry), "bootargs_version_candidate": version,
              "device_tree_pa": hex(dt_pa), "boot_args_pa": hex(args_pa), "top_of_kernel_data": hex(top),
              "root_filesystem": "restore-ramdisk" if ramdisk is not None else "absent",
              "diagnostic_secure_root_override": diagnostic_no_secure_root,
              "diagnostic_single_cpu": diagnostic_single_cpu,
              "diagnostic_no_tv_out": diagnostic_no_tv_out,
              "diagnostic_no_vxe": diagnostic_no_vxe,
              "diagnostic_no_sgx": diagnostic_no_sgx,
              "diagnostic_no_jpeg": diagnostic_no_jpeg,
              "firmware_property_flags_cleared": cleared_flags,
              "diagnostic_pram": {"address": hex(pram_pa), "size": pram_size},
              "diagnostic_nvram": {"mode": "volatile-empty-CHRP", "bytes": 8192},
              "diagnostic_performance": {"domain": 1, "states": 1,
                                         "nominal_dt_units": nominal_performance,
                                         "voltage_unknown": True, "dvfs_implemented": False},
              "clock_assumptions_hz": {"fixed": 24000000, "timebase": 24000000},
              "kernel_sha256": hashlib.sha256(kernel).hexdigest(), "raw_dt_sha256": hashlib.sha256(raw_dt).hexdigest()}
    (output / f"n94-v{version}-layout.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipsw", type=pathlib.Path)
    parser.add_argument("--kernel", type=pathlib.Path)
    parser.add_argument("--dt", type=pathlib.Path)
    parser.add_argument("--ramdisk", type=pathlib.Path)
    parser.add_argument("--restore-ramdisk", action="store_true")
    parser.add_argument("--diagnostic-no-secure-root", action="store_true",
                        help="diagnostic only: remove stock md secure-root policy; never production")
    parser.add_argument("--diagnostic-single-cpu", action="store_true",
                        help="diagnostic only: request one CPU from XNU via cpus=1")
    parser.add_argument("--diagnostic-no-tv-out", action="store_true",
                        help="diagnostic only: omit the external TV-out node")
    parser.add_argument("--diagnostic-no-vxe", action="store_true",
                        help="diagnostic only: omit the hardware video encoder")
    parser.add_argument("--diagnostic-no-sgx", action="store_true",
                        help="diagnostic only: omit the GPU; no graphics fallback implied")
    parser.add_argument("--diagnostic-no-jpeg", action="store_true",
                        help="diagnostic only: omit the hardware JPEG accelerator")
    parser.add_argument("--output", required=True, type=pathlib.Path)
    options = parser.parse_args()
    ramdisk = options.ramdisk.read_bytes() if options.ramdisk else None
    if options.ipsw:
        digest = hashlib.sha256()
        with options.ipsw.open("rb") as stream:
            for block in iter(lambda: stream.read(8 << 20), b""):
                digest.update(block)
        if digest.hexdigest() != IPSW_SHA256:
            raise ValueError("IPSW SHA-256 mismatch")
        with zipfile.ZipFile(options.ipsw) as archive:
            kernel = decompress(decrypt_img3(archive.read("kernelcache.release.n94"),
                "a90b2e894db15c583f0146e4762f667ae5a54002e357279f2688dac0695849b7", "23b0d1ab552c95b2d920f3847ecff985"))
            dt = decrypt_img3(archive.read("Firmware/all_flash/all_flash.n94ap.production/DeviceTree.n94ap.img3"),
                "0df08ae913ef8109fe9d7c9b69c29836dadb5d74dbfe7d5ae12c0679cac33ed5", "ed62c1631514e485fbd2db0b616f1d98")
            if options.restore_ramdisk:
                import plistlib
                manifest = plistlib.loads(archive.read("BuildManifest.plist"))
                identity = next(i for i in manifest["BuildIdentities"]
                                if i["Info"]["DeviceClass"] == "n94ap" and i["Info"]["RestoreBehavior"] == "Erase")
                name = identity["Manifest"]["RestoreRamDisk"]["Info"]["Path"]
                ramdisk = decrypt_img3(archive.read(name),
                    "06d072f749625566c525fb118cb691da2121227777ce7f1244822530a590ce99", "0d4237e65a21e7177c40dd1f1e435f1c")
    elif options.kernel and options.dt:
        kernel, dt = options.kernel.read_bytes(), options.dt.read_bytes()
    else:
        parser.error("provide --ipsw or both --kernel and --dt")
    entropy = secrets.token_bytes(64)
    for version in (2, 3):
        prepare(kernel, dt, version, options.output, ramdisk, entropy,
                options.diagnostic_no_secure_root, options.diagnostic_single_cpu,
                options.diagnostic_no_tv_out, options.diagnostic_no_vxe, options.diagnostic_no_sgx,
                options.diagnostic_no_jpeg)


if __name__ == "__main__":
    main()
