#!/usr/bin/env python3
"""Boot-image regressions, including the actual unmasked-length failure mode in XNU."""
import json
import pathlib
import struct
import tempfile
import unittest

from n94_prepare_kernel import Node, prepare, u32, diagnostic_nvram, diagnostic_performance


def node(name, children=(), **properties):
    return Node({"name": (name.encode() + b"\0", 0), **{k: (v, 0) for k, v in properties.items()}}, list(children))


def kernel_walk(data, offset=0):
    count, children = struct.unpack_from("<II", data, offset)
    offset += 8
    for _ in range(count):
        if offset + 36 > len(data):
            raise ValueError("XNU DT walk escaped the image")
        length = struct.unpack_from("<I", data, offset + 32)[0]
        # Deliberately no mask: this is what guest instructions at 0x8038783c do.
        offset += 36 + ((length + 3) & ~3)
        if offset > len(data):
            raise ValueError("XNU DT walk escaped the image")
    for _ in range(children):
        offset = kernel_walk(data, offset)
    return offset


class Preparation(unittest.TestCase):
    def test_blank_performance_table_has_one_nominal_diagnostic_state(self):
        pmgr = node('pmgr', **{'voltage-states1': bytes(24), 'nominal-performance1': u32(0x14000)})
        self.assertEqual(struct.unpack_from('<I', pmgr.props['voltage-states1'][0])[0], 0)
        self.assertEqual(diagnostic_performance(pmgr), 0x14000)
        values = list(struct.iter_unpack('<II', pmgr.props['voltage-states1'][0]))
        # Actual guest stops at the first zero performance, not at buffer end.
        self.assertEqual(values, [(0x14000, 0), (0, 0), (0, 0)])
        with self.assertRaisesRegex(ValueError, 'blank performance'):
            diagnostic_performance(pmgr)

    def test_nvram_proxy_advances_through_complete_partitions(self):
        # Reproduce the guest's length read and offset update at 0x803684d0.
        self.assertEqual(struct.unpack_from('<H', bytes(8192), 2)[0] * 16, 0)
        image = diagnostic_nvram()
        offset, names = 0, []
        while offset < len(image):
            length = struct.unpack_from('<H', image, offset + 2)[0] * 16
            self.assertGreaterEqual(length, 16)
            self.assertLessEqual(offset + length, len(image))
            header = bytearray(image[offset:offset + 16])
            expected, header[1] = header[1], 0
            checksum = 0
            for byte in header:
                total = checksum + byte
                checksum = (total & 255) + (total >> 8)
            self.assertEqual(expected, checksum)
            names.append(bytes(header[4:16]).rstrip(b'\0'))
            offset += length
        self.assertEqual(offset, 8192)
        self.assertEqual(names, [b'common', b'free'])

    def test_flagged_firmware_is_normalized_without_overlapping_boot_objects(self):
        chosen = node("chosen", [node("memory-map", **{f"MemoryMapReserved-{i}": bytes(8) for i in range(16)})],
                      **{'nvram-proxy-data': bytes(8192)})
        for name in ("marketing-hardware-behavior", "marketing-software-behavior"):
            chosen.props[name] = (b"placeholder\0", 0x80000000)
        root = node("device-tree", [node("memory", reg=bytes(8)), chosen,
                                     node("cpus", [node("cpu0")]), node("vram", reg=bytes(8)), node("pram", reg=bytes(8)),
                                     node('arm-io', [node('pmgr', **{'voltage-states1': bytes(24),
                                                                   'nominal-performance1': u32(0x14000)})])])
        raw = root.encode()
        with self.assertRaisesRegex(ValueError, "escaped"):
            kernel_walk(raw)
        header = struct.pack("<7I", 0xfeedface, 12, 9, 2, 2, 136, 0)
        segment = struct.pack("<II16s8I", 1, 56, b"__TEXT", 0x80001000, 4096, 164, 4, 7, 5, 0, 0)
        registers = [0] * 16
        registers[15] = 0x80001000
        thread = struct.pack("<4I16I", 5, 80, 1, 16, *registers)
        kernel = header + segment + thread + u32(0xeafffffe)
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            for version in (2, 3):
                prepare(kernel, raw, version, output)
                image = (output / f"n94-v{version}.kboot").read_bytes()
                magic, base, entry, args, length = struct.unpack_from("<8s4I", image, len(image) - 24)
                self.assertEqual((magic, base, entry, length), (b"N94KBOOT", 0x80000000, 0x80001000, len(image) - 24))
                self.assertEqual(struct.unpack_from("<HH", image, args - base), (1, version))
                top = struct.unpack_from("<I", image, args - base + 16)[0]
                dt, size = struct.unpack_from("<II", image, args - base + 48)
                self.assertGreaterEqual(dt, entry + 4096)
                self.assertGreaterEqual(args, dt + size)
                self.assertGreaterEqual(top, args + 320)
                self.assertEqual(top % 16384, 0)
                cooked = image[dt - base:dt - base + size]
                self.assertEqual(kernel_walk(cooked), size)
                tree, _ = Node.read(cooked)
                seed = tree.at("chosen").props["random-seed"][0]
                self.assertEqual(len(seed), 64)
                self.assertTrue(any(seed))
                pram_pa, pram_size = struct.unpack("<II", tree.at("pram").props["reg"][0])
                self.assertGreaterEqual(pram_pa, top)
                self.assertGreater(pram_size, 0)
                self.assertLessEqual(pram_pa + pram_size, base + (512 << 20))
                report = json.loads((output / f"n94-v{version}-layout.json").read_text())
                self.assertEqual(report["firmware_property_flags_cleared"], 2)


if __name__ == "__main__":
    unittest.main()
