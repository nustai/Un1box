#!/usr/bin/env python3
"""Boot-image regressions, including the actual unmasked-length failure mode in XNU."""
import json
import pathlib
import struct
import tempfile
import unittest

from n94_prepare_kernel import Node, prepare, u32


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
    def test_flagged_firmware_is_normalized_without_overlapping_boot_objects(self):
        chosen = node("chosen", [node("memory-map", **{f"MemoryMapReserved-{i}": bytes(8) for i in range(16)})])
        for name in ("marketing-hardware-behavior", "marketing-software-behavior"):
            chosen.props[name] = (b"placeholder\0", 0x80000000)
        root = node("device-tree", [node("memory", reg=bytes(8)), chosen,
                                     node("cpus", [node("cpu0")]), node("vram", reg=bytes(8)), node("pram", reg=bytes(8))])
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
