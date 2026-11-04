#!/usr/bin/env python3
"""Validate bounded parsing of the n94 compressed touch-property resource."""
import struct
import unittest
import zlib

from n94_touch_firmware import decompress_resource


def resource(blocks):
    compressed = [zlib.compress(block) for block in blocks]
    offset = 4 + 8 * len(blocks)
    table = bytearray(struct.pack('<I', len(blocks)))
    for chunk in compressed:
        table.extend(struct.pack('<II', offset, len(chunk)))
        offset += len(chunk)
    body = bytes(table) + b''.join(compressed)
    return struct.pack('>III', 0x100, 0, len(body)) + bytes(0x100 - 12) + struct.pack('>I', len(body)) + body


class ResourceTests(unittest.TestCase):
    def test_two_chunks_round_trip(self):
        self.assertEqual(decompress_resource(resource([b'a' * 65536, b'n94'])), b'a' * 65536 + b'n94')

    def test_rejects_bad_offset_and_oversized_chunk(self):
        bad = bytearray(resource([b'valid']))
        struct.pack_into('<I', bad, 0x108, 0xffffffff)
        with self.assertRaises(ValueError):
            decompress_resource(bad)
        with self.assertRaises(ValueError):
            decompress_resource(resource([b'x' * 65537]))


if __name__ == '__main__':
    unittest.main()
