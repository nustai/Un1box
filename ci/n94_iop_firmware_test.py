#!/usr/bin/env python3
"""Exercise n94 IOP metadata, section bounds and reset-vector checks."""
import struct
import unittest
from unittest.mock import patch

from n94_iop_firmware import extract, prepare_diagnostic, prepare_diagnostic_rings


def kernel_fixture():
    metadata = (b'<plist><dict><key>CFBundleIdentifier</key>'
                b'<string>com.apple.driver.IOP_s5l8940xiop_firmware</string>'
                b'<key>_PrelinkExecutableLoadAddr</key><integer>0x80001000</integer>'
                b'</dict></plist>')
    image = bytearray(0x2100)
    image[:len(metadata)] = metadata
    struct.pack_into('<7I', image, 0x1000, 0xfeedface, 12, 9, 11, 1, 124, 0)
    segment = 0x1000 + 28
    struct.pack_into('<II16s8I', image, segment, 1, 124, b'__DATA',
                     0x80002000, 64, 0, 64, 7, 7, 1, 0)
    section = segment + 56
    image[section:section + 16] = b'fwFirmwareImage\0'
    struct.pack_into('<II', image, section + 32, 0x80002000, 64)
    struct.pack_into('<I', image, 0x2000, 0xea00000e)
    segments = [('__PRELINK_INFO', 0x80000000, len(metadata), 0, len(metadata)),
                ('__PRELINK_TEXT', 0x80001000, 0x1100, 0x1000, 0x1100)]
    return image, segments


class IOPFirmwareTests(unittest.TestCase):
    def test_ring_preparation_checks_ranges_and_does_not_mutate_input(self):
        source = bytes(0x23000)
        rings = [(0x80100000 + index * 0x1000, 8) for index in range(5)]
        prepared = prepare_diagnostic_rings(source, rings)
        self.assertEqual(struct.unpack_from('<II', prepared, 0x13028), rings[2])
        self.assertEqual(source[0x13028:0x13030], bytes(8))
        with self.assertRaisesRegex(ValueError, 'overlap'):
            prepare_diagnostic_rings(source, [rings[0]] * 5)
        with self.assertRaisesRegex(ValueError, 'invalid'):
            prepare_diagnostic_rings(source, [(0x80100001, 8)] + rings[1:])
        with self.assertRaisesRegex(ValueError, 'placeholders'):
            prepare_diagnostic_rings(prepared, rings)

    def test_prepare_validates_placeholders_alignment_and_overlap(self):
        firmware = bytearray(0x23000)
        for offset in (0x1318c, 0x13190, 0x1334c):
            struct.pack_into('<I', firmware, offset, 0xffffffff)
        struct.pack_into('<I', firmware, 0x13348, 0x4000)
        before = bytes(firmware)
        prepared = prepare_diagnostic(firmware, 0x30000, 0x40000)
        self.assertEqual(bytes(firmware), before)
        self.assertEqual(struct.unpack_from('<II', prepared, 0x1318c), (0x30000, 0xb000))
        self.assertEqual(struct.unpack_from('<I', prepared, 0x1334c)[0], 0x40000)
        with self.assertRaisesRegex(ValueError, 'overlap'):
            prepare_diagnostic(firmware, 0x3c000, 0x40000)
        with self.assertRaisesRegex(ValueError, 'layout'):
            prepare_diagnostic(firmware, 0x30000, 0x41000)
        with self.assertRaisesRegex(ValueError, 'placeholders'):
            prepare_diagnostic(prepared, 0x30000, 0x40000)

    def test_extract_section_and_reject_invalid_vector(self):
        image, segments = kernel_fixture()
        with patch('n94_iop_firmware.macho', return_value=(segments, 0)):
            address, firmware = extract(bytes(image))
            self.assertEqual((address, len(firmware)), (0x80002000, 64))
            image[0x2000] = 0
            with self.assertRaisesRegex(ValueError, 'reset vector'):
                extract(bytes(image))

    def test_reject_section_outside_file_backed_segment(self):
        image, segments = kernel_fixture()
        section = 0x1000 + 28 + 56
        struct.pack_into('<II', image, section + 32, 0x90000000, 64)
        with patch('n94_iop_firmware.macho', return_value=(segments, 0)):
            with self.assertRaisesRegex(ValueError, 'not file-backed'):
                extract(bytes(image))


if __name__ == '__main__':
    unittest.main()
