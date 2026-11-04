#!/usr/bin/env python3
"""Check observed n94 touch frame validation, including malformed packets."""
import struct
import unittest

from n94_touch_z2 import decode_result_frame


def frame(payload, response=0xea, padding=b''):
    length = len(payload) + 2
    header = bytearray((response, 0, length & 0xff, length >> 8, 0))
    header[4] = -sum(header) & 0xff
    return bytes(header) + payload + padding + struct.pack('<H', sum(payload) & 0xffff)


class Z2FrameTests(unittest.TestCase):
    def test_payload_padding_and_alternate(self):
        self.assertEqual(decode_result_frame(frame(b'\x10\x20', padding=b'\0\0')), b'\x10\x20')
        alternate = frame(b'a', response=0xeb)
        with self.assertRaises(ValueError):
            decode_result_frame(alternate)
        self.assertEqual(decode_result_frame(alternate, allow_alternate=True), b'a')

    def test_rejects_corruption_and_invalid_length(self):
        packet = bytearray(frame(b'abc'))
        packet[4] ^= 1
        with self.assertRaisesRegex(ValueError, 'header checksum'):
            decode_result_frame(packet)
        packet = bytearray(frame(b'abc'))
        packet[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'payload checksum'):
            decode_result_frame(packet)
        packet = bytearray(frame(b'abc'))
        packet[2:4] = b'\xff\x00'
        packet[4] = -sum(packet[:4]) & 0xff
        with self.assertRaisesRegex(ValueError, 'payload length'):
            decode_result_frame(packet)


if __name__ == '__main__':
    unittest.main()
