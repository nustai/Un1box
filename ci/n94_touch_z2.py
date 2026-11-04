"""Validate the observed Z2 result-frame subset from the stock n94 driver.

This is a diagnostic decoder, not an emulated touch controller. Observed in
13G37 AppleMultitouchSPI at 0x807ebdca..0x807ebe5c and 0x807ef048.
"""
import struct


def decode_result_frame(frame, *, allow_alternate=False):
    """Return payload after validating header, length, and additive checksum.

    The caller supplies the entire SPI transfer, including optional padding.
    Byte 0 is 0xea, or 0xeb when the driver enables the alternate response.
    Bytes 2..3 encode payload length plus two checksum bytes (little-endian).
    The last two bytes of the transfer contain the payload checksum. Empty
    control responses with a zero length field are outside this subset.
    """
    frame = bytes(frame)
    if len(frame) < 7:
        raise ValueError('short touch result frame')
    if frame[0] != 0xea and not (allow_alternate and frame[0] == 0xeb):
        raise ValueError('unexpected touch response')
    if sum(frame[:5]) & 0xff:
        raise ValueError('invalid touch frame header checksum')
    length = struct.unpack_from('<H', frame, 2)[0]
    if length < 2 or 5 + length - 2 > len(frame) - 2:
        raise ValueError('invalid touch payload length')
    payload = frame[5:5 + length - 2]
    expected = struct.unpack_from('<H', frame, len(frame) - 2)[0]
    if sum(payload) & 0xffff != expected:
        raise ValueError('invalid touch payload checksum')
    return payload
