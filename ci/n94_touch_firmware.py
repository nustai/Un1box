#!/usr/bin/env python3
"""Inspect or extract n94 touch properties from a local, read-only HFS volume."""
import argparse
import hashlib
import json
import pathlib
import plistlib
import struct
import zlib

from n94_rootfs import HFS


class RawVolume:
    def __init__(self, path):
        self.file = path.open('rb')
        self.size = path.stat().st_size

    def read(self, offset, size):
        if offset < 0 or size < 0 or offset + size > self.size:
            raise ValueError('volume read out of range')
        self.file.seek(offset)
        data = self.file.read(size)
        if len(data) != size:
            raise ValueError('truncated volume')
        return data


def decompress_resource(raw):
    """Read the observed n94 resource-fork chunk table, with bounded output."""
    if len(raw) < 0x108:
        raise ValueError('short resource fork')
    data_offset, _, data_length = struct.unpack_from('>III', raw)
    if data_offset != 0x100 or data_length > len(raw) - data_offset - 4:
        raise ValueError('unexpected resource data layout')
    base = data_offset + 4
    count = struct.unpack_from('<I', raw, base)[0]
    if not 1 <= count <= 16 or base + 4 + 8 * count > len(raw):
        raise ValueError('invalid compressed chunk table')
    result = bytearray()
    for index in range(count):
        offset, length = struct.unpack_from('<II', raw, base + 4 + 8 * index)
        if offset < 4 + 8 * count or length > data_length or base + offset + length > data_offset + 4 + data_length:
            raise ValueError('compressed chunk out of range')
        decoder = zlib.decompressobj()
        block = decoder.decompress(raw[base + offset:base + offset + length], 65537)
        if not decoder.eof or decoder.unused_data or len(block) > 65536:
            raise ValueError('invalid or oversized compressed chunk')
        result.extend(block)
    return bytes(result)


def find_touch_properties(volume):
    """Find the exact path using catalog ancestry; never alter the source."""
    folders, matches = {}, []
    node_id, visited = volume.first_leaf, set()
    while node_id:
        if node_id in visited:
            raise ValueError('cyclic HFS catalog')
        visited.add(node_id)
        node = volume.fork(volume.catalog, node_id * volume.node_size, volume.node_size)
        if node[8] != 255:
            raise ValueError('expected HFS catalog leaf')
        for index in range(struct.unpack_from('>H', node, 10)[0]):
            at = struct.unpack_from('>H', node, len(node) - 2 * (index + 1))[0]
            length, parent, count = struct.unpack_from('>HIH', node, at)
            name = node[at + 8:at + 8 + count * 2].decode('utf-16-be')
            record = node[at + 2 + length:]
            kind = struct.unpack_from('>H', record)[0]
            if kind == 1:
                folders[struct.unpack_from('>I', record, 8)[0]] = (parent, name)
            elif kind == 2 and name == 'N94.mtprops':
                matches.append((parent, record[41], record[168:248]))
        node_id = struct.unpack_from('>I', node)[0]
    for parent, flags, resource in matches:
        parts, seen = ['N94.mtprops'], set()
        while parent != 2:
            if parent in seen or parent not in folders:
                raise ValueError('invalid HFS catalog ancestry')
            seen.add(parent)
            parent, name = folders[parent]
            parts.append(name)
        if '/'.join(reversed(parts)) != 'usr/share/firmware/multitouch/N94.mtprops':
            continue
        length = struct.unpack_from('>Q', resource)[0]
        if not flags & 0x20 or not 0 < length <= 1 << 20:
            raise ValueError('unexpected N94 properties storage')
        return decompress_resource(volume.fork(resource, 0, length))
    raise ValueError('stock N94.mtprops not found')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('hfs', type=pathlib.Path, help='local raw HFS+ system volume')
    parser.add_argument('--output', type=pathlib.Path, help='optional local plist output')
    args = parser.parse_args()
    data = find_touch_properties(HFS(RawVolume(args.hfs)))
    parsed = plistlib.loads(data)
    profile = parsed['N1F56,1']
    firmware = profile['Constructed Firmware']
    if not isinstance(firmware, bytes) or not firmware:
        raise ValueError('missing n94 touch firmware')
    if args.output:
        with args.output.open('xb') as destination:
            destination.write(data)
    print(json.dumps({'personality': 'N1F56,1',
                      'bootload_packet_type': profile.get('PreconstructedBootloadPacketType'),
                      'firmware_version': profile.get('Constructed Firmware Version'),
                      'plist_bytes': len(data),
                      'plist_sha256': hashlib.sha256(data).hexdigest(),
                      'firmware_bytes': len(firmware),
                      'firmware_sha256': hashlib.sha256(firmware).hexdigest(),
                      'touch_controller_implemented': False}))


if __name__ == '__main__':
    main()
