#!/usr/bin/env python3
"""Locate n94 IOP firmware in a local decrypted kernelcache without modifying it."""
import argparse
import hashlib
import json
import pathlib
import struct
import xml.etree.ElementTree as ET

from n94_prepare_kernel import macho

IDENTIFIER = 'com.apple.driver.IOP_s5l8940xiop_firmware'
HEAP_BASE_OFFSET = 0x1318c
HEAP_SIZE_OFFSET = 0x13190
PAGE_TABLE_SIZE_OFFSET = 0x13348
PAGE_TABLE_BASE_OFFSET = 0x1334c
HEAP_REQUIRED = 0xb000


def extract(kernel):
    segments, _ = macho(kernel)

    def virtual(address, length):
        for _, start, _, offset, size in segments:
            if start <= address and address + length <= start + size:
                return kernel[offset + address - start:offset + address - start + length]
        raise ValueError('IOP firmware address is not file-backed')

    metadata = next((kernel[offset:offset + length] for name, _, _, offset, length in segments
                     if name == '__PRELINK_INFO'), None)
    if metadata is None:
        raise ValueError('kernel prelink metadata missing')
    tree = ET.fromstring(metadata.rstrip(b'\0'))
    ids = {element.attrib['ID']: element for element in tree.iter() if 'ID' in element.attrib}

    def value(element):
        for _ in range(32):
            reference = element.attrib.get('IDREF')
            if reference is None:
                return element.text
            element = ids[reference]
        raise ValueError('cyclic metadata reference')

    matches = []
    for node in tree.iter('dict'):
        children = list(node)
        props = {value(children[i]): value(children[i + 1]) for i in range(len(children) - 1)
                 if children[i].tag == 'key'}
        if props.get('CFBundleIdentifier') == IDENTIFIER:
            matches.append(int(props['_PrelinkExecutableLoadAddr'], 0))
    if len(matches) != 1:
        raise ValueError('expected one n94 IOP firmware kext')
    start = matches[0]
    header = virtual(start, 28)
    magic, cpu, _, kind, count, command_bytes, _ = struct.unpack('<7I', header)
    if (magic, cpu, kind) != (0xfeedface, 12, 11) or count > 128 or command_bytes > 1 << 20:
        raise ValueError('invalid n94 IOP kext header')
    commands = virtual(start + 28, command_bytes)
    cursor = 0
    sections = []
    for _ in range(count):
        if cursor + 8 > len(commands):
            raise ValueError('truncated kext command')
        command, length = struct.unpack_from('<II', commands, cursor)
        if length < 8 or cursor + length > len(commands):
            raise ValueError('invalid kext command length')
        if command == 1:
            if length < 56:
                raise ValueError('short kext segment')
            section_count = struct.unpack_from('<I', commands, cursor + 48)[0]
            if 56 + 68 * section_count > length:
                raise ValueError('truncated kext sections')
            for i in range(section_count):
                section = cursor + 56 + 68 * i
                name = commands[section:section + 16].rstrip(b'\0')
                if name == b'fwFirmwareImage':
                    sections.append(struct.unpack_from('<II', commands, section + 32))
        cursor += length
    if len(sections) != 1:
        raise ValueError('expected one IOP firmware image')
    address, size = sections[0]
    if not 64 <= size <= 1 << 20:
        raise ValueError('unexpected IOP firmware size')
    firmware = virtual(address, size)
    if struct.unpack_from('<I', firmware)[0] != 0xea00000e:
        raise ValueError('unexpected n94 IOP reset vector')
    return address, firmware


def prepare_diagnostic(firmware, heap_base, page_table_base):
    """Populate published boot variables, not the still-unknown IOP rings."""
    if len(firmware) < PAGE_TABLE_BASE_OFFSET + 4:
        raise ValueError('short n94 IOP firmware')
    if (heap_base <= 0 or heap_base % 4 or page_table_base <= 0 or
            page_table_base % 0x4000 or heap_base + HEAP_REQUIRED > 1 << 32 or
            page_table_base + 0x4000 > 1 << 32):
        raise ValueError('invalid diagnostic IOP memory layout')
    if heap_base < page_table_base + 0x4000 and page_table_base < heap_base + HEAP_REQUIRED:
        raise ValueError('diagnostic IOP heap and page table overlap')
    page_size = struct.unpack_from('<I', firmware, PAGE_TABLE_SIZE_OFFSET)[0]
    sentinels = [struct.unpack_from('<I', firmware, offset)[0] for offset in
                 (HEAP_BASE_OFFSET, HEAP_SIZE_OFFSET, PAGE_TABLE_BASE_OFFSET)]
    if page_size != 0x4000 or sentinels != [0xffffffff] * 3:
        raise ValueError('unexpected stock IOP boot-variable placeholders')
    result = bytearray(firmware)
    struct.pack_into('<I', result, HEAP_BASE_OFFSET, heap_base)
    struct.pack_into('<I', result, HEAP_SIZE_OFFSET, HEAP_REQUIRED)
    struct.pack_into('<I', result, PAGE_TABLE_BASE_OFFSET, page_table_base)
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kernel', type=pathlib.Path, help='local decrypted n94 kernelcache')
    parser.add_argument('--output', type=pathlib.Path, help='optional new local firmware file')
    parser.add_argument('--diagnostic-heap-base', type=lambda value: int(value, 0),
                        help='hypothetical IOP-visible heap address; requires page table and output')
    parser.add_argument('--diagnostic-page-table-base', type=lambda value: int(value, 0),
                        help='hypothetical aligned IOP-visible page-table address')
    args = parser.parse_args()
    address, firmware = extract(args.kernel.read_bytes())
    diagnostic = args.diagnostic_heap_base is not None or args.diagnostic_page_table_base is not None
    if diagnostic:
        if args.output is None or args.diagnostic_heap_base is None or args.diagnostic_page_table_base is None:
            parser.error('diagnostic preparation requires both addresses and --output')
        output_data = prepare_diagnostic(firmware, args.diagnostic_heap_base, args.diagnostic_page_table_base)
    else:
        output_data = firmware
    if args.output:
        with args.output.open('xb') as output:
            output.write(output_data)
    print(json.dumps({'kext': IDENTIFIER, 'address': hex(address), 'firmware_bytes': len(firmware),
                      'sha256': hashlib.sha256(firmware).hexdigest(), 'diagnostic_prepared': diagnostic,
                      'diagnostic_output_sha256': hashlib.sha256(output_data).hexdigest() if diagnostic else None,
                      'iop_emulated': False}))


if __name__ == '__main__':
    main()
