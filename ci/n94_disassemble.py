#!/usr/bin/env python3
"""Inspect addresses in a local, decrypted ARMv7 n94 Mach-O (never modifies it)."""
import argparse
import pathlib
import struct
import xml.etree.ElementTree as ET
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from n94_prepare_kernel import macho

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('kernel', type=pathlib.Path)
parser.add_argument('addresses', nargs='+', type=lambda value: int(value, 0))
parser.add_argument('--arm', action='store_true')
parser.add_argument('--bytes', type=int, default=128)
args = parser.parse_args()
data = args.kernel.read_bytes()
segments, _ = macho(data)
symbols = []
offset = 28
for _ in range(struct.unpack_from('<I', data, 16)[0]):
    command, size = struct.unpack_from('<II', data, offset)
    if command == 2:
        symoff, count, stroff, strsize = struct.unpack_from('<4I', data, offset + 8)
        strings = data[stroff:stroff + strsize]
        for index in range(count):
            name, kind, section, desc, value = struct.unpack_from('<IBBHI', data, symoff + index * 12)
            if name < len(strings) and value and kind & 0xe == 0xe:
                symbols.append((value & ~1, strings[name:].split(b'\0', 1)[0].decode(errors='replace')))
    offset += size
symbols.sort()
kexts = []
for name, base, memory, offset, length in segments:
    if name == '__PRELINK_INFO':
        tree = ET.fromstring(data[offset:offset + length].rstrip(b'\0'))
        identifiers = {element.attrib['ID']: element for element in tree.iter() if 'ID' in element.attrib}
        def value_text(element):
            for _ in range(32):
                reference = element.attrib.get('IDREF')
                if reference is None:
                    return element.text
                element = identifiers[reference]
            raise ValueError('cyclic prelink XML IDREF')
        for dictionary in tree.iter('dict'):
            children = list(dictionary)
            values = {value_text(children[i]): value_text(children[i + 1]) for i in range(len(children) - 1)
                      if children[i].tag == 'key'}
            try:
                start = int(values['_PrelinkExecutableLoadAddr'], 0)
                size = int(values['_PrelinkExecutableSize'], 0)
                kexts.append((start, size, values.get('CFBundleIdentifier', '?')))
            except (KeyError, TypeError, ValueError):
                pass
decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM if args.arm else CS_MODE_THUMB)
for address in args.addresses:
    for name, base, _, offset, length in segments:
        if base <= address < base + length:
            start = offset + address - base
            print(f'\n{address:#010x} ({name})')
            for kext_base, size, bundle in kexts:
                if kext_base <= address < kext_base + size:
                    print(f'{bundle}+{address - kext_base:#x}')
            previous = [entry for entry in symbols if entry[0] <= address] if name != '__PRELINK_TEXT' else []
            if previous:
                base_symbol, symbol = previous[-1]
                print(f'{symbol}+{address - base_symbol:#x}')
            for instruction in decoder.disasm(data[start:start + min(args.bytes, base + length - address)], address):
                print(f'{instruction.address:08x}: {instruction.mnemonic:9} {instruction.op_str}')
            break
    else:
        raise ValueError(f'address {address:#x} is not file-backed')
