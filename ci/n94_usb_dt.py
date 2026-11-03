#!/usr/bin/env python3
"""Inspect USB register descriptions in a decrypted n94 Apple DeviceTree."""
import argparse
import pathlib
import struct

from n94_prepare_kernel import Node

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('device_tree', type=pathlib.Path)
args = parser.parse_args()
root, _ = Node.read(args.device_tree.read_bytes())

def walk(node, parent=''):
    path = parent + '/' + node.props.get('name', (b'', 0))[0].rstrip(b'\0').decode(errors='replace')
    if '/usb-complex' in path:
        print(path)
        for key in ('compatible', 'reg', 'ranges', 'interrupts'):
            if key not in node.props:
                continue
            value = node.props[key][0]
            if key == 'compatible':
                print(f'  {key}: {value.rstrip(bytes([0])).decode(errors="replace").replace(chr(0), ", ")}')
            elif len(value) % 4 == 0:
                words = struct.unpack('<' + 'I' * (len(value) // 4), value)
                print(f'  {key}: ' + ' '.join(f'0x{word:08x}' for word in words))
            else:
                print(f'  {key}: {value.hex()}')
    for child in node.children:
        walk(child, path)

walk(root)
