#!/usr/bin/env python3
"""Verify real restore userspace evidence; this does not certify a normal iOS boot."""
import argparse
import json
import pathlib
import re

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('images', type=pathlib.Path)
parser.add_argument('traces', type=pathlib.Path)
args = parser.parse_args()

for version in (2, 3):
    layout = json.loads((args.images / f'n94-v{version}-layout.json').read_text())
    directory = args.traces / f'bootargs-v{version}'
    summary = json.loads((directory / 'summary.json').read_text())
    uart = (directory / 'uart.log').read_text(errors='replace')
    if (layout['root_filesystem'] != 'restore-ramdisk' or
            layout.get('diagnostic_secure_root_override') is not True):
        raise SystemExit(f'v{version}: expected explicit insecure restore diagnostic')
    if summary['probe_error'] or summary['exit_code'] != 0:
        raise SystemExit(f'v{version}: probe failed: {summary}')
    if 'panic(' in uart.lower():
        raise SystemExit(f'v{version}: kernel panic in restore diagnostic')
    if 'BSD root: md0' not in uart or not re.search(
            r'com\.apple\.xpc\.launchd\[1\].*Restore environment starting', uart):
        raise SystemExit(f'v{version}: restore root or launchd PID 1 not observed')
    print(f'PASS v{version}: restore ramdisk and real launchd PID 1 observed '
          '(diagnostic secure-root override; normal iOS boot not confirmed)')
