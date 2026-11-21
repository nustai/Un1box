#!/usr/bin/env python3
"""Check actual QEMU screenshots reflect guest RAM and display takeover."""
import json
import pathlib
import re
import struct
import subprocess
import sys
import tempfile

from n94_cdma_test import connect
from n94_smoke import bundle


def run(binary, directory):
    image = bytearray(bundle())
    struct.pack_into('<6I', image, 0x800 + 20, 0x8fd00000, 0, 2560, 640, 960, 32)
    boot = directory / 'boot.bin'
    boot.write_bytes(image)
    command = [str(binary), '-M', f'n94,kboot={boot}', '-S', '-display', 'none',
               '-monitor', 'none', '-serial', 'null',
               '-qtest', f'unix:{directory / "qtest.sock"},server=on,wait=off',
               '-qtest-log', str(directory / 'qtest.log'),
               '-qmp', f'unix:{directory / "qmp.sock"},server=on,wait=off']
    with (directory / 'stderr.log').open('w+') as errors:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors)
        try:
            with connect(directory / 'qtest.sock', process) as test, connect(directory / 'qmp.sock', process) as monitor:
                t = test.makefile('rwb', buffering=0)
                q = monitor.makefile('rwb', buffering=0)
                assert 'QMP' in json.loads(q.readline())

                def qmp(name, arguments=None):
                    request = {'execute': name}
                    if arguments is not None:
                        request['arguments'] = arguments
                    q.write((json.dumps(request) + '\n').encode())
                    while True:
                        response = json.loads(q.readline())
                        if 'error' in response:
                            raise AssertionError(response)
                        if 'return' in response:
                            return response['return']

                def qtest(command):
                    t.write((command + '\n').encode())
                    response = t.readline().decode().strip()
                    assert response.startswith('OK'), (command, response)
                    return response

                def pixel(address, bgra):
                    qtest(f'write 0x{address:x} 4 0x{bgra.hex()}')

                def screenshot():
                    target = directory / 'screen.ppm'
                    qmp('screendump', {'filename': str(target)})
                    data = target.read_bytes()
                    header = re.match(rb'P6\s+(\d+)\s+(\d+)\s+255\s', data)
                    assert header and header.group(1, 2) == (b'640', b'960')
                    return data[header.end():]

                qmp('qmp_capabilities')
                assert not any(screenshot()), 'boot display contains pixels before any guest writes'
                assert int(qtest('readl 0x39500000').split()[1], 0) & 0x400
                assert int(qtest('readl 0x3f110000').split()[1], 0) & 0x100
                qtest('writel 0x39500034 0xb114')
                assert int(qtest('readl 0x3950003c').split()[1], 0) == 0x41a
                assert int(qtest('readl 0x3950003c').split()[1], 0) == 0x0969e5a1
                assert int(qtest('readl 0x39200050').split()[1], 0) == 1
                assert int(qtest('readl 0x39200060').split()[1], 0) == 0x027f03bf
                qtest('writel 0x39200050 0x0')
                assert int(qtest('readl 0x39200050').split()[1], 0) == 2
                # Driver initializes DPCIRQ by writing all ones. A write to
                # a clear-only status register must not invent pending IRQs.
                qtest('writel 0x3a10102c 0xffffffff')
                assert int(qtest('readl 0x3a10102c').split()[1], 0) == 0
                qtest('writel 0x3a101028 0x1fa42')
                assert int(qtest('readl 0x3a101028').split()[1], 0) == 0x1fa42
                pixel(0x8fd00000, bytes.fromhex('0000ff00'))
                pixel(0x8fd00004, bytes.fromhex('00ff0000'))
                pixel(0x8fd00000 + 959 * 2560, bytes.fromhex('ff000000'))
                screen = screenshot()
                assert screen[:6] == bytes.fromhex('ff000000ff00'), screen[:6].hex()
                assert screen[959 * 640 * 3:959 * 640 * 3 + 3] == bytes.fromhex('0000ff')
                print('PASS boot framebuffer displays actual guest RAM including bottom row', flush=True)

                pixel(0x8fb00000, bytes.fromhex('00ffff00'))
                pixel(0x8fb00000 + 0xb00, bytes.fromhex('ff00ff00'))
                qtest('writel 0x3a104044 0x8fb00000')
                qtest('writel 0x3a104048 0x0b02')
                screen = screenshot()
                assert screen[:3] == bytes.fromhex('ffff00')
                assert screen[640 * 3:640 * 3 + 3] == bytes.fromhex('ff00ff')
                assert int(qtest('readl 0x3a101028').split()[1], 0) == 0x1fa42
                print('PASS DisplayPipe uses the programmed source and pitch', flush=True)

                pixel(0x8fc00000, bytes.fromhex('ff000000'))
                qtest('writel 0x3a100010 0x8fc00000')
                qtest('writel 0x3a100000 0x1')
                assert screenshot()[:3] == bytes.fromhex('0000ff')
                print('PASS configured framebuffer takes over the boot display', flush=True)
                qtest('writel 0x39200060 0x1')
                qtest('writel 0x39300004 0x12345678')
                qmp('system_reset')
                assert int(qtest('readl 0x3a101028').split()[1], 0) == 0
                assert int(qtest('readl 0x39200050').split()[1], 0) == 1
                assert int(qtest('readl 0x39200060').split()[1], 0) == 0x027f03bf
                assert int(qtest('readl 0x39300004').split()[1], 0) == 0
                # The board's validated boot-framebuffer handoff survives reset.
                pixel(0x8fd00000, bytes.fromhex('0000ff00'))
                assert screenshot()[:3] == bytes.fromhex('ff0000')
                print('PASS display reset clears registers and restores boot framebuffer', flush=True)
                q.write(b'{"execute":"quit"}\n')
                process.wait(timeout=10)
                assert process.returncode == 0
        except Exception:
            errors.seek(0)
            print(errors.read(), file=sys.stderr)
            raise
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='n94-display-') as temporary:
        run(pathlib.Path(sys.argv[1]).resolve(), pathlib.Path(temporary))
