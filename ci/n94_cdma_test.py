#!/usr/bin/env python3
"""Exercise actual n94 DMA transactions and IRQ pins via QTest, not a mocked model."""
import json
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import time
from n94_smoke import bundle

BASE = 0x37000000
CHANNEL = BASE + 0x1000
DESCRIPTOR = 0x80003000
BUFFER = 0x80004000


def connect(path, process):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and process.poll() is None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.connect(str(path))
            connection.settimeout(10)
            return connection
        except OSError:
            connection.close()
            time.sleep(0.05)
    raise RuntimeError(f'QEMU socket not ready: {path}, exit={process.poll()}')


def execute(binary, directory):
    (directory / 'boot.bin').write_bytes(bundle())
    uart = directory / 'uart.log'
    command = [str(binary), '-M', f'n94,kboot={directory / "boot.bin"}',
               '-S', '-display', 'none', '-monitor', 'none', '-serial', f'file:{uart}',
               '-qtest', f'unix:{directory / "test.sock"},server=on,wait=off',
               '-qtest-log', str(directory / 'qtest.log'),
               '-qmp', f'unix:{directory / "qmp.sock"},server=on,wait=off']
    with (directory / 'stderr.log').open('w+') as errors:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors)
        try:
            with connect(directory / 'test.sock', process) as test, connect(directory / 'qmp.sock', process) as monitor:
                test_stream = test.makefile('rwb', buffering=0)
                monitor_stream = monitor.makefile('rwb', buffering=0)
                assert 'QMP' in json.loads(monitor_stream.readline())
                levels, transitions = {}, []

                def qmp(name):
                    monitor_stream.write((json.dumps({'execute': name}) + '\n').encode())
                    while True:
                        response = json.loads(monitor_stream.readline())
                        if 'error' in response:
                            raise AssertionError(response)
                        if 'return' in response:
                            return response['return']

                def request(command):
                    test_stream.write((command + '\n').encode())
                    while True:
                        line = test_stream.readline().decode().strip()
                        if line.startswith('IRQ '):
                            _, edge, number = line.split()
                            levels[int(number)] = edge == 'raise'
                            transitions.append(line)
                            continue
                        assert line.startswith('OK'), (command, line)
                        return line

                def write(address, data):
                    request(f'write 0x{address:x} {len(data)} 0x{data.hex()}')

                def read(address, size):
                    return bytes.fromhex(request(f'read 0x{address:x} {size}').split()[1][2:])

                def writel(address, value):
                    request(f'writel 0x{address:x} 0x{value:x}')

                def readl(address):
                    return int(request(f'readl 0x{address:x}').split()[1], 16)

                def descriptor(address, next_address, flags, data_address, length):
                    write(address, struct.pack('<8I', next_address, flags, data_address, length, 0, 0, 0, 0))

                def prepare(config=0, endpoint=0x32500010):
                    writel(CHANNEL, 2)  # reset; output IRQ must deassert
                    writel(CHANNEL + 4, config)
                    writel(CHANNEL + 8, endpoint)
                    writel(CHANNEL + 0x14, DESCRIPTOR)
                    writel(BASE, 2)  # unmask channel 1, whose IRQ pin is 0

                qmp('qmp_capabilities')
                request('irq_intercept_out /machine/soc/cdma sysbus-irq')
                # Read a real UART status register repeatedly into guest RAM.
                sentinel = bytes([0xa5]) * 32
                write(BUFFER, sentinel)
                descriptor(DESCRIPTOR, DESCRIPTOR, 0x303, BUFFER, 16)
                prepare()
                expected = readl(0x32500010) & 255
                writel(CHANNEL, 0x19)
                assert read(BUFFER, 32) == bytes([expected]) * 16 + sentinel[16:]
                assert readl(CHANNEL + 0xc) == 16
                assert readl(CHANNEL + 0x10) == BUFFER + 16
                assert not readl(CHANNEL) & 0x40000
                assert levels.get(0), transitions
                writel(CHANNEL, 0x180000)  # W1C completion events
                readl(CHANNEL)
                assert not levels.get(0), transitions
                print('PASS CDMA device-to-RAM bytes, boundaries, counters, IRQ assertion and W1C', flush=True)

                # Scatter/gather reads memory and emits bytes through a real
                # UART device callback. A plain register backing cannot pass.
                payload = b'N94_DMA_SCATTER\n'
                write(BUFFER, payload)
                descriptor(DESCRIPTOR, DESCRIPTOR + 32, 3, BUFFER, 5)
                descriptor(DESCRIPTOR + 32, DESCRIPTOR + 64, 0x303, BUFFER + 5, len(payload) - 5)
                prepare(2, 0x32500020)
                writel(BASE + 8, 2)  # mask channel before submission
                writel(CHANNEL, 0x19)
                assert uart.read_bytes() == payload
                assert readl(CHANNEL + 0xc) == len(payload)
                assert not levels.get(0)
                writel(BASE, 2)  # pending completion must become visible
                readl(CHANNEL)
                assert levels.get(0)
                print('PASS CDMA RAM-to-UART scatter/gather, exact bytes, masked and pending IRQ', flush=True)

                # Invalid descriptors/commands cannot silently succeed or
                # damage the target buffer; malformed cycles terminate.
                for label, pointer, flags, count, next_address in (
                    ('misaligned descriptor', DESCRIPTOR + 1, 0x303, 16, DESCRIPTOR),
                    ('unsupported command', DESCRIPTOR, 0x302, 16, DESCRIPTOR),
                    ('oversize transfer', DESCRIPTOR, 0x303, (16 << 20) + 1, DESCRIPTOR),
                    ('descriptor cycle', DESCRIPTOR, 3, 0, DESCRIPTOR),
                ):
                    write(BUFFER, sentinel)
                    descriptor(DESCRIPTOR, next_address, flags, BUFFER, count)
                    prepare()
                    writel(CHANNEL + 0x14, pointer)
                    writel(CHANNEL, 0x19)
                    assert readl(CHANNEL) & 0x40000, label
                    assert read(BUFFER, len(sentinel)) == sentinel, label
                    print('PASS CDMA rejects ' + label, flush=True)

                # Unsupported crypto is explicitly rejected, not passthrough.
                prepare()
                descriptor(DESCRIPTOR, DESCRIPTOR, 0x303, BUFFER, 16)
                writel(0x37800000, 1)
                writel(CHANNEL, 0x19)
                assert readl(CHANNEL) & 0x40000
                assert read(BUFFER, len(sentinel)) == sentinel
                qmp('system_reset')
                assert readl(CHANNEL) == 0x20000
                assert readl(CHANNEL + 0xc) == 0
                assert readl(BASE) == 0
                assert readl(0x37800000) == 0
                assert not levels.get(0)
                print('PASS CDMA unsupported crypto rejected and reset clears channel/masks/IRQ/crypto', flush=True)
                monitor_stream.write(b'{"execute":"quit"}\n')
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
    with tempfile.TemporaryDirectory(prefix='n94-cdma-') as temporary:
        execute(pathlib.Path(sys.argv[1]).resolve(), pathlib.Path(temporary))
