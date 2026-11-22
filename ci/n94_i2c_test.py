#!/usr/bin/env python3
"""Exercise the n94 I2C controller against the emulated D1881 PMU."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

from n94_smoke import bundle


def main(binary):
    with tempfile.TemporaryDirectory() as tmp:
        directory = pathlib.Path(tmp)
        (directory / 'boot.bin').write_bytes(bundle())
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        command = [str(binary), '-M', f'n94,kboot={directory / "boot.bin"}', '-S',
                   '-display', 'none', '-monitor', 'none', '-serial', 'null',
                   '-qtest', f'tcp:127.0.0.1:{port},server=on,wait=off']
        with (directory / 'stderr.log').open('w+') as errors:
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors)
            try:
                deadline = time.monotonic() + 15
                while True:
                    try:
                        connection = socket.create_connection(('127.0.0.1', port), timeout=1)
                        break
                    except OSError:
                        if process.poll() is not None or time.monotonic() >= deadline:
                            errors.seek(0)
                            raise RuntimeError('QEMU qtest did not start: ' + errors.read())
                        time.sleep(0.05)
                with connection:
                    stream = connection.makefile('rwb', buffering=0)
                    def request(command):
                        stream.write((command + '\n').encode())
                        response = stream.readline().decode().strip()
                        if not response.startswith('OK'):
                            raise AssertionError((command, response))
                        return response
                    base = 0x33200000
                    def write(offset, value):
                        request(f'writel {base + offset:#x} {value:#x}')
                    def read(offset):
                        return int(request(f'readl {base + offset:#x}').split()[1], 16)
                    # Select STATUS_A then issue a one-byte repeated-start read.
                    write(0, 0x1e8)
                    write(0, 0x08)
                    write(0, 0x1e9)
                    write(0, 0x601)
                    status = read(0x14)
                    value = read(4)
                    assert status & 0x08000000, f'transfer did not complete: {status:#x}'
                    assert value == 0x48, f'unexpected PMU STATUS_A: {value:#x}'
                    # A transfer to an absent device reports a NAK.
                    write(0x14, 0xffffffff)
                    write(0, 0x1fe)
                    assert read(0x14) & 0x00200000, 'missing NAK for absent device'
                    print('PASS n94 I2C: D1881 read, transfer completion, absent-device NAK')
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: n94_i2c_test.py /path/to/qemu-system-arm')
    main(pathlib.Path(sys.argv[1]).resolve())
