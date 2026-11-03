#!/usr/bin/env python3
"""Exercise real n94 machine realization and ARM execution; this is not an iOS test."""
import json
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import time


def bundle():
    # UART0 is boot-console in the stock n94 DeviceTree.
    # Refuse to report a working CPU boot if the real early-XNU clock is frozen.
    # Each entry must see reset GPIO=0, then preserve a port write. On the
    # second entry this proves reset cleared the previous value, not just RAM.
    words = [0, 0, 0, 0xE5974000, 0xE3540000, 0x1AFFFFFE,
             0xE3A0405A, 0xE5874000, 0xE5976000, 0xE1540006, 0x1AFFFFFE,
             0xE5934000, 0xE3A050FF, 0xE2555001, 0x1AFFFFFD,
             0xE5936000, 0xE1560004, 0x0AFFFFFE]
    for byte in b"N94_SMOKE\n":
        words += [0xE3A01000 | byte, 0xE5821000]  # mov r1, #byte; str r1, [r2]
    words += [0xEAFFFFFE]
    words[0] = 0xE59F2000 | (len(words) * 4 - 8)  # ldr r2, [pc, #literal]
    words[1] = 0xE59F3000 | (len(words) * 4 - 8)
    words[2] = 0xE59F7000 | (len(words) * 4 - 8)
    image = struct.pack("<" + "I" * len(words), *words) + struct.pack("<III", 0x32500020, 0x3f200020, 0x3fa00000)
    image = image.ljust(4096, b"\0")
    return image + struct.pack("<8s4I", b"N94KBOOT", 0x80001000, 0x80001000, 0x80001800, len(image))


def execute(binary, directory, machine):
    serial = directory / (machine + ".serial")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    command = [binary, "-M", f"{machine},kboot={directory / 'valid.bin'},nand={directory},nand-overlay={directory}",
               "-S", "-display", "none", "-monitor", "none", "-serial", f"file:{serial}",
               "-qmp", f"tcp:127.0.0.1:{port},server=on,wait=off"]
    with (directory / (machine + ".stderr")).open("w+") as errors:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors)
        try:
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    errors.seek(0)
                    raise AssertionError("machine initialization failed: " + errors.read())
                try:
                    connection = socket.create_connection(("127.0.0.1", port), timeout=1)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise AssertionError("QMP startup timed out")
                    time.sleep(0.05)
            with connection:
                connection.settimeout(10)
                stream = connection.makefile("rwb", buffering=0)
                assert "QMP" in json.loads(stream.readline())

                def qmp(name, arguments=None):
                    request = {"execute": name}
                    if arguments is not None:
                        request["arguments"] = arguments
                    stream.write((json.dumps(request) + "\n").encode())
                    while True:
                        response = json.loads(stream.readline())
                        if "error" in response:
                            raise AssertionError(response)
                        if "return" in response:
                            return response["return"]

                qmp("qmp_capabilities")
                assert len(qmp("query-cpus-fast")) == 2
                info = qmp('human-monitor-command', {'command-line': 'xp /1wx 0x3f200004'})
                assert '0x000100c0' in info, info
                qmp("cont")
                for attempt in range(2):
                    deadline = time.monotonic() + 10
                    while serial.read_bytes().count(b"N94_SMOKE\n") < attempt + 1:
                        if process.poll() is not None or time.monotonic() > deadline:
                            raise AssertionError("ARM payload did not reach UART0 boot console")
                        time.sleep(0.05)
                    if attempt == 0:
                        qmp("system_reset")
                # This fork closes QMP during quit before a reply is guaranteed.
                stream.write(b'{"execute":"quit"}\n')
            process.wait(timeout=10)
            if process.returncode != 0:
                errors.seek(0)
                raise AssertionError(f"QEMU exit {process.returncode}: {errors.read()}")
            print(f"PASS {machine}: two CPUs, AIC INFO/counter, GPIO port write/read/reset, UART, re-execution", flush=True)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


def main():
    binary = str(pathlib.Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="n94-smoke-") as temp:
        directory = pathlib.Path(temp)
        data = bundle()
        (directory / "valid.bin").write_bytes(data)
        for machine in ("n94", "iPhone-4S"):
            execute(binary, directory, machine)
        malformed = {
            "short": (b"bad", "invalid kboot size"),
            "magic": (data[:-24] + b"BADMAGIC" + data[-16:], "invalid kboot magic"),
            "length": (data[:-4] + struct.pack("<I", 1), "invalid kboot memory layout"),
            "outside-ram": (data[:-16] + struct.pack("<I", 0) + data[-12:], "invalid kboot memory layout"),
        }
        for name, (contents, expected) in malformed.items():
            path = directory / (name + ".bin")
            path.write_bytes(contents)
            result = subprocess.run([binary, "-M", f"n94,kboot={path}", "-display", "none", "-serial", "null"],
                                    capture_output=True, text=True, timeout=15)
            assert result.returncode != 0 and expected in result.stderr, result.stderr
            print(f"PASS rejects malformed bundle: {name}", flush=True)


if __name__ == "__main__":
    main()
