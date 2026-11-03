#!/usr/bin/env python3
"""Collect bounded traces of an actual kernel; successful collection is not an iOS boot pass."""
import argparse
import collections
import json
import os
import pathlib
import re
import socket
import subprocess
import time


def probe(binary, bundle, output, seconds):
    output.mkdir(parents=True, exist_ok=True)
    serial, log = output / "uart.log", output / "qemu.log"
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        gdb_port = reservation.getsockname()[1]
    command = [str(binary), "-M", f"n94,kboot={bundle}", "-S", "-display", "none",
               "-monitor", "none", "-serial", f"file:{serial}", "-no-reboot",
               "-qmp", f"tcp:127.0.0.1:{port},server=on,wait=off", "-d", "in_asm,int,guest_errors,unimp", "-D", str(log)]
    breakpoint_address = os.environ.get('N94_BREAKPOINT')
    if breakpoint_address:
        command += ['-gdb', f'tcp:127.0.0.1:{gdb_port}']
    snapshots = []
    failure = None
    breakpoint_hit = False
    with (output / "stderr.log").open("w+") as errors:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors)
        connection = None
        debugger = None
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    connection = socket.create_connection(("127.0.0.1", port), timeout=1)
                    break
                except OSError:
                    time.sleep(0.05)
            if connection is None:
                errors.seek(0)
                raise RuntimeError("QEMU did not start: " + errors.read())
            connection.settimeout(10)
            stream = connection.makefile("rwb", buffering=0)
            greeting = json.loads(stream.readline())
            if "QMP" not in greeting:
                raise ValueError(greeting)

            def qmp(name, arguments=None):
                request = {"execute": name}
                if arguments is not None:
                    request["arguments"] = arguments
                stream.write((json.dumps(request) + "\n").encode())
                while True:
                    line = stream.readline()
                    if not line:
                        raise RuntimeError("QMP closed")
                    reply = json.loads(line)
                    if "error" in reply:
                        raise RuntimeError(reply)
                    if "return" in reply:
                        return reply["return"]

            qmp("qmp_capabilities")
            if breakpoint_address:
                debugger = socket.create_connection(('127.0.0.1', gdb_port), timeout=10)
                debugger.settimeout(10)
                payload = f'Z0,{int(breakpoint_address, 0):x},2'.encode()
                debugger.sendall(b'$' + payload + b'#' + f'{sum(payload) & 255:02x}'.encode())
                reply = b''
                while b'#' not in reply or len(reply.split(b'#', 1)[1]) < 2:
                    chunk = debugger.recv(128)
                    if not chunk:
                        raise RuntimeError('GDB closed before breakpoint reply')
                    reply += chunk
                if b'$OK#' not in reply:
                    raise RuntimeError(f'GDB breakpoint rejected: {reply!r}')
                debugger.sendall(b'+')
            qmp("cont")
            started = time.monotonic()
            for sample in range(max(1, int(seconds / 2))):
                time.sleep(0.25 if sample == 0 else 2)
                if debugger is not None and qmp('query-status')['status'] == 'debug':
                    registers = qmp('human-monitor-command', {'command-line': 'info registers'})
                    match = re.search(r'R00=([0-9a-fA-F]{8})', registers)
                    if not match:
                        raise RuntimeError('R00 missing at USB breakpoint')
                    address = int(match.group(1), 16)
                    mapping = qmp('human-monitor-command', {'command-line': f'gva2gpa 0x{address:x}'})
                    (output / 'breakpoint.json').write_text(json.dumps(
                        {'registers': registers, 'virtual_address': hex(address), 'mapping': mapping}, indent=2))
                    breakpoint_hit = True
                    break
                qmp("stop")
                registers = qmp("human-monitor-command", {"command-line": "info registers"})
                snapshot = {"sample": sample, "elapsed_seconds": round(time.monotonic() - started, 3), "registers": registers}
                if sample in (0, 3) or sample == max(1, int(seconds / 2)) - 1:
                    for command_name, label in (('info irq', 'irq_info'), ('info pic', 'pic_info')):
                        snapshot[label] = qmp('human-monitor-command', {'command-line': command_name})
                    # Frame pointers and stack words help identify a wait loop
                    # when the stock release kernel omits a UART diagnostic.
                    for register, label, words in (('R13', 'stack', 32), ('R07', 'frame', 8)):
                        match = re.search(register + r'=([0-9a-fA-F]{8})', registers)
                        if match:
                            address = int(match.group(1), 16)
                            if address >= 0x80000000:
                                snapshot[label] = qmp('human-monitor-command', {
                                    'command-line': f'x /{words}wx 0x{address:x}'})
                if sample == 0 or sample == 3:
                    # Stock 13G37 mach_absolute_time uses the pointer at this
                    # global; capture the actual MMU translation, not a guess.
                    clock = qmp("human-monitor-command", {"command-line": "x /1wx 0x803ff084"})
                    snapshot["clock_pointer"] = clock
                    values = re.findall(r"0x[0-9a-fA-F]+", clock)
                    if values and int(values[-1], 16) >= 0x80000000:
                        snapshot["clock_mapping"] = qmp("human-monitor-command", {"command-line": "gva2gpa " + values[-1]})
                    snapshot["aic_counter_low"] = qmp("human-monitor-command", {"command-line": "xp /1wx 0x3f200020"})
                snapshots.append(snapshot)
                if serial.exists():
                    uart_text = serial.read_text(errors='replace')
                    fault = re.search(r'fault_addr=(0x[0-9a-fA-F]+)', uart_text)
                    if fault:
                        snapshot['fault_mapping'] = qmp('human-monitor-command', {
                            'command-line': 'gva2gpa ' + fault.group(1)})
                (output / "registers.json").write_text(json.dumps(snapshots, indent=2))
                if log.exists() and log.stat().st_size > 8 << 20:
                    break
                if serial.exists() and b"panic(" in serial.read_bytes():
                    break
                qmp("cont")
            qmp("stop")
            (output / "cpus.json").write_text(json.dumps(qmp("query-cpus-fast"), indent=2))
            stream.write(b'{"execute":"quit"}\n')
            process.wait(timeout=10)
        except Exception as error:
            failure = f"{type(error).__name__}: {error}"
            (output / "probe-error.txt").write_text(failure + "\n")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            if connection is not None:
                connection.close()
            if debugger is not None:
                debugger.close()
    # Retain a bounded head and tail, rather than upload repeated multi-GB MMIO polls.
    log_size = log.stat().st_size if log.exists() else 0
    if log.exists():
        low_pc = collections.Counter()
        exception_counts = collections.Counter()
        with log.open(errors='replace') as source:
            for line in source:
                match = re.match(r'^0x([0-9a-fA-F]{8}):', line)
                if match and int(match.group(1), 16) < 0x80000000:
                    low_pc[match.group(1)] += 1
                match = re.search(r'Taking exception \d+ \[([^]]+)\]', line)
                if match:
                    exception_counts[match.group(1)] += 1
        (output / 'execution-evidence.json').write_text(json.dumps({
            'note': 'Low addresses are observed translation blocks, not proof of a user process; QEMU in_asm logs translation, not every execution.',
            'low_address_translation_blocks': sum(low_pc.values()),
            'low_address_examples': low_pc.most_common(32),
            'logged_exceptions': dict(exception_counts),
        }, indent=2))
        # Preserve actual 13G37 driver instructions before truncating repeated
        # exception output; otherwise the interesting initialization is lost.
        ranges = ((0x80d97200, 0x80d97b00), (0x80c8e000, 0x80c92000),
                  (0x80d26000, 0x80d27a00))  # stock n94 USB driver
        with log.open(errors='replace') as source, (output / 'driver-init.log').open('w') as target:
            selected, block_bytes, retained = False, 0, 0
            for line in source:
                if line.startswith('----------------'):
                    selected, block_bytes = False, 0
                address = re.match(r'^0x([0-9a-fA-F]+):', line)
                if address:
                    selected = any(start <= int(address.group(1), 16) < end for start, end in ranges)
                if (selected and block_bytes < 8192) or line.startswith('n94 '):
                    target.write(line)
                    block_bytes += len(line)
                    retained += len(line)
                    if retained >= 512 << 10:
                        break
    if log_size > 2 << 20:
        with log.open("rb") as source:
            head = source.read(1 << 20)
            source.seek(-(1 << 20), 2)
            tail = source.read()
        log.write_bytes(head + b"\n... TRUNCATED ...\n" + tail)
    summary = {"diagnostic_only": True, "bundle": bundle.name, "exit_code": process.returncode,
               "samples": len(snapshots), "untrimmed_log_bytes": log_size,
               "uart_bytes": serial.stat().st_size if serial.exists() else 0,
               "ios_boot_confirmed": False, "probe_error": failure}
    (output / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary), flush=True)
    if snapshots:
        print(snapshots[-1]["registers"], flush=True)
    if failure:
        raise RuntimeError(failure)
    if breakpoint_address and not breakpoint_hit:
        raise RuntimeError(f'Breakpoint {breakpoint_address} was not reached')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("images", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--seconds", type=int, default=60)
    args = parser.parse_args()
    for version in (2, 3):
        probe(args.binary.resolve(), (args.images / f"n94-v{version}.kboot").resolve(),
              args.output / f"bootargs-v{version}", min(max(args.seconds, 1), 180))


if __name__ == "__main__":
    main()
