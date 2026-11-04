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
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        qtest_port = reservation.getsockname()[1]
    breakpoint_address = os.environ.get('N94_BREAKPOINT')
    clcd_handoff = os.environ.get('N94_DIAGNOSTIC_CLCD_HANDOFF') == 'true'
    # Exception tracing can grow tens of MB per second in demand-paged
    # guests; breakpoint runs prioritize reaching the requested instruction.
    log_flags = 'in_asm,guest_errors,unimp' if breakpoint_address else 'in_asm,int,guest_errors,unimp'
    command = [str(binary), "-M", f"n94,kboot={bundle}", "-S", "-display", "none",
               "-monitor", "none", "-serial", f"file:{serial}", "-no-reboot",
               "-qmp", f"tcp:127.0.0.1:{port},server=on,wait=off", "-d", log_flags, "-D", str(log)]
    if breakpoint_address:
        command += ['-gdb', f'tcp:127.0.0.1:{gdb_port}']
    if clcd_handoff:
        command += ['-qtest', f'tcp:127.0.0.1:{qtest_port},server=on,wait=off',
                    '-qtest-log', str(output / 'qtest.log')]
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
            if clcd_handoff:
                # Values are an explicit, unverified handoff hypothesis; use
                # physical MMIO before the guest starts and verify readback.
                with socket.create_connection(('127.0.0.1', qtest_port), timeout=10) as qtest:
                    qtest.settimeout(10)
                    qstream = qtest.makefile('rwb', buffering=0)
                    def qtest_command(command):
                        qstream.write((command + '\n').encode())
                        reply = qstream.readline().decode().strip()
                        if not reply.startswith('OK'):
                            raise RuntimeError(f'QTest rejected {command}: {reply}')
                        return reply
                    qtest_command('writel 0x39200050 0x1')
                    qtest_command('writel 0x39200060 0x03c00280')
                    observed = [qtest_command('readl 0x39200050'), qtest_command('readl 0x39200060')]
                    values = [int(reply.split()[1], 0) for reply in observed]
                    if values != [1, 0x03c00280]:
                        raise RuntimeError(f'CLCD diagnostic writes did not read back: {observed}')
                    (output / 'diagnostic-clcd-handoff.json').write_text(json.dumps({
                        'diagnostic_only': True, 'physical_base': '0x39200000',
                        'assumed_values': {'0x50': '0x1', '0x60': '0x03c00280'},
                        'observed': observed}, indent=2))
            if breakpoint_address:
                debugger = socket.create_connection(('127.0.0.1', gdb_port), timeout=10)
                debugger.settimeout(10)
                def gdb_command(command):
                    payload = command.encode()
                    debugger.sendall(b'$' + payload + b'#' + f'{sum(payload) & 255:02x}'.encode())
                    while True:
                        byte = debugger.recv(1)
                        if not byte:
                            raise RuntimeError('GDB closed before reply')
                        if byte != b'$':
                            continue
                        packet = bytearray()
                        while True:
                            byte = debugger.recv(1)
                            if not byte:
                                raise RuntimeError('GDB closed during packet')
                            if byte == b'#':
                                break
                            packet.extend(byte)
                        checksum = debugger.recv(2)
                        while len(checksum) < 2:
                            more = debugger.recv(2 - len(checksum))
                            if not more:
                                raise RuntimeError('GDB checksum truncated')
                            checksum += more
                        if int(checksum, 16) != sum(packet) & 255:
                            raise RuntimeError('GDB reply checksum mismatch')
                        debugger.sendall(b'+')
                        if packet[:1] in (b'T', b'S'):
                            continue  # pending asynchronous stop notification
                        if packet != b'OK':
                            raise RuntimeError(f'GDB command rejected: {command}: {bytes(packet)!r}')
                        return
                gdb_command(f'Z0,{int(breakpoint_address, 0):x},2')
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
                    r1_match = re.search(r'R01=([0-9a-fA-F]{8})', registers)
                    r1_address = int(r1_match.group(1), 16) if r1_match else 0
                    r1_mapping = qmp('human-monitor-command', {'command-line':
                                     f'gva2gpa 0x{r1_address:x}'}) if r1_match else ''
                    object_words = qmp('human-monitor-command', {'command-line': f'x /24wx 0x{address:x}'})
                    first_frame_match = re.search(r'R07=([0-9a-fA-F]{8})', registers)
                    first_frame = int(first_frame_match.group(1), 16) if first_frame_match else 0
                    frame_before = qmp('human-monitor-command', {'command-line':
                                       f'x /64wx 0x{first_frame:x}'}) if first_frame else ''
                    (output / 'breakpoint.json').write_text(json.dumps(
                        {'registers': registers, 'virtual_address': hex(address), 'mapping': mapping,
                         'r1_virtual_address': hex(r1_address), 'r1_mapping': r1_mapping,
                         'object_words': object_words, 'initial_frame': frame_before}, indent=2))
                    breakpoint_hit = True
                    follow = os.environ.get('N94_FOLLOW_BREAKPOINT')
                    if follow:
                        gdb_command(f'z0,{int(breakpoint_address, 0):x},2')
                        gdb_command(f'Z0,{int(follow, 0):x},2')
                        qmp('cont')
                        follow_deadline = time.monotonic() + 30
                        while time.monotonic() < follow_deadline:
                            time.sleep(0.25)
                            if qmp('query-status')['status'] == 'debug':
                                state = qmp('human-monitor-command', {'command-line': 'info registers'})
                                match = re.search(r'R07=([0-9a-fA-F]{8})', state)
                                frame = qmp('human-monitor-command', {'command-line':
                                            f'x /4wx 0x{int(match.group(1), 16):x}'}) if match else ''
                                match = re.search(r'R01=([0-9a-fA-F]{8})', state)
                                object_words = qmp('human-monitor-command', {'command-line':
                                                   f'x /12wx 0x{int(match.group(1), 16):x}'}) if match else ''
                                string_bytes = ''
                                if match:
                                    word = qmp('human-monitor-command', {'command-line':
                                               f'x /1wx 0x{int(match.group(1), 16) + 16:x}'})
                                    values = re.findall(r'0x[0-9a-fA-F]+', word)
                                    if values and 0x80000000 <= int(values[-1], 16) < 0xa0000000:
                                        string_bytes = qmp('human-monitor-command', {'command-line':
                                                           f'x /48bx {values[-1]}'})
                                (output / 'follow-breakpoint.json').write_text(json.dumps(
                                    {'registers': state, 'frame': frame, 'argument_object': object_words,
                                     'argument_string_bytes': string_bytes}, indent=2))
                                break
                        else:
                            qmp('stop')
                            state = qmp('human-monitor-command', {'command-line': 'info registers'})
                            evidence = {'status': 'not reached in 30 seconds', 'registers': state}
                            if first_frame:
                                evidence['initial_thread_frame_after_wait'] = qmp('human-monitor-command', {
                                    'command-line': f'x /64wx 0x{first_frame:x}'})
                                if first_frame >= 512:
                                    evidence['initial_thread_stack_below_frame'] = qmp('human-monitor-command', {
                                        'command-line': f'x /128wx 0x{first_frame - 512:x}'})
                            for register, label in (('R13', 'stack'), ('R07', 'frame')):
                                match = re.search(register + r'=([0-9a-fA-F]{8})', state)
                                if match:
                                    address = int(match.group(1), 16)
                                    evidence[label] = qmp('human-monitor-command', {
                                        'command-line': f'x /32wx 0x{address:x}'})
                            (output / 'follow-timeout.json').write_text(json.dumps(evidence, indent=2))
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
            try:
                # This captures the actual QEMU console, which may be blank
                # until a guest display driver is implemented and initialized.
                qmp('screendump', {'filename': str((output / 'screen.ppm').resolve())})
            except RuntimeError as error:
                (output / 'screen-error.txt').write_text(str(error) + '\n')
            framebuffer = (output / 'boot-framebuffer.raw').resolve()
            result = qmp('human-monitor-command', {'command-line':
                         f'pmemsave 0x8fd00000 0x258000 "{framebuffer}"'})
            if result or not framebuffer.is_file():
                (output / 'framebuffer-error.txt').write_text(str(result) + '\n')
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
            'exception_tracing_enabled': not bool(breakpoint_address),
            'low_address_translation_blocks': sum(low_pc.values()),
            'low_address_examples': low_pc.most_common(32),
            'logged_exceptions': dict(exception_counts),
        }, indent=2))
        # Preserve surrounding control flow before truncation. This is useful
        # when a device start routine calls another driver and never returns.
        starts = ('0x811a875e:', '0x80e4b560:', '0x80551744:')
        with log.open(errors='replace') as source, (output / 'startup-flow.log').open('w') as target:
            remaining, seen = 0, set()
            for line in source:
                for marker in starts:
                    if line.startswith(marker) and marker not in seen:
                        seen.add(marker)
                        remaining = 2000
                        target.write(f'\n--- following {marker} ---\n')
                if remaining:
                    target.write(line)
                    remaining -= 1
        # Preserve actual 13G37 driver instructions before truncating repeated
        # exception output; otherwise the interesting initialization is lost.
        ranges = ((0x80d97200, 0x80d97b00), (0x80c8e000, 0x80c92000),
                  (0x80d26000, 0x80d27a00),  # stock n94 USB driver
                  (0x80e4a000, 0x80e5a000),  # AppleIOPFMI
                  (0x8108f000, 0x81097000),  # EmbeddedIOP
                  (0x811a8000, 0x811ab000),  # AppleA5IOP
                  (0x80f09000, 0x80f0d000),  # AppleInterruptController
                  (0x80849000, 0x80857000))  # IOCryptoAcceleratorFamily
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
