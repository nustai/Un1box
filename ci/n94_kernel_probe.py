#!/usr/bin/env python3
"""Collect bounded traces of an actual kernel; successful collection is not an iOS boot pass."""
import argparse
import json
import pathlib
import socket
import subprocess
import time


def probe(binary, bundle, output, seconds):
    output.mkdir(parents=True, exist_ok=True)
    serial, log = output / "uart.log", output / "qemu.log"
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    command = [str(binary), "-M", f"n94,kboot={bundle}", "-S", "-display", "none",
               "-monitor", "none", "-serial", f"file:{serial}", "-no-reboot",
               "-qmp", f"tcp:127.0.0.1:{port},server=on,wait=off", "-d", "in_asm,int,guest_errors,unimp", "-D", str(log)]
    snapshots = []
    failure = None
    with (output / "stderr.log").open("w+") as errors:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors)
        connection = None
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
            qmp("cont")
            started = time.monotonic()
            for sample in range(max(1, int(seconds / 2))):
                time.sleep(0.25 if sample == 0 else 2)
                qmp("stop")
                registers = qmp("human-monitor-command", {"command-line": "info registers"})
                snapshots.append({"sample": sample, "elapsed_seconds": round(time.monotonic() - started, 3), "registers": registers})
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
    # Retain a bounded head and tail, rather than upload repeated multi-GB MMIO polls.
    log_size = log.stat().st_size if log.exists() else 0
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
