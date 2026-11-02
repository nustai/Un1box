#!/usr/bin/env python3
"""Read the actual n94 encrypted rootfs, UDIF and HFS+ without mounting or modifying it."""
import argparse
import bisect
import functools
import hashlib
import hmac
import json
import pathlib
import plistlib
import shutil
import struct
import zipfile
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes.fromhex("66aa77da612711b942ff984d91d7a657c57bb3510b284c592b86d0f93587fe09884ec669")


class EncryptedDMG:
    def __init__(self, path):
        self.file = path.open("rb")
        header = self.file.read(256)
        if header[:8] != b"encrcdsa":
            raise ValueError("not an encrypted v2 DMG")
        self.block = struct.unpack_from(">I", header, 52)[0]
        self.size, self.start = struct.unpack_from(">QQ", header, 56)
        if not 16 <= self.block <= 1 << 20 or self.block % 16:
            raise ValueError("invalid encrypted chunk size")
        self.aes = algorithms.AES(KEY[:16])

    def read(self, offset, length):
        if offset < 0 or length < 0 or offset + length > self.size:
            raise ValueError("DMG read out of range")
        first, last = offset // self.block, (offset + length + self.block - 1) // self.block
        self.file.seek(self.start + first * self.block)
        ciphertext = self.file.read((last - first) * self.block)
        if len(ciphertext) != (last - first) * self.block:
            raise ValueError("truncated encrypted DMG")
        result = bytearray()
        for block in range(first, last):
            iv = hmac.digest(KEY[16:], struct.pack(">I", block), "sha1")[:16]
            decryptor = Cipher(self.aes, modes.CBC(iv)).decryptor()
            at = (block - first) * self.block
            result += decryptor.update(ciphertext[at:at + self.block]) + decryptor.finalize()
        return bytes(result[offset % self.block:offset % self.block + length])


class UDIF:
    def __init__(self, source):
        self.source = source
        trailer = source.read(source.size - 512, 512)
        if trailer[:4] != b"koly":
            raise ValueError("decryption failed: no UDIF trailer")
        data_fork = struct.unpack_from(">Q", trailer, 0x18)[0]
        xml_offset, xml_size = struct.unpack_from(">QQ", trailer, 0xd8)
        self.size = struct.unpack_from(">Q", trailer, 0x1ec)[0] * 512
        metadata = plistlib.loads(source.read(xml_offset, xml_size))
        self.chunks = []
        for entry in metadata["resource-fork"]["blkx"]:
            table = entry["Data"]
            if len(table) < 204 or table[:4] != b"mish":
                raise ValueError("invalid UDIF block table")
            sector = struct.unpack_from(">Q", table, 8)[0]
            base = data_fork + struct.unpack_from(">Q", table, 24)[0]
            count = struct.unpack_from(">I", table, 200)[0]
            if len(table) < 204 + 40 * count:
                raise ValueError("truncated UDIF table")
            for index in range(count):
                kind, _, start, sectors, offset, length = struct.unpack_from(">II4Q", table, 204 + 40 * index)
                if kind in (0x7ffffffe, 0xffffffff) or not sectors:
                    continue
                if kind not in (0, 1, 2, 0x80000005):
                    raise ValueError(f"unsupported UDIF compression: {kind:#x}")
                self.chunks.append(((sector + start) * 512, sectors * 512, kind, base + offset, length))
        self.chunks.sort()
        self.starts = [entry[0] for entry in self.chunks]

    @functools.lru_cache(maxsize=8)
    def chunk(self, index):
        _, expected, kind, offset, length = self.chunks[index]
        if expected > 32 << 20:
            raise ValueError("UDIF data chunk unexpectedly large")
        data = self.source.read(offset, length)
        if kind == 0x80000005:
            decoder = zlib.decompressobj()
            data = decoder.decompress(data, expected + 1)
            if not decoder.eof:
                raise ValueError("UDIF chunk truncated or exceeds its output range")
        if len(data) != expected:
            raise ValueError("UDIF chunk length mismatch")
        return data

    def read(self, offset, length):
        if offset < 0 or length < 0 or offset + length > self.size:
            raise ValueError("UDIF read out of range")
        result = bytearray(length)
        index = max(0, bisect.bisect_right(self.starts, offset) - 1)
        while index < len(self.chunks) and self.chunks[index][0] < offset + length:
            start, size, kind, _, _ = self.chunks[index]
            lo, hi = max(start, offset), min(start + size, offset + length)
            if lo < hi and kind not in (0, 2):
                result[lo - offset:hi - offset] = self.chunk(index)[lo - start:hi - start]
            index += 1
        return bytes(result)


class HFS:
    def __init__(self, disk):
        self.disk = disk
        head = disk.read(0, 64 * 512)
        self.start, self.size = 0, disk.size
        if head[:2] == b"ER":
            block = struct.unpack_from(">H", head, 2)[0]
            count = struct.unpack_from(">I", head, block + 4)[0]
            for index in range(1, min(count + 1, len(head) // block)):
                at = index * block
                kind = head[at + 48:at + 80].rstrip(b"\0")
                if kind in (b"Apple_HFS", b"Apple_HFSX"):
                    start, sectors = struct.unpack_from(">II", head, at + 8)
                    self.start, self.size = start * block, sectors * block
                    break
            else:
                raise ValueError("no HFS partition")
        header = disk.read(self.start + 1024, 512)
        if header[:2] not in (b"H+", b"HX"):
            raise ValueError("invalid HFS+ volume header")
        self.block = struct.unpack_from(">I", header, 40)[0]
        self.catalog = header[272:352]
        tree = self.fork(self.catalog, 0, 64)
        self.first_leaf = struct.unpack_from(">I", tree, 24)[0]
        self.node_size = struct.unpack_from(">H", tree, 32)[0]
        if self.node_size < 512 or self.node_size > 32768:
            raise ValueError("invalid HFS catalog node size")

    def fork(self, descriptor, offset, length):
        logical = struct.unpack_from(">Q", descriptor)[0]
        if offset + length > logical:
            raise ValueError("HFS fork read out of range")
        output, cursor = bytearray(), 0
        for index in range(8):
            start, count = struct.unpack_from(">II", descriptor, 16 + index * 8)
            size = count * self.block
            lo, hi = max(offset, cursor), min(offset + length, cursor + size)
            if lo < hi:
                output += self.disk.read(self.start + start * self.block + lo - cursor, hi - lo)
            cursor += size
        if len(output) != length:
            raise ValueError("HFS overflow extents needed; not implemented")
        return bytes(output)

    def lookup(self, paths):
        targets = {tuple(path.strip("/").split("/")): path for path in paths}
        folders, files, candidates = {}, {}, []
        wanted_names = {parts[-1] for parts in targets}
        node_id, visited = self.first_leaf, set()
        while node_id:
            if node_id in visited:
                raise ValueError("cyclic HFS catalog")
            visited.add(node_id)
            node = self.fork(self.catalog, node_id * self.node_size, self.node_size)
            records = struct.unpack_from(">H", node, 10)[0]
            if node[8] != 255:
                raise ValueError("expected HFS catalog leaf")
            for index in range(records):
                at = struct.unpack_from(">H", node, len(node) - 2 * (index + 1))[0]
                key_length, parent, count = struct.unpack_from(">HIH", node, at)
                name = node[at + 8:at + 8 + count * 2].decode("utf-16-be")
                record = node[at + 2 + key_length:]
                kind = struct.unpack_from(">H", record)[0]
                if kind not in (1, 2):
                    continue
                cnid = struct.unpack_from(">I", record, 8)[0]
                if kind == 1:
                    folders[cnid] = (parent, name)
                elif name in wanted_names:
                    candidates.append((parent, name, record[88:168], record[168:248],
                                       record[40], record[41], struct.unpack_from(">H", record, 42)[0]))
            node_id = struct.unpack_from(">I", node)[0]

        def folder_path(cnid):
            parts, visited = [], set()
            while cnid != 2:
                if cnid in visited or cnid not in folders:
                    raise ValueError("invalid HFS folder ancestry")
                visited.add(cnid)
                cnid, name = folders[cnid]
                parts.append(name)
            return tuple(reversed(parts))

        for parent, name, descriptor, resource, admin_flags, owner_flags, mode in candidates:
            path = folder_path(parent) + (name,)
            if path in targets:
                size = struct.unpack_from(">Q", descriptor)[0]
                files[targets[path]] = {"data_fork_bytes": size,
                    "resource_fork_bytes": struct.unpack_from(">Q", resource)[0],
                    "bsd_mode": oct(mode), "owner_flags": owner_flags, "admin_flags": admin_flags,
                    "compressed": bool(owner_flags & 0x20),
                    "head": self.fork(descriptor, 0, min(size, 64)).hex()}
        return files

    def export(self, destination):
        if shutil.disk_usage(destination.parent).free < self.size + (512 << 20):
            raise ValueError("insufficient free space for the raw HFS volume")
        with destination.open("xb") as target:
            target.truncate(self.size)
            completed = 0
            for index, (start, size, kind, _, _) in enumerate(self.disk.chunks):
                lo, hi = max(start, self.start), min(start + size, self.start + self.size)
                if lo >= hi or kind in (0, 2):
                    continue
                chunk = self.disk.chunk(index)
                target.seek(lo - self.start)
                target.write(chunk[lo - start:hi - start])
                completed += hi - lo
                if completed // (128 << 20) != (completed - (hi - lo)) // (128 << 20):
                    print(f"Exported {completed >> 20} MiB of HFS data", flush=True)
        with destination.open("rb") as result:
            result.seek(1024)
            if result.read(2) not in (b"H+", b"HX"):
                raise ValueError("exported HFS header verification failed")
            result.seek(0)
            digest = hashlib.sha256()
            for block in iter(lambda: result.read(8 << 20), b""):
                digest.update(block)
        return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipsw", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--raw-volume", type=pathlib.Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    encrypted = args.output / "n94-rootfs.encrypted.dmg"
    with zipfile.ZipFile(args.ipsw) as archive:
        manifest = plistlib.loads(archive.read("BuildManifest.plist"))
        identity = next(i for i in manifest["BuildIdentities"] if i["Info"]["DeviceClass"] == "n94ap")
        name = identity["Manifest"]["OS"]["Info"]["Path"]
        expected = archive.getinfo(name)
        if not encrypted.exists():
            print(f"Extracting actual OS image {name} ({expected.file_size} bytes)", flush=True)
            with archive.open(name) as source, encrypted.open("xb") as destination:
                for chunk in iter(lambda: source.read(8 << 20), b""):
                    destination.write(chunk)
        if encrypted.stat().st_size != expected.file_size:
            raise ValueError("encrypted OS image is incomplete")
    crypto = EncryptedDMG(encrypted)
    disk = UDIF(crypto)
    volume = HFS(disk)
    files = volume.lookup(["/sbin/launchd", "/usr/lib/dyld", "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
                           "/System/Library/CoreServices/SystemVersion.plist"])
    report = {"ipsw_os_member": name, "encrypted_bytes": encrypted.stat().st_size,
              "logical_disk_bytes": disk.size, "hfs_volume_bytes": volume.size,
              "allocation_block_bytes": volume.block, "files": files,
              "bootable_device_implemented": False}
    if args.raw_volume:
        report["raw_volume_sha256"] = volume.export(args.raw_volume)
        report["raw_volume_path"] = str(args.raw_volume)
    (args.output / "n94-rootfs-inventory.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2), flush=True)
    crypto.file.close()


if __name__ == "__main__":
    main()
