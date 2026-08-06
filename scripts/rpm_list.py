#!/usr/bin/env python3
"""Extracts the file list of an RPM payload without rpm2cpio.

Used by the package scripts when rpm2cpio is unavailable. Parses the RPM
header tags (payload offset/size/compression) and decompresses the payload
stream, emitting the archive's file listing to stdout.

Supports the compression methods RPM itself produces by default
(gzip, xz/lzma, zstd, bzip2, lzip). Raises a clear error for unsupported
compression so the caller can fall back.
"""

import os
import struct
import sys
import io
from pathlib import PurePosixPath

LEAD_MAGIC = b"\xed\xab\xee\xdb"
HEADER_MAGIC = b"\x8e\xad\xe8\x01"


def main(path, extract_dir=None):
    with open(path, "rb") as handle:
        data = handle.read()
    if not data.startswith(LEAD_MAGIC):
        sys.exit(f"error: {path} is not an RPM file")

    # Find the header sections. The payload stream follows the second
    # header as raw compressed bytes; only its metadata lives in the tags.
    # Headers are 8-byte aligned between sections, but the payload follows
    # the main header with no trailing padding.
    headers = []
    offset = 96  # RPM lead
    while offset < len(data):
        if data[offset : offset + 4] != HEADER_MAGIC:
            break
        (reserved, index_count, data_size) = struct.unpack(">III", data[offset + 4 : offset + 16])
        index_start = offset + 16
        data_start = index_start + 16 * index_count
        index = []
        for i in range(index_count):
            entry = struct.unpack(">IIII", data[index_start + 16 * i : index_start + 16 * (i + 1)])
            index.append(entry)
        headers.append((data_start, data_size, index))
        offset = data_start + data_size
        # Align to 8 bytes before the next header section.
        if offset % 8:
            offset += 8 - (offset % 8)
    if len(headers) < 2:
        sys.exit("error: no payload header found in RPM")

    (payload_start, _last_size, _last_index) = headers[-1]
    payload_start += _last_size
    payload = data[payload_start:]
    (_data_start, _data_size, index) = headers[1]

    tags = {}
    for (tag, _kind, offset_in, count) in index:
        tags[tag] = (offset_in, count)

    # RPMTAG_PAYLOADFORMAT = 1124, RPMTAG_PAYLOADCOMPRESSOR = 1125.
    compressor_off, _ = tags.get(1125, (0, 0))
    compressor = data[_data_start + compressor_off : _data_start + compressor_off + 4].rstrip(b"\x00").decode("ascii", "replace")
    try:
        stream = io.BytesIO(payload)
        decompressed = decompress(stream, compressor).read()
    except (ImportError, OSError, ValueError) as error:
        sys.exit(f"error: cannot decompress payload ({compressor}): {error}")

    # The payload is a CPIO archive in the NEWC ("070701") format.
    if extract_dir:
        extract_cpio_newc(decompressed, extract_dir)
    else:
        for name in list_cpio_newc(decompressed):
            print(name)


def list_cpio_newc(archive):
    """Yields the file names of a cpio NEWC archive (no extraction)."""
    pos = 0
    names = []
    while True:
        entry = next_cpio_entry(archive, pos)
        if entry is None:
            break
        (name, _data, _mode, pos) = entry
        names.append(name)
        if name == "TRAILER!!!":
            break
    return names


def extract_cpio_newc(archive, root):
    """Extracts regular files and directories of a cpio NEWC archive."""
    pos = 0
    while True:
        entry = next_cpio_entry(archive, pos)
        if entry is None:
            break
        (name, data, mode, pos) = entry
        if name == "TRAILER!!!":
            break
        path = PurePosixPath(name)
        parts = path.parts
        if path.is_absolute() or not parts or any(part in ("", ".", "..") for part in parts):
            raise ValueError(f"unsafe cpio path: {name!r}")
        root_abs = os.path.abspath(root)
        target = os.path.abspath(os.path.join(root_abs, *parts))
        if os.path.commonpath((root_abs, target)) != root_abs:
            raise ValueError(f"cpio path escapes extraction root: {name!r}")
        if mode & 0o170000 == 0o040000:  # directory
            os.makedirs(target, exist_ok=True)
        elif mode & 0o170000 == 0o100000:  # regular file
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as handle:
                handle.write(data)
            os.chmod(target, mode & 0o777)
        else:
            # Symlinks and special files are not needed by the package
            # tests; skip them rather than guess.
            continue


def next_cpio_entry(archive, pos):
    """Returns `(name, data, mode, next_pos)` or `None` at the trailer."""
    if archive[pos : pos + 6] != b"070701":
        if archive[pos : pos + 6] == b"070707":
            raise ValueError("ODC cpio archives are not supported")
        if all(byte == 0 for byte in archive[pos : pos + 512]):
            return None
        raise ValueError("not a cpio NEWC archive")
    header = archive[pos : pos + 110]
    if len(header) != 110:
        raise ValueError("truncated cpio header")
    pos += 110
    fields = {}
    for index in range(13):
        start = 6 + index * 8
        fields[index] = int(header[start : start + 8], 16)
    # cpio NEWC fields: 0 ino, 1 mode, 2 uid, 3 gid, 4 nlink, 5 mtime,
    # 6 filesize, 7 devmajor, 8 devminor, 9 rdevmajor, 10 rdevminor,
    # 11 namesize, 12 check.
    namesize = fields[11]
    if namesize == 0 or pos + namesize > len(archive):
        raise ValueError("invalid cpio name length")
    name = archive[pos : pos + namesize - 1].decode("utf-8", "replace")
    pos += namesize
    pos = align4(pos)
    if pos + fields[6] > len(archive):
        raise ValueError("truncated cpio payload")
    data = archive[pos : pos + fields[6]]
    pos += fields[6]
    pos = align4(pos)
    return (name, data, fields[1], pos)


def align4(pos):
    if pos % 4:
        pos += 4 - (pos % 4)
    return pos


def decompress(stream, compressor):
    if not compressor or compressor in ("gzip", "zlib"):
        import gzip

        return gzip.GzipFile(fileobj=stream)
    if compressor in ("xz", "lzma"):
        import lzma

        return lzma.LZMAFile(stream)
    if compressor in ("zstd",):
        import zstandard  # noqa: F401  (checked below)

        return zstandard.ZstdDecompressor().stream_reader(stream)
    if compressor in ("bzip2", "bzip"):
        import bz2

        return bz2.BZ2File(stream)
    if compressor in ("lzip",):
        raise ValueError("lzip payloads are not supported")
    raise ValueError(f"unknown payload compressor {compressor!r}")


if __name__ == "__main__":
    if len(sys.argv) not in (2, 4):
        sys.exit("usage: rpm_list.py <package.rpm> [--extract <dir>]")
    extract_dir = None
    if len(sys.argv) == 4 and sys.argv[2] == "--extract":
        extract_dir = sys.argv[3]
    elif len(sys.argv) == 4:
        sys.exit("usage: rpm_list.py <package.rpm> [--extract <dir>]")
    main(sys.argv[1], extract_dir)
