#!/usr/bin/env python3
"""WTIU firmware patcher: stock v1.3.0 image -> patched v1.3.4 image.

Takes a stock MTH WTIU firmware .bin (WTIU-v1.3.0-20250814.bin), applies our
binary patches to usr/bin/wtiu and usr/bin/mux2tiu inside the squashfs,
patches the Track Processor blob lib/firmware/tp-v2.05-0-g049bee4.bin for
chopped-waveform (Lionel ZW-L) input tolerance, stamps the version strings,
and reassembles a flashable sysupgrade image.  The patched TP blob is
flashed automatically at first boot: tp_config sees the cksum mismatch and
reflashes the STM32 via stm32flash.

Copyright-safe by construction: this tool contains only our patch hunks
(wtiu_patch_data.py) -- no MTH code. The user supplies the stock image.

Requires: python3, squashfs-tools (unsquashfs, mksquashfs).
Runs on Linux / WSL / macOS.

Usage:
    python3 wtiu_fw_patch.py WTIU-v1.3.0-20250814.bin
    python3 wtiu_fw_patch.py stock.bin -o WTIU-v1.3.4-20260912.bin
"""

import argparse
import binascii
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

from wtiu_patch_data import (
    WTIU_STOCK_SHA256, WTIU_PATCHED_SHA256, WTIU_SIZE, WTIU_HUNKS,
    MUX2TIU_STOCK_SHA256, MUX2TIU_PATCHED_SHA256, MUX2TIU_SIZE, MUX2TIU_HUNKS,
    TP_STOCK_SHA256, TP_PATCHED_SHA256, TP_SIZE, TP_HUNKS,
)

VERSION = 'v1.3.4-20260912'
REVISION = 'r26639-4dcf577f9d'

# Regex matches the stock stamp and any previously-stamped release.
VER_RE = re.compile(r'v1\.3\.\d+-\d{8}(-\d+)?')

UIMAGE_HDR_LEN = 64
SQUASHFS_MAGIC = b'hsqs'
DEADC0DE = b'\xde\xad\xc0\xde'
FWIMAGE_MAGIC = b'FWx0'
FWIMAGE_INFO = 1


def die(msg):
    print(f'ERROR: {msg}', file=sys.stderr)
    sys.exit(1)


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def apply_hunks(data, hunks, stock_sha, patched_sha, size, name):
    """Apply (offset, old_sha8, new_bytes) hunks; verify before and after."""
    if len(data) != size:
        die(f'{name}: size {len(data)} != expected {size} — '
            'not the stock v1.3.0 binary?')
    if sha256(data) != stock_sha:
        die(f'{name}: sha256 mismatch — input is not the stock v1.3.0 binary')
    buf = bytearray(data)
    for off, old_sha8, newb in hunks:
        region = bytes(buf[off:off + len(newb)])
        if hashlib.sha256(region).hexdigest()[:16] != old_sha8:
            die(f'{name}: hunk at 0x{off:05X} does not match stock bytes — '
                'already patched or wrong base?')
        buf[off:off + len(newb)] = newb
    if sha256(bytes(buf)) != patched_sha:
        die(f'{name}: patched sha256 mismatch — patch did not apply cleanly')
    print(f'  {name}: {len(hunks)} hunks applied, sha256 verified')
    return bytes(buf)


def stamp_version(rootfs):
    """Rewrite the release version in the rootfs release files."""
    files = ['etc/openwrt_release', 'usr/lib/os-release', 'etc/banner']
    for rel in files:
        p = os.path.join(rootfs, rel)
        if not os.path.isfile(p) or os.path.islink(p):
            continue
        with open(p, 'r', encoding='utf-8') as f:
            text = f.read()
        new_text, n = VER_RE.subn(VERSION, text)
        if n:
            with open(p, 'w', encoding='utf-8') as f:
                f.write(new_text)
        print(f'  {rel}: {n} version string(s) -> {VERSION}')


def parse_image(fw):
    """Split a stock image into (uImage header, kernel, squashfs offset)."""
    if len(fw) < UIMAGE_HDR_LEN:
        die('input too small to be a firmware image')
    header = fw[:UIMAGE_HDR_LEN]
    if header[:4] != b'\x27\x05\x19\x56':  # uImage magic
        die('no uImage magic — not a WTIU firmware image?')
    data_size = struct.unpack_from('>I', header, 12)[0]
    kend = UIMAGE_HDR_LEN + data_size
    if fw[kend:kend + 4] != SQUASHFS_MAGIC:
        die('squashfs not found right after kernel — unexpected image layout')
    print(f'  uImage kernel: {data_size} bytes, '
          f'squashfs at 0x{kend:X}')
    return header, fw[UIMAGE_HDR_LEN:kend], kend


def metadata_json():
    return ('{  "metadata_version": "1.1", "compat_version": "1.0",   '
            '"supported_devices":["mth,wtiu","mth,wifi-tiu","asiarf,awm688"], '
            '"version": { "dist": "MTH", "version": "' + VERSION + '", '
            '"revision": "' + REVISION + '", "target": "ramips/mt76x8", '
            '"board": "mth_wtiu" } }\n').encode('ascii')


def fwimage_info_part(image, data):
    """Build an fwimage INFO part (header + data + trailer), matching
    `fwtool -I`. The CRC is seeded ~0 with no final xor and covers the
    entire image plus this part's data; size covers data+hdr+trailer."""
    part = struct.pack('<II', 0, 0) + data            # fwimage_header
    crc = binascii.crc32(image + part) ^ 0xFFFFFFFF
    size = len(part) + 16
    trailer = (FWIMAGE_MAGIC + struct.pack('>I', crc) +
               bytes([FWIMAGE_INFO]) + b'\x00' * 3 +
               struct.pack('>I', size))
    return part + trailer


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n', maxsplit=1)[0])
    ap.add_argument('input', help='stock WTIU v1.3.0 firmware .bin')
    ap.add_argument('-o', '--output',
                    help=f'output path (default: WTIU-{VERSION}.bin '
                         'next to the input)')
    args = ap.parse_args()

    for tool in ('unsquashfs', 'mksquashfs'):
        if not shutil.which(tool):
            die(f'{tool} not found — install squashfs-tools')

    out_path = args.output or os.path.join(
        os.path.dirname(os.path.abspath(args.input)),
        f'WTIU-{VERSION}.bin')

    print(f'Reading {args.input}...')
    fw = open(args.input, 'rb').read()
    header, kernel, sqfs_off = parse_image(fw)

    with tempfile.TemporaryDirectory(prefix='wtiu_patch_') as td:
        sqfs_path = os.path.join(td, 'stock.squashfs')
        # squashfs runs to the 4K pad after the kernel region; give
        # unsquashfs everything up to the DEADC0DE marker
        tail = fw.find(DEADC0DE, sqfs_off)
        if tail < 0:
            die('DEADC0DE marker not found — unexpected image layout')
        with open(sqfs_path, 'wb') as f:
            f.write(fw[sqfs_off:tail])
        print(f'  squashfs region: {tail - sqfs_off} bytes '
              f'(includes 0xFF padding, fine for unsquashfs)')

        rootfs = os.path.join(td, 'rootfs')
        print('Extracting squashfs...')
        # -ignore-errors/-no-exit-code: /dev device nodes can't be created
        # without root, and that's fine — the WTIU mounts devtmpfs at boot
        # anyway (the previously deployed rebuild had no /dev nodes either).
        # Real failures still surface: the hunk step below refuses if the
        # target binaries didn't extract.
        subprocess.run(['unsquashfs', '-d', rootfs, '-ig', '-no-exit-code',
                        sqfs_path], capture_output=True, check=False)
        if not os.path.isdir(rootfs):
            die('unsquashfs produced no rootfs — corrupt image?')

        print('Patching binaries...')
        for rel, hunks, ssha, psha, size in (
            ('usr/bin/wtiu', WTIU_HUNKS, WTIU_STOCK_SHA256,
             WTIU_PATCHED_SHA256, WTIU_SIZE),
            ('usr/bin/mux2tiu', MUX2TIU_HUNKS, MUX2TIU_STOCK_SHA256,
             MUX2TIU_PATCHED_SHA256, MUX2TIU_SIZE),
            ('lib/firmware/tp-v2.05-0-g049bee4.bin', TP_HUNKS,
             TP_STOCK_SHA256, TP_PATCHED_SHA256, TP_SIZE),
        ):
            p = os.path.join(rootfs, rel)
            if not os.path.isfile(p):
                die(f'{rel} missing from image rootfs')
            data = open(p, 'rb').read()
            patched = apply_hunks(data, hunks, ssha, psha, size, rel)
            st = os.stat(p)
            with open(p, 'wb') as f:
                f.write(patched)
            os.chmod(p, st.st_mode)

        print('Stamping version...')
        stamp_version(rootfs)

        new_sqfs = os.path.join(td, 'new.squashfs')
        print('Rebuilding squashfs (xz, 1MB blocks)...')
        subprocess.run(
            ['mksquashfs', rootfs, new_sqfs, '-noappend',
             '-comp', 'xz', '-b', '1048576', '-no-xattrs', '-all-root'],
            check=True, capture_output=True)
        sqfs = open(new_sqfs, 'rb').read()

    print('Assembling image...')
    image = bytearray()
    image += header
    image += kernel
    image += sqfs
    image += b'\xff' * ((4096 - len(image) % 4096) % 4096)
    image += DEADC0DE
    # fwimage metadata part: the 8-zero fwimage_header doubles as the
    # zero pad that follows DEADC0DE in the stock layout.
    image += fwimage_info_part(bytes(image), metadata_json())

    with open(out_path, 'wb') as f:
        f.write(image)

    print(f'\nDone: {out_path}')
    print(f'  size:   {len(image)} bytes')
    print(f'  sha256: {sha256(bytes(image))}')
    print('  (unsigned — stock sysupgrade does not enforce signatures)')


if __name__ == '__main__':
    main()
