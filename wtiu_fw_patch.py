#!/usr/bin/env python3
"""WTIU firmware patcher: stock v1.3.0 image -> patched v1.3.3 image.

Takes a stock MTH WTIU firmware .bin (WTIU-v1.3.0-20250814.bin), applies our
binary patches to usr/bin/wtiu and usr/bin/mux2tiu inside the squashfs,
stamps the version strings, and reassembles a flashable sysupgrade image.

Copyright-safe by construction: this tool contains only our patch hunks
(wtiu_patch_data.py) -- no MTH code. The user supplies the stock image.

Squashfs handling: prefers squashfs-tools-ng (sqfs2tar/tar2sqfs), which are
bundled in win_tools/bin for Windows builds and for the packaged app.
Falls back to classic squashfs-tools (unsquashfs/mksquashfs) as found on
Linux / WSL / macOS.

Usage:
    python3 wtiu_fw_patch.py WTIU-v1.3.0-20250814.bin
    python3 wtiu_fw_patch.py stock.bin -o WTIU-v1.3.3-20260911.bin
"""

import argparse
import binascii
import hashlib
import io
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile

from wtiu_patch_data import (
    WTIU_STOCK_SHA256, WTIU_PATCHED_SHA256, WTIU_SIZE, WTIU_HUNKS,
    MUX2TIU_STOCK_SHA256, MUX2TIU_PATCHED_SHA256, MUX2TIU_SIZE, MUX2TIU_HUNKS,
)

VERSION = 'v1.3.3-20260911'
REVISION = 'r26639-4dcf577f9d'

# Regex matches the stock stamp and any previously-stamped release.
VER_RE = re.compile(r'v1\.3\.\d+-\d{8}(-\d+)?')

UIMAGE_HDR_LEN = 64
SQUASHFS_MAGIC = b'hsqs'
DEADC0DE = b'\xde\xad\xc0\xde'
FWIMAGE_MAGIC = b'FWx0'
FWIMAGE_INFO = 1

STAMP_FILES = ('etc/openwrt_release', 'usr/lib/os-release', 'etc/banner')
BIN_PATCHES = (
    ('usr/bin/wtiu', WTIU_HUNKS, WTIU_STOCK_SHA256,
     WTIU_PATCHED_SHA256, WTIU_SIZE),
    ('usr/bin/mux2tiu', MUX2TIU_HUNKS, MUX2TIU_STOCK_SHA256,
     MUX2TIU_PATCHED_SHA256, MUX2TIU_SIZE),
)


class PatchError(Exception):
    pass


def die(msg):
    raise PatchError(msg)


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def apply_hunks(data, hunks, stock_sha, patched_sha, size, name, log):
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
    log(f'  {name}: {len(hunks)} hunks applied, sha256 verified')
    return bytes(buf)


def stamp_data(data):
    """Return (new_bytes, count) with release version strings rewritten."""
    text = data.decode('utf-8', errors='surrogateescape')
    new_text, n = VER_RE.subn(VERSION, text)
    if n:
        data = new_text.encode('utf-8', errors='surrogateescape')
    return data, n


def stamp_version(rootfs, log):
    """Rewrite the release version in the rootfs release files."""
    for rel in STAMP_FILES:
        p = os.path.join(rootfs, rel)
        if not os.path.isfile(p) or os.path.islink(p):
            continue
        with open(p, 'rb') as f:
            data = f.read()
        new_data, n = stamp_data(data)
        if n:
            with open(p, 'wb') as f:
                f.write(new_data)
        log(f'  {rel}: {n} version string(s) -> {VERSION}')


def parse_image(fw, log):
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
    log(f'  uImage kernel: {data_size} bytes, '
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


# --------------------------------------------------------------------------
# Tool discovery
# --------------------------------------------------------------------------

def _bundled_tool_dir():
    """win_tools/bin next to the script, or inside a frozen exe."""
    if getattr(sys, 'frozen', False):
        base = sys._MEIPASS  # PyInstaller unpack dir
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, 'win_tools', 'bin')


def find_ng_tools():
    """Locate (sqfs2tar, tar2sqfs): bundled dir first, then PATH."""
    exe = '.exe' if os.name == 'nt' else ''
    d = _bundled_tool_dir()
    a, b = (os.path.join(d, 'sqfs2tar' + exe),
            os.path.join(d, 'tar2sqfs' + exe))
    if os.path.isfile(a) and os.path.isfile(b):
        return a, b
    a, b = shutil.which('sqfs2tar'), shutil.which('tar2sqfs')
    if a and b:
        return a, b
    return None


def find_classic_tools():
    """Locate (unsquashfs, mksquashfs) on PATH."""
    a, b = shutil.which('unsquashfs'), shutil.which('mksquashfs')
    return (a, b) if a and b else None


# --------------------------------------------------------------------------
# squashfs-tools-ng backend (tar round-trip, no filesystem extraction)
# --------------------------------------------------------------------------

def sqfs_to_tar(sqfs_path, sqfs2tar, log):
    log('Extracting squashfs (sqfs2tar)...')
    r = subprocess.run([sqfs2tar, '-r', '.', sqfs_path],
                       capture_output=True)
    if r.returncode != 0 or not r.stdout:
        die('sqfs2tar failed: '
            + r.stderr.decode('utf-8', 'replace').strip()[:400])
    log(f'  tar stream: {len(r.stdout)} bytes')
    return r.stdout


def patch_tar(tar_bytes, log):
    """Patch binaries and stamp version strings inside a tar stream."""
    log('Patching binaries...')
    src = tarfile.open(fileobj=io.BytesIO(tar_bytes))
    buf = io.BytesIO()
    patched, stamped = set(), []
    with tarfile.open(fileobj=buf, mode='w',
                      format=tarfile.PAX_FORMAT) as dst:
        for m in src:
            if not m.isreg():
                dst.addfile(m)          # dirs, links, dev nodes: metadata only
                continue
            data = src.extractfile(m).read()
            rel = m.name.lstrip('./')
            for path, hunks, ssha, psha, size in BIN_PATCHES:
                if rel == path:
                    data = apply_hunks(data, hunks, ssha, psha, size,
                                       rel, log)
                    patched.add(rel)
            if rel in STAMP_FILES:
                data, n = stamp_data(data)
                if n:
                    stamped.append(f'  {rel}: {n} version string(s)')
            m.size = len(data)
            dst.addfile(m, io.BytesIO(data))
    missing = {p for p, *_ in BIN_PATCHES} - patched
    if missing:
        die(f'{sorted(missing)[0]} missing from image rootfs')
    log('Stamping version...')
    for line in stamped:
        log(line + f' -> {VERSION}')
    return buf.getvalue()


def tar_to_sqfs(tar_bytes, tar2sqfs, out_path, log):
    log('Rebuilding squashfs (tar2sqfs, xz, 1MB blocks)...')
    jobs = min(4, os.cpu_count() or 1)
    r = subprocess.run(
        [tar2sqfs, '-q', '-f', '-c', 'xz', '-b', '1048576',
         '-j', str(jobs), out_path],
        input=tar_bytes, capture_output=True)
    if r.returncode != 0 or not os.path.isfile(out_path):
        die('tar2sqfs failed: '
            + r.stderr.decode('utf-8', 'replace').strip()[:400])


# --------------------------------------------------------------------------
# Classic backend (unsquashfs to a temp rootfs, patch files, mksquashfs)
# --------------------------------------------------------------------------

def rebuild_classic(sqfs_path, new_sqfs, tools, td, log):
    unsquashfs, mksquashfs = tools
    rootfs = os.path.join(td, 'rootfs')
    log('Extracting squashfs (unsquashfs)...')
    # -ignore-errors/-no-exit-code: /dev device nodes can't be created
    # without root, and that's fine — the WTIU mounts devtmpfs at boot
    # anyway (the previously deployed rebuild had no /dev nodes either).
    # Real failures still surface: the hunk step below refuses if the
    # target binaries didn't extract.
    subprocess.run([unsquashfs, '-d', rootfs, '-ig', '-no-exit-code',
                    sqfs_path], capture_output=True)
    if not os.path.isdir(rootfs):
        die('unsquashfs produced no rootfs — corrupt image?')

    log('Patching binaries...')
    for rel, hunks, ssha, psha, size in BIN_PATCHES:
        p = os.path.join(rootfs, rel)
        if not os.path.isfile(p):
            die(f'{rel} missing from image rootfs')
        data = open(p, 'rb').read()
        patched = apply_hunks(data, hunks, ssha, psha, size, rel, log)
        st = os.stat(p)
        with open(p, 'wb') as f:
            f.write(patched)
        os.chmod(p, st.st_mode)

    log('Stamping version...')
    stamp_version(rootfs, log)

    log('Rebuilding squashfs (mksquashfs, xz, 1MB blocks)...')
    subprocess.run(
        [mksquashfs, rootfs, new_sqfs, '-noappend',
         '-comp', 'xz', '-b', '1048576', '-no-xattrs', '-all-root'],
        check=True, capture_output=True)


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------

def patch_firmware(input_path, out_path=None, log=print):
    """Patch a stock WTIU v1.3.0 image. Returns (out_path, size, sha256)."""
    if out_path is None:
        out_path = os.path.join(
            os.path.dirname(os.path.abspath(input_path)),
            f'WTIU-{VERSION}.bin')

    ng = find_ng_tools()
    classic = None if ng else find_classic_tools()
    if not ng and not classic:
        die('no squashfs tools found — install squashfs-tools-ng '
            '(sqfs2tar/tar2sqfs) or squashfs-tools (unsquashfs/mksquashfs)')

    log(f'Reading {input_path}...')
    with open(input_path, 'rb') as f:
        fw = f.read()
    header, kernel, sqfs_off = parse_image(fw, log)

    with tempfile.TemporaryDirectory(prefix='wtiu_patch_') as td:
        sqfs_path = os.path.join(td, 'stock.squashfs')
        new_sqfs = os.path.join(td, 'new.squashfs')
        # squashfs runs to the 4K pad after the kernel region; give
        # the unpacker everything up to the DEADC0DE marker
        tail = fw.find(DEADC0DE, sqfs_off)
        if tail < 0:
            die('DEADC0DE marker not found — unexpected image layout')
        with open(sqfs_path, 'wb') as f:
            f.write(fw[sqfs_off:tail])
        log(f'  squashfs region: {tail - sqfs_off} bytes '
            '(includes 0xFF padding, fine)')

        if ng:
            tar = sqfs_to_tar(sqfs_path, ng[0], log)
            tar_to_sqfs(patch_tar(tar, log), ng[1], new_sqfs, log)
        else:
            rebuild_classic(sqfs_path, new_sqfs, classic, td, log)
        with open(new_sqfs, 'rb') as f:
            sqfs = f.read()

    log('Assembling image...')
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

    digest = sha256(bytes(image))
    log(f'\nDone: {out_path}')
    log(f'  size:   {len(image)} bytes')
    log(f'  sha256: {digest}')
    log('  (unsigned — stock sysupgrade does not enforce signatures)')
    return out_path, len(image), digest


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('input', help='stock WTIU v1.3.0 firmware .bin')
    ap.add_argument('-o', '--output',
                    help=f'output path (default: WTIU-{VERSION}.bin '
                         'next to the input)')
    args = ap.parse_args()

    try:
        patch_firmware(args.input, args.output)
    except PatchError as e:
        print(f'ERROR: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
