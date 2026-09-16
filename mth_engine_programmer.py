#!/usr/bin/env python3
# pylint: disable=too-many-lines
"""
Engine Manufacturing Data Programmer (for the MTH WTIU)

Reads and writes engine manufacturing data (engine name, cab number, road name,
serial number, etc.) through the WTIU TCP bridge using the DCS loader protocol.

This tool implements the same K/R/W command protocol used by the MTH DCS
Consumer Loader V5.0.0. See LOADER_PROTOCOL.md for full protocol details.

Usage:
  # Read current manufacturing data (safe, read-only)
  python mth_engine_programmer.py --host 192.168.1.174 --read

  # Read and display in hex dump
  python mth_engine_programmer.py --host 192.168.1.174 --read --hex

  # Write engine name and cab number
  python mth_engine_programmer.py --host 192.168.1.174 --write \\
      --engine-name "Big Boy 4014" --cab-number "4014"

  # Write full mfg data
  python mth_engine_programmer.py --host 192.168.1.174 --write \\
      --engine-name "Big Boy 4014" --cab-number "4014" \\
      --road-name "Union Pacific" --serial-number "AA1234567"

  # Use a custom port or debug mode
  python mth_engine_programmer.py --host 192.168.1.174 --read --debug

WARNING: The --write command modifies engine flash memory. Always do a
--read first to verify connectivity and see the current data. The tool
preserves all existing fields that you don't explicitly change.
"""

import argparse
import datetime
import os
import socket
import struct
import sys
import tempfile
import time
import zipfile

try:
    from zeroconf import Zeroconf, ServiceBrowser
    ZEROCONF_AVAILABLE = True
except ImportError:
    ZEROCONF_AVAILABLE = False

# ============================================================================
# Speck Cipher (same as wtiu_client.py)
# ============================================================================

SPECK_ROUNDS = 22
SPECK_KEY_LEN = 4
MASK16 = 0xFFFF

def ror16(x, r):
    """Rotate a 16-bit value right by r bits."""
    r = r % 16
    return ((x >> r) | (x << (16 - r))) & MASK16

def rol16(x, r):
    """Rotate a 16-bit value left by r bits."""
    r = r % 16
    return ((x << r) | (x >> (16 - r))) & MASK16

def speck_round(x, y, k):
    """Perform one Speck cipher round on state (x, y) with key k."""
    x = ror16(x, 7)
    x = (x + y) & MASK16
    x = x ^ k
    y = rol16(y, 2)
    y = y ^ x
    return x, y

def speck_expand(key):
    """Expand a 4-word Speck key into a 22-word round-key schedule."""
    b = key[0]
    a = [key[i + 1] for i in range(SPECK_KEY_LEN - 1)]
    s = [0] * SPECK_ROUNDS
    s[0] = b
    for i in range(SPECK_ROUNDS - 1):
        a_idx = i % (SPECK_KEY_LEN - 1)
        a[a_idx], b = speck_round(a[a_idx], b, i)
        s[i + 1] = b
    return s

def speck_encrypt(pt, k):
    """Encrypt a 2-word plaintext block with the Speck cipher."""
    ct = [pt[0], pt[1]]
    for i in range(SPECK_ROUNDS):
        ct[1], ct[0] = speck_round(ct[1], ct[0], k[i])
    return ct

# Speck key from MTH remote-control source
SPECK_KEY = [5196, 46084, 38013, 32838]

# ============================================================================
# mDNS Discovery
# ============================================================================

# WTIU advertises via mDNS under several possible service types.
# The WTIU picks a RANDOM port on each boot, so we must use mDNS to find it.
# Based on the DCS loader protocol reverse-engineered from the MTH DCS
# Consumer Loader V5.0.0 .NET assembly.
WTIU_MDNS_SERVICE_TYPES = [
    '_mth-dcs._tcp.local.',
    '_wtiu._tcp.local.',
    '_mth._tcp.local.',
    '_dcs._tcp.local.',
]

class WTIUDiscoveryListener:
    """Zeroconf listener that collects WTIU service entries.

    Handles WTIU firmware quirks:
    - Service names with spaces (zeroconf rejects these normally)
    - Random ports on each boot
    """

    def __init__(self):
        self.found = []

    def add_service(self, zc, service_type, name):
        """Handle a newly discovered mDNS service, adding it to the found list."""
        try:
            info = zc.get_service_info(service_type, name, timeout=3000)
        except Exception:  # pylint: disable=broad-exception-caught
            # Some WTIU firmware advertises service names with spaces
            # which zeroconf rejects. Try to parse the info manually.
            try:
                from zeroconf import ServiceInfo  # pylint: disable=import-outside-toplevel
                parts = name.split('.')
                st = service_type
                for i, p in enumerate(parts):
                    if p.startswith('_') and '-dcs' in p:
                        st = '.'.join(parts[i:]) if i < len(parts) - 1 else service_type
                        break
                info = ServiceInfo(type_=st, name=name)
                entries = zc.cache.get_all_by_name(name)
                if entries:
                    for entry in entries:
                        entry.as_service_info(info)
            except Exception:  # pylint: disable=broad-exception-caught
                return

        if info:
            try:
                addr = info.parsed_addresses()[0]
            except (IndexError, Exception):  # pylint: disable=broad-exception-caught
                return

            self.found.append({
                'name': name,
                'host': addr,
                'port': info.port,
                'properties': {k.decode(): v.decode() if v else ''
                               for k, v in info.properties.items()} if info.properties else {},
            })

    def remove_service(self, zeroconf, service_type, name):
        """Handle a removed mDNS service (no-op)."""
    def update_service(self, zeroconf, service_type, name):
        """Handle an updated mDNS service (no-op)."""

def discover_wtiu(timeout=2.0, debug=False):
    """Discover WTIU devices on the local network via mDNS.

    Tries multiple service type names since the WTIU advertises under
    different names depending on firmware version.

    Returns a list of dicts with 'name', 'host', 'port', 'properties'.
    """
    if not ZEROCONF_AVAILABLE:
        print("mDNS discovery requires the 'zeroconf' package: pip install zeroconf")
        return []

    zc = Zeroconf()
    listener = WTIUDiscoveryListener()

    for service_type in WTIU_MDNS_SERVICE_TYPES:
        if debug:
            print(f"  Browsing for {service_type}...")
        browser = ServiceBrowser(zc, service_type, listener)
        time.sleep(timeout)

        if listener.found:
            if debug:
                print(f"  Found WTIU using service: {service_type}")
            break
        browser.cancel()

    zc.close()

    if debug:
        for d in listener.found:
            print(f"  Found: {d['name']} at {d['host']}:{d['port']}")

    return listener.found

def resolve_wtiu_host(host, debug=False):  # pylint: disable=too-many-branches
    """Resolve a host string to (ip, port).

    If host is None, discovers via mDNS (the WTIU uses a random port).
    If host is an IP address, uses the default port 38885.
    If host is an mDNS name (*.local), resolves it via zeroconf.
    """
    if host is None:
        if debug:
            print("  Discovering WTIU via mDNS...")
        devices = discover_wtiu(debug=debug)
        if not devices:
            print("No WTIU found via mDNS. Specify --host explicitly.")
            sys.exit(1)
        if len(devices) == 1:
            d = devices[0]
            print(f"  Found WTIU: {d['name']} at {d['host']}:{d['port']}")
            return d['host'], d['port']
        # Multiple devices found
        print("Multiple WTIU devices found:")
        for i, d in enumerate(devices):
            print(f"  [{i}] {d['name']} at {d['host']}:{d['port']}")
        choice = input("Select device [0]: ").strip()
        idx = int(choice) if choice else 0
        d = devices[idx]
        return d['host'], d['port']

    # Resolve .local names via mDNS
    if host.endswith('.local'):
        if debug:
            print(f"  Resolving mDNS name: {host}")
        if not ZEROCONF_AVAILABLE:
            print(f"Cannot resolve {host} without zeroconf package. pip install zeroconf")
            sys.exit(1)
        zc = Zeroconf()
        try:
            for service_type in WTIU_MDNS_SERVICE_TYPES:
                info = zc.get_service_info(service_type, host + '.' + service_type, timeout=3000)
                if info:
                    try:
                        addr = info.parsed_addresses()[0]
                    except (IndexError, Exception):  # pylint: disable=broad-exception-caught
                        continue
                    if debug:
                        print(f"  Resolved {host} -> {addr}:{info.port}")
                    return addr, info.port
        finally:
            zc.close()
        # Fallback: try regular DNS resolution
        try:
            ip = socket.gethostbyname(host)
            return ip, 38885
        except socket.gaierror:
            print(f"Could not resolve mDNS name: {host}")
            sys.exit(1)

    # Plain IP address - use default port
    return host, 38885

# ============================================================================
# WTIU Connection
# ============================================================================

class WTIUConnection:
    """TCP connection to the WTIU."""

    def __init__(self, host, port=38885, debug=False):
        self.host = host
        self.port = port
        self.debug = debug
        self.sock = None
        self.expanded_key = None

    def connect(self):
        """Open a TCP connection to the WTIU."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10.0)
        self.sock.connect((self.host, self.port))
        if self.debug:
            print(f"  Connected to {self.host}:{self.port}")

    def disconnect(self):
        """Close the TCP connection to the WTIU."""
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_cmd(self, cmd, timeout=15.0):
        """Send an ASCII command with CRLF and return the response."""
        if isinstance(cmd, str):
            data = cmd.encode('ascii') + b'\r\n'
        else:
            data = cmd + b'\r\n'
        if self.debug:
            print(f"  TX: {data.decode('ascii', errors='replace').strip()}")
        self.sock.sendall(data)
        return self.recv_response(timeout=timeout)

    def send_w(self, cmd, payload, timeout=15.0):
        """Send a W command header with CRLF, then raw payload bytes."""
        if isinstance(cmd, str):
            data = cmd.encode('ascii') + b'\r\n'
        else:
            data = cmd + b'\r\n'
        if self.debug:
            print(f"  TX: {data.decode('ascii', errors='replace').strip()}"
                  f" + {len(payload)} raw bytes")
        self.sock.sendall(data)
        self.sock.sendall(payload)
        return self.recv_response(timeout=timeout)

    def send_y(self, body, timeout=20.0):
        """Send a hand-built DI frame through the `Y` diagnostic command.

        `Y` exists only in the custom reconnaissance firmware; it hands
        frame[1..len-1] straight to the client so frame geometry can be tested
        without a reflash.  Stock firmware answers "input error".

        `body` is frame[1..] -- build it with di_header_frame/di_short_frame.
        The dispatcher collapses the result to "okay" regardless of the DI
        transport's verdict; the real return code is only in the daemon's
        syslog line `Y: len=%d rc=%d`.
        """
        return self.send_cmd(di_y_command(body), timeout=timeout)

    def send_s(self, data, msg_type, timeout=30.0):
        """Send a burst through the stock long-transfer path via `S`.

        `S<2-hex count><hex data>`.  The firmware stages the 30-byte payload
        ([channel|0x80, count-1, 0x40, data..., 0xFF padding]) and calls the
        stock FUN_004049d8, which stamps the sequence nibble, checksums the
        payload and emits a real 41-length long-transfer frame.

        That frame shape is what reaches LM8 `long_transfer_handler`, the only
        code path that emits the burst terminator (control 5).  As with `Y`,
        the dispatcher collapses the result to "okay"; the real verdict is the
        daemon's `S: n=%d rc=%d` syslog line, and the only proof the engine
        acted on it is the 07 07 00 address pointer advancing.
        """
        return self.send_cmd(di_s_command(data, msg_type), timeout=timeout)

    def recv_response(self, timeout=15.0):
        """Receive until we get a complete response (ends with okay or error)."""
        self.sock.settimeout(timeout)
        data = b''
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b'\r\n' in data:
                    break
        except socket.timeout:
            pass
        result = data.decode('ascii', errors='replace')
        if self.debug:
            print(f"  RX: {result.strip()}")
        return result

    def drain_buffer(self, timeout=2.0):
        """Drain any stale data from the socket receive buffer.

        After a command timeout (e.g. K erase timeout), the daemon may
        still send its response later. That stale data would be read by
        the next command's recv_response, causing a protocol desync.
        This method reads and discards any pending data.
        """
        self.sock.settimeout(timeout)
        discarded = b''
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                discarded += chunk
        except socket.timeout:
            pass
        if discarded and self.debug:
            print(f"  Drained stale data: {discarded.decode('ascii', errors='replace').strip()}")

    def authenticate(self):
        """Perform H5/H6 Speck authentication."""
        self.expanded_key = speck_expand(SPECK_KEY)

        # H5: get challenge
        resp = self.send_cmd("H5")
        if "okay" not in resp:
            print(f"  H5 failed: {resp}")
            return False

        # Parse challenge: "H5 XXXXXXXX okay"
        parts = resp.strip().split()
        if len(parts) < 2:
            print(f"  Cannot parse H5 response: {resp}")
            return False

        hex_part = parts[1]
        if len(hex_part) != 8:
            print(f"  Challenge not 8 hex digits: {hex_part}")
            return False

        plain_hi = int(hex_part[0:4], 16)
        plain_lo = int(hex_part[4:8], 16)
        plain = [plain_lo, plain_hi]

        # Encrypt
        enc = speck_encrypt(plain, self.expanded_key)

        # H6: send encrypted response (word1 first, then word0)
        h6_cmd = f"H6{enc[1]:04X}{enc[0]:04X}"
        resp = self.send_cmd(h6_cmd)
        if "okay" not in resp:
            print(f"  H6 failed: {resp}")
            return False

        if self.debug:
            print("  Authentication successful")
        return True

# ============================================================================
# DCS Loader Protocol
# ============================================================================

# ----------------------------------------------------------------------------
# Patched WTIU firmware limits (v1.3.1-20260818, daemon v1.07-2-gklw)
# ----------------------------------------------------------------------------
# The daemon reads a command line into an 80-byte buffer at 0x004204DC
# (0x004204DC..0x0042052B, with the length counter immediately after at
# 0x0042052C). The main loop rejects anything at or beyond 0x50 bytes and logs
# "loop: input buffer overflow" / "loop: command buffer overflow", so the
# longest usable command line is 79 characters.
#
# A W command is "W" + 6 hex address + 6 hex length + 2 hex chars per byte.
# The v17 firmware handler parses the command line and reads 2*len hex chars
# from the input, so the whole line plus hex payload must fit the daemon's
# 80-byte command buffer. The v17 handler sends the full TIU-compatible
# sequence internally (l1, 0x07 address setup, 0x0D init, 0x0B write-enable,
# 0x07 poll, the data burst in a header frame, 0x0B cleanup, l0) — the
# programmer only needs to send W<addr><len><hexdata>.
WTIU_CMD_LINE_MAX = 79          # usable characters per command line
W_CMD_OVERHEAD = 13             # 'W' + 6 addr + 6 len
# Per-command data limit is BURST_DATA_MAX (27): the firmware wraps each W
# body in a header frame and rejects bodies > 31 bytes (FUN_00404444 traps at
# a 42-byte frame), so write_burst chunks to 27 data bytes per W.

# --- Flash-write burst CRC ---------------------------------------------------
#
# The TIU appends a 16-bit CRC to every flash-write burst. Its byte pump
# (data/tiu_0e9574_disasm.txt) initialises the M16C CRCD register to 0xFFFF
# at 0x0e9596, feeds every staging-buffer byte through CRCIN at 0x0e95b0
# (so the channel|0x80 and count-1 bytes are covered, not just the data), and
# transmits CRCD high byte first (0x03BD at 0x0e95df) then low (0x03BC at
# 0x0e960a).
#
# The polynomial direction is the one thing the firmware cannot tell us: CRCD
# is a hardware unit we cannot execute. Renesas documents it as CRC-CCITT
# shifted LSB-first, which is the reflected form (0x8408) -- but the previous
# firmware used the MSB-first form (0x1021) over the data bytes only, which
# _check_crc_variant.py confirms is what produced the `f9 0a` seen on the
# wire. Both the variant and the span were wrong there.
#
# The CRC is computed here rather than in the firmware precisely so that
# trying the other variant costs one line and no reflash.
# Both variants were tried live (2026-08-26) and produced an identical
# rc=-112 / stage 10 DCS timeout, so the CRC is not what the engine is
# objecting to. Left on the reflected form because that is what Renesas
# documents for the CRCD unit.
BURST_CRC_REFLECTED = True      # True selects the reflected 0x8408 form (proven live)

# DI transceiver mode, carried in the top nibble of the W length field.
# The TIU's FUN_0e9730 seeds DAT_0x318f from `TB2 & 3` and FUN_0e90bc maps that
# to P7 bits 5/6. Its transaction retry loop re-samples the mode each attempt,
# so the TIU tries all four. On the WTIU, frame[1]'s high nibble is the
# candidate for the same field: short frames use 0x00 (mode 0), long frames
# 0x10 (mode 1). Our burst has only ever run in mode 1 because it copied the
# tone frame's 0x10. This makes 0/2/3 reachable from the client with no
# reflash.
BURST_MODE = 1


def burst_crc(channel, data):
    """CRC-16 over the burst payload, matching the TIU's CRCD unit.

    Spans [channel|0x80, len(data)-1] followed by `data`, mirroring the
    staging buffer that FUN_0e9574 walks.
    """
    buf = bytes([channel | 0x80, (len(data) - 1) & 0xFF]) + bytes(data)
    if BURST_CRC_REFLECTED:
        crc = 0xFFFF
        for b in buf:
            crc ^= b
            for _ in range(8):
                crc = ((crc >> 1) ^ 0x8408) if (crc & 1) else (crc >> 1)
        return crc
    crc = 0xFFFF
    for b in buf:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if (crc & 0x8000) else (crc << 1)
            crc &= 0xFFFF
    return crc


# Handlers that report success unconditionally, so their " okay" proves nothing:
#   K -- runs the DI erase sequence but discards every helper return code
#   C -- a bare "return 0" stub (the TIU original only toggled M16C port pins)
#   Y -- the diagnostic frame probe; always returns 0 so the dispatcher does
#        not run its error jump table.  Read `Y: len=%d rc=%d` from syslog.
# Erases and writes must therefore be confirmed by reading the flash back.
WTIU_TRUSTWORTHY_ACKS = False


# ============================================================================
# DI frame geometry
# ============================================================================
# Confirmed on hardware 2026-08-31 by replaying commands through the `Y` probe
# and diffing `di_transfer tx/rx` against the stock handlers at -vvvvv.
#
#   frame[0]      COBS overhead, written by FUN_00404444
#   frame[1]      control: bit 4 = 8-byte header present,
#                 low nibble = track index, ORed in by FUN_00404658
#   frame[2..3]   little-endian timeout            (header frames only)
#   frame[4]      0
#   frame[5]      expected INBOUND response length (header frames only)
#   frame[6]      flags, 0xC3 on every frame the engine answers
#   frame[7]      DAT_0042048a, observed constant 0x02
#   frame[8..9]   0x7FFF
#   frame[10..]   DI wire payload                  (frame[2..] when no header)
#   frame[len-1]  payload checksum, 0xFF - sum(payload)
#
# `len` is the value FUN_00404444 receives; it transmits len+1 bytes after COBS
# stuffing and traps at len > 41.
#
# frame[5] is the length of the reply the engine is expected to send, counting
# its trailing checksum -- it is NOT derived from the outbound payload:
#   `56 07 04 14` (read 20) -> rx `00 00 ff*20 13`, frame[5] = 0x15 = 20 + 1
#   `56 07 07 00` (poll)    -> rx `00 00 00 1d d2 00 10`, frame[5] = 0x05 = 4 + 1
# Overstating it makes the engine report -0x60 "DCS overrun"; understating it
# truncates the reply.  Both leave the engine wedged until track power cycles,
# so never guess this field.
DI_FLAGS_DEFAULT = 0xC3
DI_DAT48A = 0x02
DI_FRAME_LEN_MAX = 41

# Engine status byte -> dispatcher string, as decoded by FUN_00404444's caller.
DI_STATUS = {
    0: 'ok',
    -0x40: 'checksum error',
    -0x60: 'DCS overrun error',
    -0x70: 'DCS timeout',
}


def di_checksum(payload):
    """One's complement of the payload byte sum; reproduces FUN_00404430."""
    return (0xFF - (sum(payload) & 0xFF)) & 0xFF


def di_read_timeout(n):
    """FUN_00404ebc read branch: (n+3)*0x43 + (n+0x7f).

    Reproduces the timeout field of four captured `R` frames exactly for
    n = 4, 12, 16 and 20.
    """
    return ((n + 3) & 0xFF) * 0x43 + ((n + 0x7F) & 0xFF)


def di_short_frame(payload, ctrl=0, trailer=True):
    """7-byte-style frame: no header, payload at frame[2]."""
    body = bytes([(ctrl & 0xF) << 4]) + bytes(payload)
    return body + bytes([di_checksum(payload)]) if trailer else body


def di_header_frame(payload, timeout, resp, flags=DI_FLAGS_DEFAULT, ctrl=1,
                    trailer=True, dat48a=DI_DAT48A):  # pylint: disable=too-many-arguments,too-many-positional-arguments
    """15/41-byte-style frame: 8-byte FPGA header, payload at frame[10].

    `resp` is the expected inbound reply length including its checksum; see
    the geometry notes above before changing it.
    """
    body = bytes([(ctrl & 0xF) << 4,
                  timeout & 0xFF, (timeout >> 8) & 0xFF,
                  0x00, resp & 0xFF, flags, dat48a, 0xFF, 0x7F]) + bytes(payload)
    return body + bytes([di_checksum(payload)]) if trailer else body


# LM8 long_transfer_handler rejects a transfer count above 0x16, so the stock
# long-transfer path can carry at most 22 data bytes per frame.
DI_LONG_MAX = 22


# LM8 dispatches payload[2]'s high nibble as a message type at 0x03f0-0x03ff.
# Only these six have a case; anything else (notably the 0x40 this code used to
# hardcode) runs off the end of program memory, so the transfer never completes
# and the LM8 answers status 0x90 -> FUN_00404444 returns -112.
DI_LONG_TYPES = (0x0, 0x1, 0x2, 0x3, 0x5, 0x6)
DI_LONG_TYPE_TONE = 0x3          # stock tone blob DAT_00408f30 uses [2] = 0x30


def di_s_command(data, msg_type):
    """Wrap burst data into the `S` long-transfer command string.

    msg_type is the payload[2] high nibble. It is NOT optional: the correct
    value for a flash-data burst is still unproven, and defaulting it would
    reintroduce exactly the silent wrong-constant bug that cost us several
    flash cycles.
    """
    if not 1 <= len(data) <= DI_LONG_MAX:
        raise ValueError(f'S carries 1..{DI_LONG_MAX} bytes, got {len(data)} '
                         f'(LM8 long_transfer_handler caps SPM[0x0F] at 0x16)')
    if not 0 <= msg_type <= 0xF:
        raise ValueError(f'msg_type {msg_type:#x} is not a nibble')
    if msg_type not in DI_LONG_TYPES:
        raise ValueError(
            f'msg_type {msg_type:#x} has no LM8 dispatch case; '
            f'recognised types are {[hex(t) for t in DI_LONG_TYPES]}')
    cmd = 'S%X%02X%s' % (msg_type, len(data), bytes(data).hex().upper())
    if len(cmd) > WTIU_CMD_LINE_MAX:
        raise ValueError(f'command line would be {len(cmd)} chars, over the '
                         f'daemon limit of {WTIU_CMD_LINE_MAX}')
    return cmd


def di_y_command(body):
    """Wrap a frame body (frame[1..]) into the `Y` diagnostic command string."""
    length = len(body) + 1                    # + frame[0], the COBS slot
    if not 3 <= length <= DI_FRAME_LEN_MAX:
        raise ValueError(f'frame length {length} outside 3..{DI_FRAME_LEN_MAX}')
    cmd = 'Y%02X%s' % (length, body.hex().upper())
    if len(cmd) > WTIU_CMD_LINE_MAX:
        raise ValueError(f'command line would be {len(cmd)} chars, over the '
                         f'daemon limit of {WTIU_CMD_LINE_MAX}')
    return cmd


# --- Flash-write burst --------------------------------------------------------
#
# The `z`-command data word's high nibble (cmd_type 7) selects the DI
# operation; this is how the engine is told to set an address byte, run a
# read, arm a write, or report the write pointer:
#
#   z07 + 0x0hh        set address high byte
#   z07 + 0x1mm        set address mid byte
#   z07 + 0x2ll        set address low byte
#   z07 + 0x4nn        READ  nn bytes at the current pointer
#   z07 + 0x6nn        WRITE nn bytes at the current pointer (arms the burst)
#   z07 + 0x0700       status poll -> returns the live write pointer
#
# (FUN_00404ebc issues the 0x400|len read and 0x600|len write command words;
# FUN_00404984 sends the three 0x07 address bytes.  Verified against the
# decompiled block-write.)
#
# The data itself is carried by the proven `Y` raw-frame burst:
#   [channel|0x80] [count] [count data bytes] [0xFF pad to index 28]
#   [CRC_hi] [CRC_lo] [0x0A]
# A single burst advanced the write pointer and persisted (2026-09-11).
#
# Per-block protocol (mirrors TIU FUN_0e9906 / WTIU FUN_00404ebc): re-set the
# address, issue the 0x600|len write command, send the data burst, then poll
# the write pointer until it has advanced past the block -- the engine is
# busy committing flash between blocks and drops bursts sent too early
# (observed rc=-112/-96).  Blocks are at most 0x14 (20) bytes -- the TIU's
# staging limit -- and at least 2.
#
# CORRECTED 2026-09 from static TIU analysis (W_WRITE_PATH_ANALYSIS.md s10.1):
# the burst data limit is 27, not 20.  FUN_0ef2cc fills buf[2..28] and flushes
# when the byte just stored landed at index 0x1c (28), so the body is 29 bytes
# and carries up to 27 data bytes.  The 0x14 (20) constants in FUN_0e9bd2 are
# the READBACK VERIFICATION chunk size used by FUN_0e9906 -- a different
# mechanism that the old value conflated with the burst size.
BURST_DATA_MAX = 27

# Engine erase-block size, measured live (2026-09): `K000000` erased
# 0x0000-0x1FFF while 0x2000 kept its data.  The engine's `07 0300` command
# erases the 8KB flash block containing the write pointer.  Logical sectors
# (_sector_size_for_addr) can span several erase blocks, so erase_at_addr
# walks them one at a time.
ERASE_BLOCK = 0x2000


def _crc16_reflected(block):
    """CRC-16, init 0xFFFF, reflected poly 0x8408 (the proven burst CRC)."""
    crc = 0xFFFF
    for b in block:
        crc ^= b
        for _ in range(8):
            crc = ((crc >> 1) ^ 0x8408) if (crc & 1) else (crc >> 1)
    return crc


BURST_BODY_LEN = 31            # 29-byte padded body + 2 CRC bytes


def burst_frame(channel, data, terminator=True):
    """Build the flash-write burst body: [ch|0x80, count, data, 0xFF-pad, CRC16].

    Returns frame[1..] for the headerless `Y` form -- feed it to
    di_y_command / send_y.

    `terminator` appends the trailing 0x0A.  On the TIU wire FUN_0e9574 emits
    body, CRC_hi, CRC_lo, 0x0A, 0x05, but the 0x0A/0x05 are NOT frame data --
    they are DI-bus framing generated by the WTIU's FPGA.  Proof: the stock
    7-byte short command is [cobs, 0, channel, subcmd, hi, lo, checksum] with
    neither byte, and the engine answers it (recorded trace
    `tx: 02 00 56 12 00 00 97`, where ~(0x56+0x12+0x00+0x00) = 0x97), while the
    TIU emits 0x0A/0x05 after its short commands too (FUN_0e9428).

    terminator=True  -> 32 bytes, the exact burst that has programmed flash via
                        the headerless `Y` path.  Kept as the known-good form.
    terminator=False -> 31 bytes, for the header-frame `W` path, where
                        10 (header) + 31 = 41 = FUN_00404444's maximum frame.

    See W_WRITE_PATH_ANALYSIS.md sections 11.5-11.7.
    """
    data = bytes(data)
    if not 1 <= len(data) <= BURST_DATA_MAX:
        raise ValueError(f'burst carries 1..{BURST_DATA_MAX} bytes, '
                         f'got {len(data)}')
    blk = bytes([channel | 0x80, len(data) & 0xFF]) + data
    blk += b'\xff' * (29 - len(blk))
    crc = _crc16_reflected(blk)
    body = blk + bytes([(crc >> 8) & 0xFF, crc & 0xFF])
    assert len(body) == BURST_BODY_LEN
    return body + b'\x0a' if terminator else body


def burst_y_command(channel, data):
    """Full `Y` command string for one flash-write burst."""
    return di_y_command(bytes([0]) + burst_frame(channel, data))


def _di_addr_cmds(addr):
    """The three 0x07 address-set commands for `addr` (high/mid/low)."""
    return (
        'z0700%02x' % ((addr >> 16) & 0xFF),   # 0x0hh: address high
        'z0701%02x' % ((addr >> 8) & 0xFF),    # 0x1mm: address mid
        'z0702%02x' % (addr & 0xFF),           # 0x2ll: address low
    )


# DI program-mode command sequence (raw `z<cmd><data>` transfers).
def program_entry_cmds(addr):
    """z-commands that enter program mode and set the write pointer to `addr`."""
    return (
        ('z0f0000',) +                          # l1 / enter PC mode
        _di_addr_cmds(addr) +                   # set write pointer
        ('z0d3e81', 'z0d5e82', 'z0dbe82') +     # flash init x3
        ('z0b0010',)                            # write enable
    )


PROGRAM_EXIT_CMDS = ('z0b0000', 'z0e0000', 'l0')       # disable + exit

# Manufacturing data sector (EIS header + engine config)
MFG_SECTOR = 1
MFG_SECTOR_ADDR = 0x004000
MFG_SECTOR_SIZE = 0x100  # 256 bytes (full sector, used by official loader)
MFG_READ_BLOCK = 0x100   # 256 bytes per read (same as official loader: R004000000100)

# Engine info sector (read by TransferMfgData in the loader)
# Contains: cab number, road name, engine name, serial number, PCB rev, date, customer
ENG_INFO_ADDR = 0x001DD2
ENG_INFO_SIZE = 0x106    # 262 bytes (basic engine info read by TransferMfgData)

# Extended engine info — customer data fields after the basic 262 bytes.
# Layout from MergeMfgData (RVA 0x66444) IL analysis for frmSendingMfgDataToEngineWithSound.
# The dealer loader's combined form writes additional customer fields after the basic
# engine info. These offsets are relative to ENG_INFO_ADDR.
# NOTE: These offsets need verification with a live engine that has populated customer data.
ENG_INFO_EXTENDED_SIZE = 0x1AD  # 429 bytes total (262 basic + 167 extended)

# Customer data field offsets (relative to ENG_INFO_ADDR)
CUST_ADDR1_OFF  = 0x106  # Address line 1 (32 bytes, PadRight ' ')
CUST_ADDR2_OFF  = 0x126  # Address line 2 (32 bytes, PadRight ' ')
CUST_CITY_OFF   = 0x146  # City (32 bytes, PadRight ' ')
CUST_STATE_OFF  = 0x166  # State (32 bytes, PadRight ' ')
CUST_ZIP_OFF    = 0x186  # Zip code (7 bytes, PadLeft '0')
CUST_EMAIL_OFF  = 0x18D  # Email (32 bytes, PadRight ' ')
CUST_ADDR1_SIZE = 32
CUST_ADDR2_SIZE = 32
CUST_CITY_SIZE  = 32
CUST_STATE_SIZE = 32
CUST_ZIP_SIZE   = 7
CUST_EMAIL_SIZE = 32

class EngineProgrammer:  # pylint: disable=too-many-public-methods
    """Reads and writes engine manufacturing data via the DCS loader protocol."""

    def __init__(self, conn, debug=False):
        self.conn = conn
        self.debug = debug
        self.engine_addr = 1  # Updated by setup_engine() from I0 discovery
        self._engine_setup_done = False
        self._validated_flash_size = None
        self._protected_bootloader_start = None
        self._protected_bootloader_end = None
        self._zsess_unsupported = False
        self._zsess_announced = False

    @staticmethod
    def _ask_yes(prompt="  Type 'YES' to continue: ", confirm_cb=None):
        """Interactive YES gate; confirm_cb(msg)->bool replaces console input()."""
        if confirm_cb is not None:
            return bool(confirm_cb(prompt.strip()))
        try:
            return input(prompt) == 'YES'
        except EOFError:
            return False

    def check_for_existing_engines(self):
        # pylint: disable=too-many-branches,too-many-locals,too-many-statements,too-many-nested-blocks
        """Check how many engines are on the track.

        Sends the 'I0' command (letter I + zero) which queries all 100
        possible engine addresses via the DCS track signal.
        The official MTH Consumer Loader refuses to proceed unless exactly
        one engine is found.

        The I0 command takes ~10.5 seconds because the WTIU must poll
        all 100 possible engine addresses over the track signal.

        Returns:
            (count, addresses) where count is the number of engines found
            and addresses is a list of engine numbers (1-99).
        """
        print("  Checking for engines on track (takes ~10 seconds)...")

        # Flush any stale data in the socket buffer first
        self.conn.sock.setblocking(False)
        try:
            while True:
                stale = self.conn.sock.recv(512)
                if not stale:
                    break
                if self.debug:
                    print(f"  Flushed stale data: {stale[:50]}")
        except (BlockingIOError, OSError):
            pass
        self.conn.sock.setblocking(True)

        # Send I0 command with long timeout (WTIU polls all 100 engines)
        # Mark's reference code uses I_WAIT=10500ms
        self.conn.sock.settimeout(12.0)
        data = b"I0\r\n"
        if self.debug:
            print("  TX: I0")
        self.conn.sock.sendall(data)

        # Wait for response
        time.sleep(0.1)
        try:
            resp = self.conn.sock.recv(512).decode('latin-1')
        except socket.timeout:
            print("  ERROR: I0 command timed out (no response from WTIU)")
            self.conn.sock.settimeout(10.0)
            return (0, [])
        self.conn.sock.settimeout(10.0)

        if self.debug:
            print(f"  RX: {resp.strip()}")

        # Parse I0 response - WTIU returns hex bytes representing engine bitmap
        # Format: I0:HH,HH,HH,... okay (13 bytes, engine 1 = bit 0 of last byte)
        if "I0" not in resp or "okay" not in resp.lower():
            print(f"  I0 command failed: {resp.strip()}")
            return (0, [])

        # Extract hex data between "I0:" and " okay"
        # Response format: "I0:00,00,00,00,00,00,00,00,00,00,00,04,20 okay"
        import re  # pylint: disable=import-outside-toplevel
        hex_match = re.search(r'I0[:\s]*([\dA-Fa-f,]+)', resp)
        if not hex_match:
            print(f"  Could not parse I0 response: {resp.strip()}")
            return (0, [])

        hex_part = hex_match.group(1).strip()
        hex_bytes = [h.strip() for h in hex_part.split(",") if h.strip()]

        if self.debug:
            print(f"  I0 hex bytes: {hex_bytes}")

        # Bitmap is reversed: rightmost bit of last byte = engine 1
        # So we read from the end backwards
        engines = []
        num_bytes = len(hex_bytes)
        for byte_idx, hex_byte in enumerate(hex_bytes):
            try:
                byte_val = int(hex_byte, 16)
                for bit in range(8):
                    if byte_val & (1 << bit):
                        reverse_byte_idx = num_bytes - 1 - byte_idx
                        engine_num = reverse_byte_idx * 8 + bit + 1
                        if 1 <= engine_num <= 99:
                            engines.append(engine_num)
                            if self.debug:
                                print(f"  Found engine {engine_num} "
                                      f"(byte {byte_idx}, bit {bit})")
            except ValueError:
                continue

        count = len(engines)
        print(f"  Found {count} engine(s) on track: {engines}")

        return (count, engines)

    def setup_engine(self):
        """Set up the engine for programming (safe commands).

        Checks that exactly one engine is on the track first, matching
        what the official MTH Consumer Loader does. Uses the discovered
        engine's DCS address for the y command.
        """
        print("  Setting up engine for programming...")

        # Check for existing engines first (safety check)
        count, engines = self.check_for_existing_engines()

        if count == 0:
            print("\n  ERROR: No engine found on the track.")
            print("  Place one engine on the track and retry.")
            print("  NOTE: Be sure the engine address is NOT set to 0.")
            return False

        if count > 1:
            print(f"\n  ERROR: Multiple engines ({count}) found on the track.")
            print(f"  Engines at DCS addresses: {engines}")
            print("  Place only ONE engine on the track and retry.")
            print("  Writing with multiple engines on the track will")
            print("  program ALL of them simultaneously!")
            return False

        # Use the discovered engine's DCS address
        self.engine_addr = engines[0]
        print(f"  Exactly one engine found (DCS #{self.engine_addr}) - proceeding.")

        # Disable scan
        resp = self.conn.send_cmd("X0")
        if "okay" not in resp:
            print(f"  Warning: X0 response: {resp}")

        # Set working engine address to the discovered engine
        # The y command takes the DCS engine number directly
        resp = self.conn.send_cmd(f"y{self.engine_addr}")
        if "okay" not in resp and f"y{self.engine_addr}" not in resp:
            print(f"  Warning: y{self.engine_addr} response: {resp}")

        # SCS mode
        resp = self.conn.send_cmd("m4")
        if "okay" not in resp and "m4" not in resp:
            print(f"  Warning: m4 response: {resp}")

        # Throttle off
        self.conn.send_cmd("s0000")
        # Volume off
        self.conn.send_cmd("v0000")
        # Lights off
        self.conn.send_cmd("aa0")

        # Quality check
        resp = self.conn.send_cmd("Q")
        if self.debug:
            print(f"  Quality: {resp.strip()}")

        self._engine_setup_done = True
        return True

    def check_quality(self):
        """Check track signal quality.

        Mirrors the dealer loader's CheckQuality (RVA 0x30900).
        Sends Q command and checks the response.
        The loader aborts with "Track Interface Quality level is too low"
        if quality is insufficient.
        Returns True if quality is acceptable, False otherwise.
        """
        resp = self.conn.send_cmd("Q")
        if not resp:
            print("  No response to Q command")
            return False

        if "okay" not in resp:
            print(f"  Quality check failed: {resp.strip()}")
            return False

        # Parse quality level from response
        # Response format: "Q <level> okay"
        # The loader reads a numeric quality level and checks thresholds
        if self.debug:
            print(f"  Quality response: {resp.strip()}")

        return True

    def get_engine_type(self):
        """Read the engine type using q commands.

        The loader's GetEngineType (RVA 0x30A18) sends q1E80 then q7E80.
        The engine type character is at position 5 of the q7E80 response
        (right after the "q7E80" echo). If it is "E", the loader sets
        a flag that causes ModifySoundFileBit to set bit 5 of byte 0x191C.

        Returns the raw q1E80 response string (for compatibility with
        existing callers). Use check_engine_type_e() for the type-E check.
        """
        # q1E80 / q7E80 read the engine type
        resp = self.conn.send_cmd("q1E80")
        if self.debug:
            print(f"  Engine type query (q1E80): {resp.strip()}")

        # Parse the response to determine engine type
        # Response format: "q1E80 <data> okay"
        return resp

    def check_engine_type_e(self):
        """Check if the engine type character is 'E'.

        Mirrors the loader's GetEngineType logic:
        1. Send q7E80
        2. Find "q7E80" in the response
        3. Get the character at position+5 (right after the echo)
        4. Return True if it is "E", False otherwise.

        When this returns True, the loader sets bit 5 (0x20) of
        capability byte 0x191C before writing the sound file.
        """
        resp = self.conn.send_cmd("q7E80")
        if self.debug:
            print(f"  Engine type query (q7E80): {resp.strip()}")

        if not resp:
            print("  No response to q7E80")
            return False

        # Find "q7E80" in the response
        marker = "q7E80"
        idx = resp.find(marker)
        if idx < 0:
            print(f"  Could not find '{marker}' in response")
            return False

        # Get the character right after "q7E80"
        char_pos = idx + 5
        if char_pos >= len(resp):
            print("  Response too short to read type character")
            return False

        type_char = resp[char_pos]
        if self.debug:
            print(f"  Engine type character: '{type_char}'")

        is_e = type_char == 'E'
        if is_e:
            print("  Engine type is 'E' — will set bit 0x191C:0x20")
        return is_e

    def detect_engine_family(self):
        """Classify the engine as 'ps3', 'ps2', or 'unknown'.

        The TIU firmware is engine-agnostic — all PS2/PS3 differences are
        in the loader's client flow. The reliable discriminator is the EIS
        table: PS3 engines have 'EIS!' magic at 0x004000; PS2 engines have
        a manufacturing sector there but no EIS records.

        Returns 'ps3' if EIS magic present, 'ps2' if the sector reads back
        but has no EIS header, 'unknown' if the read fails.
        """
        eis = self.read_raw(0x004000, 0x10)
        if not eis:
            return 'unknown'
        return 'ps3' if eis[0:4] == b'EIS!' else 'ps2'

    def detect_flash_size(self, stock_file=None):  # pylint: disable=too-many-branches
        """Detect the engine's flash memory size.

        Primary method: use a stock .mth file size, matching how the TIU
        firmware determines chip size (from ADPCM_Player.cpp):
          <= 1 MB file  -> 1 MB chip (PS2)
          <= 2 MB file  -> 2 MB chip (PS2)
          >  2 MB file  -> 4 MB chip (PS3, usable = 0x3A0000)

        Fallback method (no stock file): probe by reading at each test
        address and checking for wrap-around (data matches address 0).

        Args:
            stock_file: Path to a stock .mth file for this engine. If
                        provided, its size determines the chip size.

        Returns the size in bytes, or None on failure.
        """
        # --- Primary: use stock file size (matches TIU logic) ---
        if stock_file:
            try:
                file_size = os.path.getsize(stock_file)
                print(f"  Detecting flash size from stock file: {stock_file}")
                print(f"    Stock file size: {file_size} bytes (0x{file_size:X})")
                if file_size <= 0x100000:
                    detected_size = 0x100000
                    print("    -> 1 MB chip (PS2)")
                elif file_size <= 0x200000:
                    detected_size = 0x200000
                    print("    -> 2 MB chip (PS2)")
                else:
                    detected_size = 0x400000
                    print("    -> 4 MB chip (PS3)")
                print(f"  Detected flash size: {detected_size} bytes "
                      f"({detected_size // 1024 // 1024} MB)")
                return detected_size
            except OSError as e:
                print(f"  Could not read stock file: {e}")
                print("  Falling back to probe method...")

        # --- Fallback: probe by wrap-around detection ---
        print("  Detecting flash size (probe method)...")

        # Reference at the EIS/ manufacturing data header (0x004000), which
        # is always readable and has a stable 'EIS!' signature.  We read at
        # size + 0x004000; on a 1MB chip, 0x104000 wraps back to 0x004000.
        ref_addr = MFG_SECTOR_ADDR  # 0x004000
        ref_data = self.read_raw(ref_addr, 16)
        if not ref_data:
            print(f"  Could not read reference data at 0x{ref_addr:06X}")
            return None

        if self.debug:
            print(f"    Reference at 0x{ref_addr:06X}: {ref_data.hex()}")

        # Test the wrap points for 1/2/4 MB chips.  No MTH board has 8MB flash.
        test_sizes = [
            (0x100000, "1 MB"),
            (0x200000, "2 MB"),
            (0x400000, "4 MB"),
        ]

        detected_size = 0x100000  # minimum 1 MB
        for size, label in test_sizes:
            test_addr = ref_addr + size
            test_data = self.read_raw(test_addr, 16)
            if not test_data:
                print(f"    {label} (0x{test_addr:06X}): read failed (stopping)")
                break

            if self.debug:
                print(f"    At 0x{test_addr:06X}: {test_data.hex()}")

            # If data matches the reference, the read wrapped around
            if test_data == ref_data:
                print(f"    {label}: wrapped (data matches 0x{ref_addr:06X}) "
                      f"— chip size is {label}")
                detected_size = size
                break

            # 0xFF means erased flash within the chip (or beyond); treat as
            # present.  Anything else is also real flash.  Continue to the
            # next (larger) test address.
            if test_data == b'\xFF' * 16:
                print(f"    {label}: present (erased)")
                detected_size = size
            else:
                print(f"    {label}: present (different data)")
                detected_size = size

        print(f"  Detected flash size: {detected_size} bytes "
              f"({detected_size // 1024 // 1024} MB)")
        return detected_size

    def read_flash_range(self, addr, length, progress=True):
        """Read a range of flash memory.

        Reads in 256-byte blocks (matching the loader's block size).
        Returns bytes or None on failure.
        """
        data = bytearray()
        block = 0x100  # 256 bytes per read
        offset = 0

        while offset < length:
            chunk_len = min(block, length - offset)
            chunk = self.read_raw(addr + offset, chunk_len)
            if chunk is None:
                if self.debug:
                    print(f"  Read failed at offset 0x{offset:06X}")
                return None
            data.extend(chunk)
            offset += chunk_len

            if progress and (offset % 0x1000 == 0 or offset == length):
                pct = offset * 100 // length
                print(f"\r  Read {offset}/{length} bytes ({pct}%)", end='', flush=True)

        if progress:
            print()
        return bytes(data)

    def read_sound_file(self, output_path, flash_size=None, stock_file=None):
        """Read the entire flash and save as a .mth file.

        This mirrors the dealer loader's "Get Sound From Engine" function.
        Reads all flash sectors and saves to a .mth file.

        If a stock file is provided, reads exactly that many bytes (matching
        the stock sound file size). Otherwise, reads the full detected chip.

        Args:
            output_path: Path to save the .mth file
            flash_size: Flash size in bytes. If None, auto-detects.
            stock_file: Path to stock .mth file. If provided, its size
                        determines the read length.
        Returns True on success.
        """
        if flash_size is None:
            if stock_file:
                try:
                    flash_size = os.path.getsize(stock_file)
                    print(f"  Reading {flash_size} bytes "
                          f"(matching stock file: {stock_file})")
                except OSError as e:
                    print(f"  Could not read stock file: {e}")
                    flash_size = self.detect_flash_size()
                    if flash_size is None:
                        print("  Cannot determine flash size. Aborting.")
                        return False
            else:
                flash_size = self.detect_flash_size()
                if flash_size is None:
                    print("  Cannot determine flash size. Aborting.")
                    return False

        print(f"\n  Reading {flash_size} bytes from flash...")

        data = self.read_flash_range(0x000000, flash_size)
        if data is None:
            print("  Failed to read flash")
            return False

        with open(output_path, 'wb') as f:
            f.write(data)
        print(f"  Saved {len(data)} bytes to {output_path}")
        return True

    def validate_sound_file(self, mth_data, eis_records=None):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
        """Validate a .mth sound file against EIS region constraints.

        Mirrors the dealer loader's pre-write validation in
        frmSendingMfgDataToEngineWithSound (RVA 0x5869C state machine):
        - Reads EIS fields (ReadEISFields, RVA 0x332B0)
        - Checks EIS Length <= 8192
        - Checks file fits in DSP/Flash, Boiler, and Sound File regions
        - Checks file fits in detected flash size
        - Checks engine type compatibility for code files
        - Checks track quality (CheckQuality, RVA 0x30900)

        Args:
            mth_data: The .mth file bytes
            eis_records: Output of read_eis_records(). If None, reads EIS live.
        Returns (True, []) if valid, (False, [warnings]) if issues found.
        """
        file_size = len(mth_data)
        warnings = []

        if eis_records is None:
            print("\n  Reading EIS for sound file validation...")
            eis_records = self.read_eis_records()

        if not eis_records:
            warnings.append("Could not read EIS — skipping validation")
            return (True, warnings)

        # --- Check 1: EIS Length <= 8192 (from ReadEISFields IL) ---
        eis_len = eis_records.get('eis_len', 0)
        if eis_len > 8192:
            msg = (f"EIS Length field too large: {eis_len} (max 8192). "
                   f"ReadEISFields would reject this.")
            print(f"  ERROR: {msg}")
            warnings.append(msg)
        else:
            print(f"  OK: EIS Length ({eis_len} bytes) within limit (8192)")

        # --- Check 2: image must not reach the DSP/bootloader region ---
        # The file is a flat image at flash 0; if it extends to dsp_addr
        # it would overlap the DSP region (the write path skips those
        # sectors, leaving a silently incomplete write).  Compare against
        # the region START, not its end.
        dsp_addr = eis_records.get('dsp_addr')
        dsp_max_len = eis_records.get('dsp_max_len')
        if dsp_addr is not None and dsp_max_len is not None:
            dsp_end = dsp_addr + dsp_max_len
            if file_size > dsp_addr:
                msg = (f"Sound file ({file_size} bytes) reaches the "
                       f"DSP/bootloader region (0x{dsp_addr:06X}-"
                       f"0x{dsp_end:06X}). File may be too large.")
                print(f"  WARNING: {msg}")
                warnings.append(msg)
            else:
                print(f"  OK: File ends below DSP region "
                      f"(ends 0x{file_size:06X}, DSP starts "
                      f"0x{dsp_addr:06X})")
        else:
            warnings.append("DSP/Flash region not found in EIS")
            print("  WARNING: DSP/Flash region not found in EIS")

        # --- Check 3: Boiler region ---
        boiler_addr = eis_records.get('boiler_addr')
        boiler_max_len = eis_records.get('boiler_max_len')
        if boiler_addr is not None and boiler_max_len is not None:
            boiler_end = boiler_addr + boiler_max_len
            if file_size > boiler_end:
                msg = (f"Sound file ({file_size} bytes) extends past Boiler "
                       f"code region end (0x{boiler_end:06X}).")
                print(f"  WARNING: {msg}")
                warnings.append(msg)
            else:
                print(f"  OK: File fits in Boiler code region "
                      f"(0x{boiler_addr:06X}-0x{boiler_end:06X})")
        else:
            # Boiler region may not exist for non-steam engines
            print("  Note: Boiler code region not found in EIS "
                  "(may not apply to this engine type)")

        # --- Check 4: image must not reach the code regions ---
        # The .mth file is a flat flash image starting at 0x000000.  The
        # 0x2004 "Sound Data" record describes the parameter/header area
        # INSIDE the image (16KB on this engine) -- it is not a bound on
        # file size, and comparing file_size to it fails for every real
        # sound file.  The real bound is the lowest code region above the
        # sound area (Engine Data at 0xFA0000 here): an image that reaches
        # it would overwrite engine config / DSP / FPGA code.
        code_starts = [a for a in (eis_records.get('eng_data_addr'),
                                   eis_records.get('dcc_cv_addr'),
                                   eis_records.get('dsp_addr'),
                                   eis_records.get('fpga_addr'),
                                   eis_records.get('boiler_addr'))
                       if a]
        if code_starts:
            code_start = min(code_starts)
            if file_size > code_start:
                msg = (f"Sound file ({file_size} bytes) extends into code "
                       f"regions starting at 0x{code_start:06X}.")
                print(f"  WARNING: {msg}")
                warnings.append(msg)
            else:
                print(f"  OK: File ends below code regions "
                      f"(ends 0x{file_size:06X}, code starts "
                      f"0x{code_start:06X})")

        # --- Check 5: Flash size vs file size ---
        # The loader checks: "Code File may only be installed on '4 MB' or
        # larger engine memory sizes and is not compatable with the Engine
        # memory size" (IL at 0x1DDC)
        print("\n  Checking flash size vs file size...")
        flash_size = self.detect_flash_size()
        if flash_size and file_size > flash_size:
            msg = (f"Sound file ({file_size} bytes, {file_size // 1024 // 1024} MB) "
                   f"is larger than detected flash ({flash_size} bytes, "
                   f"{flash_size // 1024 // 1024} MB). "
                   f"File cannot fit in this engine's flash.")
            print(f"  ERROR: {msg}")
            warnings.append(msg)
        elif flash_size:
            print(f"  OK: File ({file_size} bytes) fits in flash "
                  f"({flash_size} bytes)")

        # --- Check 6: Track quality ---
        # The loader checks track quality before writing:
        # "Track Interface Quality level is too low" (IL at 0x0F16)
        print("\n  Checking track quality...")
        if not self.check_quality():
            msg = ("Track quality too low — loader would abort. "
                   "Check track connections and retry.")
            print(f"  ERROR: {msg}")
            warnings.append(msg)
        else:
            print("  OK: Track quality acceptable")

        return (len(warnings) == 0, warnings)

    def write_sound_file(self, input_path, preserve_mfg=True, validate=True,  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals,too-many-branches,too-many-statements,too-many-return-statements
                         stamp_loader=True, loader_version=None,
                         set_bits=None, clear_bits=None,
                         auto_engine_type=True, backup_flash=False,
                         recovery_file=None, assume_yes=False,
                         confirm_cb=None):
        """Write a .mth sound file to the engine's flash.

        This mirrors the dealer loader's "Send Sound To Engine" function.
        The .mth file is the flash image — it maps directly to flash addresses.

        The write process:
        1. Read the .mth file
        2. Validate against EIS regions (Boiler/Flash/DSP) if requested
        3. Query engine type and set bit 0x191C:0x20 if type is 'E'
           (mirrors loader's GetEngineType + ModifySoundFileBit)
        4. Apply explicit feature bit modifications (if requested)
        5. Stamp loader data at 0x1950 (if requested)
        6. Detect flash size and determine which sectors to write
        7. Read and backup current mfg data (if preserving)
        8. Erase each sector
        9. Write each sector
        10. Verify each sector
        11. Restore mfg data (if preserving)

        Args:
            input_path: Path to the .mth file
            preserve_mfg: If True, preserve the current manufacturing data
                          at 0x1DD2 (engine info) and 0x004000 (EIS)
            validate: If True, validate file against EIS regions before writing
            stamp_loader: If True, stamp loader data at 0x1950
            loader_version: Override loader version string for stamping
            auto_engine_type: If True, query engine type and automatically
                              set bit 0x191C:0x20 when type is 'E'
            backup_flash: If True, read full flash and save to
                          <input_path>.flash_backup before writing.
                          Default False — sound files are available from
                          MTH's website, so a full backup is usually
                          unnecessary. Use True for one-off/custom files.
            recovery_file: Path to a .mth file to use for recovery if a
                          write fails. If None, uses the original .mth
                          file being written. This is the file to re-flash
                          if something goes wrong.
        Returns True on success.
        """
        # Read the .mth file
        with open(input_path, 'rb') as f:
            mth_data = f.read()

        file_size = len(mth_data)
        print(f"  .mth file: {input_path}")
        print(f"  File size: {file_size} bytes (0x{file_size:06X})")

        # Engine family check — the TIU write path is engine-agnostic, but
        # PS2 engines have no EIS and their flash-write sequence is
        # untested on this tool. Detect by EIS magic so the user gets an
        # explicit warning before anything destructive happens.
        family = self.detect_engine_family()
        if family == 'ps2':
            print("\n  *** PS2 engine detected (no EIS at 0x004000) ***")
            print("  PS2 sound writes are UNTESTED on this tool.")
            print("  The TIU protocol is engine-agnostic and the flow should")
            print("  work, but erase granularity and mfg layout are unverified.")
            if not assume_yes and not self._ask_yes(
                    "  Type 'YES' to proceed with PS2 write: ",
                    confirm_cb):
                print("Aborted.")
                return False
        elif family == 'unknown':
            print("\n  WARNING: could not read flash at 0x004000 — "
                  "engine family unknown")

        # EIS validation (safety check before erasing flash)
        if validate:
            ok, warnings = self.validate_sound_file(mth_data)
            if not ok:
                print("\n  VALIDATION FAILED — aborting write to protect engine.")
                for w in warnings:
                    print(f"    - {w}")
                return False

        # Automatic engine type check — mirrors the dealer loader's behavior.
        # The loader queries the engine type via q7E80 and, if the type
        # character is "E", sets bit 5 (0x20) of capability byte 0x191C
        # before writing the sound file. This is not a user choice —
        # the loader does it automatically.
        if auto_engine_type:
            print("\n  Checking engine type (q7E80)...")
            is_type_e = self.check_engine_type_e()
            if is_type_e:
                print("  Auto-setting bit 0x191C:0x20 (engine type 'E')")
                mth_data = modify_sound_file_bit(
                    mth_data, 0x1C, 0x20, set_true=True)
            else:
                print("  Engine type is not 'E' — leaving 0x191C unchanged")

        # Apply explicit feature bit modifications (if any)
        if set_bits:
            for byte_idx, bit_val in set_bits:
                print(f"  Setting feature bit: byte {byte_idx}, bit 0x{bit_val:02X}")
                mth_data = modify_sound_file_bit(mth_data, byte_idx, bit_val, set_true=True)
        if clear_bits:
            for byte_idx, bit_val in clear_bits:
                print(f"  Clearing feature bit: byte {byte_idx}, bit 0x{bit_val:02X}")
                mth_data = modify_sound_file_bit(mth_data, byte_idx, bit_val, set_true=False)

        # Stamp loader data into the flash image
        if stamp_loader:
            print("\n  Stamping loader data at 0x1950...")
            mth_data = insert_loader_data(mth_data, loader_version=loader_version)
            ld = parse_loader_data(mth_data)
            if ld:
                print(f"    PC: {ld.get('pc_name', '?')}")
                print(f"    Date/Time: {ld.get('date', '?')} {ld.get('time', '?')}")
                print(f"    Version: {ld.get('version', '?')}")

        # Determine which sectors to write
        # Sector layout (PS2/PS3 O-scale):
        #   0: 0x000000, 16 KB
        #   1: 0x004000, 8 KB
        #   2: 0x006000, 8 KB
        #   3: 0x008000, up to 0x78000 (rest of first 512KB)
        #   4+: 0x80000+, 128 KB each
        sectors_to_write = []
        addr = 0x000000
        while addr < file_size:
            sectors_to_write.append(addr)
            if addr == 0x000000:
                addr = 0x004000
            elif addr == 0x004000:
                addr = 0x006000
            elif addr == 0x006000:
                addr = 0x008000
            elif addr == 0x008000:
                addr = 0x80000
            else:
                addr += 0x20000

        # Validate sector count against flash size
        # From GetNumberOfSectors (RVA 0x2F17C):
        #   1MB flash: 11 sectors max
        #   2MB flash: 19 sectors max
        #   4MB flash: 39 sectors max
        max_sectors = {
            0x100000: 11,
            0x200000: 19,
            0x400000: 39,
        }
        print(f"  Sectors to write: {len(sectors_to_write)}")
        for s_addr in sectors_to_write:
            print(f"    0x{s_addr:06X}")

        # Detect flash size for sector count validation
        detected_flash = self.detect_flash_size()
        if detected_flash and detected_flash in max_sectors:
            max_sec = max_sectors[detected_flash]
            if len(sectors_to_write) > max_sec:
                print(f"\n  ERROR: File requires {len(sectors_to_write)} sectors "
                      f"but flash ({detected_flash // 1024 // 1024} MB) only "
                      f"supports {max_sec} sectors.")
                print("  Aborting write to protect engine.")
                return False
            print(f"  OK: {len(sectors_to_write)} sectors within "
                  f"flash limit ({max_sec} for {detected_flash // 1024 // 1024} MB)")

        # --- Full flash backup (optional) ---
        # A full flash backup reads the entire chip before writing, allowing
        # per-sector recovery if a write fails. This is OFF by default because:
        # - Sound files are available from MTH's website
        # - Upgrade kits ship with the stock SD70 default file
        # - The backup read takes several minutes
        # Enable for custom/one-off files that can't be re-downloaded.
        flash_backup = None
        backup_path = None
        if backup_flash:
            backup_path = input_path + ".flash_backup"
            print(f"\n  Reading full flash for backup ({detected_flash or 0x200000} bytes)...")
            flash_backup = self.read_flash_range(0x000000,
                                                 detected_flash or 0x200000)
            if flash_backup is None:
                print("  ERROR: Could not read full flash for backup. Aborting.")
                print("  No writes will be performed without a backup.")
                return False

            with open(backup_path, 'wb') as f:
                f.write(flash_backup)
            print(f"  Full flash backup saved to {backup_path}")
            print(f"  Backup size: {len(flash_backup)} bytes")
        else:
            recovery_path = recovery_file or input_path
            print("\n  Full flash backup: SKIPPED (default)")
            print(f"  Recovery file if write fails: {recovery_path}")
            print("  (Use --backup-flash to enable full backup for custom files)")

        # --- Bootloader/DSP sector protection ---
        # Read EIS to find where the DSP/bootloader code lives.
        # We will NOT erase/write that sector — if the bootloader is
        # corrupted, the engine becomes unresponsive and unrecoverable.
        print("\n  Reading EIS for bootloader protection...")
        eis_records = self.read_eis_records()
        bootloader_addr = None
        bootloader_end = None
        if eis_records and 'dsp_addr' in eis_records:
            bootloader_addr = eis_records['dsp_addr']
            bootloader_max = eis_records.get('dsp_max_len', 0)
            bootloader_end = bootloader_addr + bootloader_max
            print(f"  Bootloader/DSP region: 0x{bootloader_addr:06X}-0x{bootloader_end:06X}")
            print("  This region will NOT be erased or written")
            self.set_bootloader_protection(bootloader_addr, bootloader_end)
        else:
            print("  ERROR: Could not determine bootloader region from EIS")
            print("  REFUSING to write without bootloader protection — "
                  "corrupting the bootloader bricks the engine permanently")
            return False

        # Filter out any sectors that overlap the bootloader region
        safe_sectors = []
        skipped_sectors = []
        for sector_addr in sectors_to_write:
            if sector_addr == 0x000000:
                sector_end_calc = 0x004000
            elif sector_addr == 0x004000:
                sector_end_calc = 0x006000
            elif sector_addr == 0x006000:
                sector_end_calc = 0x008000
            elif sector_addr == 0x008000:
                sector_end_calc = 0x80000
            else:
                sector_end_calc = sector_addr + 0x20000

            if bootloader_addr is not None:
                # Check if this sector overlaps the bootloader region
                if sector_addr < bootloader_end and sector_end_calc > bootloader_addr:
                    print(f"  SKIP sector 0x{sector_addr:06X}: overlaps bootloader")
                    skipped_sectors.append(sector_addr)
                    continue

            safe_sectors.append(sector_addr)

        if skipped_sectors:
            print(f"  {len(skipped_sectors)} sector(s) skipped to protect bootloader")
            print(f"  {len(safe_sectors)} sector(s) will be written")

        # Preserve mfg data if requested
        eis_backup = None
        eng_info_backup = None
        if preserve_mfg:
            print("\n  Reading current manufacturing data for preservation...")

            # Read EIS sector (0x004000, 256 bytes)
            eis_backup = self.read_raw(0x004000, 0x100)
            if eis_backup:
                print(f"    EIS sector: {len(eis_backup)} bytes read")
            else:
                print("    WARNING: Could not read EIS sector")

            # Read engine info (0x001DD2, 262 bytes)
            eng_info_backup = self.read_raw(ENG_INFO_ADDR, ENG_INFO_SIZE)
            if eng_info_backup:
                print(f"    Engine info: {len(eng_info_backup)} bytes read")
            else:
                print("    WARNING: Could not read engine info")

            # Persist the preserved regions to a recovery image so they
            # survive a crashed or aborted run — mth_flash_recovery.py can
            # write them back (--range 0x1DD2+0x106 and --range 0x4000+0x100).
            rec = bytearray(b'\xFF' * 0x6000)
            if eng_info_backup:
                rec[ENG_INFO_ADDR:ENG_INFO_ADDR + len(eng_info_backup)] = \
                    eng_info_backup
            if eis_backup:
                rec[0x4000:0x4000 + len(eis_backup)] = eis_backup
            mfg_rec_path = input_path + '.mfg-recovery.bin'
            try:
                with open(mfg_rec_path, 'wb') as fh:
                    fh.write(rec)
                print(f"    Mfg recovery image: {mfg_rec_path}")
            except OSError as exc:
                print(f"    WARNING: could not write recovery image: {exc}")

        # Confirm
        print(f"\n*** ABOUT TO WRITE {file_size} bytes TO ENGINE FLASH ***")
        print(f"  This will erase and rewrite {len(safe_sectors)} sectors.")
        print("  Do not remove power or the engine from the track!")
        print("  This will take several minutes.")
        if backup_path:
            print(f"  Full flash backup: {backup_path}")
        else:
            recovery_path = recovery_file or input_path
            print(f"  No flash backup (recovery: re-flash {recovery_path})")
        if preserve_mfg:
            print("  Manufacturing data will be preserved.")
        else:
            print("  WARNING: Manufacturing data will be overwritten!")
        if skipped_sectors:
            print(f"  {len(skipped_sectors)} bootloader sector(s) protected")
        if not assume_yes and not self._ask_yes(confirm_cb=confirm_cb):
            print("Aborted.")
            return False

        # Enter fast programming mode
        if not self.enter_fast_mode():
            print("  Warning: could not enter fast programming mode")

        # Warn about duration up front.  Each W command carries up to
        # BURST_DATA_MAX (27) bytes and runs the complete program cycle in
        # firmware: PC-mode entry, address setup x3, 0x0D init x3,
        # write-enable, pointer poll, the burst itself, disable, and exit --
        # roughly 11 DI round-trips per block, plus the TCP round-trip for the
        # command itself.  A full sound file is therefore thousands of W
        # commands.  The actual per-round-trip time is set by the DI bus
        # hardware and the flash chip's program time, which are not visible in
        # the firmware code.  Rather than guess, we calibrate by timing a real
        # R read (same DI path, safe — no write risk).
        planned = sum(min(self._sector_bounds(a)[1], file_size) - a for a in safe_sectors
                      if min(self._sector_bounds(a)[1], file_size) > a)
        n_cmds = (planned + BURST_DATA_MAX - 1) // BURST_DATA_MAX
        n_di = n_cmds * 11
        print(f"\n  {planned:,} bytes to write in {BURST_DATA_MAX}-byte blocks "
              f"= {n_cmds:,} W commands (~{n_di:,} DI round-trips), "
              f"plus readback verification.")

        # Calibrate: time a real R read to measure the actual DI round-trip
        # time. R uses the same FUN_00404EBC path as W, so this is a direct
        # measurement, not a guess. Reads are safe — no write risk.
        per_di, _ = self.calibrate_timing()
        if per_di is not None:
            write_min = n_di * per_di / 60
            print(f"  Measured {per_di * 1000:.2f} ms per DI round-trip.")
            print(f"  Estimated write time: {write_min:.0f} minutes "
                  f"(plus readback verification).")
        else:
            print("  Calibration failed. Cannot estimate write time.")
            print("  Proceeding anyway — progress will be shown per sector.")
        print("  Do not interrupt this or power off the engine.")

        # Write each sector with recovery on failure
        # Sector 0x4000 overlaps the EIS/mfg region (0x4000-0x4100).  The
        # erase granularity (8KB) means writing file data above 0x4100
        # necessarily erases the EIS, so allow the overlap only when the EIS
        # backup was captured for the post-write restore — or when the caller
        # declined preservation, making the file's own EIS authoritative.
        allow_mfg_sector = (eis_backup is not None) or (not preserve_mfg)
        if not allow_mfg_sector:
            print("  WARNING: no EIS backup — sector 0x4000 will be refused")
        mfg_rec_path = input_path + '.mfg-recovery.bin'

        def _restore_mfg_regions():
            """Restore preserved regions; returns (eng_ok, eis_ok).  Called
            on success AND on abort — the image leaves these regions erased,
            so bailing without restoring could leave the engine unbootable
            (no EIS => can't locate DSP/FPGA code)."""
            eng_ok = eis_ok = True
            if preserve_mfg and eng_info_backup:
                print("\n  Restoring engine info at 0x001DD2...")
                eng_ok = self._restore_preserved(
                    "engine info", ENG_INFO_ADDR, eng_info_backup,
                    0x000000, 0x4000)
            if preserve_mfg and eis_backup:
                print("  Restoring EIS at 0x004000...")
                eis_ok = self._restore_preserved(
                    "EIS", 0x004000, eis_backup, 0x004000, 0x2000,
                    allow_mfg=True)
            if not eis_ok:
                print("  *** EIS RESTORE FAILED — the engine may not find "
                      "its DSP/FPGA code and may not boot ***")
                print(f"  Recovery image: {mfg_rec_path}")
                print("  Restore with:")
                print(f"    python mth_flash_recovery.py --backup "
                      f"{mfg_rec_path} --range 0x4000 0x6000")
                print("  or re-run the sound-file write.")
            return eng_ok, eis_ok

        total_written = 0
        failed_sectors = []
        aborted = False
        for sector_addr in safe_sectors:
            # But sector boundaries are fixed — we must write full sectors
            if sector_addr == 0x000000:
                sector_end_calc = 0x004000
            elif sector_addr == 0x004000:
                sector_end_calc = 0x006000
            elif sector_addr == 0x006000:
                sector_end_calc = 0x008000
            elif sector_addr == 0x008000:
                sector_end_calc = 0x80000
            else:
                sector_end_calc = sector_addr + 0x20000

            # Data to write for this sector
            sector_data_start = sector_addr
            sector_data_end = min(sector_end_calc, file_size)
            sector_data = mth_data[sector_data_start:sector_data_end]

            # Pad to sector boundary with 0xFF if needed
            sector_size = sector_end_calc - sector_addr
            if len(sector_data) < sector_size:
                sector_data = sector_data + b'\xFF' * (sector_size - len(sector_data))

            print(f"\n  Sector at 0x{sector_addr:06X} ({sector_size} bytes)...")

            # Helper for recovery on failure
            def _handle_failure(reason, sector_addr=sector_addr,  # pylint: disable=cell-var-from-loop
                                sector_end_calc=sector_end_calc):  # pylint: disable=cell-var-from-loop
                """Attempt recovery or abort. Returns True if recovered."""
                print(f"  {reason} at 0x{sector_addr:06X}!")
                if flash_backup is not None:
                    # Full backup available — restore this sector
                    print("  Attempting recovery from backup...")
                    backup_sector = flash_backup[sector_addr:sector_end_calc]
                    if self._recover_sector(sector_addr, backup_sector):
                        print("  Sector recovered from backup")
                        failed_sectors.append(sector_addr)
                        return True
                    print(f"  RECOVERY FAILED! Sector 0x{sector_addr:06X} is corrupted.")
                    print(f"  Use {backup_path} with mth_flash_recovery.py to restore.")
                    return False
                # No backup — the sector is in an unknown state
                # The erase may have succeeded, leaving it as 0xFF
                recovery_path = recovery_file or input_path
                print("  No flash backup available.")
                print(f"  The sector at 0x{sector_addr:06X} may be erased (0xFF).")
                print("  To recover: re-flash the original sound file:")
                print(f"    python mth_engine_programmer.py --write-sound {recovery_path}")
                print("  Or use mth_flash_recovery.py if you have a backup.")
                return False

            # Erase
            if not self.erase_at_addr(sector_addr, allow_mfg=allow_mfg_sector):
                if _handle_failure("Erase failed"):
                    continue
                aborted = True
                break

            # Write in BURST_DATA_MAX-byte blocks (one W command per block)
            if not self.write_raw(sector_addr, sector_data,
                                  allow_mfg=allow_mfg_sector):
                if _handle_failure("Write failed"):
                    continue
                aborted = True
                break

            # Verify
            if not self.verify_raw(sector_addr, sector_data):
                if _handle_failure("Verification failed"):
                    continue
                aborted = True
                break

            total_written += len(sector_data)
            pct = total_written * 100 // file_size
            print(f"  Progress: {total_written}/{file_size} bytes ({pct}%)")

        if aborted:
            # The image write left the mfg regions erased — try to put them
            # back before giving up so the engine stays bootable.
            print("\n  Write aborted — restoring preserved regions...")
            _restore_mfg_regions()
            self.enter_normal_mode()
            return False

        if failed_sectors:
            print(f"\n  {len(failed_sectors)} sector(s) failed and were recovered:")
            for s in failed_sectors:
                print(f"    0x{s:06X}")
            print("  The engine should be in its original state.")
            print(f"  Backup file: {backup_path}")
            # Recovery restored original data to recovered sectors, but any
            # mfg-overlapping sector that completed normally still holds the
            # file's 0xFF — restore preserved regions before leaving.
            _restore_mfg_regions()
            self.enter_normal_mode()
            return False

        # Restore mfg data if preserved.  The .mth image leaves these regions
        # 0xFF, and the dealer loader writes them separately after the sound
        # file — a direct write, no re-erase.  _restore_preserved does that
        # and only rewrites the whole sector as a fallback.
        eng_ok, _eis_ok = _restore_mfg_regions()
        if not eng_ok:
            print("  ERROR: engine info restore failed — it may be lost.")
            print(f"  Recovery image: {mfg_rec_path}")
            self.enter_normal_mode()
            return False

        # --- Post-write sequence (mirrors dealer loader IL) ---
        # The loader sends: power cycle off/on, re-address engine,
        # SCS mode, startup, feature reset, then enable scan.
        # This forces the engine to reload sound data from the newly
        # written flash. Without this, the engine may run with stale data.
        print("\n  Post-write sequence (power cycle + restart)...")
        self._post_write_restart()

        self.enter_normal_mode()
        self.cleanup()
        print(f"\n  Sound file write complete! {total_written} bytes written.")
        return True

    def _post_write_restart(self):
        """Post-write restart sequence matching the dealer loader.

        From the loader IL (tmrStateMachine_Tick, RVA 0x5869C):
        1. Power cycle off (o0)
        2. Hold for power cycle reset
        3. Power cycle on (o1)
        4. Set working engine address (y{addr})
        5. Set SCS mode (m4)
        6. Send startup (u4)
        7. Send feature reset (F0)
        8. Enable scan (X1) — done by cleanup()

        This forces the engine to reload sound data from flash.
        """
        # Power cycle off
        print("  Power cycle off (o0)...")
        resp = self.conn.send_cmd("o0")
        if self.debug:
            print(f"    Response: {resp.strip() if resp else 'None'}")

        # Hold for power cycle reset (loader waits several seconds)
        print("  Waiting for power cycle reset...")
        time.sleep(3)

        # Power cycle on
        print("  Power cycle on (o1)...")
        resp = self.conn.send_cmd("o1")
        if self.debug:
            print(f"    Response: {resp.strip() if resp else 'None'}")

        # Wait for engine to come back up
        print("  Waiting for engine to restart...")
        time.sleep(3)

        # Re-set working engine address
        if self.engine_addr:
            print(f"  Setting engine address (y{self.engine_addr})...")
            resp = self.conn.send_cmd(f"y{self.engine_addr}")
            if self.debug:
                print(f"    Response: {resp.strip() if resp else 'None'}")

        # Set SCS mode
        print("  Setting SCS mode (m4)...")
        resp = self.conn.send_cmd("m4")
        if self.debug:
            print(f"    Response: {resp.strip() if resp else 'None'}")

        # Send startup
        print("  Sending startup (u4)...")
        resp = self.conn.send_cmd("u4")
        if self.debug:
            print(f"    Response: {resp.strip() if resp else 'None'}")
        time.sleep(1)

        # Feature reset
        print("  Sending feature reset (F0)...")
        resp = self.conn.send_cmd("F0")
        if self.debug:
            print(f"    Response: {resp.strip() if resp else 'None'}")
        time.sleep(1)

        print("  Post-write restart complete.")

    def read_engine_info(self, extended=False):
        """Read the engine info sector at 0x001DD2.

        This is the data read by TransferMfgData in the official loader.
        Contains: cab number, road name, engine name, serial number,
        PCB rev, date, customer name, and optionally extended customer data.

        Args:
            extended: If True, read ENG_INFO_EXTENDED_SIZE bytes (includes
                      address, city, state, zip, email fields).
        """
        read_size = ENG_INFO_EXTENDED_SIZE if extended else ENG_INFO_SIZE
        print(f"  Reading engine info at 0x{ENG_INFO_ADDR:06X} "
              f"({read_size} bytes)...")

        data = self.read_flash_range(ENG_INFO_ADDR, read_size, progress=False)
        if data:
            print(f"  Read complete: {len(data)} bytes")
        return data

    def read_mfg_data(self):
        """Read the manufacturing data sector (sector 1 at 0x004000).

        Uses the same single 256-byte read as the official MTH loader:
            R004000000100

        Retries on transient DCS errors. Falls back to 4-byte blocks
        if the full 256-byte read fails repeatedly.
        Returns the raw bytes of the manufacturing data sector.
        """
        block_len = MFG_READ_BLOCK
        max_retries = 20

        while True:
            print(f"  Reading mfg data at 0x{MFG_SECTOR_ADDR:06X} "
                  f"({MFG_SECTOR_SIZE} bytes, {block_len}-byte blocks)...")

            result = b''
            offset = 0
            retries = 0

            while offset < MFG_SECTOR_SIZE:
                addr = MFG_SECTOR_ADDR + offset
                cur_len = min(block_len, MFG_SECTOR_SIZE - offset)

                cmd = f"R{addr:06X}{cur_len:06X}"
                resp = self.conn.send_cmd(cmd)

                if "okay" not in resp:
                    if retries < max_retries:
                        retries += 1
                        delay = min(0.5 * retries, 3.0)
                        print(f"  Retry {retries}/{max_retries} at 0x{offset:02X}: "
                              f"{resp.strip()} (waiting {delay:.1f}s)")
                        time.sleep(delay)
                        continue
                    print(f"  Failed at 0x{offset:02X} after {max_retries} retries")
                    # Fall back to smaller blocks
                    if block_len > 4:
                        block_len = max(4, block_len // 4)
                        print(f"  Falling back to {block_len}-byte blocks...")
                        break
                    # Save partial data
                    if result:
                        self._save_partial_read(result)
                        return None if not result else result
                else:
                    retries = 0

                block_data = self._parse_read_response(resp, addr, cur_len)
                if block_data is None:
                    print(f"  Could not parse response at 0x{offset:02X}")
                    if result:
                        self._save_partial_read(result)
                    return None if not result else result

                result += block_data
                offset += cur_len
                pct = (offset / MFG_SECTOR_SIZE) * 100
                print(f"  Read {offset}/{MFG_SECTOR_SIZE} bytes ({pct:.0f}%)")
                time.sleep(0.1)
            else:
                # Completed successfully
                print(f"  Read complete: {len(result)} bytes")
                return result

    def _save_partial_read(self, data):
        """Save partial read data to a file for analysis."""
        outfile = "mfg_data_partial.bin"
        with open(outfile, 'wb') as f:
            f.write(data)
        print(f"  Partial data saved to {outfile}")

    def _parse_read_response(self, resp, addr, length):
        """Parse the response from an R command into raw bytes.

        Actual response format observed from WTIU:
            "R00400000001045495321FFE303000100000054000000 okay"

        Where:
            - "R" + 6 hex addr + 6 hex len = 13-char command echo
            - hex data immediately follows (no space)
            - " okay" at the end

        Args:
            resp: The raw response string from the WTIU.
            addr: The expected flash address (used to validate the echo).
            length: The expected data length (used to validate the result).
        """
        # The command echo is "R" + 6 hex addr + 6 hex len = 13 chars
        expected_echo = f"R{addr:06X}{length:06X}"
        resp_stripped = resp.strip().replace('\r', '').replace('\n', '')

        # Find the command echo in the response
        echo_idx = resp_stripped.find(expected_echo)
        if echo_idx < 0:
            if self.debug:
                print(f"  Expected echo '{expected_echo}' not found in: {repr(resp)}")
            return None

        # Everything after the echo, up to " okay"
        after_echo = resp_stripped[echo_idx + len(expected_echo):]

        # Remove " okay" suffix
        okay_idx = after_echo.lower().rfind(' okay')
        if okay_idx >= 0:
            hex_data = after_echo[:okay_idx]
        else:
            hex_data = after_echo

        # Remove any spaces (data should be pure hex)
        hex_data = hex_data.replace(' ', '').strip()

        if not hex_data:
            if self.debug:
                print(f"  No hex data found in response: {repr(resp)}")
            return None

        try:
            raw = bytes.fromhex(hex_data)
            if length and len(raw) < length:
                if self.debug:
                    print(f"  Warning: expected {length} bytes, got {len(raw)}")
            return raw
        except ValueError:
            print(f"  Cannot parse hex data: {hex_data[:80]}...")
            return None

    def read_sector(self, sector):
        """Read a sector by sector number."""
        addr = self._sector_to_addr(sector)
        size = self._sector_size(sector)
        cmd = f"R{addr:06X}{size:06X}"
        resp = self.conn.send_cmd(cmd)
        if "okay" not in resp:
            print(f"  Read sector {sector} failed: {resp}")
            return None
        return self._parse_read_response(resp, addr, size)

    def _sector_to_addr(self, sector):
        """Convert sector number to flash address."""
        if sector == 0:
            return 0x000000
        if sector == 1:
            return 0x004000
        if sector == 2:
            return 0x006000
        if sector == 3:
            return 0x008000
        return 0x80000 + (sector - 3) * 0x20000

    def _sector_size(self, sector):
        """Get the size of a sector."""
        if sector == 0:
            return 0x4000  # 16 KB
        if sector in (1, 2):
            return 0x2000  # 8 KB
        if sector == 3:
            return 0x78000  # rest of first 512KB block
        return 0x20000  # 128 KB

    def verify_erased(self, addr, size, samples=4):
        """Confirm a region really is erased by reading it back.

        The K handler's execute call is soft — the engine holds the erase
        response for the erase duration, so "okay" only proves the command
        was issued, and C (DI 0x18) resets DI state without verifying either.
        This readback is the only trustworthy erase check.

        Reads up to `samples` blocks spread across the region (start, end, and
        interior points) and requires every byte to be 0xFF.

        Returns True if all sampled data is erased.
        """
        block = min(0x100, size)
        samples = max(samples, 1)
        if size <= block:
            offsets = [0]
        else:
            step = (size - block) // max(1, samples - 1)
            offsets = sorted({min(i * step, size - block)
                              for i in range(samples)})

        for off in offsets:
            data = self.read_raw(addr + off, block)
            if data is None:
                print(f"  Erase check: read failed at 0x{addr + off:06X}")
                return False
            bad = next((i for i, b in enumerate(data) if b != 0xFF), None)
            if bad is not None:
                print(f"  Erase check: 0x{addr + off + bad:06X} is "
                      f"0x{data[bad]:02X}, expected 0xFF")
                print(f"    Raw data at 0x{addr + off:06X} ({len(data)} bytes): "
                      f"{data[:64].hex(' ')}")
                print(f"    First non-FF at offset {bad}: "
                      f"context={data[max(0,bad-4):bad+4].hex(' ')}")
                return False
        return True

    def erase_sector(self, sector):
        """Erase a flash sector and confirm it by readback. True on success."""
        addr = self._sector_to_addr(sector)
        print(f"  Erasing sector {sector} at 0x{addr:06X}...")
        # erase_at_addr walks the logical sector in ERASE_BLOCK units and
        # handles K, the C reset, the post-erase settle, and verification.
        return self.erase_at_addr(addr)

    def write_sector(self, sector, data):
        """Write data to a flash sector. Returns True on success.

        Delegates to write_raw so the payload is split into firmware-legal
        chunks. The previous implementation put the whole sector into a single
        W command, which cannot work: even 256 bytes is a 525-character line
        against an 80-byte command buffer.
        """
        addr = self._sector_to_addr(sector)
        print(f"  Writing {len(data)} bytes to sector {sector} "
              f"at 0x{addr:06X}...")
        return self.write_raw(addr, data)

    def verify_sector(self, sector, expected_data):
        """Verify written data by reading it back."""
        addr = self._sector_to_addr(sector)
        size = len(expected_data)

        print(f"  Verifying sector {sector}...")

        cmd = f"R{addr:06X}{size:06X}"
        resp = self.conn.send_cmd(cmd)
        if "okay" not in resp:
            print(f"  Verify read failed: {resp}")
            return False

        read_data = self._parse_read_response(resp, addr, size)
        if read_data is None:
            print("  Could not parse read-back data")
            return False

        if read_data == expected_data:
            print("  Verification successful!")
            return True
        print("  Verification FAILED!")
        print(f"  Expected {len(expected_data)} bytes, got {len(read_data)} bytes")
        # Show first difference
        for i in range(min(len(expected_data), len(read_data))):
            if expected_data[i] != read_data[i]:
                print(f"  First diff at offset {i}: expected 0x{expected_data[i]:02X},"
                      f" got 0x{read_data[i]:02X}")
                break
        return False

    # Max bytes per single R command.  Each byte of response becomes ~2 hex
    # chars in the daemon reply, and mux2tiu stages that reply through a
    # fixed 1024-byte bounce buffer -- a reply larger than ~1KB can leave
    # >1023 bytes pending in its output ring and (on unpatched firmware)
    # overflow that buffer.  256 bytes -> ~530-char replies, safe margin.
    READ_CHUNK = 0x100

    def read_raw(self, addr, length):
        """Read raw flash data from an arbitrary address.

        The dealer loader sends an 'A' (advance) command after each read
        to acknowledge the data. We mirror this behavior.

        Large reads are split into READ_CHUNK-sized R commands; the returned
        bytes are identical to a single big read.

        Returns bytes or None on failure.
        """
        if length > self.READ_CHUNK:
            out = bytearray()
            off = 0
            while off < length:
                n = min(self.READ_CHUNK, length - off)
                part = self.read_raw(addr + off, n)
                if part is None:
                    return None
                out += part
                off += n
            return bytes(out)

        cmd = f"R{addr:06X}{length:06X}"
        resp = self.conn.send_cmd(cmd)
        if self.debug:
            print(f"  R{addr:06X}{length:06X} resp: {repr(resp[:120])}")
        if "okay" not in resp:
            if self.debug:
                print(f"  Read failed: {resp.strip()}")
            return None

        # Send A (advance/acknowledge) command after read, like the loader
        self.conn.send_cmd("A")

        return self._parse_read_response(resp, addr, length)

    def calibrate_timing(self, sample_addr=0x000000, sample_size=256):
        """Measure the actual DI round-trip time by timing a real R read.

        R uses the same FUN_00404EBC path as W — same DI transactions,
        same 20-byte chunk size, same blocking write()/read() to fd_fpga.
        The only difference is the direction flag. So timing R gives us
        the real per-DI-round-trip time without any write risk.

        Each 20-byte chunk = 4 DI round-trips (3 address setup + 1 transfer).
        For sample_size bytes: ceil(sample_size/20) chunks * 4 = N DI trips.
        We time the whole R command and divide.

        Returns (seconds_per_di_round_trip, total_seconds) or (None, None).
        """
        n_chunks = (sample_size + 19) // 20
        n_di = n_chunks * 4
        print(f"  Calibrating DI timing: reading {sample_size} bytes "
              f"from 0x{sample_addr:06X} ({n_di} DI round-trips)...")
        t0 = time.monotonic()
        data = self.read_raw(sample_addr, sample_size)
        t1 = time.monotonic()
        if data is None:
            print("  Calibration failed: read returned None")
            return None, None
        elapsed = t1 - t0
        per_di = elapsed / n_di if n_di > 0 else 0
        print(f"  Calibration: {elapsed:.3f}s total, {per_di * 1000:.2f} ms "
              f"per DI round-trip ({len(data)} bytes read)")
        return per_di, elapsed

    def _restore_preserved(self, name, addr, backup, sector_addr,
                           sector_size, allow_mfg=False):
        """Restore preserved bytes after a sound-file write.

        The .mth image carries 0xFF over the mfg regions, so right after the
        image write the region reads erased and a direct write programs it
        with no extra erase — mirroring the dealer loader, which writes mfg
        data separately after the sound file.  Falls back to
        read-patch-erase-rewrite only when the region isn't already erased
        or already correct.

        Returns True on success.
        """
        cur = self.read_raw(addr, len(backup))
        if cur == bytes(backup):
            print(f"  {name}: already intact")
            return True
        if cur is not None and all(b == 0xFF for b in cur):
            if self.write_raw(addr, bytes(backup), allow_mfg=allow_mfg) and \
                    self.verify_raw(addr, bytes(backup)):
                print(f"  {name}: restored")
                return True
            print(f"  WARNING: {name} direct restore failed; "
                  "retrying via sector rewrite")

        sec = self.read_flash_range(sector_addr, sector_size, progress=False)
        if sec is None:
            print(f"  WARNING: could not read sector for {name} restore!")
            return False
        sec = bytearray(sec)
        off = addr - sector_addr
        sec[off:off + len(backup)] = backup
        if not self.erase_at_addr(sector_addr, allow_mfg=allow_mfg):
            print(f"  WARNING: could not erase sector for {name} restore!")
            return False
        if not self.write_raw(sector_addr, bytes(sec), allow_mfg=allow_mfg):
            print(f"  WARNING: could not write sector for {name} restore!")
            return False
        if not self.verify_raw(sector_addr, bytes(sec)):
            print(f"  WARNING: {name} sector verification failed!")
            return False
        print(f"  {name}: restored (sector rewrite)")
        return True

    def _recover_sector(self, sector_addr, sector_data):
        """Recover a failed sector by erasing and writing backup data.

        Called when an erase/write/verify fails during a sound file write.
        Attempts to restore the sector to its pre-write state from the
        full flash backup.

        Args:
            sector_addr: Flash address of the sector start
            sector_data: Backup data for this sector
        Returns True if recovery succeeded, False if it failed.
        """
        print(f"    Recovery: erasing sector at 0x{sector_addr:06X}...")
        if not self.erase_at_addr(sector_addr, allow_mfg=True):
            print("    Recovery: erase failed")
            return False

        print(f"    Recovery: writing {len(sector_data)} bytes...")
        if not self.write_raw(sector_addr, sector_data, allow_mfg=True):
            print("    Recovery: write failed")
            return False

        print("    Recovery: verifying...")
        if not self.verify_raw(sector_addr, sector_data):
            print("    Recovery: verify failed")
            return False

        print("    Recovery: sector restored successfully")
        return True

    def _validate_flash_range(self, addr, length, allow_mfg=False,  # pylint: disable=too-many-return-statements
                              allow_bootloader=False):
        """Safety interlock: reject writes/erases to protected flash regions.

        Checks:
        - addr and addr+length within [0, flash_size)
        - length > 0
        - no 32-bit overflow
        - address not in bootloader/DSP region (if known)
        - address not in manufacturing region (unless allow_mfg=True)
        - bootloader/DSP region must be known (hard stop if not)

        allow_bootloader=True skips the bootloader region check — use only
        for write_chain_code, which intentionally writes to the DSP region
        after verifying the range against EIS.

        Returns True if safe, False (and prints) if rejected.
        """
        if length <= 0:
            print(f"  REFUSE: zero/negative length ({length})")
            return False
        if addr < 0:
            print(f"  REFUSE: negative address (0x{addr:X})")
            return False
        end = addr + length
        if end < addr:
            print(f"  REFUSE: address+length overflow "
                  f"(0x{addr:06X}+0x{length:X} wraps to 0x{end:X})")
            return False
        if not getattr(self, '_validated_flash_size', 0):
            fs = self.detect_flash_size()
            if not fs:
                print("  REFUSE: cannot determine flash size for range validation")
                return False
            self._validated_flash_size = fs
        if end > self._validated_flash_size:
            print(f"  REFUSE: write end 0x{end:06X} exceeds flash size "
                  f"0x{self._validated_flash_size:06X}")
            return False
        # Bootloader/DSP protection (if EIS was read)
        bl_start = getattr(self, '_protected_bootloader_start', None)
        bl_end = getattr(self, '_protected_bootloader_end', None)
        if bl_start is not None and bl_end is not None:
            if not allow_bootloader and addr < bl_end and end > bl_start:
                print(f"  REFUSE: range 0x{addr:06X}-0x{end:06X} overlaps "
                      f"bootloader/DSP 0x{bl_start:06X}-0x{bl_end:06X}")
                return False
        elif not allow_bootloader:
            print("  REFUSE: bootloader/DSP region unknown — "
                  "cannot safely erase or write without EIS protection")
            print("  Call set_bootloader_protection() first or read EIS records")
            return False
        # Manufacturing region protection
        if not allow_mfg:
            mfg_start = MFG_SECTOR_ADDR
            mfg_end = mfg_start + MFG_SECTOR_SIZE
            if addr < mfg_end and end > mfg_start:
                print(f"  REFUSE: range 0x{addr:06X}-0x{end:06X} overlaps "
                      f"manufacturing data 0x{mfg_start:06X}-0x{mfg_end:06X} "
                      f"(use allow_mfg=True to override)")
                return False
        return True

    def set_bootloader_protection(self, start, end):
        """Record the bootloader/DSP region to protect from writes/erases."""
        self._protected_bootloader_start = start
        self._protected_bootloader_end = end
        print(f"  Bootloader protection: 0x{start:06X}-0x{end:06X}")

    def erase_at_addr(self, addr, retries=3, allow_mfg=False,
                      allow_bootloader=False, size=None):
        """Erase the flash covering [addr, addr+size) and verify by readback.

        With size=None, erases the whole logical sector containing `addr`
        (_sector_size_for_addr), matching callers that rewrite a full sector.

        The engine's `07 0300` command erases the 8KB flash block containing
        the write pointer — measured live: `K000000` erased 0x0000-0x1FFF
        while 0x2000 kept its data. A logical sector can span several erase
        blocks, so each is sent its own K and verified. Blocks that already
        read 0xFF are skipped, which also self-adapts if a higher flash
        region turns out to use larger erase units.

        allow_bootloader=True skips the bootloader region check — use only
        for write_chain_code, which intentionally writes to the DSP region.

        Returns True on success.
        """
        if size is None:
            size = self._sector_size_for_addr(addr)
        if not self._validate_flash_range(addr, size, allow_mfg=allow_mfg,
                                          allow_bootloader=allow_bootloader):
            return False
        print(f"  Erasing 0x{size:X} bytes at 0x{addr:06X}...")
        end = addr + size
        unit = addr - (addr % ERASE_BLOCK)   # erase blocks are address-aligned
        while unit < end:
            if not self._erase_block(unit, min(ERASE_BLOCK, end - unit),
                                     retries):
                return False
            unit += ERASE_BLOCK
        return True

    def _erase_block(self, addr, size, retries):
        """Erase and verify the single 8KB engine erase block containing addr.

        The dealer loader (EraseAndVerifySector, RVA 0x30714) sends only
        "K<addr>" with a 30-second timeout — the TIU-side handler blocks on
        the erase-done response.  The WTIU K handler's execute call is soft
        (its DI read caps at ~200 ms), so K can return while the engine is
        still erasing; the settle loop below waits for the engine to answer
        an R probe before verifying, which is the equivalent of the TIU's
        response-hold.
        """
        # Skip K entirely if the block already reads erased.
        probe = self.read_raw(addr, min(0x40, size))
        if probe is not None and all(b == 0xFF for b in probe) \
                and self.verify_erased(addr, size):
            print(f"  Block 0x{addr:06X} already erased — skipping K")
            return True

        print(f"  Erasing block at 0x{addr:06X}...")
        cmd = f"K{addr:06X}"
        for attempt in range(retries):
            resp = self.conn.send_cmd(cmd, timeout=30.0)
            if self.debug:
                print(f"  K response: {repr(resp)}")
            if "okay" in resp:
                break
            print(f"  Erase attempt {attempt+1}/{retries} failed: "
                  f"{resp.strip()}")
            # Even on "DCS timeout" the erase may have started — the
            # readback below is the real verdict, so keep retrying.
            if attempt < retries - 1:
                time.sleep(0.5)

        # K → C sequence, matching the Consumer Loader: C sends DI 0x18
        # (erase-verify / DI-state reset) so post-erase reads are clean.
        self.conn.send_cmd("C")
        self.conn.drain_buffer()

        # Wait for the engine to finish the erase before reading — up to
        # ~20s, far under the dealer loader's 30s erase budget.
        for _ in range(40):
            if self.read_raw(addr, 0x10) is not None:
                break
            time.sleep(0.5)

        if self.verify_erased(addr, size):
            return True

        # Adaptive fallback for engines whose K erases a smaller unit than
        # requested (unverified on PS2 — if the engine's erase block is
        # half the size, K at addr only cleared the first half).  K the
        # second half explicitly and re-verify the whole range.  Never
        # runs on the PS3 happy path — only after a real verify failure.
        half = size // 2
        if half >= 0x1000:
            print(f"  Partial erase at 0x{addr:06X} — retrying second half "
                  f"(engine erase unit may be smaller)")
            resp = self.conn.send_cmd(f"K{addr + half:06X}", timeout=30.0)
            if self.debug:
                print(f"  K response: {repr(resp)}")
            self.conn.send_cmd("C")
            self.conn.drain_buffer()
            for _ in range(40):
                if self.read_raw(addr + half, 0x10) is not None:
                    break
                time.sleep(0.5)
            if self.verify_erased(addr + half, size - half):
                return True

        print(f"  Erase verification failed at 0x{addr:06X}")
        return False

    def _sector_size_for_addr(self, addr):
        """Sector size covering a flash address.

        Same geometry as _sector_to_addr/_sector_size, expressed by address:
        16 KB boot sector, two 8 KB sectors, the remainder of the first 512 KB,
        then 128 KB blocks.
        """
        if addr < 0x004000:
            return 0x4000
        if addr < 0x008000:
            return 0x2000
        if addr < 0x080000:
            return 0x78000
        return 0x20000

    def _sector_end(self, addr):
        """End address (exclusive) of the sector containing addr."""
        return addr + self._sector_size_for_addr(addr)

    def write_raw(self, addr, data, verify=False, progress=True,
                  allow_mfg=False, allow_bootloader=False):
        """Write raw data to a flash address.  Delegates to write_burst(),
        which drives the firmware `W` handler -- the path verified to program
        flash on hardware (2026-09-11: single- and multi-block writes at
        20 bytes/block read back correctly).

        The flash must already be erased; W programs bits but cannot
        un-program them.  W's "okay" return is not evidence of success --
        always confirm with a readback (verify=True does this).

        Returns True on success.
        """
        return self.write_burst(addr, data, progress=progress, verify=verify,
                                allow_mfg=allow_mfg,
                                allow_bootloader=allow_bootloader)

    def verify_raw(self, addr, expected_data, retries=3):
        """Verify written data by reading it back.

        The dealer loader (VerifyWriteSector, RVA 0x32684) retries
        verification on failure, up to 5 times with delays. We use
        3 retries by default.

        Returns True if data matches.
        """
        total = len(expected_data)
        print(f"  Verifying {total} bytes at 0x{addr:06X}...")

        for attempt in range(retries):
            read_data = self.read_raw(addr, total)
            if read_data is not None:
                if read_data == expected_data:
                    print("  Verification successful!")
                    return True
                print(f"  Verify attempt {attempt+1}/{retries}: data mismatch")
            else:
                print(f"  Verify attempt {attempt+1}/{retries}: read failed")

            if attempt < retries - 1:
                time.sleep(0.5)

        # Final failure report
        if read_data is not None:
            print(f"  Verification FAILED after {retries} attempts!")
            print(f"  Expected {total} bytes, got {len(read_data)}")
            for i in range(min(len(expected_data), len(read_data))):
                if expected_data[i] != read_data[i]:
                    print(f"  First diff at offset 0x{addr+i:06X}: "
                          f"expected 0x{expected_data[i]:02X}, "
                          f"got 0x{read_data[i]:02X}")
                    break
        else:
            print(f"  Verification FAILED: could not read back data "
                  f"after {retries} attempts")
        return False

    def write_burst(self, addr, data, progress=True, verify=True,
                    allow_mfg=False, allow_bootloader=False, burst_delay=0.08):
        """Write raw data to flash via the firmware `W` handler (atomic per
        block).

        Each `W<addr><len><burst>` command hands the daemon a 31-byte burst
        body ``[channel|0x80, count, data, 0xFF-pad to 29, CRC16]``; the
        handler runs the COMPLETE program cycle in firmware at TIU speed:
        l1 enter -> set address -> 0x0D init x3 -> 0x0B write-enable ->
        0x07 poll -> burst -> commit spin-delay -> 0x0B disable -> l0 exit.

        This is the only reliable way to write: client-driven `z`/`Y` command
        chains desynchronize the engine's real-time write handshake because
        each command is a separate TCP->daemon->FPGA->engine round-trip, so
        consecutive bursts landed stale/garbage.  In firmware the whole block
        transaction is atomic and engine-paced.

        Verified on hardware 2026-09-11: three consecutive 20-byte blocks
        program correctly (the pre-header build produced A1->A0->80 decay).

        Flash must already be erased; a burst programs bits but cannot
        un-program them.  Returns True on success.
        """
        data = bytes(data)
        if not self._validate_flash_range(addr, len(data),
                                          allow_mfg=allow_mfg,
                                          allow_bootloader=allow_bootloader):
            return False
        if not data:
            print('  REFUSE: nothing to write')
            return False

        total = len(data)
        n_blocks = (total + BURST_DATA_MAX - 1) // BURST_DATA_MAX
        if progress:
            print(f'  Writing {total} bytes to 0x{addr:06X} '
                  f'in {n_blocks} block(s) of up to {BURST_DATA_MAX} ...')

        # Preferred path: the `Z` persistent write session.
        #
        #   ZB<addr>   enter program mode and set the write pointer ONCE,
        #              mirroring the TIU's once-per-region entry sequence
        #   ZD<hex>    one burst of up to 27 bytes -- send, check the 5-byte
        #              response and the auto-incremented write pointer,
        #              retry in firmware (bounded 20x, re-asserting the
        #              pointer each attempt, full re-entry every 4th)
        #   ZE         write-disable and leave program mode
        #
        # Compared to the W loop below this drops ~8 DI round-trips per
        # block (per-block l1/address/init/enable/teardown) and needs no
        # blind burst_delay -- the response handshake is the pacing.  The
        # firmware still verifies every burst and the readback below stays,
        # so "okay" alone is never taken as proof.
        if self._open_zsess(addr):
            t0 = time.time()
            try:
                offset = 0
                while offset < total:
                    blk = data[offset:offset + BURST_DATA_MAX]
                    resp = self.conn.send_cmd(
                        'ZD' + blk.hex().upper(), timeout=30.0)
                    if 'okay' not in resp.lower():
                        print(f'    ZD @0x{addr + offset:06X}: '
                              f'{resp.strip()}')
                        return False
                    offset += len(blk)
                    if progress:
                        print(f'    wrote {offset}/{total} bytes')
            finally:
                # Always end the session -- an engine left in program mode
                # with writes enabled is one stray DI command away from
                # flash corruption.
                try:
                    self.conn.send_cmd('ZE', timeout=10.0)
                except Exception as exc:  # pylint: disable=broad-except
                    # cleanup must never mask the real write result
                    print(f'    ZE (session close) failed: {exc}')
            if progress:
                dt = time.time() - t0
                print(f'    session write: {dt:.1f}s '
                      f'({total / dt / 1000:.1f} KB/s)')
            if verify:
                return self.verify_raw(addr, data)
            return True

        # Fallback: one W command per block -- the daemon runs the COMPLETE
        # program cycle (PC-mode entry -> set address -> flash init ->
        # write-enable -> burst -> disable -> exit) per 27-byte burst.
        #
        # terminator=False: the firmware wraps this body in a HEADER frame
        # (frame[5] = 5 expected DI response bytes) so the LM8 turns the bus
        # around and collects the engine's 5-byte burst response.  Without that
        # the LM8's receive target is never met and the transfer stalls at
        # 0xA0 -- the cause of the multi-block corruption.  A header frame puts
        # the payload at frame[10], so the body must be 31 bytes to stay within
        # FUN_00404444's 41-byte maximum.  See W_WRITE_PATH_ANALYSIS.md s11.
        offset = 0
        while offset < total:
            blk = data[offset:offset + BURST_DATA_MAX]
            block_addr = addr + offset
            burst = burst_frame(self.engine_addr, blk, terminator=False)
            cmd = 'W%06X%06X%s' % (block_addr, len(burst),
                                   burst.hex().upper())
            # Per-block retry: a burst can transiently time out (the burst
            # frame's FUN_00404658 send returns -0x70 when the engine is
            # still finishing the previous commit).  Re-sending is safe —
            # the handler re-sets the write pointer (07 00/01/02) before
            # each burst, and re-programming identical data is a NOR no-op.
            ok = False
            for attempt in range(3):
                resp = self.conn.send_cmd(cmd, timeout=30.0)
                if 'okay' in resp.lower():
                    ok = True
                    break
                print(f'    W @0x{block_addr:06X} attempt {attempt+1}/3: '
                      f'{resp.strip()}')
                time.sleep(0.3)
            if not ok:
                return False
            offset += len(blk)
            if progress:
                print(f'    wrote {offset}/{total} bytes')
            if burst_delay and offset < total:
                time.sleep(burst_delay)

        if verify:
            return self.verify_raw(addr, data)
        return True

    def _open_zsess(self, addr):
        """Open a `Z` write session at `addr`; True when the session is open.

        ZB doubles as the capability probe: on firmware without the `Z`
        command the dispatcher answers "input error" and we permanently fall
        back to the W path.  Any other failure is a real entry failure --
        the handler tears down on its way out, so no session is left open --
        and the write is refused rather than retried through W, because a
        half-entered engine is not a state to program blind from.
        """
        if self._zsess_unsupported:
            return False
        resp = self.conn.send_cmd('ZB%06X' % addr, timeout=30.0)
        if 'okay' in resp.lower():
            if not self._zsess_announced:
                print('  Using Z-session burst writes '
                      '(program-mode entry once per write)')
                self._zsess_announced = True
            return True
        if 'input error' in resp.lower():
            self._zsess_unsupported = True
            print('  Z session not in firmware; per-block W fallback')
            return False
        print(f'  ZB @0x{addr:06X} failed: {resp.strip()}')
        return False

    def _sector_start(self, addr):
        """Start address of the flash sector containing addr."""
        if addr < 0x004000:
            return 0x000000
        if addr < 0x006000:
            return 0x004000
        if addr < 0x008000:
            return 0x006000
        if addr < 0x080000:
            return 0x008000
        return (addr // 0x20000) * 0x20000

    def _flash_sectors(self, flash_size):
        """All (start, end) sector bounds up to flash_size."""
        sectors = []
        addr = 0
        while addr < flash_size:
            end = addr + self._sector_size_for_addr(addr)
            sectors.append((addr, end))
            addr = end
        return sectors

    def dump_flash(self, output_path, flash_size=None):
        """Read the entire flash and save it as a .flash_backup image.

        Same raw-image format --write-sound --backup-flash produces, so
        restore_flash() can consume it directly.  Used for donor imaging:
        dump a healthy engine, restore its scrambled twin (same PCB rev).
        """
        if flash_size is None:
            flash_size = self.detect_flash_size()
        if not flash_size:
            print("  ERROR: could not determine flash size "
                  "(use --flash-size)")
            return False
        data = self.read_flash_range(0, flash_size)
        if data is None:
            print("  ERROR: full flash read failed")
            return False
        with open(output_path, 'wb') as f:
            f.write(data)
        print(f"  Saved {len(data)} bytes to {output_path}")
        return True

    def restore_flash(self, backup_data, sector=None, range_bounds=None,
                      force_bootloader=False, assume_yes=False):
        """Restore engine flash from a .flash_backup image.

        Erases and rewrites whole flash sectors, each verified by
        readback.  Recovery requires the engine's program-mode path to
        still answer commands -- if setup_engine() fails, the board is
        unrecoverable over the wire.

        sector/range_bounds restrict the restore.  Sectors overlapping
        the EIS bootloader/DSP region are skipped unless
        force_bootloader -- that region may host the program-mode code,
        so forcing is a last resort.
        """
        eis = self.read_eis_records()
        bl_start = bl_end = None
        if eis and eis.get('dsp_addr'):
            bl_start = eis['dsp_addr']
            bl_end = bl_start + eis.get('dsp_max_len', 0)
            print(f"  Bootloader/DSP region: 0x{bl_start:06X}-0x{bl_end:06X}")
        else:
            print("  WARNING: could not read EIS -- bootloader protection "
                  "disabled; all sectors will be restored")

        flash_size = len(backup_data)
        if sector is not None:
            s = self._sector_start(sector)
            targets = [(s, s + self._sector_size_for_addr(s))]
        elif range_bounds:
            rs, re_ = range_bounds
            targets = [(s, e) for s, e in self._flash_sectors(flash_size)
                       if s >= rs and e <= re_]
        else:
            targets = self._flash_sectors(flash_size)

        if not force_bootloader and bl_start is not None:
            skipped = [(s, e) for s, e in targets
                       if s < bl_end and e > bl_start]
            targets = [(s, e) for s, e in targets
                       if not (s < bl_end and e > bl_start)]
            for s, e in skipped:
                print(f"  Skipping 0x{s:06X}-0x{e:06X} "
                      "(bootloader protected)")

        if not targets:
            print("  No sectors to restore.")
            return False

        total = sum(e - s for s, e in targets)
        n_blocks = (total + BURST_DATA_MAX - 1) // BURST_DATA_MAX
        print(f"\n*** ABOUT TO RESTORE {len(targets)} SECTORS "
              f"({total} bytes) ***")
        per_di, _ = self.calibrate_timing()
        if per_di is not None:
            # ZD session ~= 1 DI round-trip per 27-byte block; the W
            # fallback ~= 8 per block.
            print(f"  ~{n_blocks} blocks: ~{n_blocks * per_di / 60:.0f} min "
                  f"(ZD session) to ~{n_blocks * 8 * per_di / 60:.0f} min "
                  "(W fallback), plus readback verification")
        print("  Do not remove power or the engine from the track!")
        if not assume_yes:
            if input("  Type 'YES' to continue: ") != 'YES':
                print("Aborted.")
                return False

        if not self.enter_fast_mode():
            print("  Warning: could not enter fast programming mode")

        recovered, failed = 0, []
        for s, e in targets:
            size = e - s
            print(f"\n  Restoring sector 0x{s:06X}-0x{e:06X} "
                  f"({size} bytes)...")
            data = backup_data[s:e]
            if len(data) < size:
                data += b'\xFF' * (size - len(data))
            if not self.erase_at_addr(s, allow_mfg=True,
                                      allow_bootloader=True):
                print(f"  ERROR: erase failed at 0x{s:06X}")
                failed.append(s)
                continue
            if not self.write_raw(s, data, allow_mfg=True,
                                  allow_bootloader=True):
                print(f"  ERROR: write failed at 0x{s:06X}")
                failed.append(s)
                continue
            if not self.verify_raw(s, data):
                print(f"  ERROR: verify failed at 0x{s:06X}")
                failed.append(s)
                continue
            recovered += 1
            print("  Sector restored")

        print("\n  Post-restore restart sequence...")
        self._post_write_restart()
        self.enter_normal_mode()

        print(f"\n  Sectors restored: {recovered}/{len(targets)}")
        if failed:
            print("  FAILED: " + ", ".join(f"0x{s:06X}" for s in failed))
            print("  Engine may be partially recovered -- retry the "
                  "failed sectors with --restore-sector")
            return False
        print("  All sectors restored successfully!")
        return True

    def write_consumer_zip(self, zip_path, preserve_mfg=True, validate=True,
                           stamp_loader=True, backup_flash=False,
                           assume_yes=False, confirm_cb=None):
        """Program an engine from a consumer download zip (-cnsmr.zip).

        The consumer zip wraps the whole payload: the chain code zip
        (code regions: DSP/FPGA/DCC_CV/Hardware/Boiler) and the .mth
        sound file.  Mirrors the loader's board-prep order — chain code
        first (the 'brain'), then the sound file (the 'personality') —
        and aborts before the sound write if the chain write fails.

        Exactly one engine should be powered on the track.
        """
        print("\n=== Consumer Zip Write ===")
        print(f"  Zip file: {zip_path}")
        if not zipfile.is_zipfile(zip_path):
            print(f"  ERROR: not a zip: {zip_path}")
            return False

        with tempfile.TemporaryDirectory(prefix='mth_cnsmr_') as td:
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(td)
            mths = sorted(f for f in os.listdir(td)
                          if f.lower().endswith('.mth'))
            chains = sorted(f for f in os.listdir(td)
                            if f.lower().endswith('.zip'))
            if not mths and not chains:
                print("  ERROR: no .mth or chain zip found inside")
                return False
            if len(mths) > 1 or len(chains) > 1:
                print(f"  WARNING: multiple payloads ({len(mths)} .mth, "
                      f"{len(chains)} .zip) — using first of each")
            print("  Payload:")
            for f_ in chains:
                print(f"    chain zip:   {f_}")
            for f_ in mths:
                print(f"    sound file:  {f_}")

            if not assume_yes:
                parts = []
                if chains:
                    parts.append(f"chain code ({chains[0]})")
                if mths:
                    parts.append(f"sound file ({mths[0]})")
                if not self._ask_yes(
                        "Write " + " + ".join(parts) + " to the engine? "
                        "Type 'YES' to continue: ", confirm_cb):
                    print("Aborted.")
                    return False

            if chains:
                if not self.write_chain_zip(os.path.join(td, chains[0]),
                                            assume_yes=True,
                                            confirm_cb=confirm_cb):
                    print("  ERROR: chain write failed — aborting "
                          "before the sound write")
                    return False
            if mths:
                if not self.write_sound_file(
                        os.path.join(td, mths[0]),
                        preserve_mfg=preserve_mfg, validate=validate,
                        stamp_loader=stamp_loader,
                        backup_flash=backup_flash,
                        assume_yes=True, confirm_cb=confirm_cb):
                    return False
        print("\n  Consumer image written successfully!")
        return True

    def write_engine_info(self, new_data):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements,too-many-return-statements
        """Write engine info data to flash at 0x001DD2.

        The engine info lives in sector 0 (0x000000-0x003FFF).
        We must:
          1. Read EIS and set bootloader protection
          2. Read the entire sector 0 (16KB)
          3. Merge the new engine info at offset 0x1DD2
          4. Erase sector 0
          5. Write the full sector back
          6. Verify

        This preserves all other data in sector 0 (boot code, etc.)
        Returns True on success.
        """
        sector_addr = 0x000000
        sector_size = 0x4000  # 16 KB
        info_offset = ENG_INFO_ADDR  # 0x001DD2
        info_size = len(new_data)  # ENG_INFO_SIZE or ENG_INFO_EXTENDED_SIZE

        # Set bootloader protection before any erase/write.
        # Sector 0 contains boot code — if EIS says the bootloader is in
        # sector 0, the _validate_flash_range interlock will refuse the
        # erase, preventing a brick.
        if not hasattr(self, '_protected_bootloader_start') or \
           self._protected_bootloader_start is None:
            print("\n  Reading EIS for bootloader protection...")
            eis_records = self.read_eis_records()
            if eis_records and 'dsp_addr' in eis_records:
                bl_addr = eis_records['dsp_addr']
                bl_max = eis_records.get('dsp_max_len', 0)
                self.set_bootloader_protection(bl_addr, bl_addr + bl_max)
            else:
                print("  ERROR: Could not determine bootloader region from EIS")
                print("  REFUSING to write without bootloader protection")
                return False

        print(f"\n  Engine info is in sector 0 ({sector_size} bytes)")
        print("  Reading full sector 0 to preserve other data...")

        # Read the full sector
        sector_data = bytearray()
        block = 0x100
        for off in range(0, sector_size, block):
            chunk = self.read_raw(sector_addr + off, min(block, sector_size - off))
            if chunk is None:
                print(f"  Failed to read sector 0 at offset 0x{off:04X}")
                return False
            sector_data.extend(chunk)

        print(f"  Read {len(sector_data)} bytes from sector 0")

        # Save backup — use the tools directory or a writable temp location
        backup_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "sector0_backup.bin")
        try:
            # Remove read-only attribute if file exists from a previous run
            if os.path.exists(backup_path):
                os.chmod(backup_path, 0o666)
            with open(backup_path, 'wb') as f:
                f.write(bytes(sector_data))
            print(f"  Backup saved to {backup_path}")
        except (PermissionError, OSError):
            # Fall back to user's home directory
            backup_path = os.path.join(os.path.expanduser("~"), "sector0_backup.bin")
            try:
                if os.path.exists(backup_path):
                    os.chmod(backup_path, 0o666)
                with open(backup_path, 'wb') as f:
                    f.write(bytes(sector_data))
                print(f"  Backup saved to {backup_path}")
            except OSError as e2:
                print(f"  ERROR: Could not save backup: {e2}")
                print("  Aborting write — no backup available for recovery.")
                return False

        # Merge new engine info into the sector
        info_start = info_offset  # 0x1DD2
        info_end = info_start + info_size

        # If the engine info region is already erased to 0xFF, we can write
        # just that region without erasing the entire 16 KB sector. This
        # preserves the rest of sector 0 (boot code, etc.) and avoids the
        # currently broken K handler. The write itself still only programs
        # bits to 0, so it is safe only when the target cells are 0xFF.
        existing_info = bytes(sector_data[info_start:info_end])
        info_already_erased = existing_info == b'\xFF' * info_size

        sector_data[info_start:info_end] = new_data

        # Enter fast programming mode
        # Lf may fail through the WTIU — we proceed anyway and let K/W
        # fail naturally if the engine truly doesn't accept them.
        self.enter_fast_mode()

        # Small delay to let the engine process mode change
        time.sleep(0.5)

        if info_already_erased:
            print("  Engine info region already erased (0xFF) — "
                  "skipping full sector erase.")
            # Use 0x14-byte chunks; the W handler uses this block size.
            if not self.write_raw(info_start, new_data):
                print(f"  Write failed! Sector 0 backup is in {backup_path}")
                self.enter_normal_mode()
                return False
            if not self.verify_raw(info_start, new_data):
                print(f"  Verification failed! Sector 0 backup is in {backup_path}")
                self.enter_normal_mode()
                return False
            self.enter_normal_mode()
            print("  Engine info write complete!")
            return True

        # Erase sector 0
        if not self.erase_at_addr(sector_addr):
            print(f"  Erase failed! Aborting. Sector 0 backup is in {backup_path}")
            self.enter_normal_mode()
            return False

        # Write the full sector back
        if not self.write_raw(sector_addr, bytes(sector_data)):
            print(f"  Write failed! Sector 0 backup is in {backup_path}")
            self.enter_normal_mode()
            return False

        # Verify
        if not self.verify_raw(sector_addr, bytes(sector_data)):
            print(f"  Verification failed! Sector 0 backup is in {backup_path}")
            self.enter_normal_mode()
            return False

        self.enter_normal_mode()
        print("  Engine info write complete!")
        return True

    def enter_fast_mode(self):
        """Enter fast programming mode.

        The dealer loader's state machine sends these commands before Lf:
        1. R00000000000A (TIULongAddressSupport - probe address 0)
        2. RFF000000000A (EngineMemorySize - probe address 0xFF0000)
        3. Z (remote programming mode)
        4. Lf (fast programming mode)

        However, per the TIU disassembly notes:
        - Lf/Lc only set/clear TIU RAM flags (0x3194) consumed by the TIU's
          internal bulk programmer. They have NO effect on the K/W/R path.
        - Z puts the TIU into "Remote Programming Mode Active" which the WTIU
          does not support and may leave the TIU/mux2tiu in a bad state.

        We skip Z entirely (it is not needed for K/W/R to work through the
        WTIU) and try Lf but proceed regardless of its response.
        """
        print("  Entering fast programming mode...")

        # Probe flash boundaries — the dealer loader does this before Lf
        # (TIULongAddressSupport and EngineMemorySize in the state machine)
        resp = self.conn.send_cmd("R00000000000A")
        print(f"  Probe 0x000000: {resp.strip()[:40]}")
        self.conn.send_cmd("A")  # acknowledge read

        resp = self.conn.send_cmd("RFF000000000A")
        print(f"  Probe 0xFF0000: {resp.strip()[:40]}")
        self.conn.send_cmd("A")  # acknowledge read

        # MTH DCS Consumer Loader V5.0.0 pre-flash prep state machine
        # (from decompiled state machine: SET_SCS_MODE, SET_THROTTLE,
        #  SET_VOLUME, SET_LIGHTS)
        prep_cmds = ('m4', 's0000', 'v0000', 'aa0')
        for prep in prep_cmds:
            resp = self.conn.send_cmd(prep, timeout=10.0)
            print(f"  {prep}: {resp.strip()}")

        # Lf — the TIU's "fast programming mode" flag. On the WTIU the L
        # dispatcher accepts it and returns okay (the flag is TIU-local; the
        # W handler runs the full program sequence per block regardless).
        resp = self.conn.send_cmd("Lf", timeout=10.0)
        print(f"  Lf: {resp.strip()}")

        # La<n>/Ld<n> are the WTIU's own dialect (stock FUN_00402160 drives
        # DI subcmd 0x1E/0x20) — they are not part of the TIU programming
        # sequence, and the W handler already wraps every block in l1 +
        # 0x0B enable, so no explicit L handshake is needed.
        return True

    def enter_normal_mode(self):
        """Enter normal programming mode."""
        print("  Entering normal programming mode...")
        resp = self.conn.send_cmd("Lc")
        if self.debug:
            print(f"  Lc response: {resp.strip()}")
        if "okay" not in resp:
            # Lc failed — not critical, the engine will reset on power cycle
            if self.debug:
                print(f"  Lc response: {resp.strip()}")
        self._engine_setup_done = False
        return True

    def cleanup(self):
        """Cleanup after programming."""
        # Send startup
        # Enable scan
        self.conn.send_cmd("X1")

    # ========================================================================
    # Engine runtime data (q-commands for RAM access)
    # ========================================================================

    @staticmethod
    def _ram_to_q(ram_addr):
        """Convert RAM address to q-command address.

        QTORAM(qc) = ((((qc & 0x2000) >> 13) | ((qc & 0x01FF) << 1)) ^ 0x0300)
        Inverse: find qc for a given RAM address.
        """
        val = ram_addr ^ 0x0300
        bit12 = (val >> 12) & 1
        qc_low = (val & 0x0FFE) >> 1
        return (bit12 << 13) | qc_low

    def read_ram(self, addr, size):
        """Read engine RAM using q-command.

        The q-command reads 4 bytes from a scrambled RAM address.
        Args:
            addr: RAM address (0x000-0x3FF)
            size: 1, 2, or 4 bytes (returns the low N bytes of the 4-byte read)
        Returns int value or None on failure.
        """
        qc = self._ram_to_q(addr)
        cmd = f"q{qc:04X}"
        resp = self.conn.send_cmd(cmd)
        if "okay" not in resp:
            if self.debug:
                print(f"  RAM read failed: {resp.strip()}")
            return None
        # Response format: "qXXXX<byte0> <byte1> <byte2> <byte3> okay"
        # The first byte is concatenated with the command echo.
        # e.g. "q1E80e3 00 c0 00 okay" for q1E80 with byte0=0xE3
        try:
            # Remove "okay" and strip
            data_str = resp.replace("okay", "").strip()
            # Remove the command echo (first 5 chars: "q" + 4 hex digits)
            data_str = data_str[len(cmd):]
            # Split remaining bytes by whitespace
            byte_strs = data_str.strip().split()
            if len(byte_strs) >= 4:
                raw_bytes = bytes(int(b, 16) for b in byte_strs[:4])
                if size == 1:
                    return raw_bytes[0]
                if size == 2:
                    return raw_bytes[0] | (raw_bytes[1] << 8)
                if size == 4:
                    return struct.unpack('<I', raw_bytes)[0]
        except (ValueError, struct.error, IndexError) as e:
            if self.debug:
                print(f"  Parse error: {e}")
        return None

    def read_odometer(self):
        """Read the engine odometer (scale miles).

        RAM 0x34-0x37, 4 bytes, V4034 command.
        Returns scale miles as int, or None on failure.
        """
        val = self.read_ram(0x34, 4)
        if val is not None:
            print(f"  Odometer: {val} scale miles")
        return val

    def read_trip_odometer(self):
        """Read the trip odometer (scale miles).

        RAM 0x3C-0x3F, 4 bytes, V403C command.
        Returns scale miles as int, or None on failure.
        """
        val = self.read_ram(0x3C, 4)
        if val is not None:
            print(f"  Trip odometer: {val} scale miles")
        return val

    def read_chronometer(self):
        """Read the engine chronometer (operating time).

        RAM 0x38-0x3B, 4 bytes, V4038 command.
        Raw value / 31.3197 = seconds.
        Returns (raw_value, hours) tuple or None on failure.
        """
        val = self.read_ram(0x38, 4)
        if val is not None:
            seconds = val / 31.3197
            hours = seconds / 3600
            print(f"  Chronometer: {val} raw = {hours:.2f} hours")
            return (val, hours)
        return None

    def read_speed_factor(self):
        """Read speed factor (RAM 0x04-0x05, V2004)."""
        return self.read_ram(0x04, 2)

    def read_counts_per_rev(self):
        """Read counts/revolution (RAM 0x06-0x07, V2006)."""
        return self.read_ram(0x06, 2)

    def read_scale_factor(self):
        """Read scale factor (RAM 0x08-0x09, V2008)."""
        return self.read_ram(0x08, 2)

    def read_interrupt_rate(self):
        """Read interrupt rate (RAM 0x0A-0x0B, V200A)."""
        return self.read_ram(0x0A, 2)

    def read_dcs_engine_number(self):
        """Read DCS engine number (RAM 0x0C-0x0D, V200C).
        Stored value + 1 = actual DCS address.
        """
        val = self.read_ram(0x0C, 2)
        if val is not None:
            return val + 1
        return None

    def read_volumes(self):
        """Read all volume settings (RAM 0x0E-0x17).
        Returns dict with master, engine, accent, horn, bell volumes.
        """
        volumes = {}
        labels = [
            (0x0E, 'master'), (0x10, 'engine'), (0x12, 'accent'),
            (0x14, 'horn'), (0x16, 'bell')
        ]
        for addr, label in labels:
            val = self.read_ram(addr, 2)
            if val is not None:
                volumes[label] = val
                pct = val * 100 // 327
                print(f"  {label.capitalize()} volume: {val} ({pct}%)")
        return volumes

    def read_engine_type(self):
        """Read engine type (RAM 0x22-0x23, V2022).
        Returns dict with raw value, type string, and sound set ID.
        """
        val = self.read_ram(0x22, 2)
        if val is None:
            return None
        hi_byte = (val >> 8) & 0xFF
        lo_byte = val & 0xFF
        type_map = {
            0x00: 'Steam', 0x10: 'Steam (Big Boy)',
            0x05: 'Diesel', 0x85: 'Diesel (newer PS3)',
            0x25: 'Electric',
            0xE3: 'Steam (PS3.2)',
        }
        type_str = type_map.get(lo_byte, f'Unknown (0x{lo_byte:02X})')
        result = {
            'raw': val,
            'type_byte': lo_byte,
            'sound_set_id': hi_byte,
            'type': type_str,
        }
        print(f"  Engine type: {type_str} (sound set 0x{hi_byte:02X})")
        return result

    # ========================================================================
    # DSP code commands
    # ========================================================================

    def read_dsp_version(self):
        """Read DSP code version using E302 command.
        Returns version string or None on failure.
        """
        resp = self.conn.send_cmd("E302")
        if "okay" in resp:
            # Parse version from response
            version = resp.replace("E302", "").replace("okay", "").strip()
            print(f"  DSP code version: {version}")
            return version
        # Try alternate command
        resp = self.conn.send_cmd("E30F")
        if "okay" in resp:
            version = resp.replace("E30F", "").replace("okay", "").strip()
            print(f"  DSP code version: {version}")
            return version
        print("  Could not read DSP code version")
        return None

    # ========================================================================
    # HO engine EE parameters
    # ========================================================================

    def read_ho_ee_parameters(self):
        """Read HO engine EEPROM parameters using @R command.
        Returns response string or None on failure.
        """
        resp = self.conn.send_cmd("@R")
        if "okay" in resp:
            print(f"  HO EE parameters: {resp}")
            return resp
        print("  @R command failed (may not be an HO engine)")
        return None

    def write_ho_ee_parameters(self, data):
        """Write HO engine EEPROM parameters using @W command.
        Args:
            data: Parameter data (format TBD based on @R response)
        Returns True on success.
        """
        cmd = f"@W{data}"
        # Shares the same 80-byte command buffer as every other command.
        if len(cmd) > WTIU_CMD_LINE_MAX:
            print(f"  @W command is {len(cmd)} chars, over the "
                  f"{WTIU_CMD_LINE_MAX}-char firmware limit")
            return False
        resp = self.conn.send_cmd(cmd)
        if "okay" in resp:
            print("  HO EE parameters written")
            return True
        print(f"  @W command failed: {resp}")
        return False

    # ========================================================================
    # Chain/DSP Code (S-record firmware) write support
    # ========================================================================

    def read_eis_records(self):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
        """Read EIS sector and extract all code region records.

        The EIS (Engine Information Sector) at 0x004000 uses a TLV
        (Type-Length-Value) record format, traced from the loader's
        ReadEISFields method (RVA 0x332B0).

        Header (16 bytes):
        - 0x00: Magic "EIS!"
        - 0x04: ChecksumType (2 bytes)
        - 0x06: Version (2 bytes)
        - 0x08: EISLength (4 bytes, stored as hex string in loader)
        - 0x0C: EndOfSoundFileAddress (LE32) — used by loader as the
                EIS data length for a second R command; checked <= 8192

        Records start at byte 16. Each record:
        - bytes 0-1: type (LE16)
        - bytes 2-3: data_length (LE16; checked as "0800" string by
                     loader to identify 8-byte region records)
        - bytes 4+:  data

        For region records (data_length == 8):
        - addr = byte6*65536 + byte5*256 + byte4  (reversed LE24)
        - max_len = byte10*65536 + byte9*256 + byte8 (reversed LE24)

        Record type → region name mapping (from loader stfld to
        search pattern fields):
        - 0x2002: DSP          (m_EISDSPAddress, search "0220")
        - 0x2003: FPGA         (m_EISFPGAAddress, search "0320")
        - 0x2004: Engine Sound (m_EISENGINE_SOUNDAddress, search "0420")
        - 0x2007: DCC_CV       (m_EISDCC_CVAddress, search "0720")
        - 0x2009: Boiler       (m_EISBoilerAddress, search "0920")

        Returns dict with keys:
            'dsp_addr', 'dsp_max_len' — DSP code region (bootloader)
            'fpga_addr', 'fpga_max_len' — FPGA code region
            'dcc_cv_addr', 'dcc_cv_max_len' — DCC CV region
            'boiler_addr', 'boiler_max_len' — Boiler code region
            'sound_addr', 'sound_max_len' — Engine Sound region
            'records' — list of all records found (offset, type, addr, max_len)
            'eis_len' — EndOfSoundFileAddress value (EIS data length)
            'raw' — raw EIS bytes
        """
        eis = self.read_raw(0x004000, 0x100)
        if not eis or eis[0:4] != b'EIS!':
            print("  EIS not found at 0x004000")
            return {}

        # EndOfSoundFileAddress at 0x0C (LE32) — used by loader as EIS
        # data length. The IL reads it as a reversed hex string, which
        # is equivalent to LE32.
        eis_len = struct.unpack_from('<I', eis, 0x0C)[0]
        print(f"  EIS Length: {eis_len} bytes")

        # Read full EIS data. The eis_len value from the loader IL is
        # the record area length (excluding the 16-byte header), so the
        # total EIS is eis_len + 16 bytes. We read at least 0x100 bytes
        # initially; if that's not enough, read more.
        total_eis_size = eis_len + 16
        if total_eis_size > 0x100:
            full_eis = self.read_raw(0x004000, total_eis_size)
            if not full_eis:
                full_eis = eis
            else:
                print(f"  Read {len(full_eis)} bytes of EIS")
        else:
            full_eis = eis[:total_eis_size]
            print(f"  Using {len(full_eis)} bytes from initial read")

        result = {
            'eis_len': eis_len,
            'raw': full_eis,
            'records': [],
        }

        # Record type → region name and output key prefix
        # The EIS record type IS the TPL value from the chain file S0 header.
        # Mapped from loader IL analysis:
        #   - Loader search patterns: 0220, 0320, 0520, 0720, 0920, 0A20
        #   - Chain file S0 headers: TPL=2002 (engine-hdr), 2003 (mth_fpga-hdr),
        #     2007 (cv-hdr), 2009 (boiler-hdr), 200A (hardware-hdr)
        #   - 0x2004: sound file data (no chain file, not searched by loader)
        #   - 0x2005: engine sound boundary marker (searched, max_len=0)
        #   - 0x2008: engine data/config region (not searched, no chain file)
        #   - 0x1001: product record (non-region metadata)
        record_types = {
            0x1001: ('Product Record', None),    # PR header, non-region
            0x2002: ('DSP', 'dsp'),              # engine-hdr chain file
            0x2003: ('FPGA', 'fpga'),            # mth_fpga-hdr chain file
            0x2004: ('Sound Data', 'sound'),     # .mth sound file region
            0x2005: ('Engine Sound', 'eng_sound'), # boundary marker
            0x2007: ('DCC_CV', 'dcc_cv'),        # cv-hdr chain file
            0x2008: ('Engine Data', 'eng_data'), # config/data region
            0x2009: ('Boiler', 'boiler'),        # boiler-hdr chain file
            0x200A: ('Hardware', 'hardware'),    # hardware-hdr chain file
        }

        # Parse TLV records starting at byte 16
        pos = 16
        while pos + 4 <= len(full_eis):
            rec_type = struct.unpack_from('<H', full_eis, pos)[0]
            rec_len = struct.unpack_from('<H', full_eis, pos + 2)[0]

            # End marker: type=0, length=0
            if rec_type == 0 and rec_len == 0:
                break

            # Sanity check: record must fit within EIS data
            if pos + 4 + rec_len > len(full_eis):
                print(f"  EIS record at 0x{pos:02X}: truncated (type=0x{rec_type:04X}, "
                      f"len={rec_len}, only {len(full_eis) - pos - 4} bytes left)")
                break

            data = full_eis[pos + 4:pos + 4 + rec_len]
            region_info = record_types.get(rec_type, None)

            if region_info and rec_len >= 8 and region_info[1] is not None:
                # Region record: parse addr and max_len (reversed LE24)
                addr = (data[2] << 16) | (data[1] << 8) | data[0]
                max_len = (data[6] << 16) | (data[5] << 8) | data[4]
                name, key_prefix = region_info
                addr_key = f'{key_prefix}_addr'
                len_key = f'{key_prefix}_max_len'

                rec = {
                    'name': name,
                    'offset': pos,
                    'type': rec_type,
                    'addr': addr,
                    'max_len': max_len,
                }
                result['records'].append(rec)
                if addr_key not in result:
                    result[addr_key] = addr
                    result[len_key] = max_len
                    if max_len > 0:
                        print(f"  {name} region: addr=0x{addr:06X}, "
                              f"max_len=0x{max_len:06X} ({max_len} bytes)")
                    else:
                        print(f"  {name} marker: addr=0x{addr:06X}, "
                              f"max_len=0 (boundary marker)")
                else:
                    print(f"  {name} region (duplicate): addr=0x{addr:06X}, "
                          f"max_len=0x{max_len:06X}")
            else:
                # Non-region record (Product Record, boundary marker, or unknown)
                name = region_info[0] if region_info else f'Unknown(0x{rec_type:04X})'
                # For Product Record, show ASCII data
                data_desc = data[:16].hex().upper()
                if rec_type == 0x1001 and rec_len >= 2:
                    ascii_part = data[:2].decode('ascii', errors='replace')
                    data_desc = f"'{ascii_part}' + {data[2:].hex().upper()}"
                print(f"  EIS record at 0x{pos:02X}: {name}, "
                      f"data_len={rec_len}, data={data_desc}")
                result['records'].append({
                    'name': name,
                    'offset': pos,
                    'type': rec_type,
                    'addr': None,
                    'max_len': None,
                })

            pos += 4 + rec_len

        # Summary
        found_regions = [r['name'] for r in result['records'] if r.get('addr') is not None]
        if found_regions:
            print(f"  EIS regions found: {', '.join(found_regions)}")
        else:
            print("  WARNING: No region records found in EIS")

        return result

    # ========================================================================
    # Capability Bits / Feature Bits
    # ========================================================================

    # Capability bits are at flash offset 0x1900, 64 bytes.
    # These contain engine feature flags that can be read and modified.
    # The loader's ModifySoundFileBit (RVA 0x364D8) toggles individual bits.
    CAP_BITS_ADDR = 0x1900
    CAP_BITS_SIZE = 64

    def read_capability_bits(self):
        """Read capability bits from engine flash at 0x1900 (64 bytes).

        These bits control engine features and are part of the sound file.
        Returns bytes or None on failure.
        """
        print(f"  Reading capability bits at 0x{self.CAP_BITS_ADDR:04X} "
              f"({self.CAP_BITS_SIZE} bytes)...")
        data = self.read_raw(self.CAP_BITS_ADDR, self.CAP_BITS_SIZE)
        if data:
            print(f"  Read {len(data)} bytes")
        return data

    def read_eis_dsp_info(self):
        """Read EIS and return DSP code address/length (convenience wrapper).

        Returns (dsp_addr, dsp_max_len) or (None, None) if not found.
        """
        records = self.read_eis_records()
        return (records.get('dsp_addr'), records.get('dsp_max_len'))

    def write_chain_code(self, srec_path, dsp_addr=None, dsp_max_len=None,  # pylint: disable=too-many-locals,too-many-branches,too-many-statements,too-many-return-statements
                         assume_yes=False, confirm_cb=None):
        """Write chain/DSP code from an S-record file to engine flash.

        This mirrors the dealer loader's "Send DSP Code to Engine" function.
        The S-record file is converted to binary and written to flash at
        the DSP code address (from EIS or specified manually).

        The write process:
        1. Parse the S-record file
        2. Convert to binary
        3. Determine DSP flash address (from EIS or argument)
        4. Check that the code fits within the allocated space
        5. Enter fast programming mode
        6. Erase sectors covering the DSP code region
        7. Write the binary data in 256-byte blocks
        8. Verify each sector
        9. Return to normal programming mode
        10. Power cycle the engine

        Args:
            srec_path: Path to the .srec file
            dsp_addr: Flash address for DSP code (auto-detect from EIS if None)
            dsp_max_len: Max length for DSP code (auto-detect from EIS if None)
        Returns True on success.
        """
        # Parse the S-record file
        print("\n=== Chain/DSP Code Write ===")
        print(f"  S-record file: {srec_path}")

        srec = parse_srec(srec_path)
        if not srec['segments']:
            print("  ERROR: No data segments in S-record file")
            return False

        print_srec_info(srec)

        # Convert to binary
        base_addr, code_data = srec_to_binary(srec)
        code_size = len(code_data)
        print(f"  Binary image: 0x{base_addr:06X} - 0x{base_addr + code_size - 1:06X}")
        print(f"  Code size: {code_size} bytes (0x{code_size:06X})")

        # Determine DSP flash address
        if dsp_addr is None:
            print("\n  Reading EIS to find DSP code address...")
            dsp_addr, dsp_max_len = self.read_eis_dsp_info()

        if dsp_addr is None:
            print("  ERROR: Could not determine DSP code flash address")
            print("  Use --dsp-addr to specify it manually")
            return False

        # Set bootloader protection so _validate_flash_range can verify
        # we stay within the DSP region. We pass allow_bootloader=True
        # to erase_at_addr/write_raw below because we intentionally write
        # to the DSP region — but we verify the range first.
        if not hasattr(self, '_protected_bootloader_start') or \
           self._protected_bootloader_start is None:
            self.set_bootloader_protection(dsp_addr, dsp_addr + dsp_max_len)

        # The S-record base address is relative to the DSP code region
        # The actual flash address is dsp_addr + srec_base_addr
        flash_base = dsp_addr + base_addr
        flash_end = flash_base + code_size

        print(f"\n  Flash write range: 0x{flash_base:06X} - 0x{flash_end:06X}")

        # Check against max length
        if dsp_max_len and code_size > dsp_max_len:
            print(f"  ERROR: Code size ({code_size}) exceeds max length ({dsp_max_len})")
            return False

        # Verify the write range is entirely within the DSP region.
        # This prevents a malformed S-record from writing outside the
        # DSP code area into the bootloader or other critical regions.
        bl_start = getattr(self, '_protected_bootloader_start', dsp_addr)
        bl_end = getattr(self, '_protected_bootloader_end', dsp_addr + dsp_max_len)
        if flash_base < bl_start or flash_end > bl_end:
            print(f"  ERROR: Write range 0x{flash_base:06X}-0x{flash_end:06X} "
                  f"extends outside DSP region 0x{bl_start:06X}-0x{bl_end:06X}")
            print("  REFUSING — S-record data would write outside the DSP code area")
            return False

        # Determine which sectors to erase/write
        # Use the same sector layout as sound files
        sectors = self._get_sectors_for_range(flash_base, flash_end)
        print(f"  Sectors to write: {len(sectors)}")
        for s_addr in sectors:
            print(f"    0x{s_addr:06X}")

        # Confirm
        print(f"\n*** ABOUT TO WRITE {code_size} bytes OF DSP CODE TO FLASH ***")
        print(f"  Flash range: 0x{flash_base:06X} - 0x{flash_end:06X}")
        print(f"  This will erase {len(sectors)} sector(s).")
        print("  Do not remove power or the engine from the track!")
        if not assume_yes and not self._ask_yes(confirm_cb=confirm_cb):
            print("Aborted.")
            return False

        # Enter fast programming mode
        if not self.enter_fast_mode():
            print("  Warning: could not enter fast programming mode")

        # Write each sector
        for sector_addr in sectors:
            # Determine sector boundaries
            sector_start, sector_end = self._sector_bounds(sector_addr)

            # Data to write for this sector
            data_start = max(sector_start, flash_base)
            data_end = min(sector_end, flash_end)

            if data_start >= data_end:
                print(f"\n  Sector 0x{sector_addr:06X}: no data in range, skipping erase/write")
                continue

            # Read-modify-write: erase granularity covers the whole sector,
            # which can contain other regions (e.g. Engine Data @0xFA0000
            # and DCC_CV @0xFA4000 share sector 0xFA0000 with the DSP
            # region). Preserve everything outside the write range.
            print(f"\n  Sector at 0x{sector_addr:06X} ({sector_end - sector_start} bytes)...")
            print("    Reading current sector contents...")
            existing = self.read_raw(sector_start, sector_end - sector_start)
            if existing is None or len(existing) != sector_end - sector_start:
                print(f"  ERROR: Could not read sector 0x{sector_addr:06X}"
                      " — refusing to erase without preserving its data")
                self.enter_normal_mode()
                return False

            sector_data = bytearray(existing)
            offset = data_start - sector_start
            code_offset = data_start - flash_base
            copy_len = data_end - data_start
            sector_data[offset:offset + copy_len] = code_data[code_offset:code_offset + copy_len]

            # Erase — allow_bootloader=True because we verified the range
            # is within the DSP region above.
            if not self.erase_at_addr(sector_addr, allow_bootloader=True):
                print(f"  Erase failed at 0x{sector_addr:06X}! Aborting.")
                self.enter_normal_mode()
                return False

            # Write — allow_bootloader=True for the same reason.
            if not self.write_raw(sector_addr, bytes(sector_data),
                                  allow_bootloader=True):
                print(f"  Write failed at 0x{sector_addr:06X}! Aborting.")
                self.enter_normal_mode()
                return False

            # Verify
            if not self.verify_raw(sector_addr, bytes(sector_data)):
                print(f"  Verification failed at 0x{sector_addr:06X}! Aborting.")
                self.enter_normal_mode()
                return False

            print(f"  Sector 0x{sector_addr:06X}: OK")

        # Return to normal programming mode
        self.enter_normal_mode()

        print("\n  DSP code write complete!")
        print("  Power cycling engine...")

        # Power cycle (like the loader does)
        self.conn.send_cmd('o0')  # Power off
        time.sleep(2)
        self.conn.send_cmd('o1')  # Power on
        time.sleep(2)

        # Re-setup engine
        self.conn.send_cmd('u4')  # Engine startup
        time.sleep(1)
        self.conn.send_cmd('F0')  # Feature reset
        time.sleep(1)

        print("  Done!")
        return True

    def write_chain_zip(self, zip_path, assume_yes=False, confirm_cb=None):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements,too-many-return-statements
        """Write chain code from a .zip file containing multiple S-records.

        This mirrors the Consumer/Dealer Loader's chain file processing:
        1. Extract the zip and read filelist.txt for file order
        2. For each .srec, parse the S0 header to get the TPL value
        3. Map the TPL to the correct EIS region (DSP, FPGA, DCC_CV, etc.)
        4. Write each S-record to its corresponding EIS region

        The TPL value from the S0 header IS the EIS record type:
          TPL=2002 → DSP region (engine-hdr)
          TPL=2003 → FPGA region (mth_fpga-hdr)
          TPL=2007 → DCC_CV region (cv-hdr)
          TPL=2009 → Boiler region (boiler-hdr)
          TPL=200A → Hardware region (hardware-hdr)

        Args:
            zip_path: Path to the chain .zip file
        Returns True on success.
        """
        print("\n=== Chain Zip Write ===")
        print(f"  Zip file: {zip_path}")

        if not zipfile.is_zipfile(zip_path):
            print(f"  ERROR: Not a valid zip file: {zip_path}")
            return False

        # Detect board revision from the chain zip
        chain_rev = detect_chain_revision(zip_path)
        if chain_rev:
            print(f"  Chain file board revision: {chain_rev}")
        else:
            print("  Chain file board revision: unknown (no engine-hdr found)")

        # Read engine's PCB revision from manufacturing data
        eng_info = self.read_engine_info()
        if eng_info:
            info = parse_engine_info(eng_info)
            pcb_rev = info.get('pcb_rev', '').strip()
            if pcb_rev:
                print(f"  Engine PCB rev: {pcb_rev}")

                # Check for board revision mismatch
                if chain_rev:
                    pcb_upper = pcb_rev.upper()
                    if chain_rev == 'E' and 'E' in pcb_upper and 'F' not in pcb_upper:
                        pass  # Match
                    elif chain_rev == 'F' and 'F' in pcb_upper:
                        pass  # Match
                    elif chain_rev == 'E' and 'F' in pcb_upper:
                        print("  *** WARNING: Chain file is Rev E but engine has Rev F PCB! ***")
                        print("  *** Writing Rev E DSP code to a Rev F board may damage it! ***")
                        if not self._ask_yes("  Type 'YES' to proceed anyway: ",
                                             confirm_cb):
                            print("Aborted.")
                            return False
                    elif chain_rev == 'F' and 'E' in pcb_upper and 'F' not in pcb_upper:
                        print("  *** WARNING: Chain file is Rev F but engine has Rev E PCB! ***")
                        print("  *** Writing Rev F DSP code to a Rev E board may damage it! ***")
                        if not self._ask_yes("  Type 'YES' to proceed anyway: ",
                                             confirm_cb):
                            print("Aborted.")
                            return False
            else:
                print("  Engine PCB rev: (empty - cannot verify board revision)")
                if chain_rev:
                    print("  *** WARNING: Cannot verify board revision match! ***")
        else:
            print("  Could not read engine info for PCB rev check")

        # TPL value → EIS region key prefix (from loader IL analysis)
        # The EIS record type IS the TPL value from the S0 header.
        tpl_to_region = {
            '2002': ('DSP', 'dsp'),
            '2003': ('FPGA', 'fpga'),
            '2007': ('DCC_CV', 'dcc_cv'),
            '2009': ('Boiler', 'boiler'),
            '200A': ('Hardware', 'hardware'),
        }

        # Read EIS to get region addresses
        print("  Reading EIS to get region addresses...")
        eis_records = self.read_eis_records()
        if not eis_records or not eis_records.get('records'):
            print("  ERROR: Could not read EIS records")
            return False

        # Build region address map from EIS
        region_addrs = {}
        for rec in eis_records['records']:
            if rec.get('addr') is not None and rec.get('max_len') is not None:
                if rec['max_len'] > 0:  # Skip boundary markers
                    region_addrs[rec['type']] = (rec['addr'], rec['max_len'], rec['name'])

        print("  EIS regions:")
        for rtype, (addr, max_len, name) in sorted(region_addrs.items()):
            print(f"    0x{rtype:04X} {name}: 0x{addr:06X}, {max_len} bytes")

        # Extract zip to temp directory
        with tempfile.TemporaryDirectory(prefix='mth_chain_') as tmpdir:
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(tmpdir)

            # Read filelist.txt for file order
            filelist_path = os.path.join(tmpdir, 'filelist.txt')
            if os.path.exists(filelist_path):
                with open(filelist_path, 'r', encoding='utf-8') as f:
                    file_list = [line.strip() for line in f if line.strip()]
                print(f"  File list ({len(file_list)} files):")
                for fname in file_list:
                    print(f"    {fname}")
            else:
                # No filelist.txt — use all .srec files in the zip
                file_list = sorted([f for f in os.listdir(tmpdir)
                                    if f.endswith('.srec')])
                print(f"  No filelist.txt found, using {len(file_list)} .srec files")

            if not file_list:
                print("  ERROR: No S-record files found in zip")
                return False

            # Parse each S-record's S0 header to get TPL and map to region
            chain_files = []
            for fname in file_list:
                fpath = os.path.join(tmpdir, fname)
                if not os.path.exists(fpath):
                    print(f"  WARNING: File not found: {fname}, skipping")
                    continue

                tpl = parse_s0_header_tpl(fpath)
                if tpl is None:
                    print(f"  WARNING: Could not parse TPL from {fname}, skipping")
                    continue

                region_info = tpl_to_region.get(tpl)
                if region_info is None:
                    print(f"  WARNING: Unknown TPL={tpl} in {fname}, skipping")
                    continue

                region_name, _key_prefix = region_info
                eis_type = int(tpl, 16)

                if eis_type not in region_addrs:
                    print(f"  WARNING: EIS has no region for TPL={tpl} ({region_name}),"
                          f" skipping {fname}")
                    continue

                addr, max_len, _eis_name = region_addrs[eis_type]
                chain_files.append({
                    'filename': fname,
                    'path': fpath,
                    'tpl': tpl,
                    'region_name': region_name,
                    'eis_type': eis_type,
                    'addr': addr,
                    'max_len': max_len,
                })

                print(f"  {fname}: TPL={tpl} -> {region_name} "
                      f"at 0x{addr:06X} ({max_len} bytes)")

            if not chain_files:
                print("  ERROR: No valid chain files to write")
                return False

            # Confirm before writing
            print(f"\n*** ABOUT TO WRITE {len(chain_files)} CHAIN FILES ***")
            for cf in chain_files:
                print(f"  {cf['filename']} -> {cf['region_name']} "
                      f"at 0x{cf['addr']:06X}")
            print("  Do not remove power or the engine from the track!")
            if not assume_yes and not self._ask_yes(confirm_cb=confirm_cb):
                print("Aborted.")
                return False

            # Set bootloader protection for the DSP region
            dsp_info = region_addrs.get(0x2002)
            if dsp_info:
                self.set_bootloader_protection(dsp_info[0],
                                               dsp_info[0] + dsp_info[1])

            # Enter fast programming mode
            if not self.enter_fast_mode():
                print("  Warning: could not enter fast programming mode")

            # Parse all chain files first, then merge writes per erase
            # sector. Multiple EIS regions share one erase sector (e.g.
            # Engine Data @0xFA0000, DCC_CV @0xFA4000, and DSP @0xFB0000
            # all live in sector 0xFA0000-0xFC0000), so each file can't be
            # written with its own erase — the second erase would destroy
            # the first file's data. Read-modify-write per sector also
            # preserves regions the chain zip doesn't touch (Engine Data).
            parsed_files = []
            for cf in chain_files:
                srec = parse_srec(cf['path'])
                if not srec['segments']:
                    print(f"  ERROR: No data segments in {cf['filename']}")
                    break

                base_addr, code_data = srec_to_binary(srec)
                code_size = len(code_data)
                flash_base = cf['addr'] + base_addr
                flash_end = flash_base + code_size

                print(f"  {cf['filename']}: {code_size} bytes -> "
                      f"0x{flash_base:06X}-0x{flash_end:06X}")

                if code_size > cf['max_len']:
                    print(f"  ERROR: Code size ({code_size}) exceeds "
                          f"max length ({cf['max_len']})")
                    break

                parsed_files.append({
                    'cf': cf,
                    'flash_base': flash_base,
                    'flash_end': flash_end,
                    'code_data': code_data,
                })

            if len(parsed_files) != len(chain_files):
                print("\n  Chain write FAILED!")
                self.enter_normal_mode()
                return False

            # Group writes by sector: sector_addr -> list of
            # (offset_in_sector, bytes, filename, is_dsp)
            sector_plans = {}
            for pf in parsed_files:
                cf = pf['cf']
                for sector_addr in self._get_sectors_for_range(
                        pf['flash_base'], pf['flash_end']):
                    s_start, s_end = self._sector_bounds(sector_addr)
                    lo = max(s_start, pf['flash_base'])
                    hi = min(s_end, pf['flash_end'])
                    if lo >= hi:
                        continue
                    sector_plans.setdefault(sector_addr, []).append((
                        lo - s_start,
                        pf['code_data'][lo - pf['flash_base']:
                                        hi - pf['flash_base']],
                        cf['filename'],
                        cf['eis_type'] == 0x2002,
                    ))

            print(f"  Erase sectors affected: "
                  f"{', '.join(f'0x{a:06X}' for a in sorted(sector_plans))}")

            # Write each sector: read existing content, overlay chain data,
            # erase, write back, verify
            success = True
            for sector_addr in sorted(sector_plans):
                parts = sector_plans[sector_addr]
                s_start, s_end = self._sector_bounds(sector_addr)
                sector_size = s_end - s_start
                is_dsp = any(p[3] for p in parts)
                names = ', '.join(sorted({p[2] for p in parts}))

                print(f"\n  --- Sector 0x{sector_addr:06X} "
                      f"({sector_size} bytes): {names} ---")

                # Read current sector to preserve untouched regions
                print("    Reading current sector contents...")
                existing = self.read_raw(s_start, sector_size)
                if existing is None or len(existing) != sector_size:
                    print(f"    ERROR: Could not read sector 0x{sector_addr:06X}"
                          " — refusing to erase without preserving its data")
                    success = False
                    break

                # Persist the pre-erase image — if power dies mid-write,
                # the untouched regions (Engine Data, gaps) are only in
                # RAM otherwise.
                bak = f"{zip_path}.sector-{sector_addr:06X}-recovery.bin"
                try:
                    with open(bak, 'wb') as bf:
                        bf.write(existing)
                    print(f"    Pre-erase backup: {bak}")
                except OSError as exc:
                    print(f"    WARNING: could not save backup ({exc})")

                sector_data = bytearray(existing)
                for off, chunk, _fname, _dsp in parts:
                    sector_data[off:off + len(chunk)] = chunk

                if not self.erase_at_addr(sector_addr,
                                          allow_bootloader=is_dsp):
                    print(f"    Erase failed at 0x{sector_addr:06X}!")
                    success = False
                    break

                if not self.write_raw(sector_addr, bytes(sector_data),
                                      allow_bootloader=is_dsp):
                    print(f"    Write failed at 0x{sector_addr:06X}!")
                    success = False
                    break

                if not self.verify_raw(sector_addr, bytes(sector_data)):
                    print(f"    Verification failed at 0x{sector_addr:06X}!")
                    success = False
                    break

                print(f"    Sector 0x{sector_addr:06X}: OK")

            if success:
                for pf in parsed_files:
                    print(f"  {pf['cf']['filename']}: OK")

            # Return to normal programming mode
            self.enter_normal_mode()

            if not success:
                print("\n  Chain write FAILED!")
                return False

            # Power cycle the engine
            print("\n  Chain write complete! Power cycling engine...")
            self.conn.send_cmd('o0')  # Power off
            time.sleep(2)
            self.conn.send_cmd('o1')  # Power on
            time.sleep(2)

            # Re-setup engine
            self.conn.send_cmd('u4')  # Engine startup
            time.sleep(1)
            self.conn.send_cmd('F0')  # Feature reset
            time.sleep(1)

            print("  Done!")
            return True

    def _get_sectors_for_range(self, start_addr, end_addr):
        """Get list of sector start addresses that cover the given range."""
        sectors = []
        addr = 0x000000
        while addr < end_addr:
            sector_start, sector_end = self._sector_bounds(addr)
            if sector_start < end_addr and sector_end > start_addr:
                sectors.append(addr)
            addr = sector_end
        return sectors

    def _sector_bounds(self, sector_addr):
        """Get (start, end) for a sector given its start address."""
        if sector_addr == 0x000000:
            return (0x000000, 0x004000)
        if sector_addr == 0x004000:
            return (0x004000, 0x006000)
        if sector_addr == 0x006000:
            return (0x006000, 0x008000)
        if sector_addr == 0x008000:
            return (0x008000, 0x80000)
        return (sector_addr, sector_addr + 0x20000)

    # ========================================================================
    # Comprehensive engine info dump
    # ========================================================================

    def read_all_engine_data(self):  # pylint: disable=too-many-locals,too-many-statements
        """Read all available engine data and return as a dict.

        This mirrors what the dealer loader displays when it reads an engine.
        Uses flash reads for static parameters (available through WTIU).
        Runtime data (odometer, chronometer, volumes) requires V-commands
        which are not supported through the WTIU bridge — those are noted
        as unavailable.
        """
        result = {}

        # Flash header (0x00-0xFF) — contains static engine parameters
        print("\n  --- Flash Header (static parameters) ---")
        header = self.read_raw(0x000000, 0x100)
        if header:
            result['flash_header'] = header
            # Parse key fields from the .mth header (big-endian 16-bit)
            speed_factor = (header[0x04] << 8) | header[0x05]
            counts_per_rev = (header[0x06] << 8) | header[0x07]
            scale_factor = (header[0x08] << 8) | header[0x09]
            interrupt_rate = (header[0x0A] << 8) | header[0x0B]
            dcs_num_stored = (header[0x0C] << 8) | header[0x0D]
            type_byte = header[0x23]
            sound_set = header[0x22]
            counts_chuff = (header[0x18] << 8) | header[0x19]

            # Derived values
            clock_hz = 1000000 / interrupt_rate if interrupt_rate else 0
            gear_ratio = counts_per_rev / 48 if counts_per_rev else 0

            print(f"  Speed factor:      0x{speed_factor:04X} ({speed_factor})")
            print(f"  Counts/rev:        0x{counts_per_rev:04X} ({counts_per_rev})"
                  f"  [gear ratio: {gear_ratio:.1f}]")
            print(f"  Scale factor:      0x{scale_factor:04X} ({scale_factor})")
            print(f"  Interrupt rate:    0x{interrupt_rate:04X} ({interrupt_rate})"
                  f"  [{clock_hz:.1f} Hz]")
            print(f"  DCS addr (stored): {dcs_num_stored} (runtime: set by DCS)")
            print(f"  Engine type:       {engine_type_string(type_byte)} (0x{type_byte:02X})")
            print(f"  Sound set ID:      0x{sound_set:02X}")
            print(f"  Counts/chuff:      0x{counts_chuff:04X} ({counts_chuff})")

            # Volumes (from header, big-endian)
            for label, offset in [('Master', 0x0E), ('Engine', 0x10),
                                  ('Accent', 0x12), ('Horn', 0x14),
                                  ('Bell', 0x16)]:
                vol = (header[offset] << 8) | header[offset+1]
                pct = vol * 100 // 327 if vol <= 327 else 100
                print(f"  {label:10s} volume: {vol:5d} ({pct}%)")

            result['static_params'] = {
                'speed_factor': speed_factor,
                'counts_per_rev': counts_per_rev,
                'scale_factor': scale_factor,
                'interrupt_rate': interrupt_rate,
                'engine_type': engine_type_string(type_byte),
                'sound_set_id': sound_set,
                'counts_chuff': counts_chuff,
            }

        # Engine type from q1E80 (second engine type at RAM 0x200)
        print("\n  --- Engine Type Query (q1E80) ---")
        resp = self.get_engine_type()
        if resp:
            result['engine_type_query'] = resp.strip()

        # EIS sector
        print("\n  --- EIS Sector (0x004000) ---")
        eis = self.read_raw(0x004000, 0x100)
        if eis:
            eis_parsed = parse_mfg_data(eis)
            result['eis'] = eis_parsed
            if eis_parsed:
                for k, v in eis_parsed.items():
                    print(f"  {k}: {v}")

        # Engine info
        print("\n  --- Engine Info (0x001DD2) ---")
        eng_info = self.read_engine_info()
        if eng_info:
            info_parsed = parse_engine_info(eng_info)
            result['engine_info'] = info_parsed
            if info_parsed:
                for k, v in info_parsed.items():
                    if v:
                        print(f"  {k}: {v}")

        # Flash size
        print("\n  --- Flash Size Detection ---")
        result['flash_size'] = self.detect_flash_size()

        # DSP version (may not work through WTIU)
        print("\n  --- DSP Code Version ---")
        dsp = self.read_dsp_version()
        if dsp:
            result['dsp_version'] = dsp

        # Runtime data note
        print("\n  --- Runtime Data (odometer, chronometer) ---")
        print("  NOTE: Runtime RAM access (V-commands) is not supported")
        print("  through the WTIU bridge. These require a direct serial")
        print("  connection to the engine.")

        return result

    def print_report(self, file=None):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
        """Read and display a formatted report of all engine data.

        This mirrors the dealer loader's "View Mfg Data Report" function.
        Displays engine info, EIS fields, capability bits, loader data,
        and flash size in a clean, labeled format.
        """
        if file is None:
            file = sys.stdout
        print("=" * 60, file=file)
        print("  MTH Engine Manufacturing Data Report", file=file)
        print("=" * 60, file=file)

        # Engine info (extended — includes customer address fields)
        print("\n--- Engine Info (0x001DD2) ---", file=file)
        eng_info = self.read_engine_info(extended=True)
        if eng_info:
            info = parse_engine_info(eng_info)
            print(f"  Cab Number:       {info.get('cab_number', '')}", file=file)
            print(f"  Road Name:        {info.get('road_name', '')}", file=file)
            print(f"  Engine Name:      {info.get('engine_name', '')}", file=file)
            cp = info.get('composite_parts', {})
            if cp:
                print(f"  Dealer Number:    {cp.get('dealer_number', '')}", file=file)
                # Use YYMMDD field as the date (composite field date format
                # varies between dealer loader and upgrade tools)
                ymd = info.get('date_yymmdd', '')
                if len(ymd) == 6:
                    comp_date = f"{ymd[2:4]}/{ymd[4:6]}/{ymd[0:2]}"
                else:
                    comp_date = ''
                print(f"  Composite Date:   {comp_date}", file=file)
                print(f"  MTH Product #:    {cp.get('comp_product', '')}", file=file)
                print(f"  Serial+1:         {cp.get('comp_serial', '')}", file=file)
            print(f"  Date (YYMMDD):    {info.get('date_yymmdd', '')}", file=file)
            print(f"  DSP Filename:     {info.get('dsp_filename', '')}", file=file)
            print(f"  PCB Rev:          {info.get('pcb_rev', '')}", file=file)
            print(f"  Sound Filename:   {info.get('sound_filename', '')}", file=file)
            print(f"  MTH Product #:    {info.get('mth_product_num', '')}", file=file)
            print(f"  Phone Number:     {info.get('phone_number', '')}", file=file)
            print(f"  Customer Name:    {info.get('customer_name', '')}", file=file)
            if 'address1' in info:
                print(f"  Address 1:        {info.get('address1', '')}", file=file)
                print(f"  Address 2:        {info.get('address2', '')}", file=file)
                print(f"  City:             {info.get('city', '')}", file=file)
                print(f"  State:            {info.get('state', '')}", file=file)
                print(f"  Zip:              {info.get('zip', '')}", file=file)
                print(f"  Email:            {info.get('email', '')}", file=file)
        else:
            print("  (could not read)", file=file)

        # EIS sector
        print("\n--- EIS Sector (0x004000) ---", file=file)
        eis = self.read_raw(0x004000, 0x100)
        if eis:
            if eis[0:4] == b'EIS!':
                print("  Header:           EIS!", file=file)
                eis_len = struct.unpack_from('<I', eis, 0x0C)[0]
                print(f"  EIS Length:       {eis_len} bytes", file=file)
                dsp_addr, dsp_max = struct.unpack_from('<II', eis, 0x10)
                if 0 < dsp_addr < 0x800000:
                    print(f"  DSP/Flash Addr:   0x{dsp_addr:06X}", file=file)
                    print(f"  DSP/Flash Max:    0x{dsp_max:06X} ({dsp_max} bytes)", file=file)
                etype = engine_type_string(eis[5])
                print(f"  Engine Type Byte: 0x{eis[5]:02X} ({etype})", file=file)
            else:
                print(f"  Header:           {eis[0:4].hex()} (not EIS!)", file=file)
        else:
            print("  (could not read)", file=file)

        # Capability bits
        print("\n--- Capability Bits (0x1900) ---", file=file)
        cap = self.read_capability_bits()
        if cap:
            labeled = decode_capability_bits(cap)
            if labeled:
                print("  Labeled feature bits:", file=file)
                for addr, mask, label in labeled:
                    print(f"    0x{addr:04X} bit 0x{mask:02X}: {label}", file=file)
            # Also show raw non-zero/non-FF bytes
            has_set = False
            for i, b in enumerate(cap):
                if b not in (0, 0xFF):
                    bits = []
                    for bit in range(8):
                        if b & (1 << bit):
                            bits.append(str(bit))
                    bit_str = ', '.join(bits)
                    print(f"  Byte {i:2d} (0x{0x1900+i:04X}):"
                          f" 0x{b:02X} = bits {bit_str}", file=file)
                    has_set = True
            if not has_set and not labeled:
                print("  (all bytes are 0x00 or 0xFF — no feature bits set)", file=file)
        else:
            print("  (could not read)", file=file)

        # Loader data
        print("\n--- Loader Data (0x1950) ---", file=file)
        # Read from flash for the loader data
        loader_raw = self.read_raw(0x1950, 128)
        if loader_raw:
            ld = parse_loader_data(loader_raw)
            if ld:
                print(f"  PC Name:          {ld.get('pc_name', '')}", file=file)
                print(f"  Date:             {ld.get('date', '')}", file=file)
                print(f"  Time:             {ld.get('time', '')}", file=file)
                print(f"  Loader Version:   {ld.get('version', '')}", file=file)
            else:
                print("  (no loader data stamped)", file=file)
        else:
            print("  (could not read)", file=file)

        # Flash size
        print("\n--- Flash Size ---", file=file)
        flash_size = self.detect_flash_size()
        if flash_size:
            print(f"  Flash Size:       {flash_size} bytes ({flash_size // 1024} KB)", file=file)
        else:
            print("  (could not detect)", file=file)

        print("\n" + "=" * 60, file=file)


# ============================================================================
# Manufacturing Data Parser
# ============================================================================

def parse_mfg_data(data):
    """Parse EIS manufacturing data bytes (from 0x004000) into a dictionary.

    Based on actual flash dump and ReadEISFields IL analysis:
    - 0x00: "EIS!" header magic (4 bytes)
    - 0x04: Engine type/version info
    - 0x08: Field1 (LE32) - engine type/version
    - 0x0C: Field2 (LE32) - engine ID
    - 0x10: Field3 (8 bytes) - config data
    - 0x18: EIS Length (4x LE16 combined)
    - 0x18-0x5F: Configuration records (12-byte each)
    - 0x60+: Erased flash (0xFF)
    """
    if data is None or len(data) < 32:
        return {}

    result = {}

    # Header magic
    header = data[0:4]
    result['header'] = header.decode('ascii', errors='replace')
    result['is_eis'] = header == b'EIS!'

    # Engine type (from q1E80 response, also at offset 0x05)
    result['engine_type_byte'] = data[5]

    # Fields from ReadEISFields IL
    result['field1_0x08'] = struct.unpack_from('<I', data, 0x08)[0]
    result['field2_0x0C'] = struct.unpack_from('<I', data, 0x0C)[0]
    result['field3_0x10'] = struct.unpack_from('<Q', data, 0x10)[0]

    # ASCII string at 0x14 (2 bytes)
    ascii_14 = data[0x14:0x16]
    result['ascii_0x14'] = ascii_14.decode('ascii', errors='replace')

    # Find all ASCII strings (2+ printable chars)
    strings = []
    i = 0
    while i < len(data):
        if 32 <= data[i] < 127:
            s = b''
            start = i
            while i < len(data) and 32 <= data[i] < 127:
                s += bytes([data[i]])
                i += 1
            if len(s) >= 2:
                strings.append((start, s.decode('ascii', errors='replace')))
        else:
            i += 1
    result['_strings'] = strings

    # Count configuration records (12-byte records starting at 0x18)
    records = []
    for off in range(0x18, len(data), 12):
        rec = data[off:off+12]
        if rec == b'\xFF' * 12:
            break
        if all(b in (0x00, 0x20, 0x08) or 32 <= b < 127 or b in (0xFA, 0xFB, 0xFC) for b in rec):
            records.append((off, rec))
    result['_records'] = records
    result['record_count'] = len(records)

    return result


# ============================================================================
# Loader Data Stamping
# ============================================================================

# Flash offset where the loader stamps its identification data.
# Derived from InsertLoaderData (RVA 0x317C8): hex string index 12960 / 2 = 0x1950.
LOADER_DATA_OFFSET = 0x1950
LOADER_DATA_SIZE = 128  # Reserve 128 bytes for loader data stamp
DEFAULT_LOADER_VERSION = "MTH_DCS_Loader_V2.0_betaP"

def insert_loader_data(flash_data, loader_version=None, pc_name=None,
                       timestamp=None):
    """Stamp loader identification data into a flash image.

    Mirrors the dealer loader's InsertLoaderData (RVA 0x317C8) method.
    Writes the following at flash offset 0x1950:
      - PC name (computer name, max 9 chars, space-padded)
      - Date (MM/DD/YY format)
      - Time (HH:MM:SS format)
      - Loader version string

    The loader uses this to track which PC and loader version last
    programmed the engine.

    Args:
        flash_data: bytearray or bytes of the flash image
        loader_version: Version string (default: DEFAULT_LOADER_VERSION)
        pc_name: PC name (default: auto-detect via socket.gethostname())
        timestamp: datetime object (default: now)
    Returns:
        bytearray with loader data stamped in
    """
    if loader_version is None:
        loader_version = DEFAULT_LOADER_VERSION
    if pc_name is None:
        try:
            pc_name = socket.gethostname()
        except Exception:  # pylint: disable=broad-exception-caught
            pc_name = "UNKNOWN"
    if timestamp is None:
        timestamp = datetime.datetime.now()

    # Truncate/pad PC name to 9 chars (matching loader behavior)
    pc_name = pc_name[:9].ljust(9, ' ')

    # Build the stamp string: PC name(9) + date(8) + time(8) + version
    date_str = timestamp.strftime("%m/%d/%y")
    time_str = timestamp.strftime("%H:%M:%S")
    stamp = f"{pc_name}{date_str}{time_str}{loader_version}"

    data = bytearray(flash_data)

    # Write the stamp at the loader data offset
    stamp_bytes = stamp.encode('ascii', errors='replace')
    for i, b in enumerate(stamp_bytes):
        if LOADER_DATA_OFFSET + i >= len(data):
            break
        data[LOADER_DATA_OFFSET + i] = b

    return data


def parse_loader_data(flash_data):
    """Parse loader data from a flash image.

    Reads the stamp at offset 0x1950 and returns the components.
    Returns dict with keys: 'pc_name', 'date', 'time', 'version', 'raw'
    Returns empty dict if no loader data found.
    """
    if len(flash_data) < LOADER_DATA_OFFSET + 10:
        return {}

    raw = flash_data[LOADER_DATA_OFFSET:LOADER_DATA_OFFSET + LOADER_DATA_SIZE]
    # Find end of stamp (first 0xFF or non-printable after printable data)
    end = 0
    for i, b in enumerate(raw):
        if b == 0xFF or (b < 32 and b != 0):
            end = i
            break
        end = i + 1

    stamp = raw[:end].decode('ascii', errors='replace').strip()
    if not stamp:
        return {}

    # Try to parse the stamp components
    # Format: PCNAME(9)MM/DD/YY(8)HH:MM:SS(8)VERSION(rest)
    result = {'raw': stamp}
    if len(stamp) >= 25:
        result['pc_name'] = stamp[:9].strip()
        result['date'] = stamp[9:17]
        result['time'] = stamp[17:25]
        result['version'] = stamp[25:].strip()
    else:
        result['pc_name'] = stamp

    return result


# ============================================================================
# Feature Bit Modification
# ============================================================================

# Capability/feature bits are at flash offset 0x1900, 64 bytes.
# The loader's ModifySoundFileBit (RVA 0x364D8) toggles individual bits
# in this region of the sound file.
CAP_BITS_OFFSET = 0x1900
CAP_BITS_LEN = 64

# Softkey / feature bit map from Mark DiVecchio's ADPCM Softkeys editor
# (Edit_the_Softkeys.cpp). Key: (flash_offset, bitmask) -> label.
SOFTKEY_BIT_MAP = {
    # Engine Sounds (S01-S10)
    (0x1906, 0x04): 'S01 (Engine Sound 1)',
    (0x1906, 0x08): 'S02 (Engine Sound 2)',
    (0x1906, 0x10): 'S03 (Engine Sound 3)',
    (0x1906, 0x20): 'S04 (Engine Sound 4)',
    (0x1906, 0x40): 'S05 (Engine Sound 5)',
    (0x1906, 0x80): 'S06 (Engine Sound 6)',
    (0x1907, 0x01): 'S07 (Engine Sound 7)',
    (0x1907, 0x02): 'S08 (Engine Sound 8)',
    (0x1907, 0x04): 'S09 (Engine Sound 9)',
    (0x1907, 0x08): 'S10 (Engine Sound 10)',
    # Idle Sounds (I01-I08)
    (0x1909, 0x08): 'I01 (Idle Sound 1)',
    (0x1909, 0x10): 'I02 (Idle Sound 2)',
    (0x1909, 0x20): 'I03 (Idle Sound 3)',
    (0x1909, 0x40): 'I04 (Idle Sound 4)',
    (0x1909, 0x80): 'I05 (Idle Sound 5)',
    (0x190A, 0x01): 'I06 (Idle Sound 6)',
    (0x190A, 0x02): 'I07 (Idle Sound 7)',
    (0x190A, 0x04): 'I08 (Idle Sound 8)',
    (0x190A, 0x20): 'Cab Chat FCH',
    # Sound features
    (0x190B, 0x02): 'Extended Startup SSU',
    (0x190B, 0x04): 'Extended Shutdown SSD',
    (0x190B, 0x40): 'Forward Sound SFS',
    (0x190B, 0x80): 'Reverse Sound SRS',
    (0x190C, 0x01): 'Alternate Horn SAH (n243)',
    (0x190C, 0x02): 'Xing Signal SXS (n42)',
    (0x190C, 0x08): 'Proto Whistle SPW',
    (0x190C, 0x10): 'Smoking Whistle FSW',
    (0x190C, 0x20): 'Swinging Bell FSB',
    (0x1912, 0x40): 'Clickity Clack FCC',
    (0x1916, 0x20): 'Boiler Startup & Release FBS & FPR',
    # Coors Door (two bytes must be set together)
    (0x191E, 0x80): 'Coors Door Open/Close (n121/n122)',
    (0x191F, 0x03): 'Coors Door Open/Close (n121/n122)',
    # Lights
    (0x190F, 0x20): 'Interior Light on Interior',
    (0x190F, 0x40): 'Ditch Light Menu LDI',
    (0x190F, 0x80): 'Mars Light on Mars LMA',
    (0x1910, 0x01): 'Beacon Light LBE',
    (0x1910, 0x04): 'Marker LED LMK',
    (0x1910, 0x08): 'Marker Light on Interior',
    (0x1910, 0x10): 'Headlight on Interior LHD',
    (0x1910, 0x20): 'Number Boards on Mars',
    (0x1910, 0x40): 'Track Inspection Light on Ditch LTI',
    (0x1910, 0x80): 'Number Boards on Ditch',
    (0x1911, 0x01): 'Firebox Glow on Interior',
    (0x1911, 0x02): 'Marker Light on Ditch',
    (0x1911, 0x04): 'Running Lights on Mars and Ditch LRL',
    (0x1911, 0x08): 'Interior Light on Mars',
    (0x1911, 0x10): 'Interior Light on Ditch',
    (0x1911, 0x20): 'Number Boards on Mars and Ditch',
    (0x1911, 0x40): 'Firebox Glow on Mars',
    (0x1911, 0x80): 'Firebox Glow on Ditch',
    (0x1912, 0x01): 'Marker Light on Mars',
    (0x1912, 0x08): 'Aux Light 1 on Interior LA1',
    (0x1912, 0x10): 'Aux Light 2 on Mars LA2',
    (0x1912, 0x20): 'Aux Light 3 on Ditch LA3',
}


def label_capability_bit(flash_offset, bitmask):
    """Return a human-readable label for a capability bit, or None if unknown."""
    return SOFTKEY_BIT_MAP.get((flash_offset, bitmask))


def decode_capability_bits(cap_data):
    """Decode capability bit bytes into a list of (offset, bitmask, label) tuples
    for all set bits that have known labels."""
    results = []
    for i, b in enumerate(cap_data):
        if b in (0x00, 0xFF):
            continue
        for bit in range(8):
            mask = 1 << bit
            if b & mask:
                addr = CAP_BITS_OFFSET + i
                label = label_capability_bit(addr, mask)
                if label:
                    results.append((addr, mask, label))
    return results

def modify_sound_file_bit(flash_data, byte_index, bit_value, set_true=True):
    """Modify a feature bit in a sound file image.

    Mirrors the dealer loader's ModifySoundFileBit (RVA 0x364D8).
    The feature bits are at flash offset 0x1900 (64 bytes).

    Args:
        flash_data: bytearray or bytes of the flash/sound image
        byte_index: Index within the capability bits region (0-63)
        bit_value: Bit to set/clear (1, 2, 4, 8, 16, 32, 64, 128)
        set_true: If True, set the bit; if False, clear it
    Returns:
        bytearray with the modified bit
    """
    if byte_index < 0 or byte_index >= CAP_BITS_LEN:
        raise ValueError(f"byte_index must be 0-{CAP_BITS_LEN-1}, got {byte_index}")
    if bit_value < 0 or bit_value > 255:
        raise ValueError(f"bit_value must be 0-255, got {bit_value}")

    data = bytearray(flash_data)
    offset = CAP_BITS_OFFSET + byte_index

    if offset >= len(data):
        raise ValueError(
            f"Flash data too short: offset 0x{offset:04X} beyond data length {len(data)}")

    current = data[offset]
    if set_true:
        data[offset] = current | bit_value
    else:
        data[offset] = current & (255 - bit_value)

    return data


def parse_engine_info(data):
    """Parse engine info data (from 0x001DD2).

    This is the data read by TransferMfgData in the official loader.
    All fields are space-padded ASCII (PadLeft in the loader).

    Basic layout (262 bytes, verified from actual engine data):
    - 0x00-0x1F: txtEngineCabNumber  (32 bytes, PadLeft ' ')
    - 0x20-0x3F: txtEngineRoadName   (32 bytes, PadLeft ' ')
    - 0x40-0x5F: txtEngineName       (32 bytes, PadLeft ' ')
    - 0x60-0x7F: Composite field     (32 bytes, PadLeft ' ')
      Contains: DealerNumber(6) + Year(2) + Month(2) + Day(2)
                + MTHProductNumber(7) + LastSerialNumber+1(4)
    - 0x80-0x85: Date YYMMDD         (6 bytes, PadLeft '0')
    - 0x86-0xA5: txtDSPFilename      (32 bytes, PadLeft ' ')
    - 0xA6-0xC5: txtPCBRevData       (32 bytes, PadLeft ' ')
    - 0xC6-0xE5: txtSoundFilename    (32 bytes, PadLeft ' ')
    - 0xE6-0xEC: txtMTHProductNumber (7 bytes, PadLeft '0')
    - 0xED-0xF6: txtPhoneNumber      (10 bytes, PadLeft '0')
    - 0xF7-0x105: txtCustomerName    (15 bytes, Substring of PadRight 32)

    Extended layout (from MergeMfgData RVA 0x66444, needs verification):
    - 0x106-0x125: txtAddress1       (32 bytes, PadRight ' ')
    - 0x126-0x145: txtAddress2       (32 bytes, PadRight ' ')
    - 0x146-0x165: txtCity           (32 bytes, PadRight ' ')
    - 0x166-0x185: txtState          (32 bytes, PadRight ' ')
    - 0x186-0x18C: txtZip            (7 bytes, PadLeft '0')
    - 0x18D-0x1AC: txtEmail          (32 bytes, PadRight ' ')
    """
    if data is None or len(data) < 0x60:
        return {}

    def extract_str(offset, length):
        """Extract space-padded ASCII string. Returns '' for erased flash (0xFF).
        Strips 0xFF bytes (erased flash padding) from mixed fields."""
        raw = data[offset:offset+length]
        if all(b == 0xFF for b in raw):
            return ''
        # Replace 0xFF bytes with spaces so they're treated as padding
        cleaned = bytes(b if b != 0xFF else 0x20 for b in raw)
        return cleaned.decode('ascii', errors='replace').strip()

    def extract_zero_padded(offset, length):
        """Extract zero-padded numeric string. Returns '' for erased flash (0xFF).
        Strips 0xFF bytes from mixed fields."""
        raw = data[offset:offset+length]
        if all(b == 0xFF for b in raw):
            return ''
        # Replace 0xFF bytes with '0' so they're treated as padding
        cleaned = bytes(b if b != 0xFF else 0x30 for b in raw)
        return cleaned.decode('ascii', errors='replace').lstrip('0') or '0'

    def extract_str_safe(offset, length):
        """Extract string, returning '' if offset is beyond data length."""
        if offset + length > len(data):
            return ''
        return extract_str(offset, length)

    def extract_zero_padded_safe(offset, length):
        """Extract zero-padded string, returning '' if offset is beyond data."""
        if offset + length > len(data):
            return ''
        return extract_zero_padded(offset, length)

    # Parse composite field at 0x60
    composite = extract_str(0x60, 0x20)
    composite_parts = {}
    if len(composite) >= 23:
        composite_parts = {
            'dealer_number':  composite[0:6],
            'comp_year':      composite[6:8],
            'comp_month':     composite[8:10],
            'comp_day':       composite[10:12],
            'comp_product':   composite[12:19],
            'comp_serial':    composite[19:23],
        }

    # Parse date YYMMDD at 0x80
    ymd_raw = data[0x80:0x86]
    if all(b == 0xFF for b in ymd_raw):
        ymd = ''
    else:
        # Replace any 0xFF bytes with '0' padding to keep it ASCII-safe
        ymd = bytes(b if b != 0xFF else 0x30 for b in ymd_raw)
        ymd = ymd.decode('ascii', errors='replace').lstrip('0')

    result = {
        'cab_number':        extract_str(0x00, 0x20),
        'road_name':         extract_str(0x20, 0x20),
        'engine_name':       extract_str(0x40, 0x20),
        'composite':         composite,
        'composite_parts':   composite_parts,
        'date_yymmdd':       ymd,
        'dsp_filename':      extract_str(0x86, 0x20),
        'pcb_rev':           extract_str(0xA6, 0x20),
        'sound_filename':    extract_str(0xC6, 0x20),
        'mth_product_num':   extract_zero_padded(0xE6, 0x07),
        'phone_number':      extract_zero_padded(0xED, 0x0A),
        'customer_name':     extract_str(0xF7, 0x0F),
    }

    # Parse extended customer data fields (if data is long enough)
    if len(data) >= ENG_INFO_EXTENDED_SIZE:
        result.update({
            'address1':     extract_str_safe(CUST_ADDR1_OFF, CUST_ADDR1_SIZE),
            'address2':     extract_str_safe(CUST_ADDR2_OFF, CUST_ADDR2_SIZE),
            'city':         extract_str_safe(CUST_CITY_OFF, CUST_CITY_SIZE),
            'state':        extract_str_safe(CUST_STATE_OFF, CUST_STATE_SIZE),
            'zip':          extract_zero_padded_safe(CUST_ZIP_OFF, CUST_ZIP_SIZE),
            'email':        extract_str_safe(CUST_EMAIL_OFF, CUST_EMAIL_SIZE),
        })
    elif len(data) > ENG_INFO_SIZE:
        # Partial extended data — parse what we can
        for off, size, name, zero in [
            (CUST_ADDR1_OFF, CUST_ADDR1_SIZE, 'address1', False),
            (CUST_ADDR2_OFF, CUST_ADDR2_SIZE, 'address2', False),
            (CUST_CITY_OFF,  CUST_CITY_SIZE,  'city',     False),
            (CUST_STATE_OFF, CUST_STATE_SIZE, 'state',    False),
            (CUST_ZIP_OFF,   CUST_ZIP_SIZE,   'zip',      True),
            (CUST_EMAIL_OFF, CUST_EMAIL_SIZE, 'email',    False),
        ]:
            if off + size <= len(data):
                if zero:
                    result[name] = extract_zero_padded(off, size)
                else:
                    result[name] = extract_str(off, size)

    return result

def build_engine_info(existing, **kwargs):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    """Build new engine info data (262 bytes at 0x001DD2) from existing data.

    Replaces specified fields while preserving all others.
    All text fields are space-padded (PadLeft) except product number and phone
    which are zero-padded.

    Mirrors the dealer loader's MergeMfgData (RVA 0x46538):
      - Rebuilds the composite field (0x60-0x7F) as:
        dealer(6) + YY(2) + MM(2) + DD(2) + product(7) + serial+1(4)
      - Rebuilds the YYMMDD field (0x80-0x85) with today's date
      - Increments the serial number from the existing composite field

    Keyword args (all optional):
        cab_number, road_name, engine_name, dsp_filename, pcb_rev,
        sound_filename, mth_product_num, phone_number, customer_name,
        address1, address2, city, state, zip, email,
        dealer_number (overrides existing, for composite field),
        serial_number (overrides existing, for composite field),
        stamp_date (bool, default True — stamp today's date)
    """
    if existing is None:
        existing = b'\x20' * ENG_INFO_SIZE

    data = bytearray(existing)
    # Ensure correct total length — extend to full extended size if needed
    target_size = ENG_INFO_SIZE
    # If any extended field is specified, use the extended size
    extended_keys = {'address1', 'address2', 'city', 'state', 'zip', 'email'}
    if any(kwargs.get(k) is not None for k in extended_keys):
        target_size = ENG_INFO_EXTENDED_SIZE
    if len(data) < target_size:
        data.extend(b'\x20' * (target_size - len(data)))
    elif len(data) > target_size:
        data = data[:target_size]

    def pad_left(text, field_size, pad_char=b'\x20'):
        """Pad text to field_size on the left (PadLeft / right-justified)."""
        encoded = text.encode('ascii', errors='replace')[:field_size]
        return encoded.rjust(field_size, pad_char)

    def pad_right(text, field_size):
        """Pad text to field_size on the right (PadRight / left-justified)."""
        encoded = text.encode('ascii', errors='replace')[:field_size]
        return encoded.ljust(field_size, b'\x20')

    def _pad_right_substring(text, field_size, substr_len):
        """Pad text on the right to field_size, then take first substr_len bytes."""
        encoded = text.encode('ascii', errors='replace')[:field_size]
        padded = encoded.ljust(field_size, b'\x20')
        return padded[:substr_len]

    # --- Rebuild composite field (0x60-0x7F) and YYMMDD (0x80-0x85) ---
    # Mirrors MergeMfgData: dealer(6) + YY(2) + MM(2) + DD(2) + product(7) + serial+1(4)
    # The dealer loader uses DateTime.Now for the date and increments serial.
    stamp_date = kwargs.get('stamp_date', True)
    now = datetime.datetime.now()

    # Extract existing composite field — strip leading/trailing spaces
    # like extract_str does in parse_engine_info, then slice fixed positions
    existing_composite = data[0x60:0x80].decode('ascii', errors='replace').strip()
    existing_dealer = existing_composite[0:6] if len(existing_composite) >= 6 else ''
    existing_serial = existing_composite[19:23] if len(existing_composite) >= 23 else ''

    # Allow overrides via kwargs
    dealer_number = kwargs.get('dealer_number', existing_dealer) or existing_dealer
    if not dealer_number:
        dealer_number = '000000'
    # Increment serial (Val(serial) + 1, like the loader)
    try:
        serial_int = int(existing_serial) if existing_serial else 0
    except ValueError:
        serial_int = 0
    serial_int += 1
    serial_str = str(serial_int)

    # Get product number — use kwarg, or read from 0xE6 field, or from composite
    product_num = kwargs.get('mth_product_num')
    if product_num is None:
        # Read from existing 0xE6 field (zero-padded, 7 bytes)
        product_raw = data[0xE6:0xED]
        product_num = product_raw.decode('ascii', errors='replace').lstrip('0') or '0'
        # Also check the composite field's product portion (bytes 12-18)
        if not product_num or product_num == '0':
            product_num = existing_composite[12:19] if len(existing_composite) >= 19 else ''

    # Build composite field: dealer(6) + YY(2) + MM(2) + DD(2) + product(7) + serial+1(4)
    # PadLeft each subfield like the loader does
    yy = f"{now.year}"[2:4].zfill(2)  # Mid(Year.ToString(), 3, 2) + PadLeft(2, '0')
    mm = str(now.month).zfill(2)      # Month.ToString() + PadLeft(2, '0')
    dd = str(now.day).zfill(2)        # Day.ToString() + PadLeft(2, '0')

    dealer_padded = dealer_number.encode('ascii', errors='replace')[:6].rjust(6, b'\x20')
    product_padded = product_num.encode('ascii', errors='replace')[:7].rjust(7, b'\x30')
    serial_padded = serial_str.encode('ascii', errors='replace')[:4].rjust(4, b'\x30')

    if stamp_date:
        composite = (dealer_padded + yy.encode() + mm.encode() + dd.encode()
                     + product_padded + serial_padded)
        # PadLeft the composite to 32 chars (the loader does PadLeft(32, ' '))
        composite = composite.rjust(32, b'\x20')
        data[0x60:0x80] = composite

        # Also rebuild YYMMDD at 0x80-0x85
        yymmdd = (yy + mm + dd).encode('ascii', errors='replace')
        data[0x80:0x86] = yymmdd

    # Field mappings: (offset, size, pad_mode, kwargs_key)
    # pad_mode: 'left' = PadLeft with spaces, 'zero' = PadLeft with zeros,
    #           'right' = PadRight with spaces, 'right_sub' = PadRight then Substring
    fields = [
        (0x00, 0x20, 'left',      'cab_number'),
        (0x20, 0x20, 'left',      'road_name'),
        (0x40, 0x20, 'left',      'engine_name'),
        # 0x60-0x7F: composite field — rebuilt above
        # 0x80-0x85: YYMMDD — rebuilt above
        (0x86, 0x20, 'left',      'dsp_filename'),
        (0xA6, 0x20, 'left',      'pcb_rev'),
        (0xC6, 0x20, 'left',      'sound_filename'),
        (0xE6, 0x07, 'zero',      'mth_product_num'),
        (0xED, 0x0A, 'zero',      'phone_number'),
        (0xF7, 0x0F, 'right_sub', 'customer_name'),
        # Extended customer data fields (from MergeMfgData RVA 0x66444)
        (CUST_ADDR1_OFF, CUST_ADDR1_SIZE, 'right', 'address1'),
        (CUST_ADDR2_OFF, CUST_ADDR2_SIZE, 'right', 'address2'),
        (CUST_CITY_OFF,  CUST_CITY_SIZE,  'right', 'city'),
        (CUST_STATE_OFF, CUST_STATE_SIZE, 'right', 'state'),
        (CUST_ZIP_OFF,   CUST_ZIP_SIZE,   'zero',  'zip'),
        (CUST_EMAIL_OFF, CUST_EMAIL_SIZE, 'right', 'email'),
    ]

    for offset, size, pad_mode, key in fields:
        value = kwargs.get(key)
        if value is not None:
            if pad_mode == 'left':
                data[offset:offset+size] = pad_left(value, size, b'\x20')
            elif pad_mode == 'zero':
                data[offset:offset+size] = pad_left(value, size, b'\x30')
            elif pad_mode == 'right':
                data[offset:offset+size] = pad_right(value, size)
            elif pad_mode == 'right_sub':
                # PadRight to 32, then Substring(0, 15) — but we only have
                # 15 bytes in the flash. Just pad right to 15 and truncate.
                encoded = value.encode('ascii', errors='replace')[:size]
                data[offset:offset+size] = encoded.ljust(size, b'\x20')

    return bytes(data)

# ============================================================================
# Hex Dump Utility
# ============================================================================

def hex_dump(data, offset=0, length=None, file=None):
    """Print a hex dump of data."""
    if file is None:
        file = sys.stdout
    if length is None:
        length = len(data)
    for i in range(0, min(length, len(data)), 16):
        hex_part = ' '.join(f'{data[i+j]:02X}' for j in range(min(16, length - i)))
        ascii_part = ''.join(
            chr(data[i+j]) if 32 <= data[i+j] < 127 else '.'
            for j in range(min(16, length - i))
        )
        print(f"  {offset+i:06X}: {hex_part:<48s} {ascii_part}", file=file)

# ============================================================================
# S-Record Parser (for chain code files)
# ============================================================================

def parse_s0_header(filepath):
    """Parse all fields from an S-record file's S0 header.

    The S0 header contains an ASCII string like:
        MTH=00,BRD=11,TPL=200A,VER=0          (rev E format)
        MTH=1,BRD=0xA3B,TPL=0x2002,VER=0x6d4eb3bc,VSTRING=e3.1.02  (rev F format)

    Returns a dict with keys: MTH, BRD, TPL, VER, and optionally VSTRING.
    TPL and BRD values are normalized to uppercase hex without 0x prefix.
    Returns None if no S0 record is found.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line.startswith('S0'):
                    continue
                length = int(line[2:4], 16)
                data = bytes.fromhex(line[8:8 + (length - 3) * 2])
                header = data.decode('ascii', errors='replace')
                fields = {}
                for field in header.split(','):
                    field = field.strip().strip('\t')
                    if '=' in field:
                        k, v = field.split('=', 1)
                        k = k.strip()
                        v = v.strip()
                        # Strip 0x prefix from hex values
                        if v.upper().startswith('0X'):
                            v = v[2:]
                        fields[k] = v.upper() if k in ('BRD', 'TPL') else v
                return fields
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    return None

def parse_s0_header_tpl(filepath):
    """Extract the TPL value from an S-record file's S0 header.

    Returns the TPL value as an uppercase string (e.g. "200A"), or None.
    Handles both rev E (TPL=200A) and rev F (TPL=0x200A) formats.
    """
    fields = parse_s0_header(filepath)
    if fields and 'TPL' in fields:
        return fields['TPL']
    return None

def detect_chain_revision(zip_path):
    """Detect whether a chain zip is for rev E or rev F stacker board.

    Rev E: engine-hdr has MTH=00, numeric VER (e.g. VER=3528)
    Rev F: engine-hdr has MTH=1, hex VER with VSTRING (e.g. VSTRING=e3.1.01)

    Returns 'E', 'F', or None if the engine-hdr file is not found.
    """
    if not zipfile.is_zipfile(zip_path):
        return None

    with tempfile.TemporaryDirectory(prefix='mth_rev_') as tmpdir:
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(tmpdir)

        filelist_path = os.path.join(tmpdir, 'filelist.txt')
        if os.path.exists(filelist_path):
            with open(filelist_path, 'r', encoding='utf-8') as f:
                file_list = [line.strip() for line in f if line.strip()]
        else:
            file_list = sorted([f for f in os.listdir(tmpdir)
                                if f.endswith('.srec')])

        for fname in file_list:
            fpath = os.path.join(tmpdir, fname)
            if not os.path.exists(fpath):
                continue
            fields = parse_s0_header(fpath)
            if not fields:
                continue
            tpl = fields.get('TPL', '')
            if tpl == '2002':
                # This is the engine-hdr (DSP code) file
                mth = fields.get('MTH', '')
                vstring = fields.get('VSTRING', '')
                if mth == '1' or vstring:
                    return 'F'
                return 'E'

    return None

def parse_srec(filepath):
    """Parse a Motorola S-record file.

    Returns dict with:
        'header': S0 header string
        'data': dict mapping address -> byte value
        'address_ranges': list of (start, end) tuples
        'total_bytes': total data bytes
    """
    result = {
        'header': '',
        'segments': [],  # list of (addr, bytes)
        'total_bytes': 0,
    }

    current_addr = None
    current_data = bytearray()

    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith('S'):
                continue

            rec_type = line[0:2]
            length = int(line[2:4], 16)

            if rec_type == 'S0':
                # Header record
                addr = int(line[4:8], 16)
                data = bytes.fromhex(line[8:8 + (length - 3) * 2])
                result['header'] = data.decode('ascii', errors='replace')

            elif rec_type in ('S1', 'S2', 'S3'):
                # Data record
                if rec_type == 'S1':
                    addr = int(line[4:8], 16)
                    addr_len = 2
                elif rec_type == 'S2':
                    addr = int(line[4:10], 16)
                    addr_len = 3
                else:
                    addr = int(line[4:12], 16)
                    addr_len = 4

                data_len = length - addr_len - 1
                data = bytes.fromhex(line[4 + addr_len * 2:4 + addr_len * 2 + data_len * 2])

                # Check if this continues the previous segment
                if current_addr is not None and addr == current_addr + len(current_data):
                    current_data.extend(data)
                else:
                    # Save previous segment
                    if current_addr is not None and current_data:
                        result['segments'].append((current_addr, bytes(current_data)))
                    current_addr = addr
                    current_data = bytearray(data)

                result['total_bytes'] += len(data)

            elif rec_type in ('S7', 'S8', 'S9'):
                # End/termination record
                break

    # Save last segment
    if current_addr is not None and current_data:
        result['segments'].append((current_addr, bytes(current_data)))

    return result


def srec_to_binary(srec_data):
    """Convert parsed S-record segments to a contiguous binary image.

    Returns (base_address, bytes) tuple.
    """
    if not srec_data['segments']:
        return (0, b'')

    base_addr = min(seg[0] for seg in srec_data['segments'])
    max_end = max(seg[0] + len(seg[1]) for seg in srec_data['segments'])

    binary = bytearray(b'\xFF' * (max_end - base_addr))

    for addr, data in srec_data['segments']:
        offset = addr - base_addr
        binary[offset:offset + len(data)] = data

    return (base_addr, bytes(binary))


def print_srec_info(srec_data):
    """Print summary info about a parsed S-record file."""
    print(f"  Header: {srec_data['header']}")
    print(f"  Segments: {len(srec_data['segments'])}")
    print(f"  Total data: {srec_data['total_bytes']} bytes")
    for i, (addr, data) in enumerate(srec_data['segments']):
        print(f"    Segment {i}: 0x{addr:06X}-0x{addr + len(data) - 1:06X} "
              f"({len(data)} bytes)")


# ============================================================================
# Serial Number File Format
# ============================================================================

def save_serial_number_file(filepath, engine_info, eis_data=None):  # pylint: disable=unused-argument
    """Save engine info as an MTH serial number file.

    Format from the loader:
        MTH-SCS SERIAL NUMBER FILE (DO NOT CHANGE THIS LINE!)
        *********************************************************
        START:
        ENG CAB#: <cab number>
        ENG ROAD NAME: <road name>
        ENG ENGINE TYPE: <engine type>
        DSP CODE INFO: <dsp info>
        PCB REV: <pcb revision>
        FLASH FILE NAME: <sound file name>
        AUX: <customer info>
        *********************************************************
    """
    info = parse_engine_info(engine_info) if engine_info else {}

    lines = [
        "MTH-SCS SERIAL NUMBER FILE (DO NOT CHANGE THIS LINE!)",
        "*********************************************************",
        "START:",
        f"ENG CAB#: {info.get('cab_number', '')}",
        f"ENG ROAD NAME: {info.get('road_name', '')}",
        f"ENG ENGINE TYPE: {info.get('engine_name', '')}",
        f"DSP CODE INFO: {info.get('dsp_filename', '')}",
        f"PCB REV: {info.get('pcb_rev', '')}",
        f"FLASH FILE NAME: {info.get('sound_filename', '')}",
        f"AUX: {info.get('customer_name', '')}",
        "*********************************************************",
    ]

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f"  Serial number file saved to {filepath}")


def load_serial_number_file(filepath):
    """Load an MTH serial number file and parse it into a dict of fields.

    Parses the SN file format:
        MTH-SCS SERIAL NUMBER FILE (DO NOT CHANGE THIS LINE!)
        *********************************************************
        START:
        ENG CAB#: <cab number>
        ENG ROAD NAME: <road name>
        ENG ENGINE TYPE: <engine type>
        DSP CODE INFO: <dsp info>
        PCB REV: <pcb revision>
        FLASH FILE NAME: <sound file name>
        AUX: <customer info>
        *********************************************************

    Returns dict mapping engine_info field names to values:
        cab_number, road_name, engine_name, dsp_filename,
        pcb_rev, sound_filename, customer_name
    Returns None if the file is not a valid SN file.
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Verify it's a valid SN file
    if "MTH-SCS SERIAL NUMBER FILE" not in content:
        print("  Error: Not a valid MTH serial number file")
        return None

    # Parse field lines
    field_map = {
        'ENG CAB#':         'cab_number',
        'ENG ROAD NAME':    'road_name',
        'ENG ENGINE TYPE':  'engine_name',
        'DSP CODE INFO':    'dsp_filename',
        'PCB REV':          'pcb_rev',
        'FLASH FILE NAME':  'sound_filename',
        'AUX':              'customer_name',
    }

    result = {}
    for line in content.splitlines():
        line = line.strip()
        for prefix, key in field_map.items():
            if line.startswith(prefix + ':'):
                value = line[len(prefix) + 1:].strip()
                result[key] = value
                break

    if not result:
        print("  Error: No fields found in SN file")
        return None

    print(f"  Loaded SN file: {filepath}")
    for key, val in result.items():
        print(f"    {key}: {val}")

    return result


# ============================================================================
# Dealer Number Logging
# ============================================================================

def append_dealer_log(log_path, dealer_number, engine_info, pc_name=None):
    """Append a programming event to the dealer number log file.

    Mirrors the dealer loader's "Appending SN Data to Dealer Number log file"
    behavior. Creates the log file if it doesn't exist.

    Args:
        log_path: Path to the log file
        dealer_number: Dealer number string (e.g. "920000")
        engine_info: Engine info bytes (from read_engine_info)
        pc_name: PC name (default: auto-detect)
    """
    if pc_name is None:
        try:
            pc_name = socket.gethostname()
        except Exception:  # pylint: disable=broad-exception-caught
            pc_name = "UNKNOWN"

    info = parse_engine_info(engine_info) if engine_info else {}
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    entry = (
        f"--- {timestamp} ---\n"
        f"  Dealer Number:  {dealer_number}\n"
        f"  PC Name:        {pc_name}\n"
        f"  Eng Cab#:       {info.get('cab_number', '?')}\n"
        f"  Eng Road Name:  {info.get('road_name', '?')}\n"
        f"  Eng Engine:     {info.get('engine_name', '?')}\n"
        f"  MTH Product #:  {info.get('mth_product_num', '?')}\n"
        f"  Customer:       {info.get('customer_name', '?')}\n"
        f"  Phone:          {info.get('phone_number', '?')}\n"
        "\n"
    )

    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(entry)
    print(f"  Dealer log entry appended to {log_path}")


# ============================================================================
# Engine Type Detection
# ============================================================================

ENGINE_TYPE_MAP = {
    0x00: 'Steam',
    0x10: 'Steam (Big Boy #4014)',
    0x05: 'Diesel',
    0x85: 'Diesel (newer PS3)',
    0x25: 'Electric',
    0xE3: 'Steam (PS3.2)',  # Observed on C&O Allegheny #1604 (PS1->PS3 upgrade)
}

def engine_type_string(type_byte):
    """Get engine type string from type byte."""
    return ENGINE_TYPE_MAP.get(type_byte, f'Unknown (0x{type_byte:02X})')

# ============================================================================
# Main
# ============================================================================

def main():
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    # pylint: disable=too-many-return-statements,too-many-nested-blocks
    """Main entry point: parse arguments and dispatch subcommands."""
    parser = argparse.ArgumentParser(
        description='Engine Manufacturing Data Programmer (for the MTH WTIU)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
WARNING: The --write command modifies engine flash memory. Always do a
--read first to verify connectivity and see the current data.

Examples:
  # Read current engine info (safe)
  %(prog)s --read

  # Read and show hex dump (auto-discover WTIU via mDNS)
  %(prog)s --read --hex

  # Write engine name only
  %(prog)s --write --engine-name "Big Boy"

  # Write engine name and cab number
  %(prog)s --write --engine-name "Big Boy" --cab-number "4014"

  # Write road name and customer
  %(prog)s --write --road-name "UP" --customer-name "John Smith"

  # Write phone number (10 digits, zero-padded)
  %(prog)s --write --phone-number "4125551234"

  # Read entire flash as .mth sound file
  %(prog)s --read-sound engine_backup.mth

  # Read with explicit flash size
  %(prog)s --read-sound engine_backup.mth --flash-size 0x400000

  # Write .mth sound file to engine (preserves mfg data)
  %(prog)s --write-sound new_sound.mth

  # Write .mth sound file, overwriting mfg data too
  %(prog)s --write-sound new_sound.mth --no-preserve-mfg

  # Dump all engine data (flash header, EIS, engine info, flash size)
  %(prog)s --dump-all

  # Read odometer and trip odometer (requires direct serial, not WTIU)
  %(prog)s --read-odo

  # Read chronometer (operating hours, requires direct serial, not WTIU)
  %(prog)s --read-chrono

  # Read DSP code version (requires direct serial, not WTIU)
  %(prog)s --read-dsp

  # Read HO engine EE parameters (HO engines only)
  %(prog)s --read-ho-ee

  # Read engine RAM at address (1, 2, or 4 bytes, via q-command)
  %(prog)s --read-ram 0x22 --ram-size 2

  # Save engine info as serial number file
  %(prog)s --save-sn-file engine_sn.txt

  # Parse an S-record file (no engine connection needed)
  %(prog)s --info-srec engine-hdr-3528.srec

  # Read EIS and show DSP code address/length
  %(prog)s --read-eis-dsp

  # Write chain/DSP code from S-record file (auto-detect address from EIS)
  %(prog)s --write-chain cv-hdr-3226-STEAM.srec

  # Write full chain zip (multiple S-records to different EIS regions)
  %(prog)s --write-chain p132_f_alleghnyall_3369_chain.zip

  # Write chain/DSP code with explicit flash address
  %(prog)s --write-chain cv-hdr-3226-STEAM.srec --dsp-addr 0x041001 --dsp-max-len 0x5250

  # Dump the entire flash (donor imaging / standalone backup)
  %(prog)s --dump-flash healthy_donor.flash_backup

  # Restore an engine from a flash image (bootloader/DSP sector skipped)
  %(prog)s --restore-flash healthy_donor.flash_backup

  # Restore only the manufacturing sector
  %(prog)s --restore-flash backup.flash_backup --restore-sector 0x004000

  # Program an engine from the consumer download zip (chain + sound, one pass)
  %(prog)s --write-image r22a_f_sw1200__md_231123aupd-cnsmr.zip
""")
    parser.add_argument('--host', default=None,
                        help='WTIU IP or mDNS name (e.g. 192.168.1.174 or '
                             'mthdcs-3E74.local). If omitted, auto-discovers via mDNS.')
    parser.add_argument('--port', type=int, default=38885,
                        help='WTIU TCP port (default: 38885, overridden by mDNS)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug output (show all TX/RX)')
    parser.add_argument('--read', action='store_true',
                        help='Read manufacturing data from engine')
    parser.add_argument('--write', action='store_true',
                        help='Write manufacturing data to engine')
    parser.add_argument('--hex', action='store_true',
                        help='Show hex dump of data')
    parser.add_argument('--engine-name', help='New engine name (max 32 chars)')
    parser.add_argument('--cab-number', help='New cab number (max 32 chars)')
    parser.add_argument('--road-name', help='New road name (max 32 chars)')
    parser.add_argument('--dsp-filename', help='New DSP filename (max 32 chars)')
    parser.add_argument('--pcb-rev', help='New PCB rev (max 32 chars)')
    parser.add_argument('--sound-filename', help='New sound filename (max 32 chars)')
    parser.add_argument('--mth-product-num', help='MTH product number (7 digits, zero-padded)')
    parser.add_argument('--phone-number', help='Phone number (10 digits, zero-padded)')
    parser.add_argument('--customer-name', help='Customer name (max 15 chars)')
    parser.add_argument('--address1', help='Customer address line 1 (max 32 chars)')
    parser.add_argument('--address2', help='Customer address line 2 (max 32 chars)')
    parser.add_argument('--city', help='Customer city (max 32 chars)')
    parser.add_argument('--state', help='Customer state (max 32 chars)')
    parser.add_argument('--zip', help='Customer zip code (7 digits, zero-padded)')
    parser.add_argument('--email', help='Customer email (max 32 chars)')
    parser.add_argument('--serial-number', help='(deprecated, use --mth-product-num)')
    parser.add_argument('--product-number', help='(deprecated, use --mth-product-num)')
    parser.add_argument('--no-stamp-date', action='store_true',
                        help='Do not rebuild the composite date field and YYMMDD '
                             'with today\'s date (default: stamp like dealer loader)')
    parser.add_argument('--dealer-number', metavar='NUMBER',
                        help='Dealer number (6 digits). Used for the composite field '
                             'in --write and for dealer logging in --write-sound.')
    parser.add_argument('--yes', action='store_true',
                        help='Skip the confirmation prompt before writing to flash')
    parser.add_argument('--sector', type=int, default=MFG_SECTOR,
                        help='Sector number to read/write (default: 1)')
    parser.add_argument('--read-sector', type=int,
                        help='Read a specific sector number')
    parser.add_argument('--read-addr', type=lambda x: int(x, 0),
                        help='Read from a specific flash address (e.g. 0x380000)')
    parser.add_argument('--read-length', type=lambda x: int(x, 0), default=0x100,
                        help='Number of bytes to read with --read-addr (default: 256)')
    parser.add_argument('--write-addr', type=lambda x: int(x, 0),
                        help='Write raw data to a specific flash address (e.g. 0x380000)')
    parser.add_argument('--write-hex', type=str,
                        help='Hex data to write with --write-addr (e.g. 0123456789ABCDEF)')
    parser.add_argument('--write-erase', action='store_true',
                        help='Erase the sector before writing with --write-addr')
    parser.add_argument('--write-no-verify', action='store_true',
                        help='Skip readback verification after --write-addr')
    parser.add_argument('--burst-mode', type=int, default=None, choices=[0, 1, 2, 3],
                        help='DI transceiver mode 0-3 (carried in W length field top nibble)')
    parser.add_argument('--write-allow-mfg', action='store_true',
                        help='Allow --write-addr to target the manufacturing data region')
    parser.add_argument('--no-setup', action='store_true',
                        help='Skip engine setup (for use when engine already set up)')
    parser.add_argument('--read-sound', metavar='OUTPUT_FILE',
                        help='Read entire flash and save as .mth file')
    parser.add_argument('--write-sound', metavar='INPUT_FILE',
                        help='Write a .mth sound file to engine flash')
    parser.add_argument('--flash-size', type=lambda x: int(x, 0),
                        help='Flash size in bytes (for --read-sound, auto-detects if omitted)')
    parser.add_argument('--no-preserve-mfg', action='store_true',
                        help='Do not preserve manufacturing data when writing sound file')
    parser.add_argument('--no-validate', action='store_true',
                        help='Skip EIS validation when writing sound file (not recommended)')
    parser.add_argument('--no-loader-stamp', action='store_true',
                        help='Skip stamping loader data at 0x1950 when writing sound file')
    parser.add_argument('--backup-flash', action='store_true',
                        help='Read full flash and save to <file>.flash_backup before '
                             'writing (default: off, sound files available from MTH)')
    parser.add_argument('--recovery-file', metavar='FILE',
                        help='Sound file to re-flash if write fails '
                             '(default: same as --write-sound)')
    parser.add_argument('--loader-version', metavar='VERSION',
                        help=f'Override loader version string for stamping '
                             f'(default: {DEFAULT_LOADER_VERSION})')
    parser.add_argument('--dump-all', action='store_true',
                        help='Read and display all engine data (mfg, runtime, DSP, flash size)')
    parser.add_argument('--report', action='store_true',
                        help='Print a formatted manufacturing data report')
    parser.add_argument('--read-odo', action='store_true',
                        help='Read odometer and trip odometer')
    parser.add_argument('--read-chrono', action='store_true',
                        help='Read chronometer (operating hours)')
    parser.add_argument('--read-dsp', action='store_true',
                        help='Read DSP code version')
    parser.add_argument('--read-ho-ee', action='store_true',
                        help='Read HO engine EE parameters (@R command)')
    parser.add_argument('--read-ram', type=lambda x: int(x, 0),
                        help='Read engine RAM at address (e.g. 0x22 for engine type)')
    parser.add_argument('--ram-size', type=int, default=2, choices=[1, 2, 4],
                        help='RAM read size: 1, 2, or 4 bytes (default: 2)')
    parser.add_argument('--save-sn-file', metavar='OUTPUT_FILE',
                        help='Save engine info as MTH serial number file')
    parser.add_argument('--load-sn-file', metavar='INPUT_FILE',
                        help='Load MTH serial number file and write fields to engine')
    parser.add_argument('--info-srec', metavar='SREC_FILE',
                        help='Parse and display S-record file info (no engine connection needed)')
    parser.add_argument('--dump-flash', metavar='FILE',
                        help='Read the full flash to FILE (.flash_backup '
                             'image for donor imaging or --restore-flash)')
    parser.add_argument('--restore-flash', metavar='FILE',
                        help='Restore flash from a .flash_backup image '
                             '(per-sector erase/write/verify)')
    parser.add_argument('--restore-sector', metavar='ADDR',
                        help='Restore only the sector containing ADDR (hex)')
    parser.add_argument('--restore-range', nargs=2,
                        metavar=('START', 'END'),
                        help='Restore sectors fully inside START-END (hex)')
    parser.add_argument('--force-bootloader', action='store_true',
                        help='Allow restoring the bootloader/DSP sector '
                             '(DANGEROUS — it may host program-mode code)')
    parser.add_argument('--write-image', metavar='FILE',
                        help='Program engine from a consumer download zip '
                             '(-cnsmr.zip): chain code + sound file in one pass')
    parser.add_argument('--write-chain', metavar='FILE',
                        help='Write chain/DSP code from S-record (.srec) or '
                             'chain zip (.zip) file to engine flash')
    parser.add_argument('--dsp-addr', type=str, default=None,
                        help='DSP code flash address (hex, e.g. 0x041001). '
                             'Auto-detect from EIS if omitted.')
    parser.add_argument('--dsp-max-len', type=str, default=None,
                        help='DSP code max length (hex, e.g. 0x5250). '
                             'Auto-detect from EIS if omitted.')
    parser.add_argument('--read-eis-dsp', action='store_true',
                        help='Read EIS and display DSP code address/length info')
    parser.add_argument('--read-cap-bits', action='store_true',
                        help='Read capability bits from engine flash at 0x1900 (64 bytes)')
    parser.add_argument('--set-feature-bit', metavar='BYTE:BIT',
                        help='Set a feature bit in a .mth file before writing. '
                             'Format: byte_index:bit_value (e.g. 0:128). '
                             'Use with --write-sound.')
    parser.add_argument('--clear-feature-bit', metavar='BYTE:BIT',
                        help='Clear a feature bit in a .mth file before writing. '
                             'Format: byte_index:bit_value (e.g. 0:128). '
                             'Use with --write-sound.')
    parser.add_argument('--log-file', metavar='PATH', default='dealer_log.txt',
                        help='Dealer log file path (default: dealer_log.txt)')

    args = parser.parse_args()

    # Override the default DI transceiver mode if requested.  BURST_MODE is a
    # module-level knob read by write_raw(), and --burst-mode exists so modes
    # 0/2/3 can be tried without editing the file; a CLI flag rebinding it is
    # the intended use.
    if args.burst_mode is not None:
        global BURST_MODE  # pylint: disable=global-statement
        BURST_MODE = args.burst_mode

    # --info-srec doesn't need a WTIU connection
    if args.info_srec:
        srec = parse_srec(args.info_srec)
        print_srec_info(srec)
        return

    # pylint: disable=too-many-boolean-expressions
    if not args.read and not args.write and not args.read_sector and args.read_addr is None \
            and not args.read_sound and not args.write_sound and not args.dump_all \
            and not args.read_odo and not args.read_chrono and not args.read_dsp \
            and not args.read_ho_ee and args.read_ram is None \
            and not args.save_sn_file and not args.load_sn_file and not args.write_chain \
            and not args.dump_flash and not args.restore_flash \
            and not args.write_image \
            and not args.read_eis_dsp and not args.read_cap_bits \
            and not args.report and args.write_addr is None:
        # pylint: enable=too-many-boolean-expressions
        parser.print_help()
        return

    # pylint: disable=too-many-boolean-expressions
    if args.write and not args.engine_name and not args.cab_number and not args.road_name \
            and not args.dsp_filename and not args.pcb_rev and not args.sound_filename \
            and not args.mth_product_num and not args.phone_number and not args.customer_name:
        # pylint: enable=too-many-boolean-expressions
        print("Error: --write requires at least one field to set:")
        print("  --engine-name, --cab-number, --road-name, --dsp-filename,")
        print("  --pcb-rev, --sound-filename, --mth-product-num,")
        print("  --phone-number, --customer-name")
        return

    # Resolve host (mDNS discovery if not specified)
    host, port = resolve_wtiu_host(args.host, debug=args.debug)
    if args.port != 38885:
        port = args.port  # explicit port override

    # Connect and authenticate
    print(f"Connecting to WTIU at {host}:{port}...")
    conn = WTIUConnection(host, port, debug=args.debug)
    try:
        conn.connect()
        print("Authenticating...")
        if not conn.authenticate():
            print("Authentication failed!")
            return
        print("Authentication successful!")

        prog = EngineProgrammer(conn, debug=args.debug)

        # Read a specific sector
        if args.read_sector is not None:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            data = prog.read_sector(args.read_sector)
            if data:
                print(f"\nSector {args.read_sector} ({len(data)} bytes):")
                if args.hex:
                    hex_dump(data)
                else:
                    print(f"  {data.hex().upper()}")
            return

        # Read from a specific address
        if args.read_addr is not None:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            print(f"\nReading {args.read_length} bytes from 0x{args.read_addr:06X}...")
            cmd = f"R{args.read_addr:06X}{args.read_length:06X}"
            resp = prog.conn.send_cmd(cmd)
            if "okay" not in resp:
                print(f"Read failed: {resp}")
                return
            data = prog._parse_read_response(resp, args.read_addr, args.read_length)  # pylint: disable=protected-access
            if data:
                print(f"\nFlash at 0x{args.read_addr:06X} ({len(data)} bytes):")
                if args.hex:
                    hex_dump(data, offset=args.read_addr)
                else:
                    print(f"  {data.hex().upper()}")
            else:
                print("Failed to parse response")
            return

        # Write to a specific address (v17 W command test)
        if args.write_addr is not None:
            if not args.write_hex:
                print("Error: --write-addr requires --write-hex")
                return
            try:
                data = bytes.fromhex(args.write_hex)
            except ValueError as e:
                print(f"Error: invalid --write-hex data: {e}")
                return
            if not data:
                print("Error: --write-hex is empty")
                return
            # No size cap here: write_raw splits data into BURST_DATA_MAX-byte
            # W blocks and _validate_flash_range enforces the real limits.
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            # Read EIS so we can set bootloader protection before any write
            eis = prog.read_eis_records()
            if eis and 'dsp_addr' in eis:
                prog.set_bootloader_protection(eis['dsp_addr'],
                                               eis['dsp_addr'] + eis['dsp_max_len'])
            else:
                print("ERROR: Could not read EIS for bootloader protection. Aborting.")
                return
            # Optionally erase first — only the erase blocks covering the
            # write, not the whole logical sector (which can be 128KB).
            if args.write_erase:
                if not prog.erase_at_addr(args.write_addr, size=len(data),
                                          allow_mfg=args.write_allow_mfg):
                    return
            # Write and verify
            if not prog.write_raw(args.write_addr, data, verify=not args.write_no_verify,
                                  allow_mfg=args.write_allow_mfg):
                print("Write failed.")
                return
            print("Write raw completed.")
            return

        # Read sound file mode
        if args.read_sound:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            if not prog.read_sound_file(args.read_sound, flash_size=args.flash_size):
                print("Failed to read sound file.")
            return

        # Write sound file mode
        if args.write_sound:
            if not args.no_setup:
                if not prog.setup_engine():
                    return

            # Parse feature bit arguments
            set_bits = []
            clear_bits = []
            if args.set_feature_bit:
                for spec in args.set_feature_bit.split(','):
                    parts = spec.strip().split(':')
                    if len(parts) == 2:
                        set_bits.append((int(parts[0]), int(parts[1], 0)))
            if args.clear_feature_bit:
                for spec in args.clear_feature_bit.split(','):
                    parts = spec.strip().split(':')
                    if len(parts) == 2:
                        clear_bits.append((int(parts[0]), int(parts[1], 0)))

            if not prog.write_sound_file(args.write_sound,
                                         preserve_mfg=not args.no_preserve_mfg,
                                         validate=not args.no_validate,
                                         stamp_loader=not args.no_loader_stamp,
                                         loader_version=args.loader_version,
                                         set_bits=set_bits or None,
                                         clear_bits=clear_bits or None,
                                         backup_flash=args.backup_flash,
                                         recovery_file=args.recovery_file,
                                         assume_yes=args.yes):
                print("Failed to write sound file.")
            else:
                # Log to dealer log file if dealer number specified
                if args.dealer_number:
                    eng_info = prog.read_engine_info()
                    if eng_info:
                        append_dealer_log(args.log_file, args.dealer_number, eng_info)
            return

        # Dump all engine data
        if args.dump_all:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            print("\n=== Complete Engine Data Dump ===\n")
            prog.read_all_engine_data()
            return

        # Full flash dump (donor imaging / standalone backup)
        if args.dump_flash:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            prog.dump_flash(args.dump_flash, flash_size=args.flash_size)
            return

        # Restore flash from a .flash_backup image
        if args.restore_flash:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            try:
                with open(args.restore_flash, 'rb') as f:
                    backup_data = f.read()
            except OSError as e:
                print(f"Cannot read {args.restore_flash}: {e}")
                return
            sector = (int(args.restore_sector, 16)
                      if args.restore_sector else None)
            rng = ((int(args.restore_range[0], 16),
                    int(args.restore_range[1], 16))
                   if args.restore_range else None)
            prog.restore_flash(backup_data, sector=sector, range_bounds=rng,
                               force_bootloader=args.force_bootloader,
                               assume_yes=args.yes)
            return

        # Formatted report
        if args.report:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            print()
            prog.print_report()
            return

        # Read odometer
        if args.read_odo:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            print("\n=== Odometer Data ===\n")
            prog.read_odometer()
            prog.read_trip_odometer()
            return

        # Read chronometer
        if args.read_chrono:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            print("\n=== Chronometer Data ===\n")
            prog.read_chronometer()
            return

        # Read DSP version
        if args.read_dsp:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            print("\n=== DSP Code Version ===\n")
            prog.read_dsp_version()
            return

        # Read HO EE parameters
        if args.read_ho_ee:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            print("\n=== HO Engine EE Parameters ===\n")
            prog.read_ho_ee_parameters()
            return

        # Read RAM
        if args.read_ram is not None:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            print(f"\n=== RAM Read at 0x{args.read_ram:04X} ({args.ram_size} bytes) ===\n")
            val = prog.read_ram(args.read_ram, args.ram_size)
            if val is not None:
                print(f"  Value: 0x{val:0{args.ram_size*2}X} ({val})")
            else:
                print("  Read failed.")
            return

        # Save serial number file
        if args.save_sn_file:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            print("\n=== Saving Serial Number File ===\n")
            eng_info = prog.read_engine_info()
            if eng_info:
                save_serial_number_file(args.save_sn_file, eng_info)
            else:
                print("  Could not read engine info.")
            return

        # Load serial number file and write to engine
        if args.load_sn_file:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            print("\n=== Loading Serial Number File ===\n")
            sn_fields = load_serial_number_file(args.load_sn_file)
            if sn_fields is None:
                return

            # Read existing engine info
            print("\nReading existing engine info...")
            existing = prog.read_engine_info()
            if existing is None:
                print("Cannot read existing engine info. Aborting.")
                return

            # Build new data from SN file fields
            new_data = build_engine_info(existing, **sn_fields)
            if new_data == existing:
                print("No changes to write (SN file matches existing data).")
                return

            # Show changes
            print("\n  Changes:")
            old_info = parse_engine_info(existing)
            new_info = parse_engine_info(new_data)
            for field, label in [
                ('cab_number', 'Cab Number'),
                ('road_name', 'Road Name'),
                ('engine_name', 'Engine Name'),
                ('dsp_filename', 'DSP Filename'),
                ('pcb_rev', 'PCB Rev'),
                ('sound_filename', 'Sound Filename'),
                ('customer_name', 'Customer'),
            ]:
                old_val = old_info.get(field, '')
                new_val = new_info.get(field, '')
                if old_val != new_val:
                    print(f"    {label}: \"{old_val}\" -> \"{new_val}\"")

            # Confirm and write
            print("\n*** ABOUT TO WRITE TO ENGINE FLASH ***")
            print("  This will erase and rewrite sector 0 (16KB).")
            if not args.yes:
                confirm = input("  Type 'YES' to continue: ")
                if confirm != 'YES':
                    print("Aborted.")
                    return

            if prog.write_engine_info(new_data):
                print("  Serial number data written successfully!")
                if args.dealer_number:
                    append_dealer_log(args.log_file, args.dealer_number, new_data)
            else:
                print("  Failed to write serial number data.")
            return

        # Read EIS DSP info
        if args.read_eis_dsp:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            print("\n=== EIS DSP Code Info ===\n")
            prog.read_eis_dsp_info()
            return

        # Read capability bits
        if args.read_cap_bits:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            print("\n=== Capability Bits (0x1900) ===\n")
            cap_data = prog.read_capability_bits()
            if cap_data:
                hex_dump(cap_data, 0x1900)
                # Show labeled feature bits
                labeled = decode_capability_bits(cap_data)
                if labeled:
                    print("\n  Labeled feature bits:")
                    for addr, mask, label in labeled:
                        print(f"    0x{addr:04X} bit 0x{mask:02X}: {label}")
                # Show raw set bits
                print("\n  All set bits (raw):")
                for i, b in enumerate(cap_data):
                    if b not in (0, 0xFF):
                        bits = []
                        for bit in range(8):
                            if b & (1 << bit):
                                bits.append(str(bit))
                        bit_str = ', '.join(bits)
                        print(f"    Byte {i} (0x{0x1900+i:04X}):"
                              f" 0x{b:02X} = bits {bit_str}")
            else:
                print("  Could not read capability bits.")
            return

        # Program engine from a consumer download zip (chain + sound)
        if args.write_image:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            prog.write_consumer_zip(
                args.write_image,
                preserve_mfg=not args.no_preserve_mfg,
                validate=not args.no_validate,
                stamp_loader=not args.no_loader_stamp,
                backup_flash=args.backup_flash,
                assume_yes=args.yes)
            return

        # Write chain/DSP code
        if args.write_chain:
            if not args.no_setup:
                if not prog.setup_engine():
                    return
            chain_path = args.write_chain
            if chain_path.lower().endswith('.zip'):
                # Zip file containing multiple S-records
                if not prog.write_chain_zip(chain_path, assume_yes=args.yes):
                    print("Failed to write chain zip.")
            else:
                # Single S-record file
                dsp_addr = None
                dsp_max_len = None
                if args.dsp_addr:
                    dsp_addr = int(args.dsp_addr, 16)
                if args.dsp_max_len:
                    dsp_max_len = int(args.dsp_max_len, 16)
                if not prog.write_chain_code(chain_path, dsp_addr,
                                             dsp_max_len,
                                             assume_yes=args.yes):
                    print("Failed to write chain/DSP code.")
            return

        # Read mode
        if args.read:
            if not args.no_setup:
                if not prog.setup_engine():
                    return

            # Try to get engine type
            prog.get_engine_type()

            data = prog.read_mfg_data()
            if data is None:
                print("\nFailed to read manufacturing data.")
                print("Check that:")
                print("  1. The engine is on the track")
                print("  2. Only one engine is on the track")
                print("  3. The TIU is connected and powered")
                print("  4. The engine address is not 0")
                return

            print(f"\nManufacturing data ({len(data)} bytes):")
            if args.hex:
                hex_dump(data)
            else:
                hex_dump(data, length=min(64, len(data)))
                if len(data) > 64:
                    print(f"  ... ({len(data) - 64} more bytes, use --hex to see all)")

            # Parse and display EIS fields
            parsed = parse_mfg_data(data)
            print("\n=== EIS Manufacturing Data (0x004000) ===")
            print(f"  Header: {parsed.get('header', '?')}")
            print(f"  EIS magic: {parsed.get('is_eis', False)}")
            print(f"  Engine type byte (0x05): 0x{parsed.get('engine_type_byte', 0):02X}")
            print(f"  Field1 (0x08): {parsed.get('field1_0x08', 0)}")
            print(f"  Field2 (0x0C): {parsed.get('field2_0x0C', 0)}")
            print(f"  Field3 (0x10): 0x{parsed.get('field3_0x10', 0):016X}")
            print(f"  ASCII at 0x14: \"{parsed.get('ascii_0x14', '?')}\"")
            print(f"  Config records: {parsed.get('record_count', 0)}")

            # Now read the engine info sector
            print()
            eng_info = prog.read_engine_info()
            if eng_info is None:
                print("\nFailed to read engine info from 0x001DD2.")
                return

            if args.hex:
                print(f"\nEngine info raw data ({len(eng_info)} bytes):")
                hex_dump(eng_info, offset=ENG_INFO_ADDR)

            # Parse and display engine info
            info = parse_engine_info(eng_info)
            print("\n=== Engine Info (0x001DD2) ===")
            print(f"  Engine Name:      {info.get('engine_name', '?')}")
            print(f"  Road Name:        {info.get('road_name', '?')}")
            print(f"  Cab Number:       {info.get('cab_number', '?')}")
            print(f"  DSP Filename:     {info.get('dsp_filename', '?')}")
            print(f"  PCB Rev:          {info.get('pcb_rev', '?')}")
            print(f"  Sound Filename:   {info.get('sound_filename', '?')}")
            print(f"  MTH Product #:    {info.get('mth_product_num', '?')}")
            print(f"  Phone Number:     {info.get('phone_number', '?')}")
            print(f"  Customer:         {info.get('customer_name', '?')}")
            print(f"  Date (YYMMDD):    {info.get('date_yymmdd', '?')}")
            comp = info.get('composite', '')
            print(f"  Composite:        {comp}")
            cp = info.get('composite_parts', {})
            if cp:
                print(f"    Dealer #:       {cp.get('dealer_number', '?')}")
                print(f"    Comp Product:   {cp.get('comp_product', '?')}")
                print(f"    Comp Serial+1:  {cp.get('comp_serial', '?')}")
            return

        # Write mode
        if args.write:
            if not args.no_setup:
                if not prog.setup_engine():
                    return

            # Check if any extended fields are specified
            extended_fields = [args.address1, args.address2, args.city,
                             args.state, args.zip, args.email]
            use_extended = any(f is not None for f in extended_fields)

            # Read existing engine info first (extended if needed)
            print("\nReading existing engine info...")
            existing = prog.read_engine_info(extended=use_extended)
            if existing is None:
                print("Cannot read existing engine info. Aborting write.")
                print("You must be able to read before writing.")
                return

            print(f"  Read {len(existing)} bytes")

            # Show current values
            info = parse_engine_info(existing)
            print(f"  Current engine name:  {info.get('engine_name', '?')}")
            print(f"  Current road name:    {info.get('road_name', '?')}")
            print(f"  Current cab number:   {info.get('cab_number', '?')}")
            print(f"  Current customer:     {info.get('customer_name', '?')}")
            if use_extended:
                print(f"  Current address1:     {info.get('address1', '?')}")
                print(f"  Current address2:     {info.get('address2', '?')}")
                print(f"  Current city:         {info.get('city', '?')}")
                print(f"  Current state:        {info.get('state', '?')}")
                print(f"  Current zip:          {info.get('zip', '?')}")
                print(f"  Current email:        {info.get('email', '?')}")

            # Build new data
            new_data = build_engine_info(
                existing,
                engine_name=args.engine_name,
                cab_number=args.cab_number,
                road_name=args.road_name,
                dsp_filename=args.dsp_filename,
                pcb_rev=args.pcb_rev,
                sound_filename=args.sound_filename,
                mth_product_num=args.mth_product_num,
                phone_number=args.phone_number,
                customer_name=args.customer_name,
                address1=args.address1,
                address2=args.address2,
                city=args.city,
                state=args.state,
                zip=args.zip,
                email=args.email,
                dealer_number=args.dealer_number,
                stamp_date=not args.no_stamp_date,
            )

            if new_data == existing:
                print("No changes to write.")
                return

            # Show what will change
            print("\n  Changes:")
            new_info = parse_engine_info(new_data)
            for field, label in [
                ('engine_name', 'Engine Name'),
                ('road_name', 'Road Name'),
                ('cab_number', 'Cab Number'),
                ('dsp_filename', 'DSP Filename'),
                ('pcb_rev', 'PCB Rev'),
                ('sound_filename', 'Sound Filename'),
                ('mth_product_num', 'MTH Product #'),
                ('phone_number', 'Phone Number'),
                ('customer_name', 'Customer'),
                ('address1', 'Address 1'),
                ('address2', 'Address 2'),
                ('city', 'City'),
                ('state', 'State'),
                ('zip', 'Zip'),
                ('email', 'Email'),
            ]:
                old_val = info.get(field, '')
                new_val = new_info.get(field, '')
                if old_val != new_val:
                    print(f"    {label}: \"{old_val}\" -> \"{new_val}\"")

            # Show composite/date/serial changes (mirrors dealer loader MergeMfgData)
            if not args.no_stamp_date:
                old_cp = info.get('composite_parts', {})
                new_cp = new_info.get('composite_parts', {})
                old_ymd = info.get('date_yymmdd', '')
                new_ymd = new_info.get('date_yymmdd', '')
                if old_ymd != new_ymd:
                    print(f"    Date (YYMMDD): \"{old_ymd}\" -> \"{new_ymd}\"")
                old_serial = old_cp.get('comp_serial', '')
                new_serial = new_cp.get('comp_serial', '')
                if old_serial != new_serial:
                    print(f"    Serial+1:      \"{old_serial}\" -> \"{new_serial}\"")
                old_dealer = old_cp.get('dealer_number', '')
                new_dealer = new_cp.get('dealer_number', '')
                if old_dealer != new_dealer:
                    print(f"    Dealer Number: \"{old_dealer}\" -> \"{new_dealer}\"")

            # Confirm
            print("\n*** ABOUT TO WRITE TO ENGINE FLASH ***")
            print("  This will erase and rewrite sector 0 (16KB).")
            print("  The engine info at 0x001DD2 will be updated.")
            print("  A backup of sector 0 will be saved to sector0_backup.bin")
            print("  Do not remove power or the engine from the track!")
            if not args.yes:
                confirm = input("  Type 'YES' to continue: ")
                if confirm != 'YES':
                    print("Aborted.")
                    return

            # Write
            if not prog.write_engine_info(new_data):
                print("\nWrite failed! Check sector0_backup.bin for recovery data.")
                return

            prog.cleanup()
            print("\nWrite complete!")

            # Read back and show new values
            print("\nVerifying by reading back...")
            verify = prog.read_engine_info()
            if verify:
                vinfo = parse_engine_info(verify)
                print(f"  Engine Name:      {vinfo.get('engine_name', '?')}")
                print(f"  Road Name:        {vinfo.get('road_name', '?')}")
                print(f"  Cab Number:       {vinfo.get('cab_number', '?')}")
                print(f"  Customer:         {vinfo.get('customer_name', '?')}")

            # Log to dealer log file if dealer number specified
            if args.dealer_number:
                append_dealer_log(args.log_file, args.dealer_number, new_data)

    except (OSError, socket.timeout, ValueError) as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        conn.disconnect()

if __name__ == '__main__':
    main()
