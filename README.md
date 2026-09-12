# MTH WTIU Programmer

Flash programming support for the MTH **WTIU** (WiFi Track Interface Unit) —
brings the WTIU's engine-programming capabilities up to par with the
original TIU for PS3 locomotives.

With the patched firmware, the WTIU can:

- **Write sound files** (`.mth`) — erase, program, and readback-verify the
  full sound image
- **Write chain files** (`.zip` of `.srec`) — DSP, FPGA, and DCC CV code
  updates, merged per erase sector so co-resident regions are preserved
- **Write engine/manufacturing data** — engine info, serial-number files
- **Read flash** (`R`) and **erase** (`K`) — existing commands, unchanged
- **Readback verification** on every write — no blind flashing

## What's in this repo

| File | Purpose |
|---|---|
| `wtiu_fw_patch.py` | Patches a stock WTIU firmware image into the patched `v1.3.3` image |
| `wtiu_patch_data.py` | The binary patch hunks (required by the patcher) |
| `mth_engine_programmer.py` | Engine programmer — CLI and library |
| `mth_programmer_ui.py` | Tkinter GUI front-end |

## How it works

The WTIU already contained most of the low-level flash primitives the TIU
uses; what it lacked was the orchestration. The patch adds a persistent
programming session (`ZB`/`ZD`/`ZE` commands) to the `wtiu` daemon that
mirrors the TIU's write handler — same DI initialization sequence
(`0x3E81`/`0x5E82`/`0xBE82`), same write-enable (`0x0B`/`0x0010`), bounded
data bursts with pointer verification and self-healing retries, and a clean
teardown that always disables programming mode. It also fixes two
heap-buffer overflows in `mux2tiu` that crashed the daemon on large reads.

### Copyright note

This repo distributes **only the patch hunks** — a list of byte
modifications applied to binaries extracted from *your own* stock firmware
image. No MTH code is included or distributed. The patched firmware image
produced by the patcher is for your own use; do not distribute the output
`.bin`.

## Part 1 — Patch the firmware

Requires **Linux or WSL** with `squashfs-tools` installed
(`sudo apt install squashfs-tools`), plus a stock MTH firmware image
(`WTIU-v1.3.0-20250814.bin` — the patcher verifies it by SHA-256 and refuses
anything else).

```bash
python3 wtiu_fw_patch.py WTIU-v1.3.0-20250814.bin
# produces WTIU-v1.3.3-20260911.bin next to the input
```

Flash the output through the WTIU's normal update path (LuCI web UI →
System → Flash Firmware, or `sysupgrade` over SSH). The stock sysupgrade
does not enforce signatures, so the unsigned output is accepted; the
required firmware metadata is embedded and format-verified.

## Part 2 — Program engines

Requires **Python 3** with `zeroconf` (`pip install zeroconf`) for WTIU
auto-discovery. The GUI also needs `tkinter` (bundled with most Python
installs).

GUI:

```bash
python mth_programmer_ui.py
```

CLI examples:

```bash
# Write a sound file
python mth_engine_programmer.py --write-sound engine_sound.mth

# Write a chain zip (DSP/FPGA/CV update)
python mth_engine_programmer.py --write-chain PS32_Steam_Osmk_e3.1.01-CPF.zip

# Read flash (prints hex)
python mth_engine_programmer.py --read-addr 0x0 --read-length 0x4000 --hex

# Read back the installed sound image to a file
python mth_engine_programmer.py --read-sound dump.bin
```

Exactly one engine should be powered on the track during programming.

## Safety

- Manufacturing/EIS regions are read and persisted to disk
  (`*.mfg-recovery.bin`) **before** any erase touches their sector, and
  restored after the image write — matching the dealer loader's flow.
- Chain-file writes merge all files per erase sector and preserve
  co-resident regions (Engine Data) via read-modify-write; each sector's
  pre-erase image is saved to disk (`*.sector-XXXXXX-recovery.bin`).
- Every write is verified by readback. A command "okay" response is never
  trusted on its own.
- Bootloader/DSP/FPGA safeguards are enforced unless explicitly overridden.

## PS2 engines (experimental)

The TIU/WTIU wire protocol is engine-agnostic — `K`/`W`/`R` and the
program-entry sequence are identical for PS2 and PS3. The differences are
all in the loader's flow, and this tool handles them:

- PS2 has no EIS — detected automatically (no `EIS!` magic at `0x004000`),
  EIS validation is skipped, and an extra confirmation is required
- PS2 expects `R`-verify after `K` (not `C`) — we always verify by
  readback anyway
- If a PS2 `K` erases a smaller unit than 8KB, the erase step falls back
  to erasing the second half-block before failing
- Manufacturing data at `0x4000` is still preserved and restored
- Chain files do not apply to PS2 (no DSP/FPGA regions)

PS2 writes have not been tested on hardware. If you try one, keep the
`*.mfg-recovery.bin` file it creates.

## Disclaimer

Unofficial, reverse-engineered tooling. Not affiliated with or endorsed by
MTH Electric Trains. Flashing locomotive firmware can permanently damage
the engine if interrupted or if the wrong files are used — board revision
(E vs F) matters for chain files. Use at your own risk, and keep backups.
