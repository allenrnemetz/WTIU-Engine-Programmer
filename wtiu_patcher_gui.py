#!/usr/bin/env python3
"""WTIU Firmware Patcher - GUI

Double-click app that turns a stock MTH WTIU v1.3.0 firmware image into the
patched v1.3.3 image. No console, no Python, no tools to install: the
squashfs repack tools are bundled next to the app (win_tools/bin).

A firmware path may also be passed as argv[1] (e.g. dragging a .bin onto
the exe or "Open with").
"""
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wtiu_fw_patch import (  # pylint: disable=wrong-import-position
    patch_firmware,
    PatchError,
    VERSION,
)


class TextRedirector:
    """Redirect log output to a Tkinter text widget (thread-safe)."""

    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, string):
        """Schedule the append on the main thread (Tkinter is not thread-safe)."""
        self.text_widget.after(0, self._append, string)

    def _append(self, string):
        self.text_widget.configure(state='normal')
        self.text_widget.insert('end', string + '\n')
        self.text_widget.see('end')
        self.text_widget.configure(state='disabled')

    def flush(self):
        """Flush the stream (no-op for Tkinter redirect)."""


class PatcherUI:
    """Single-purpose panel: pick stock .bin -> Patch -> done.

    Usable standalone (parent = tk.Tk) or embedded as a tab
    (parent = ttk.Frame inside a Notebook)."""

    def __init__(self, parent):
        self.root = parent

        self.input_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.status_var = tk.StringVar(
            value="Select a stock WTIU v1.3.0 firmware image")
        self.busy = False

        self._build_ui()

        # Standalone mode only: drag-onto-exe / "Open with" / CLI argument
        if isinstance(parent, tk.Tk) and len(sys.argv) > 1 \
                and sys.argv[1].lower().endswith('.bin'):
            self.set_input(sys.argv[1])

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill='x')

        ttk.Label(top, text="Stock firmware (.bin):").grid(
            row=0, column=0, sticky='w', pady=2)
        ttk.Entry(top, textvariable=self.input_var, width=62).grid(
            row=1, column=0, sticky='we', padx=(0, 6))
        ttk.Button(top, text="Browse...", command=self.on_browse_input).grid(
            row=1, column=1)

        ttk.Label(top, text="Output file:").grid(
            row=2, column=0, sticky='w', pady=(8, 2))
        ttk.Entry(top, textvariable=self.output_var, width=62).grid(
            row=3, column=0, sticky='we', padx=(0, 6))
        ttk.Button(top, text="Browse...", command=self.on_browse_output).grid(
            row=3, column=1)

        top.columnconfigure(0, weight=1)

        btn_frame = ttk.Frame(self.root, padding=(10, 0, 10, 6))
        btn_frame.pack(fill='x')
        self.patch_btn = ttk.Button(
            btn_frame, text="Patch Firmware", command=self.on_patch)
        self.patch_btn.pack(side='left')
        ttk.Label(btn_frame, textvariable=self.status_var).pack(
            side='left', padx=10)

        self.log = scrolledtext.ScrolledText(
            self.root, state='disabled', wrap='word', height=16,
            font=('Consolas', 9))
        self.log.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        self.redirector = TextRedirector(self.log)

    def set_input(self, path):
        """Set the input path and derive the default output name."""
        self.input_var.set(path)
        out = os.path.join(os.path.dirname(os.path.abspath(path)),
                           f'WTIU-{VERSION}.bin')
        self.output_var.set(out)
        self.status_var.set("Ready — click Patch Firmware")

    def on_browse_input(self):
        path = filedialog.askopenfilename(
            title="Select stock WTIU v1.3.0 firmware",
            filetypes=[("Firmware image", "*.bin"), ("All files", "*.*")])
        if path:
            self.set_input(path)

    def on_browse_output(self):
        path = filedialog.asksaveasfilename(
            title="Save patched firmware as",
            defaultextension='.bin',
            initialfile=f'WTIU-{VERSION}.bin',
            filetypes=[("Firmware image", "*.bin"), ("All files", "*.*")])
        if path:
            self.output_var.set(path)

    def on_patch(self):
        if self.busy:
            return
        in_path = self.input_var.get().strip()
        out_path = self.output_var.get().strip() or None
        if not in_path:
            messagebox.showwarning(
                "No input", "Choose a stock WTIU v1.3.0 firmware image first.")
            return
        if not os.path.isfile(in_path):
            messagebox.showerror("Missing file",
                                 f"Input file not found:\n{in_path}")
            return

        self.busy = True
        self.patch_btn.configure(state='disabled')
        self.status_var.set("Patching...")
        self.log.configure(state='normal')
        self.log.delete('1.0', 'end')
        self.log.configure(state='disabled')

        def work():
            try:
                out, size, digest = patch_firmware(
                    in_path, out_path, log=self.redirector.write)
            except PatchError as e:
                self.root.after(0, self._finish, False, str(e))
            except Exception as e:  # pylint: disable=broad-except
                self.root.after(0, self._finish, False, f'Unexpected: {e}')
            else:
                self.root.after(0, self._finish, True, out)

        threading.Thread(target=work, daemon=True).start()

    def _finish(self, ok, msg):
        self.busy = False
        self.patch_btn.configure(state='normal')
        if ok:
            self.status_var.set(f"Done: {os.path.basename(msg)}")
            if messagebox.askyesno(
                    "Patch complete",
                    f"Patched firmware written to:\n{msg}\n\n"
                    "Flash it via the WTIU web UI (System -> Flash Firmware).\n\n"
                    "Open the containing folder?"):
                self._reveal(msg)
        else:
            self.status_var.set("Patch failed")
            messagebox.showerror("Patch failed", msg)

    @staticmethod
    def _reveal(path):
        try:
            if os.name == 'nt':
                os.startfile(os.path.dirname(os.path.abspath(path)))  # pylint: disable=no-member
            else:
                import subprocess  # pylint: disable=import-outside-toplevel
                subprocess.Popen(['xdg-open',
                                  os.path.dirname(os.path.abspath(path))])
        except OSError:
            pass


def main():
    root = tk.Tk()
    root.title("WTIU Firmware Patcher")
    root.geometry("720x460")
    PatcherUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
