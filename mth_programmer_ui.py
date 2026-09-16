#!/usr/bin/env python3
# pylint: disable=too-many-lines
"""MTH Engine Programmer - Pushbutton GUI

A Tkinter-based UI for the MTH engine programmer.
Provides button-driven access to read, write, sound file, and SN file operations.
"""
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# Ensure we can import from the tools directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mth_engine_programmer import (  # pylint: disable=wrong-import-position
    WTIUConnection,
    EngineProgrammer,
    discover_wtiu,
    parse_engine_info,
    build_engine_info,
    load_serial_number_file,
    save_serial_number_file,
    parse_loader_data,
    parse_srec,
    parse_s0_header,
    detect_chain_revision,
    srec_to_binary,
    print_srec_info,
    hex_dump,
    decode_capability_bits,
)


class TextRedirector:
    """Redirect print output to a Tkinter text widget (thread-safe)."""

    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, string):
        """Write a string to the text widget (thread-safe via after)."""
        # Tkinter is not thread-safe; schedule the update on the main thread
        self.text_widget.after(0, self._append, string)

    def _append(self, string):
        """Append the string to the text widget on the main thread."""
        self.text_widget.configure(state='normal')
        self.text_widget.insert('end', string)
        self.text_widget.see('end')
        self.text_widget.configure(state='disabled')

    def flush(self):
        """Flush the stream (no-op for Tkinter redirect)."""


class ProgrammerUI:  # pylint: disable=too-many-instance-attributes
    """Main UI window for the MTH Engine Programmer."""

    def __init__(self, root):
        self.root = root
        self.root.title("MTH Engine Programmer")
        self.root.geometry("900x900")

        self.conn = None
        self.prog = None
        self.engine_info_data = None  # cached engine info bytes

        self._build_ui()

    def _build_ui(self):
        """Build the main UI with connection bar and tabbed notebook."""
        # Top frame: connection controls
        conn_frame = ttk.Frame(self.root, padding=8)
        conn_frame.pack(fill='x')

        ttk.Label(conn_frame, text="Host:").grid(row=0, column=0, padx=2)
        self.host_var = tk.StringVar(value="")
        self.host_entry = ttk.Entry(conn_frame, textvariable=self.host_var, width=25)
        self.host_entry.grid(row=0, column=1, padx=2)

        ttk.Label(conn_frame, text="Port:").grid(row=0, column=2, padx=2)
        self.port_var = tk.StringVar(value="38885")
        self.port_entry = ttk.Entry(conn_frame, textvariable=self.port_var, width=8)
        self.port_entry.grid(row=0, column=3, padx=2)

        self.connect_btn = ttk.Button(conn_frame, text="Connect",
                                      command=self.on_connect)
        self.connect_btn.grid(row=0, column=4, padx=4)

        self.discover_btn = ttk.Button(conn_frame, text="Discover",
                                       command=self.on_discover)
        self.discover_btn.grid(row=0, column=5, padx=4)

        self.status_var = tk.StringVar(value="Not connected")
        self.status_label = ttk.Label(conn_frame, textvariable=self.status_var,
                                      foreground="red")
        self.status_label.grid(row=0, column=6, padx=8)

        self.debug_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(conn_frame, text="Debug", variable=self.debug_var).grid(
            row=0, column=7, padx=4)

        # Notebook with tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=8, pady=4)

        self._build_read_tab(notebook)
        self._build_write_tab(notebook, self.root)
        self._build_sound_tab(notebook)
        self._build_sn_tab(notebook)
        self._build_chain_tab(notebook)

        # Bottom: log output
        log_frame = ttk.LabelFrame(self.root, text="Log Output", padding=4)
        log_frame.pack(fill='both', expand=False, padx=8, pady=4)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=12,
                                                  state='disabled',
                                                  font=('Consolas', 9))
        self.log_text.pack(fill='both', expand=True)

        # Redirect stdout to the log widget
        sys.stdout = TextRedirector(self.log_text)

    # ========================================================================
    # Write confirmation helper
    # ========================================================================

    def _confirm_write(self, action_desc):
        """Show a confirmation dialog before any write operation.

        Writes go through the patched firmware's ZB/ZD/ZE session (or the
        per-block W fallback) and are verified by readback — the "okay"
        response is never trusted on its own.
        """
        msg = (f"You are about to: {action_desc}\n\n"
               "This erases and rewrites engine flash. Exactly one engine "
               "should be powered on the track, and power must not be "
               "removed during the write.\n\n"
               "Are you sure you want to continue?")
        return messagebox.askyesno("Confirm Write Operation", msg,
                                   icon='warning')

    # ========================================================================
    # Read & Report Tab
    # ========================================================================

    def _build_read_tab(self, notebook):  # pylint: disable=attribute-defined-outside-init
        """Build the Read & Report tab."""
        tab = ttk.Frame(notebook, padding=10)
        notebook.add(tab, text="Read & Report")

        ttk.Label(tab, text="Read engine data and display formatted reports.",
                  font=('', 10)).pack(anchor='w', pady=(0, 8))

        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill='x')

        ttk.Button(btn_frame, text="Read Engine Info",
                   command=self.run_read_engine_info).pack(side='left', padx=2)
        ttk.Button(btn_frame, text="Read EIS (0x004000)",
                   command=self.run_read_eis).pack(side='left', padx=2)
        ttk.Button(btn_frame, text="Read Capability Bits",
                   command=self.run_read_cap_bits).pack(side='left', padx=2)
        ttk.Button(btn_frame, text="Read Loader Data",
                   command=self.run_read_loader_data).pack(side='left', padx=2)
        ttk.Button(btn_frame, text="Detect Flash Size",
                   command=self.run_detect_flash).pack(side='left', padx=2)

        ttk.Separator(tab, orient='horizontal').pack(fill='x', pady=8)

        ttk.Button(tab, text="Full Report (all data)",
                   command=self.run_full_report).pack(anchor='w', pady=4)

        # Results display
        ttk.Label(tab, text="Results:").pack(anchor='w', pady=(8, 2))
        self.read_results = scrolledtext.ScrolledText(tab, height=18,  # pylint: disable=attribute-defined-outside-init
                                                      font=('Consolas', 9))
        self.read_results.pack(fill='both', expand=True)

    # ========================================================================
    # Write Engine Info Tab
    # ========================================================================

    def _build_write_tab(self, notebook, root):  # pylint: disable=too-many-locals,attribute-defined-outside-init
        """Build the Write Engine Info tab with editable fields."""
        tab = ttk.Frame(notebook, padding=10)
        notebook.add(tab, text="Write Engine Info")

        ttk.Label(tab, text="Edit engine manufacturing data fields and write to flash.",
                  font=('', 10)).pack(anchor='w', pady=(0, 8))

        # Field grid
        fields_frame = ttk.LabelFrame(tab, text="Engine Info Fields", padding=8)
        fields_frame.pack(fill='x')

        self.field_vars = {}  # pylint: disable=attribute-defined-outside-init
        # (key, label, max_chars) — max_chars from dealer loader UI limits
        # Dealer loader limits text fields to 16 chars even though flash is 32
        fields = [
            ('cab_number',     'Cab Number:',     16),
            ('road_name',      'Road Name:',      16),
            ('engine_name',    'Engine Name:',    16),
            ('dsp_filename',   'DSP Filename:',   16),
            ('pcb_rev',        'PCB Rev:',        16),
            ('sound_filename', 'Sound Filename:', 16),
            ('mth_product_num','MTH Product #:',   7),
            ('phone_number',   'Phone Number:',   10),
            ('customer_name',  'Customer Name:',  15),
            ('address1',       'Address 1:',      16),
            ('address2',       'Address 2:',      16),
            ('city',           'City:',           16),
            ('state',          'State:',          16),
            ('zip',            'Zip:',             7),
            ('email',          'Email:',          16),
        ]

        for i, (key, label, max_len) in enumerate(fields):
            row = i // 2
            col = (i % 2) * 2
            ttk.Label(fields_frame, text=label).grid(row=row, column=col,
                                                     sticky='e', padx=2, pady=2)
            var = tk.StringVar(value="")
            self.field_vars[key] = var
            # Reject keystrokes that would exceed max length
            vcmd = (root.register(
                lambda new_text, ml=max_len: len(new_text) <= ml), '%P')
            entry = ttk.Entry(fields_frame, textvariable=var, width=30,
                              validate='key', validatecommand=vcmd)
            entry.grid(row=row, column=col+1, padx=2, pady=2)

        # Buttons
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill='x', pady=8)

        ttk.Button(btn_frame, text="Read Current Values",
                   command=self.run_read_for_edit).pack(side='left', padx=2)
        ttk.Button(btn_frame, text="Write to Engine",
                   command=self.run_write_engine_info).pack(side='left', padx=2)

        # Dealer log options
        log_frame = ttk.Frame(tab)
        log_frame.pack(fill='x', pady=4)
        ttk.Label(log_frame, text="Dealer #:").pack(side='left', padx=2)
        self.dealer_var = tk.StringVar(value="")  # pylint: disable=attribute-defined-outside-init
        ttk.Entry(log_frame, textvariable=self.dealer_var, width=10).pack(
            side='left', padx=2)
        self.stamp_date_var = tk.BooleanVar(value=True)  # pylint: disable=attribute-defined-outside-init
        ttk.Checkbutton(log_frame, text="Stamp date (like dealer loader)",
                        variable=self.stamp_date_var).pack(side='left', padx=8)
        ttk.Label(log_frame, text="Log file:").pack(side='left', padx=(8, 2))
        self.logfile_var = tk.StringVar(value="dealer_log.txt")  # pylint: disable=attribute-defined-outside-init
        ttk.Entry(log_frame, textvariable=self.logfile_var, width=25).pack(
            side='left', padx=2)

    # ========================================================================
    # Sound File Tab
    # ========================================================================

    def _build_sound_tab(self, notebook):  # pylint: disable=attribute-defined-outside-init
        """Build the Sound File tab."""
        tab = ttk.Frame(notebook, padding=10)
        notebook.add(tab, text="Sound File")

        ttk.Label(tab, text="Read or write .mth sound files (flash images).",
                  font=('', 10)).pack(anchor='w', pady=(0, 8))

        # Read sound section
        read_frame = ttk.LabelFrame(tab, text="Read Sound File (Backup Flash)",
                                    padding=8)
        read_frame.pack(fill='x', pady=4)

        ttk.Label(read_frame, text="Output file:").grid(row=0, column=0, padx=2)
        self.read_sound_var = tk.StringVar(value="")  # pylint: disable=attribute-defined-outside-init
        ttk.Entry(read_frame, textvariable=self.read_sound_var,
                  width=40).grid(row=0, column=1, padx=2)
        ttk.Button(read_frame, text="Browse...",
                   command=lambda: self._browse_save(self.read_sound_var)).grid(
            row=0, column=2, padx=2)

        ttk.Label(read_frame, text="Stock file:").grid(row=1, column=0, padx=2)
        self.stock_file_var = tk.StringVar(value="")  # pylint: disable=attribute-defined-outside-init
        ttk.Entry(read_frame, textvariable=self.stock_file_var,
                  width=40).grid(row=1, column=1, padx=2)
        ttk.Button(read_frame, text="Browse...",
                   command=lambda: self._browse_open(self.stock_file_var)).grid(
            row=1, column=2, padx=2)

        ttk.Button(read_frame, text="Read Flash -> .mth",
                   command=self.run_read_sound).grid(row=2, column=0,
                                                     columnspan=3, pady=4)

        # Write sound section
        write_frame = ttk.LabelFrame(tab, text="Write Sound File (Flash .mth)",
                                     padding=8)
        write_frame.pack(fill='x', pady=4)

        ttk.Label(write_frame, text="Input file:").grid(row=0, column=0, padx=2)
        self.write_sound_var = tk.StringVar(value="")  # pylint: disable=attribute-defined-outside-init
        ttk.Entry(write_frame, textvariable=self.write_sound_var,
                  width=40).grid(row=0, column=1, padx=2)
        ttk.Button(write_frame, text="Browse...",
                   command=lambda: self._browse_open(self.write_sound_var)).grid(
            row=0, column=2, padx=2)

        # Options
        opts_frame = ttk.Frame(write_frame)
        opts_frame.grid(row=1, column=0, columnspan=3, pady=4)

        self.preserve_mfg_var = tk.BooleanVar(value=True)  # pylint: disable=attribute-defined-outside-init
        ttk.Checkbutton(opts_frame, text="Preserve Mfg Data",
                        variable=self.preserve_mfg_var).pack(side='left', padx=4)
        self.validate_var = tk.BooleanVar(value=True)  # pylint: disable=attribute-defined-outside-init
        ttk.Checkbutton(opts_frame, text="Validate EIS",
                        variable=self.validate_var).pack(side='left', padx=4)
        self.stamp_loader_var = tk.BooleanVar(value=True)  # pylint: disable=attribute-defined-outside-init
        ttk.Checkbutton(opts_frame, text="Stamp Loader Data",
                        variable=self.stamp_loader_var).pack(side='left', padx=4)
        self.backup_flash_var = tk.BooleanVar(value=False)  # pylint: disable=attribute-defined-outside-init
        ttk.Checkbutton(opts_frame, text="Backup Flash First",
                        variable=self.backup_flash_var).pack(side='left', padx=4)

        # Note: the engine type bit (0x191C:0x20) is set automatically
        # during write by querying the engine via q7E80, exactly as the
        # dealer loader does. No manual checkbox is needed.
        ttk.Label(write_frame,
                  text="Engine type bit (0x191C) is set automatically based on q7E80 query",
                  foreground="gray").grid(row=2, column=0, columnspan=3,
                                          pady=2, sticky='w')

        ttk.Button(write_frame, text="Write .mth -> Flash",
                   command=self.run_write_sound).grid(row=3, column=0,
                                                      columnspan=3, pady=4)

        # Flash recovery section
        rec_frame = ttk.LabelFrame(tab, text="Flash Recovery (raw image restore)",
                                   padding=8)
        rec_frame.pack(fill='x', pady=4)

        ttk.Label(rec_frame, text="Image file:").grid(row=0, column=0, padx=2)
        self.restore_img_var = tk.StringVar(value="")  # pylint: disable=attribute-defined-outside-init
        ttk.Entry(rec_frame, textvariable=self.restore_img_var,
                  width=40).grid(row=0, column=1, padx=2)
        ttk.Button(rec_frame, text="Browse...",
                   command=lambda: self._browse_open(self.restore_img_var)).grid(
            row=0, column=2, padx=2)

        rec_opts = ttk.Frame(rec_frame)
        rec_opts.grid(row=1, column=0, columnspan=3, pady=4, sticky='w')
        self.force_bl_var = tk.BooleanVar(value=False)  # pylint: disable=attribute-defined-outside-init
        ttk.Checkbutton(rec_opts, text="Force bootloader region (DANGEROUS)",
                        variable=self.force_bl_var).pack(side='left', padx=4)

        ttk.Label(rec_frame,
                  text="Accepts a .flash_backup or full-flash .mth image. "
                       "Bootloader/DSP sector is skipped unless forced.",
                  foreground="gray").grid(row=2, column=0, columnspan=3,
                                          pady=2, sticky='w')

        ttk.Button(rec_frame, text="Restore Image -> Flash",
                   command=self.run_restore_flash).grid(row=3, column=0,
                                                        columnspan=3, pady=4)

        # Full image (consumer download zip) section
        img_frame = ttk.LabelFrame(tab,
                                   text="Full Image (consumer download .zip)",
                                   padding=8)
        img_frame.pack(fill='x', pady=4)

        ttk.Label(img_frame, text="Zip file:").grid(row=0, column=0, padx=2)
        self.image_zip_var = tk.StringVar(value="")  # pylint: disable=attribute-defined-outside-init
        ttk.Entry(img_frame, textvariable=self.image_zip_var,
                  width=40).grid(row=0, column=1, padx=2)
        ttk.Button(img_frame, text="Browse...",
                   command=lambda: self._browse_open(self.image_zip_var)).grid(
            row=0, column=2, padx=2)

        ttk.Label(img_frame,
                  text="MTH consumer download zip — writes chain code "
                       "regions AND the sound file in one pass.",
                  foreground="gray").grid(row=1, column=0, columnspan=3,
                                          pady=2, sticky='w')

        ttk.Button(img_frame, text="Write Zip -> Engine",
                   command=self.run_write_image).grid(row=2, column=0,
                                                      columnspan=3, pady=4)

    # ========================================================================
    # SN File Tab
    # ========================================================================

    def _build_sn_tab(self, notebook):  # pylint: disable=attribute-defined-outside-init
        """Build the SN File tab."""
        tab = ttk.Frame(notebook, padding=10)
        notebook.add(tab, text="SN File")

        ttk.Label(tab, text="Save or load MTH serial number files.",
                  font=('', 10)).pack(anchor='w', pady=(0, 8))

        # Save section
        save_frame = ttk.LabelFrame(tab, text="Save SN File from Engine",
                                    padding=8)
        save_frame.pack(fill='x', pady=4)

        ttk.Label(save_frame, text="Output file:").grid(row=0, column=0, padx=2)
        self.save_sn_var = tk.StringVar(value="")  # pylint: disable=attribute-defined-outside-init
        ttk.Entry(save_frame, textvariable=self.save_sn_var,
                  width=40).grid(row=0, column=1, padx=2)
        ttk.Button(save_frame, text="Browse...",
                   command=lambda: self._browse_save(self.save_sn_var)).grid(
            row=0, column=2, padx=2)
        ttk.Button(save_frame, text="Save SN File",
                   command=self.run_save_sn).grid(row=1, column=0,
                                                  columnspan=3, pady=4)

        # Load section
        load_frame = ttk.LabelFrame(tab, text="Load SN File to Engine",
                                    padding=8)
        load_frame.pack(fill='x', pady=4)

        ttk.Label(load_frame, text="Input file:").grid(row=0, column=0, padx=2)
        self.load_sn_var = tk.StringVar(value="")  # pylint: disable=attribute-defined-outside-init
        ttk.Entry(load_frame, textvariable=self.load_sn_var,
                  width=40).grid(row=0, column=1, padx=2)
        ttk.Button(load_frame, text="Browse...",
                   command=lambda: self._browse_open(self.load_sn_var)).grid(
            row=0, column=2, padx=2)
        ttk.Button(load_frame, text="Preview SN File",
                   command=self.run_preview_sn).grid(row=1, column=0,
                                                     columnspan=3, pady=2)
        ttk.Button(load_frame, text="Write SN File to Engine",
                   command=self.run_load_sn).grid(row=2, column=0,
                                                  columnspan=3, pady=4)

    # ========================================================================
    # Chain / DSP Code Tab
    # ========================================================================

    def _build_chain_tab(self, notebook):  # pylint: disable=attribute-defined-outside-init
        """Build the Chain / DSP tab."""
        tab = ttk.Frame(notebook, padding=10)
        notebook.add(tab, text="Chain / DSP")

        ttk.Label(tab, text="Inspect and write chain/DSP code S-record and zip files.",
                  font=('', 10)).pack(anchor='w', pady=(0, 8))

        # Inspect S-record / chain zip section
        inspect_frame = ttk.LabelFrame(tab, text="Inspect S-Record or Chain Zip",
                                       padding=8)
        inspect_frame.pack(fill='x', pady=4)

        ttk.Label(inspect_frame, text="File:").grid(row=0, column=0, padx=2)
        self.srec_inspect_var = tk.StringVar(value="")  # pylint: disable=attribute-defined-outside-init
        ttk.Entry(inspect_frame, textvariable=self.srec_inspect_var,
                  width=45).grid(row=0, column=1, padx=2)
        ttk.Button(inspect_frame, text="Browse...",
                   command=lambda: self._browse_open(self.srec_inspect_var,
                                                     "*.srec;*.zip")).grid(
            row=0, column=2, padx=2)
        ttk.Button(inspect_frame, text="Inspect",
                   command=self.run_inspect_srec).grid(row=1, column=0,
                                                       columnspan=3, pady=4)

        # Read EIS DSP info section
        eis_frame = ttk.LabelFrame(tab, text="Read DSP Info from Engine EIS",
                                   padding=8)
        eis_frame.pack(fill='x', pady=4)

        ttk.Button(eis_frame, text="Read EIS DSP Address/Length",
                   command=self.run_read_eis_dsp).pack(pady=4)

        # Write chain zip section (primary workflow, like the loader)
        write_frame = ttk.LabelFrame(tab, text="Write Chain Code to Engine",
                                     padding=8)
        write_frame.pack(fill='x', pady=4)

        ttk.Label(write_frame, text="Chain zip:").grid(row=0, column=0,
                                                        padx=2, pady=2)
        self.chain_file_var = tk.StringVar(value="")  # pylint: disable=attribute-defined-outside-init
        ttk.Entry(write_frame, textvariable=self.chain_file_var,
                  width=45).grid(row=0, column=1, padx=2, pady=2)
        ttk.Button(write_frame, text="Browse...",
                   command=lambda: self._browse_open(self.chain_file_var,
                                                     "*.zip")).grid(
            row=0, column=2, padx=2, pady=2)

        ttk.Label(write_frame,
                  text="The zip is written as one chain transaction: all S-records\n"
                       "are written to their EIS regions (DSP, FPGA, CV, Boiler,\n"
                       "Hardware) in filelist.txt order, with one power cycle at end.",
                  foreground="gray", justify='left').grid(
            row=1, column=0, columnspan=3, pady=2)

        # Board revision display (filled in when a zip is selected)
        self.chain_rev_label = ttk.Label(write_frame, text="",  # pylint: disable=attribute-defined-outside-init
                                          foreground="blue")
        self.chain_rev_label.grid(row=2, column=0, columnspan=3, pady=2)

        ttk.Button(write_frame, text="Write Chain Zip to Engine",
                   command=self.run_write_chain).grid(row=3, column=0,
                                                      columnspan=3, pady=4)

        # Advanced: single S-record (for targeted DSP programming)
        advanced_frame = ttk.LabelFrame(tab, text="Advanced: Write Single S-Record",
                                        padding=8)
        advanced_frame.pack(fill='x', pady=4)

        ttk.Label(advanced_frame, text="S-record:").grid(row=0, column=0,
                                                          padx=2, pady=2)
        self.srec_write_var = tk.StringVar(value="")  # pylint: disable=attribute-defined-outside-init
        ttk.Entry(advanced_frame, textvariable=self.srec_write_var,
                  width=45).grid(row=0, column=1, padx=2, pady=2)
        ttk.Button(advanced_frame, text="Browse...",
                   command=lambda: self._browse_open(self.srec_write_var,
                                                     "*.srec")).grid(
            row=0, column=2, padx=2, pady=2)

        ttk.Label(advanced_frame, text="DSP addr (hex, optional):").grid(
            row=1, column=0, padx=2, pady=2)
        self.chain_addr_var = tk.StringVar(value="")  # pylint: disable=attribute-defined-outside-init
        ttk.Entry(advanced_frame, textvariable=self.chain_addr_var,
                  width=15).grid(row=1, column=1, sticky='w', padx=2, pady=2)

        ttk.Label(advanced_frame, text="Max len (hex, optional):").grid(
            row=2, column=0, padx=2, pady=2)
        self.chain_maxlen_var = tk.StringVar(value="")  # pylint: disable=attribute-defined-outside-init
        ttk.Entry(advanced_frame, textvariable=self.chain_maxlen_var,
                  width=15).grid(row=2, column=1, sticky='w', padx=2, pady=2)

        ttk.Label(advanced_frame,
                  text="For targeted DSP programming only. Use chain zip above\n"
                       "for full chain updates. Leave addr/len blank to auto-detect.",
                  foreground="gray", justify='left').grid(
            row=3, column=0, columnspan=3, pady=2)

        ttk.Button(advanced_frame, text="Write Single S-Record to Engine",
                   command=self.run_write_single_srec).grid(
            row=4, column=0, columnspan=3, pady=4)

    # ========================================================================
    # Connection
    # ========================================================================

    def on_discover(self):
        """Auto-discover WTIU via mDNS."""
        self._log("Discovering WTIU...")
        try:
            devices = discover_wtiu(debug=self.debug_var.get())
            if not devices:
                self._log("No WTIU found")
                messagebox.showinfo("Discovery", "No WTIU found on the network.")
                return
            if len(devices) == 1:
                d = devices[0]
                self.host_var.set(d['host'])
                self.port_var.set(str(d['port']))
                self._log(f"Found WTIU: {d['name']} at {d['host']}:{d['port']}")
            else:
                # Multiple devices — pick the first and log all
                d = devices[0]
                self.host_var.set(d['host'])
                self.port_var.set(str(d['port']))
                self._log(f"Found {len(devices)} WTIU devices, using first:")
                for dev in devices:
                    self._log(f"  {dev['name']} at {dev['host']}:{dev['port']}")
        except Exception as e:  # pylint: disable=broad-exception-caught
            self._log(f"Discovery error: {e}")

    def on_connect(self):
        """Connect or disconnect from the WTIU."""
        if self.conn is not None:
            # Disconnect
            try:
                self.conn.disconnect()
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            self.conn = None
            self.prog = None
            self.connect_btn.config(text="Connect")
            self.status_var.set("Not connected")
            self.status_label.config(foreground="red")
            self._log("Disconnected")
            return

        host = self.host_var.get().strip()
        if not host:
            messagebox.showerror("Error", "Enter a host or click Discover")
            return

        port = int(self.port_var.get().strip())
        self._log(f"Connecting to {host}:{port}...")

        try:
            self.conn = WTIUConnection(host, port, debug=self.debug_var.get())
            self.conn.connect()
            if not self.conn.authenticate():
                self._log("Authentication failed!")
                self.conn = None
                messagebox.showerror("Error", "Authentication failed")
                return

            self.prog = EngineProgrammer(self.conn, debug=self.debug_var.get())
            self.connect_btn.config(text="Disconnect")
            self.status_var.set(f"Connected to {host}")
            self.status_label.config(foreground="green")
            self._log("Connected and authenticated")
        except Exception as e:  # pylint: disable=broad-exception-caught
            self._log(f"Connection error: {e}")
            self.conn = None
            messagebox.showerror("Error", f"Connection failed: {e}")

    # ========================================================================
    # Helpers
    # ========================================================================

    def _log(self, msg):
        """Append a message to the log."""
        self.log_text.configure(state='normal')
        self.log_text.insert('end', msg + '\n')
        self.log_text.see('end')
        self.log_text.configure(state='disabled')

    def _browse_save(self, var):
        """Open a save file dialog and set the variable."""
        path = filedialog.asksaveasfilename(
            defaultextension=".mth",
            filetypes=[("MTH files", "*.mth"), ("Text files", "*.txt"),
                       ("All files", "*.*")])
        if path:
            var.set(path)

    def _browse_open(self, var, default_ext=None):
        """Open a file dialog and set the variable."""
        if default_ext and default_ext == "*.zip":
            filetypes = [("Zip files", "*.zip"), ("All files", "*.*")]
        elif default_ext and default_ext == "*.srec;*.zip":
            filetypes = [("Chain files", "*.zip;*.srec"),
                         ("Zip files", "*.zip"),
                         ("S-record files", "*.srec"),
                         ("All files", "*.*")]
        elif default_ext and default_ext == "*.srec":
            filetypes = [("S-record files", "*.srec"), ("All files", "*.*")]
        else:
            filetypes = [("MTH files", "*.mth"), ("Text files", "*.txt"),
                         ("All files", "*.*")]
        path = filedialog.askopenfilename(filetypes=filetypes)
        if path:
            var.set(path)
            # If this is the chain zip variable, update the revision label
            if var is self.chain_file_var and path.lower().endswith('.zip'):
                self._update_chain_rev_label(path)

    def _update_chain_rev_label(self, path):
        """Update the board revision label when a chain zip is selected."""
        try:
            rev = detect_chain_revision(path)
            if rev:
                self.chain_rev_label.config(
                    text=f"Board revision: Rev {rev}")
            else:
                self.chain_rev_label.config(
                    text="Board revision: unknown (no engine-hdr found)")
        except Exception:  # pylint: disable=broad-exception-caught
            self.chain_rev_label.config(text="")

    def _check_connected(self):
        """Check if connected. Returns True if connected."""
        if self.prog is None:
            messagebox.showerror("Error", "Not connected to WTIU")
            return False
        return True

    def _run_in_thread(self, func):
        """Run a function in a background thread to avoid blocking the UI."""
        def wrapper():
            try:
                func()
            except Exception as e:  # pylint: disable=broad-exception-caught
                self._log(f"Error: {e}")
            finally:
                self.root.after(0, self._set_buttons_normal)

        self._set_buttons_disabled()
        t = threading.Thread(target=wrapper, daemon=True)
        t.start()

    def _set_buttons_disabled(self):
        """Disable all buttons during operations."""
        for widget in self.root.winfo_children():
            self._disable_buttons_recursive(widget)

    def _disable_buttons_recursive(self, widget):
        """Recursively disable ttk.Button widgets."""
        for child in widget.winfo_children():
            if isinstance(child, ttk.Button):
                child.state(['disabled'])
            self._disable_buttons_recursive(child)

    def _set_buttons_normal(self):
        """Re-enable all buttons."""
        for widget in self.root.winfo_children():
            self._enable_buttons_recursive(widget)

    def _enable_buttons_recursive(self, widget):
        """Recursively enable ttk.Button widgets."""
        for child in widget.winfo_children():
            if isinstance(child, ttk.Button):
                child.state(['!disabled'])
            self._enable_buttons_recursive(child)

    def _confirm(self, message):
        """Show a yes/no confirmation dialog. Returns True if yes."""
        return messagebox.askyesno("Confirm", message)

    # ========================================================================
    # Read & Report Actions
    # ========================================================================

    def run_read_engine_info(self):
        """Read engine info and display it in the results box."""
        if not self._check_connected():
            return
        self._run_in_thread(self._do_read_engine_info)

    def _do_read_engine_info(self):
        """Worker that reads engine info and populates the edit fields."""
        self._clear_results()
        self._print_results("=== Reading Engine Info ===\n")
        if not self.prog.setup_engine():
            return
        data = self.prog.read_engine_info(extended=True)
        if data:
            info = parse_engine_info(data)
            self.engine_info_data = data
            self._print_results("\n--- Engine Info ---\n")
            for key, val in info.items():
                if val and key not in ('composite_parts',):
                    self._print_results(f"  {key}: {val}\n")
            # Populate the write tab fields
            self.root.after(0, lambda: self._populate_fields(info))
        else:
            self._print_results("  Failed to read engine info\n")

    def _populate_fields(self, info):
        """Populate the write tab entry fields from parsed info."""
        for key, var in self.field_vars.items():
            var.set(info.get(key, ''))

    def _clear_results(self):
        """Clear the Results box on the Read & Report tab."""
        self.read_results.after(0, lambda: self.read_results.delete('1.0', 'end'))

    def _print_results(self, text):
        """Append text to the Results box (thread-safe)."""
        self.read_results.after(0, self._append_results, text)

    def _append_results(self, text):
        """Append text to the Results box (called on the main thread)."""
        self.read_results.insert('end', text)
        self.read_results.see('end')

    def run_read_eis(self):
        """Read the EIS block at 0x004000 and display it."""
        if not self._check_connected():
            return
        self._run_in_thread(self._do_read_eis)

    def _do_read_eis(self):
        """Worker that reads and displays the EIS block."""
        self._clear_results()
        self._print_results("=== Reading EIS (0x004000) ===\n")
        if not self.prog.setup_engine():
            return
        data = self.prog.read_raw(0x004000, 0x100)
        if data:
            import io  # pylint: disable=import-outside-toplevel
            buf = io.StringIO()
            hex_dump(data, 0x004000, file=buf)
            self._print_results(buf.getvalue())
            # Also show parsed EIS records
            self._print_results("\n=== Parsed EIS Records ===\n")
            records = self.prog.read_eis_records()
            if records:
                self._print_results(
                    f"  EIS Length: {records.get('eis_len', 0)} bytes\n")
                for rec in records.get('records', []):
                    if rec.get('addr') is not None:
                        self._print_results(
                            f"  {rec['name']}: addr=0x{rec['addr']:06X}, "
                            f"max_len=0x{rec['max_len']:06X} "
                            f"({rec['max_len']} bytes)\n")
                    else:
                        self._print_results(
                            f"  {rec['name']} at offset 0x{rec['offset']:02X}\n")
            else:
                self._print_results("  No EIS records found\n")
        else:
            self._print_results("  Failed to read EIS\n")

    def run_read_cap_bits(self):
        """Read capability bits at 0x1900 and display them."""
        if not self._check_connected():
            return
        self._run_in_thread(self._do_read_cap_bits)

    def _do_read_cap_bits(self):
        """Worker that reads and displays capability bits."""
        self._clear_results()
        self._print_results("=== Reading Capability Bits (0x1900) ===\n")
        if not self.prog.setup_engine():
            return
        data = self.prog.read_capability_bits()
        if data:
            import io  # pylint: disable=import-outside-toplevel
            buf = io.StringIO()
            hex_dump(data, 0x1900, file=buf)
            self._print_results(buf.getvalue())
            # Show labeled feature bits
            labeled = decode_capability_bits(data)
            if labeled:
                self._print_results("\n  Labeled feature bits:\n")
                for addr, mask, label in labeled:
                    self._print_results(f"    0x{addr:04X} bit 0x{mask:02X}: {label}\n")
            # Show raw set bits
            self._print_results("\n  All set bits (raw):\n")
            for i, b in enumerate(data):
                if b not in (0, 0xFF):
                    bits = [str(bit) for bit in range(8) if b & (1 << bit)]
                    self._print_results(
                        f"    Byte {i} (0x{0x1900+i:04X}): "
                        f"0x{b:02X} = bits {', '.join(bits)}\n")
        else:
            self._print_results("  Failed to read capability bits\n")

    def run_read_loader_data(self):
        """Read loader data at 0x1950 and display it."""
        if not self._check_connected():
            return
        self._run_in_thread(self._do_read_loader_data)

    def _do_read_loader_data(self):
        """Worker that reads and displays loader data."""
        self._clear_results()
        self._print_results("=== Reading Loader Data (0x1950) ===\n")
        if not self.prog.setup_engine():
            return
        data = self.prog.read_raw(0x1950, 128)
        if data:
            ld = parse_loader_data(data)
            if ld:
                self._print_results(f"  PC Name:        {ld.get('pc_name', '')}\n")
                self._print_results(f"  Date:           {ld.get('date', '')}\n")
                self._print_results(f"  Time:           {ld.get('time', '')}\n")
                self._print_results(f"  Loader Version: {ld.get('version', '')}\n")
            else:
                self._print_results("  (no loader data stamped)\n")
        else:
            self._print_results("  Failed to read loader data\n")

    def run_detect_flash(self):
        """Detect the engine flash size."""
        if not self._check_connected():
            return
        self._run_in_thread(self._do_detect_flash)

    def _do_detect_flash(self):
        """Worker that detects the engine flash size."""
        self._clear_results()
        self._print_results("=== Detecting Flash Size ===\n")
        if not self.prog.setup_engine():
            return
        size = self.prog.detect_flash_size()
        if size:
            self._print_results(f"  Flash size: {size} bytes ({size // 1024} KB)\n")
        else:
            self._print_results("  Could not detect flash size\n")

    def run_full_report(self):
        """Generate and display a full engine report."""
        if not self._check_connected():
            return
        self._run_in_thread(self._do_full_report)

    def _do_full_report(self):
        """Worker that generates a full engine report."""
        self._clear_results()
        if not self.prog.setup_engine():
            return
        import io  # pylint: disable=import-outside-toplevel
        buf = io.StringIO()
        self.prog.print_report(file=buf)
        self._print_results(buf.getvalue())

    # ========================================================================
    # Write Engine Info Actions
    # ========================================================================

    def run_read_for_edit(self):
        """Read current engine info and populate the edit fields."""
        if not self._check_connected():
            return
        self._run_in_thread(self._do_read_engine_info)

    def run_write_engine_info(self):
        """Write the edited engine info fields to the engine."""
        if not self._check_connected():
            return
        self._run_in_thread(self._do_write_engine_info)

    def _do_write_engine_info(self):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
        """Worker that writes edited engine info to flash."""
        # Check if any extended fields are set
        extended_keys = ['address1', 'address2', 'city', 'state', 'zip', 'email']
        use_extended = any(self.field_vars[k].get().strip() for k in extended_keys)

        print("\n=== Write Engine Info ===")
        # Don't re-setup if already in programming mode — the dealer loader
        # only calls SetSCSMode once and flows directly to Lf. Re-sending m4
        # can cause "Lf input error" on some engines.
        if not getattr(self.prog, '_engine_setup_done', False):
            if not self.prog.setup_engine():
                return
        else:
            print("  (Engine already in programming mode, skipping setup)")

        # Read existing
        print("Reading existing engine info...")
        existing = self.prog.read_engine_info(extended=use_extended)
        if existing is None:
            print("Cannot read existing engine info. Aborting.")
            return

        # Build new data from fields
        kwargs = {}
        for key, var in self.field_vars.items():
            val = var.get().strip()
            if val:
                kwargs[key] = val

        # Pass dealer number and stamp_date through to build_engine_info
        # so the composite field and YYMMDD are rebuilt like the dealer loader
        dealer = self.dealer_var.get().strip()
        if dealer:
            kwargs['dealer_number'] = dealer
        kwargs['stamp_date'] = self.stamp_date_var.get()

        if not kwargs:
            print("No fields to write. Fill in at least one field.")
            return

        new_data = build_engine_info(existing, **kwargs)
        if new_data == existing:
            print("No changes to write.")
            return

        # Show changes
        old_info = parse_engine_info(existing)
        new_info = parse_engine_info(new_data)
        print("\nChanges:")
        for key in self.field_vars:
            old_val = old_info.get(key, '')
            new_val = new_info.get(key, '')
            if old_val != new_val:
                print(f"  {key}: \"{old_val}\" -> \"{new_val}\"")

        # Show composite/date/serial changes (mirrors dealer loader MergeMfgData)
        if self.stamp_date_var.get():
            old_cp = old_info.get('composite_parts', {})
            new_cp = new_info.get('composite_parts', {})
            old_ymd = old_info.get('date_yymmdd', '')
            new_ymd = new_info.get('date_yymmdd', '')
            if old_ymd != new_ymd:
                print(f"  Date (YYMMDD): \"{old_ymd}\" -> \"{new_ymd}\"")
            old_serial = old_cp.get('comp_serial', '')
            new_serial = new_cp.get('comp_serial', '')
            if old_serial != new_serial:
                print(f"  Serial+1:      \"{old_serial}\" -> \"{new_serial}\"")
            old_dealer = old_cp.get('dealer_number', '')
            new_dealer = new_cp.get('dealer_number', '')
            if old_dealer != new_dealer:
                print(f"  Dealer Number: \"{old_dealer}\" -> \"{new_dealer}\"")

        # Confirm
        if not self._confirm_write(
                "erase and rewrite sector 0 (16KB) to update "
                "engine info at 0x001DD2"):
            print("Aborted.")
            return

        if self.prog.write_engine_info(new_data):
            print("Engine info written successfully!")
            # Dealer log
            if dealer:
                from mth_engine_programmer import append_dealer_log  # pylint: disable=import-outside-toplevel
                append_dealer_log(self.logfile_var.get(), dealer, new_data)
        else:
            print("Write failed! Check sector0_backup.bin for recovery.")

    # ========================================================================
    # Sound File Actions
    # ========================================================================

    def run_read_sound(self):
        """Read the engine flash to a .mth sound file."""
        if not self._check_connected():
            return
        path = self.read_sound_var.get().strip()
        if not path:
            messagebox.showerror("Error", "Choose an output file first")
            return
        stock = self.stock_file_var.get().strip() or None
        self._run_in_thread(lambda: self._do_read_sound(path, stock))

    def _do_read_sound(self, path, stock_file=None):
        """Worker that reads the engine flash to a .mth file."""
        print(f"\n=== Reading Sound File -> {path} ===")
        if not self.prog.setup_engine():
            return
        if self.prog.read_sound_file(path, stock_file=stock_file):
            print(f"Sound file saved to {path}")
        else:
            print("Failed to read sound file")

    def run_write_sound(self):
        """Write a .mth sound file to the engine flash."""
        if not self._check_connected():
            return
        path = self.write_sound_var.get().strip()
        if not path:
            messagebox.showerror("Error", "Choose an input file first")
            return
        self._run_in_thread(lambda: self._do_write_sound(path))

    def _do_write_sound(self, path):
        """Worker that writes a .mth file to engine flash."""
        print(f"\n=== Writing Sound File: {path} ===")
        if not self.prog.setup_engine():
            return

        # The engine type bit (0x191C:0x20) is now set automatically
        # inside write_sound_file by querying the engine via q7E80,
        # exactly as the dealer loader does. No manual set_bits needed.

        # Confirm
        if not self._confirm_write(
                f"write {path} to engine flash — "
                f"this will erase and rewrite flash sectors"):
            print("Aborted.")
            return

        if self.prog.write_sound_file(
                path,
                preserve_mfg=self.preserve_mfg_var.get(),
                validate=self.validate_var.get(),
                stamp_loader=self.stamp_loader_var.get(),
                backup_flash=self.backup_flash_var.get(),
                assume_yes=True, confirm_cb=self._confirm):
            print("Sound file written successfully!")
            # Dealer log
            dealer = self.dealer_var.get().strip()
            if dealer:
                from mth_engine_programmer import append_dealer_log  # pylint: disable=import-outside-toplevel
                eng_info = self.prog.read_engine_info()
                if eng_info:
                    append_dealer_log(self.logfile_var.get(), dealer, eng_info)
        else:
            print("Failed to write sound file")

    def run_restore_flash(self):
        """Restore engine flash from a raw image (.flash_backup/.mth)."""
        if not self._check_connected():
            return
        path = self.restore_img_var.get().strip()
        if not path:
            messagebox.showerror("Error", "Choose an image file first")
            return
        force_bl = self.force_bl_var.get()
        desc = (f"restore {path} to engine flash — this erases and "
                f"rewrites whole flash sectors")
        if force_bl:
            desc += (" — INCLUDING the bootloader/DSP region: if the "
                     "program-mode code lives there, a failed write "
                     "leaves the engine unrecoverable")
        if not self._confirm_write(desc):
            print("Aborted.")
            return
        self._run_in_thread(lambda: self._do_restore_flash(path, force_bl))

    def _do_restore_flash(self, path, force_bl):
        """Worker that restores a raw flash image to the engine."""
        print(f"\n=== Restoring Flash Image: {path} ===")
        try:
            with open(path, 'rb') as f:
                data = f.read()
        except OSError as e:
            print(f"Cannot read {path}: {e}")
            return
        if not self.prog.setup_engine():
            return
        if self.prog.restore_flash(data, force_bootloader=force_bl,
                                   assume_yes=True):
            print("Flash image restored successfully!")
        else:
            print("Restore failed or incomplete — see log")

    def run_write_image(self):
        """Program the engine from a consumer download zip (chain+sound)."""
        if not self._check_connected():
            return
        path = self.image_zip_var.get().strip()
        if not path:
            messagebox.showerror("Error", "Choose a consumer zip first")
            return
        if not self._confirm_write(
                f"program the engine from {path} — writes chain code "
                "regions AND the sound file in one pass"):
            print("Aborted.")
            return
        self._run_in_thread(lambda: self._do_write_image(path))

    def _do_write_image(self, path):
        """Worker that programs the engine from a consumer zip."""
        print(f"\n=== Writing Consumer Image: {path} ===")
        if not self.prog.setup_engine():
            return
        if self.prog.write_consumer_zip(
                path,
                preserve_mfg=self.preserve_mfg_var.get(),
                validate=self.validate_var.get(),
                stamp_loader=self.stamp_loader_var.get(),
                backup_flash=self.backup_flash_var.get(),
                assume_yes=True, confirm_cb=self._confirm):
            print("Consumer image written successfully!")
        else:
            print("Image write failed — see log")

    # ========================================================================
    # SN File Actions
    # ========================================================================

    def run_save_sn(self):
        """Save the engine serial number to a file."""
        if not self._check_connected():
            return
        path = self.save_sn_var.get().strip()
        if not path:
            messagebox.showerror("Error", "Choose an output file first")
            return
        self._run_in_thread(lambda: self._do_save_sn(path))

    def _do_save_sn(self, path):
        """Worker that saves the engine SN to a file."""
        print(f"\n=== Saving SN File -> {path} ===")
        if not self.prog.setup_engine():
            return
        eng_info = self.prog.read_engine_info()
        if eng_info:
            save_serial_number_file(path, eng_info)
        else:
            print("  Could not read engine info")

    def run_preview_sn(self):
        """Preview an SN file without writing."""
        path = self.load_sn_var.get().strip()
        if not path:
            messagebox.showerror("Error", "Choose a file first")
            return
        self._run_in_thread(lambda: self._do_preview_sn(path))

    def _do_preview_sn(self, path):
        """Worker that previews an SN file without writing."""
        print(f"\n=== Previewing SN File: {path} ===")
        sn = load_serial_number_file(path)
        if sn is None:
            print("  Invalid SN file")
        else:
            print("  SN file is valid. Fields will be written when you click "
                  "'Write SN File to Engine'")

    def run_load_sn(self):
        """Load a serial number file and write it to the engine."""
        if not self._check_connected():
            return
        path = self.load_sn_var.get().strip()
        if not path:
            messagebox.showerror("Error", "Choose a file first")
            return
        self._run_in_thread(lambda: self._do_load_sn(path))

    def _do_load_sn(self, path):
        """Worker that loads an SN file and writes it to the engine."""
        print(f"\n=== Loading SN File: {path} ===")
        sn_fields = load_serial_number_file(path)
        if sn_fields is None:
            return

        if not self.prog.setup_engine():
            return

        # Read existing
        print("Reading existing engine info...")
        existing = self.prog.read_engine_info()
        if existing is None:
            print("Cannot read existing engine info. Aborting.")
            return

        new_data = build_engine_info(existing, **sn_fields)
        if new_data == existing:
            print("No changes to write (SN file matches existing data).")
            return

        # Show changes
        old_info = parse_engine_info(existing)
        new_info = parse_engine_info(new_data)
        print("\nChanges:")
        for key in sn_fields:
            old_val = old_info.get(key, '')
            new_val = new_info.get(key, '')
            if old_val != new_val:
                print(f"  {key}: \"{old_val}\" -> \"{new_val}\"")

        if not self._confirm_write("write SN data to engine flash"):
            print("Aborted.")
            return

        if self.prog.write_engine_info(new_data):
            print("SN data written successfully!")
            dealer = self.dealer_var.get().strip()
            if dealer:
                from mth_engine_programmer import append_dealer_log  # pylint: disable=import-outside-toplevel
                append_dealer_log(self.logfile_var.get(), dealer, new_data)
        else:
            print("Failed to write SN data")

    # ========================================================================
    # Chain / DSP Code Actions
    # ========================================================================

    def run_inspect_srec(self):
        """Inspect an S-record or chain zip file without connecting to the engine."""
        path = self.srec_inspect_var.get().strip()
        if not path:
            messagebox.showerror("Error", "Choose a file first")
            return
        self._run_in_thread(lambda: self._do_inspect_srec(path))

    def _do_inspect_srec(self, path):
        """Dispatch inspection to the appropriate handler based on file type."""
        if path.lower().endswith('.zip'):
            self._do_inspect_chain_zip(path)
        else:
            self._do_inspect_srec_file(path)

    def _do_inspect_srec_file(self, path):
        """Inspect a single S-record file and print its info."""
        print(f"\n=== Inspecting S-Record: {path} ===")
        try:
            srec = parse_srec(path)
            print_srec_info(srec)
        except FileNotFoundError:
            print(f"  File not found: {path}")
        except Exception as e:  # pylint: disable=broad-exception-caught
            print(f"  Error parsing S-record: {e}")

    def _do_inspect_chain_zip(self, path):  # pylint: disable=too-many-locals,too-many-statements
        """Inspect a chain zip file: list members, S0 headers, TPL mapping, and board revision."""
        import zipfile  # pylint: disable=import-outside-toplevel
        import tempfile  # pylint: disable=import-outside-toplevel
        # os is already imported at module level; re-import here for locality
        import os  # pylint: disable=import-outside-toplevel,reimported,redefined-outer-name

        print(f"\n=== Inspecting Chain Zip: {path} ===")

        if not zipfile.is_zipfile(path):
            print("  ERROR: Not a valid zip file")
            return

        # Detect board revision
        chain_rev = detect_chain_revision(path)
        if chain_rev:
            print(f"  Board revision: Rev {chain_rev}")
        else:
            print("  Board revision: unknown (no engine-hdr found)")

        tpl_to_region = {  # pylint: disable=invalid-name
            '2002': 'DSP (engine-hdr)',
            '2003': 'FPGA (mth_fpga-hdr)',
            '2007': 'DCC_CV (cv-hdr)',
            '2009': 'Boiler (boiler-hdr)',
            '200A': 'Hardware (hardware-hdr)',
        }

        with tempfile.TemporaryDirectory(prefix='mth_inspect_') as tmpdir:
            with zipfile.ZipFile(path) as zf:
                zf.extractall(tmpdir)
                members = zf.namelist()
            print(f"  Zip members: {members}")

            filelist_path = os.path.join(tmpdir, 'filelist.txt')
            if os.path.exists(filelist_path):
                with open(filelist_path, 'r', encoding='utf-8') as f:
                    file_list = [line.strip() for line in f if line.strip()]
                print(f"  File list ({len(file_list)} files)")
            else:
                file_list = sorted([f for f in os.listdir(tmpdir)
                                    if f.endswith('.srec')])
                print(f"  No filelist.txt, using {len(file_list)} .srec files")

            print()
            for fname in file_list:
                fpath = os.path.join(tmpdir, fname)
                if not os.path.exists(fpath):
                    print(f"  {fname}: NOT FOUND")
                    continue

                fields = parse_s0_header(fpath)
                if not fields:
                    print(f"  {fname}: no S0 header")
                    continue

                tpl = fields.get('TPL', '?')
                region = tpl_to_region.get(tpl, f'Unknown (TPL={tpl})')
                brd = fields.get('BRD', '?')
                ver = fields.get('VER', '?')
                vstring = fields.get('VSTRING', '')
                mth = fields.get('MTH', '?')

                # Get size
                try:
                    srec = parse_srec(fpath)
                    _base_addr, code_data = srec_to_binary(srec)
                    size = len(code_data)
                except Exception:  # pylint: disable=broad-exception-caught
                    size = 0

                ver_str = f"VER={ver}"
                if vstring:
                    ver_str += f" ({vstring})"

                print(f"  {fname}:")
                print(f"    MTH={mth}, BRD={brd}, TPL={tpl} -> {region}")
                print(f"    {ver_str}, size={size} bytes")
            print()


    def run_read_eis_dsp(self):
        """Read EIS and display DSP code address/length info."""
        if not self._check_connected():
            return
        self._run_in_thread(self._do_read_eis_dsp)

    def _do_read_eis_dsp(self):
        """Worker that reads EIS and displays DSP code info."""
        print("\n=== EIS DSP Code Info ===")
        if not self.prog.setup_engine():
            return
        dsp_addr, dsp_max = self.prog.read_eis_dsp_info()
        if dsp_addr is not None:
            print(f"  DSP Flash Address: 0x{dsp_addr:06X}")
            print(f"  DSP Max Length:    0x{dsp_max:06X} ({dsp_max} bytes)")
        else:
            print("  Could not find DSP code info in EIS")

    def run_write_chain(self):
        """Write a chain zip file to the engine (primary workflow, like the loader)."""
        if not self._check_connected():
            return
        path = self.chain_file_var.get().strip()
        if not path:
            messagebox.showerror("Error", "Choose a chain zip file first")
            return
        if not path.lower().endswith('.zip'):
            messagebox.showerror("Error",
                "This button is for chain .zip files.\n"
                "Use the Advanced section below for individual .srec files.")
            return
        self._run_in_thread(lambda: self._do_write_chain_zip(path))

    def _do_write_chain_zip(self, path):
        """Worker that writes a chain zip to the engine."""
        print(f"\n=== Writing Chain Zip: {path} ===")

        if not self.prog.setup_engine():
            return

        # Confirm
        if not self._confirm_write("write chain zip to engine flash — this will\n"
                                   "erase and rewrite multiple flash regions\n"
                                   "(DSP, FPGA, CV, Boiler, Hardware)"):
            print("Aborted.")
            return

        ok = self.prog.write_chain_zip(path, assume_yes=True,
                                       confirm_cb=self._confirm)

        if ok:
            print("Chain zip written successfully!")
            # Dealer log
            dealer = self.dealer_var.get().strip()
            if dealer:
                from mth_engine_programmer import append_dealer_log  # pylint: disable=import-outside-toplevel
                eng_info = self.prog.read_engine_info()
                if eng_info:
                    append_dealer_log(self.logfile_var.get(), dealer, eng_info)
        else:
            print("Failed to write chain zip")

    def run_write_single_srec(self):
        """Write a single S-record to the engine (advanced, targeted DSP programming)."""
        if not self._check_connected():
            return
        path = self.srec_write_var.get().strip()
        if not path:
            messagebox.showerror("Error", "Choose an S-record file first")
            return
        self._run_in_thread(lambda: self._do_write_single_srec(path))

    def _do_write_single_srec(self, path):
        """Worker that writes a single S-record to the engine DSP."""
        print(f"\n=== Writing Single S-Record: {path} ===")

        # Parse optional address/length overrides
        dsp_addr = None
        dsp_max = None
        addr_str = self.chain_addr_var.get().strip()
        len_str = self.chain_maxlen_var.get().strip()
        if addr_str:
            try:
                dsp_addr = int(addr_str, 0)
            except ValueError:
                print(f"  Invalid DSP address: {addr_str}")
                return
        if len_str:
            try:
                dsp_max = int(len_str, 0)
            except ValueError:
                print(f"  Invalid max length: {len_str}")
                return

        if not self.prog.setup_engine():
            return

        # Confirm
        if not self._confirm_write("write single S-record to engine DSP flash —\n"
                                   "this will erase and rewrite DSP code sectors"):
            print("Aborted.")
            return

        ok = self.prog.write_chain_code(path, dsp_addr=dsp_addr,
                                        dsp_max_len=dsp_max,
                                        assume_yes=True,
                                        confirm_cb=self._confirm)

        if ok:
            print("S-Record written successfully!")
            # Dealer log
            dealer = self.dealer_var.get().strip()
            if dealer:
                from mth_engine_programmer import append_dealer_log  # pylint: disable=import-outside-toplevel
                eng_info = self.prog.read_engine_info()
                if eng_info:
                    append_dealer_log(self.logfile_var.get(), dealer, eng_info)
        else:
            print("Failed to write S-Record")


def main():
    """Create the root Tk window and start the ProgrammerUI."""
    root = tk.Tk()
    ProgrammerUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
