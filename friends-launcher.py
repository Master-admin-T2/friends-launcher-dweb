# Copyright (c) 2025 Master-admin-T2
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


# friends-launcher-v9.33-win.py
#
# Based on friends-launcher-v9.32-win.py
# Changes from v9.32:
# - Window icon now uses an absolute path next to the .py/.exe
#   so the Friends logo .ico is actually found on Windows.
# - No other behavior, layout, or text changed.

import tkinter as tk
from tkinter import messagebox
import subprocess
import webbrowser
import threading
import time
import platform
import requests
import socket
import os
import sys
import psutil
import hashlib
from ecdsa import SigningKey, SECP256k1
from Crypto.Hash import keccak

APP_URL = "http://127.0.0.1:5537/dweb-open/v/friends"
APP_PORT = 5537

# Set this to the expected SHA256 hash of dweb.exe when packaging.
# Leave empty ("") to skip hash checking.
EXPECTED_DWEB_SHA256 = ""

# Icon file name (should be placed next to the .py / .exe on Windows)
ICON_FILENAME = "friends-launcher-logo.ico"


def is_windows():
    return platform.system().lower() == "windows"


def get_log_dir():
    """
    Return a suitable log directory depending on OS.
    Windows: %LOCALAPPDATA%\\FriendsLauncher\\logs  (fallback: %APPDATA% or ~)
    Other:  ~/.friends-launcher/logs
    """
    try:
        if is_windows():
            base = (
                os.environ.get("LOCALAPPDATA")
                or os.environ.get("APPDATA")
                or os.path.expanduser("~")
            )
            path = os.path.join(base, "FriendsLauncher", "logs")
        else:
            home = os.path.expanduser("~")
            path = os.path.join(home, ".friends-launcher", "logs")
        os.makedirs(path, exist_ok=True)
        return path
    except Exception:
        # As a last resort, use current directory logs/
        path = os.path.join(os.getcwd(), "logs")
        try:
            os.makedirs(path, exist_ok=True)
        except Exception:
            pass
        return path


def get_log_file_path():
    # Kept for compatibility (not used by session-based logging)
    return os.path.join(get_log_dir(), "launcher.log")


def dweb_path():
    base = os.path.dirname(os.path.abspath(sys.argv[0]))
    exe_path = os.path.join(base, "dweb.exe")
    if os.path.isfile(exe_path):
        return exe_path
    return None


def build_cmds():
    local = dweb_path()
    if not local:
        return None, None
    return [local, "serve"], [local, "open", "friends"]


def open_browser(url):
    try:
        subprocess.run(["cmd.exe", "/c", "start", url], check=True)
    except Exception:
        webbrowser.open(url)


def kill_process_tree(proc):
    try:
        parent = psutil.Process(proc.pid)
        for child in parent.children(recursive=True):
            child.kill()
        parent.kill()
    except Exception:
        pass


def _get_secret_key_from_env():
    val = os.environ.get("SECRET_KEY")
    if val:
        return val.strip()
    return None


def _get_secret_key_from_registry():
    if not is_windows():
        return None
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment")
        val, _ = winreg.QueryValueEx(key, "SECRET_KEY")
        winreg.CloseKey(key)
        if isinstance(val, str):
            val = val.strip()
        else:
            val = str(val).strip()
        if val:
            return val
    except Exception:
        pass
    return None


def _get_secret_key_from_shell_files():
    home = os.path.expanduser("~")
    for fname in (".bashrc", ".profile", ".bash_profile"):
        fpath = os.path.join(home, fname)
        if os.path.exists(fpath):
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    for line in fh:
                        if line.strip().startswith("export SECRET_KEY="):
                            candidate = (
                                line.split("=", 1)[1]
                                .strip()
                                .strip('"')
                                .strip("'")
                            )
                            if candidate:
                                return candidate
            except Exception:
                # Ignore errors reading shell files
                pass
    return None


def is_valid_eth_private_key(value: str) -> bool:
    """
    Check if a string looks like a valid Ethereum private key:
    - Optional '0x' prefix
    - 64 hex chars (32 bytes)
    """
    if not value:
        return False
    v = value.strip()
    if v.startswith("0x"):
        v = v[2:]
    if len(v) != 64:
        return False
    try:
        bytes.fromhex(v)
    except ValueError:
        return False
    return True


def find_secret_key():
    """
    Look for SECRET_KEY in env/registry/shell files,
    but only accept values that look like valid Ethereum private keys.
    """
    for getter in (_get_secret_key_from_env,
                   _get_secret_key_from_registry,
                   _get_secret_key_from_shell_files):
        k = getter()
        if k and is_valid_eth_private_key(k):
            return k
    return None


def save_secret_key_permanently(secret_key):
    if is_windows():
        try:
            subprocess.run(["setx", "SECRET_KEY", secret_key], check=True)
            return True, "Saved via setx. Restart your terminal/shell for it to take effect."
        except Exception as e:
            return False, str(e)
    else:
        path = os.path.expanduser("~/.bashrc")
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write("\n# Friends launcher secret key\nexport SECRET_KEY=" + secret_key + "\n")
            return True, f"Appended to {path}. Run 'source ~/.bashrc' or restart shell."
        except Exception as e:
            return False, str(e)


def generate_private_key():
    sk = SigningKey.generate(curve=SECP256k1)
    return "0x" + sk.to_string().hex()


def to_checksum_address(address):
    addr = address.lower().replace("0x", "")
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(addr.encode("ascii"))
    h = keccak_hash.hexdigest()
    out = ""
    for i, c in enumerate(addr):
        out += c.upper() if int(h[i], 16) >= 8 else c
    return "0x" + out


def verify_private_key(priv_hex):
    if priv_hex.startswith("0x"):
        priv_hex = priv_hex[2:]
    if len(priv_hex) != 64:
        raise ValueError("Invalid private key length (expected 32 bytes / 64 hex chars).")
    priv_bytes = bytes.fromhex(priv_hex)
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    vk = sk.get_verifying_key()
    pub_bytes = vk.to_string()
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(pub_bytes)
    addr = keccak_hash.digest()[-20:].hex()
    return to_checksum_address("0x" + addr)


def compute_sha256(path: str) -> str:
    """
    Compute SHA256 hash of a file and return it as a hex string.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


class DwebLauncherWin:
    def __init__(self, master):
        self.master = master

        # Fixed window geometry; scroll handles extra content
        self.normal_geometry = "640x620"

        self.master.title("Friends Launcher (Windows)")
        self.master.geometry(self.normal_geometry)
        self.master.protocol("WM_DELETE_WINDOW", self.shutdown)

        # Try to set window icon (Friends logo) on Windows using absolute path
        if is_windows():
            try:
                base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
                icon_path = os.path.join(base_dir, ICON_FILENAME)
                if os.path.exists(icon_path):
                    self.master.iconbitmap(icon_path)
            except Exception:
                # If icon is missing or invalid, ignore silently
                pass

        # Track if we've already shown a hash mismatch warning
        self.hash_warning_shown = False

        # -------- Scrollable container --------
        self.main_frame = tk.Frame(master)
        self.main_frame.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(self.main_frame, borderwidth=0)
        v_scrollbar = tk.Scrollbar(self.main_frame, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=v_scrollbar.set)

        v_scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.content = tk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.content, anchor="nw")

        def _on_frame_configure(event):
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))

        self.content.bind("<Configure>", _on_frame_configure)

        # -------- UI contents (inside self.content) --------

        self.title_label = tk.Label(self.content, text="Friends Launcher", font=("Arial", 14, "bold"))
        self.title_label.pack(pady=10)

        self.status_label = tk.Label(
            self.content,
            text="Click 'Start' to launch Friends",
            font=("Arial", 11)
        )
        self.status_label.pack(pady=6)

        # Dark mode toggle (default ON)
        self.dark_mode = tk.BooleanVar(value=True)
        self.theme_toggle = tk.Checkbutton(
            self.content,
            text="Dark mode",
            variable=self.dark_mode,
            command=self.apply_theme
        )
        self.theme_toggle.pack(pady=2)

        self.open_browser_var = tk.BooleanVar(value=False)
        self.open_browser_check = tk.Checkbutton(
            self.content,
            text="Open browser automatically after start",
            variable=self.open_browser_var
        )
        self.open_browser_check.pack(pady=5)

        # --- Advanced settings toggle button ---
        self.advanced_visible = False
        self.advanced_button = tk.Button(
            self.content,
            text="Show advanced settings",
            command=self.toggle_advanced_settings,
            width=20
        )
        self.advanced_button.pack(pady=2)

        # Advanced settings frame (inside content)
        self.advanced_frame = tk.Frame(self.content)

        # Logging checkbox (inside advanced frame)
        self.log_to_file_var = tk.BooleanVar(value=False)
        self.log_check = tk.Checkbutton(
            self.advanced_frame,
            text="Save launcher log to file",
            variable=self.log_to_file_var
        )
        self.log_check.pack(pady=2)

        # Button to open log folder (inside advanced frame)
        self.open_log_button = tk.Button(
            self.advanced_frame,
            text="Open log folder",
            command=self.open_log_folder,
            width=18
        )
        self.open_log_button.pack(pady=2)

        # Checkbox to hide Dweb server console window (inside advanced frame)
        # Default = False -> Dweb console window is visible by default.
        self.hide_console_var = tk.BooleanVar(value=False)
        self.hide_console_check = tk.Checkbutton(
            self.advanced_frame,
            text="Hide Dweb server console window",
            variable=self.hide_console_var
        )
        self.hide_console_check.pack(pady=2)

        # Pack once then hide initially
        self.advanced_frame.pack(pady=4)
        self.advanced_frame.pack_forget()

        # Session-specific log file path (set when first log is written)
        self.log_file_path = None

        self.start_button = tk.Button(self.content, text="Start", command=self.start, width=15)
        self.start_button.pack(pady=4)
        self.quit_button = tk.Button(self.content, text="Quit", command=self.shutdown, width=15)
        self.quit_button.pack(pady=4)

        self.dweb_title_label = tk.Label(self.content, text="Dweb Binary Status", font=("Arial", 12, "bold"))
        self.dweb_title_label.pack(pady=(14, 4))

        self.dweb_status_label = tk.Label(self.content, text="", font=("Arial", 10))
        self.dweb_status_label.pack()

        self.eth_title_label = tk.Label(self.content, text="Ethereum private key", font=("Arial", 12, "bold"))
        self.eth_title_label.pack(pady=(14, 4))

        self.key_status = tk.Label(self.content, text="", font=("Arial", 10))
        self.key_status.pack()

        self.key_entry = tk.Entry(self.content, width=80)
        self.key_entry.pack(pady=4)

        self.key_button_frame = tk.Frame(self.content)
        self.key_button_frame.pack(pady=4)
        self.save_temp_button = tk.Button(self.key_button_frame, text="Save (temporary)", command=self.set_key_temp)
        self.save_temp_button.pack(side="left", padx=4)
        self.save_perm_button = tk.Button(self.key_button_frame, text="Save Permanently", command=self.set_key_permanent)
        self.save_perm_button.pack(side="left", padx=4)
        self.gen_key_button = tk.Button(self.key_button_frame, text="Generate New Key", command=self.generate_key_ui)
        self.gen_key_button.pack(side="left", padx=4)
        self.verify_key_button = tk.Button(self.key_button_frame, text="Verify Key", command=self.verify_key_ui)
        self.verify_key_button.pack(side="left", padx=4)
        self.copy_found_button = tk.Button(self.key_button_frame, text="Copy Found Key", command=self.copy_found_key)
        self.copy_found_button.pack(side="left", padx=8)

        # --- Public address section: collapsible/expandable ---

        # Toggle button for public address tools
        self.pub_section_visible = False
        self.pub_toggle_button = tk.Button(
            self.content,
            text="Show public address tools",
            command=self.toggle_public_section,
            width=24
        )
        self.pub_toggle_button.pack(pady=(10, 2))

        # Frame that holds the public address controls (hidden by default)
        self.pub_frame = tk.Frame(self.content)

        self.pub_title_label = tk.Label(
            self.pub_frame,
            text="Get public address (from private key)",
            font=("Arial", 11, "bold")
        )
        self.pub_title_label.pack(pady=(4, 2))

        self.pub_entry = tk.Entry(self.pub_frame, width=80)
        self.pub_entry.pack(pady=4)

        self.pub_button_frame = tk.Frame(self.pub_frame)
        self.pub_button_frame.pack(pady=4)
        self.create_pub_button = tk.Button(
            self.pub_button_frame,
            text="Create Public Address",
            command=self.create_public_address_ui
        )
        self.create_pub_button.pack(side="left", padx=4)
        self.copy_pub_button = tk.Button(
            self.pub_button_frame,
            text="Copy Public Address",
            command=self.copy_public_address_ui
        )
        self.copy_pub_button.pack(side="left", padx=4)

        self.warning_label = tk.Label(
            self.content,
            text=(
                "⚠️ Your private key controls your funds.\n"
                "This launcher stores it in an environment variable called SECRET_KEY.\n"
                "Do NOT keep large balances in wallets used here."
            ),
            font=("Arial", 9),
            fg="red"
        )
        self.warning_label.pack(pady=6)

        self.process_server = None        # Dweb server process
        self.process_app = None           # Friends app process

        self.refresh_dweb_status()
        self.refresh_key_status()

        # Apply initial dark theme (dark_mode default = True)
        self.apply_theme()

        # Try to enable dark title bar on Windows if dark mode is active
        if is_windows() and self.dark_mode.get():
            self.enable_dark_titlebar()

        self.log("Launcher started.")

    # -------- Title bar dark mode (Windows-only best-effort) --------

    def enable_dark_titlebar(self):
        """
        Try to enable dark title bar on Windows 10/11 using DwmSetWindowAttribute.
        This is best-effort and silently ignored if not supported.
        """
        if not is_windows():
            return
        try:
            import ctypes

            hwnd = self.master.winfo_id()
            DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = 19

            set_window_attribute = ctypes.windll.dwmapi.DwmSetWindowAttribute
            value = ctypes.c_int(1)

            # Try newer constant first
            res = set_window_attribute(
                ctypes.c_void_p(hwnd),
                ctypes.c_int(DWMWA_USE_IMMERSIVE_DARK_MODE),
                ctypes.byref(value),
                ctypes.sizeof(value),
            )
            if res != 0:
                # Fallback to older constant
                set_window_attribute(
                    ctypes.c_void_p(hwnd),
                    ctypes.c_int(DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1),
                    ctypes.byref(value),
                    ctypes.sizeof(value),
                )
        except Exception:
            # Never break the app if dark title bar fails
            pass

    # -------- Theme handling (dark / light) --------

    def apply_theme(self):
        """Apply dark or light theme to known widgets."""
        dark = self.dark_mode.get()

        if dark:
            bg = "#111111"
            bg_alt = "#181818"
            fg = "#f5f5f5"
            entry_bg = "#1e1e1e"
            entry_fg = "#ffffff"
            button_bg = "#222222"
            button_fg = "#f5f5f5"
        else:
            bg = "#f0f0f0"
            bg_alt = "#e6e6e6"
            fg = "#000000"
            entry_bg = "#ffffff"
            entry_fg = "#000000"
            button_bg = "#e0e0e0"
            button_fg = "#000000"

        try:
            # Window & main containers
            self.master.configure(bg=bg)
            self.main_frame.configure(bg=bg)
            self.canvas.configure(bg=bg, highlightthickness=0)
            self.content.configure(bg=bg)
            self.advanced_frame.configure(bg=bg_alt)
            self.key_button_frame.configure(bg=bg)
            self.pub_frame.configure(bg=bg_alt)
            self.pub_button_frame.configure(bg=bg_alt)

            # Labels
            for lbl in (
                self.title_label,
                self.status_label,
                self.dweb_title_label,
                self.dweb_status_label,
                self.eth_title_label,
                self.key_status,
                self.pub_title_label,
                self.warning_label,
            ):
                lbl.configure(bg=lbl.master["bg"], fg=fg)

            # Checkbuttons
            for chk in (
                self.theme_toggle,
                self.open_browser_check,
                self.log_check,
                self.hide_console_check,
            ):
                chk.configure(
                    bg=chk.master["bg"],
                    fg=fg,
                    selectcolor=bg_alt,
                    activeforeground=fg,
                    activebackground=bg_alt
                )

            # Entries
            for ent in (self.key_entry, self.pub_entry):
                ent.configure(
                    bg=entry_bg,
                    fg=entry_fg,
                    insertbackground=entry_fg,
                    disabledbackground=entry_bg,
                    disabledforeground=entry_fg,
                )

            # Buttons
            all_buttons = [
                self.advanced_button,
                self.start_button,
                self.quit_button,
                self.open_log_button,
                self.save_temp_button,
                self.save_perm_button,
                self.gen_key_button,
                self.verify_key_button,
                self.copy_found_button,
                self.pub_toggle_button,
                self.create_pub_button,
                self.copy_pub_button,
            ]
            for btn in all_buttons:
                btn.configure(
                    bg=button_bg,
                    fg=button_fg,
                    activebackground=bg_alt,
                    activeforeground=fg,
                    relief="raised",
                )
        except Exception:
            # Theme errors should never break the app
            pass

        # If dark mode is active on Windows, try to darken the title bar too
        if is_windows() and dark:
            self.enable_dark_titlebar()

        # Ensure scrollregion is updated after theme changes
        self.canvas.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    # -------- Advanced settings toggle --------

    def toggle_advanced_settings(self):
        if self.advanced_visible:
            self.advanced_frame.pack_forget()
            self.advanced_visible = False
            self.advanced_button.config(text="Show advanced settings")
            self.log("Advanced settings hidden.")
        else:
            self.advanced_frame.pack(pady=4)
            self.advanced_visible = True
            self.advanced_button.config(text="Hide advanced settings")
            self.log("Advanced settings shown.")

        # After changing layout, refresh scrollregion
        self.canvas.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    # -------- Public address section toggle --------

    def toggle_public_section(self):
        if self.pub_section_visible:
            self.pub_frame.pack_forget()
            self.pub_section_visible = False
            self.pub_toggle_button.config(text="Show public address tools")
            self.log("Public address tools hidden.")
        else:
            self.pub_frame.pack(pady=4)
            self.pub_section_visible = True
            self.pub_toggle_button.config(text="Hide public address tools")
            self.log("Public address tools shown.")

        # After changing layout, refresh scrollregion
        self.canvas.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    # -------- Logging helper --------

    def log(self, msg: str):
        """
        Append a log line to a session-specific log file if logging is enabled.
        Never raises errors (logging must not break the GUI).
        """
        if not getattr(self, "log_to_file_var", None) or not self.log_to_file_var.get():
            return
        try:
            if not getattr(self, "log_file_path", None):
                ts_name = time.strftime("%Y%m%d_%H%M%S")
                self.log_file_path = os.path.join(
                    get_log_dir(), f"launcher-{ts_name}.log"
                )

            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(f"[{ts}] {msg}\n")
        except Exception:
            # Swallow any logging errors silently
            pass

    # -------- Existing methods with small logging additions --------

    def refresh_dweb_status(self):
        local = dweb_path()
        if local:
            msg = f"dweb.exe found:\n{local}"

            expected_raw = EXPECTED_DWEB_SHA256 or ""
            expected = expected_raw.strip().lower()

            if expected:
                try:
                    actual = compute_sha256(local).lower()
                    if actual == expected:
                        msg += "\nHash check: OK"
                        self.log("dweb.exe hash check OK.")
                    else:
                        msg += "\nHash check: WARNING (mismatch)"
                        self.log(
                            f"dweb.exe hash mismatch. "
                            f"Expected {expected}, got {actual}"
                        )
                        if not self.hash_warning_shown:
                            self.hash_warning_shown = True
                            messagebox.showwarning(
                                "Security warning, dweb.exe hash mismatch",
                                "Make sure that dweb has not been tampered with, check that "
                                "dweb sha256 hash matches launcher code hash.\n\n"
                                "The dweb.exe file does not match the expected hash.\n\n"
                                "This may mean the file was replaced or corrupted.\n"
                                "If you just updated dweb, update the EXPECTED_DWEB_SHA256 value."
                            )
                except Exception as e:
                    msg += "\nHash check: error"
                    self.log(f"Error computing dweb.exe hash: {e!r}")
        else:
            msg = (
                "dweb.exe NOT FOUND in the same folder as this launcher.\n"
                "Please place dweb.exe next to this .py/.exe and restart."
            )
        self.dweb_status_label.config(text=msg)
        if not local:
            self.log("dweb.exe not found next to launcher.")

    def refresh_key_status(self):
        key = find_secret_key()
        if key:
            short = key[:8] + "..." + key[-8:]
            self.key_status.config(text=f"SECRET_KEY found: {short}")
            self.log("SECRET_KEY found in environment/registry/shell files.")
        else:
            self.key_status.config(text="SECRET_KEY not found.")
            self.log("SECRET_KEY not found.")

    def set_key_temp(self):
        key = self.key_entry.get().strip()
        if not key:
            messagebox.showerror("Error", "Enter a private key first.")
            return
        if not is_valid_eth_private_key(key):
            messagebox.showerror(
                "Invalid key",
                "The value you entered is not a valid Ethereum private key.\n"
                "Expected 32 bytes / 64 hex characters (optionally with 0x prefix)."
            )
            return
        os.environ["SECRET_KEY"] = key
        messagebox.showinfo("Temporary", "SECRET_KEY set for this session only.")
        self.log("SECRET_KEY set temporarily for this process (value not logged).")
        self.refresh_key_status()

    def set_key_permanent(self):
        key = self.key_entry.get().strip()

        if not key:
            existing = find_secret_key()
            if existing:
                messagebox.showwarning(
                    "Not saved",
                    "A SECRET_KEY already exists.\n"
                    "Refusing to overwrite it with an empty value."
                )
                self.log("Attempted to save empty SECRET_KEY while one already exists. Operation refused.")
            else:
                messagebox.showerror(
                    "No key provided",
                    "You must enter a private key before saving permanently."
                )
                self.log("Attempted to save empty SECRET_KEY when none exists. Operation refused.")
            return

        if not is_valid_eth_private_key(key):
            messagebox.showerror(
                "Invalid key",
                "The value you entered is not a valid Ethereum private key.\n"
                "Expected 32 bytes / 64 hex characters (optionally with 0x prefix)."
            )
            self.log("Attempted to save invalid SECRET_KEY permanently. Operation refused.")
            return

        if not messagebox.askyesno(
            "Confirm",
            "This will save your private key permanently to your user environment.\n"
            "Are you sure?"
        ):
            self.log("User cancelled permanent SECRET_KEY save.")
            return

        ok, msg = save_secret_key_permanently(key)
        if ok:
            messagebox.showinfo("Saved", msg)
            self.log("SECRET_KEY saved permanently via OS mechanism (value not logged).")
        else:
            messagebox.showerror("Failed", msg)
            self.log(f"Failed to save SECRET_KEY permanently: {msg}")
        self.refresh_key_status()

    def generate_key_ui(self):
        try:
            priv = generate_private_key()
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, priv)
            messagebox.showinfo(
                "Generated",
                "New Ethereum private key generated.\nCopy it and store safely!"
            )
            self.log("New Ethereum private key generated in UI (value not logged).")
        except Exception as e:
            self.log(f"Error generating private key: {e!r}")
            messagebox.showerror("Error", str(e))

    def verify_key_ui(self):
        key = self.key_entry.get().strip()
        if not key:
            messagebox.showerror("Error", "Enter a private key first.")
            return
        try:
            addr = verify_private_key(key)
            messagebox.showinfo("Verified", f"Valid key.\nDerived address:\n{addr}")
            self.log("Private key verified successfully.")
        except Exception as e:
            self.log(f"Private key verification failed: {e!r}")
            messagebox.showerror("Invalid", str(e))

    def copy_found_key(self):
        key = find_secret_key()
        if not key:
            messagebox.showerror("No key", "No Private key found to copy.")
            self.log("Copy Found Key clicked but no key found.")
            return
        try:
            self.master.clipboard_clear()
            self.master.clipboard_append(key)
            messagebox.showinfo("Copied", "Private key copied to clipboard.\nBe careful where you paste it.")
            self.log("Private key copied to clipboard (value not logged).")
        except Exception as e:
            self.log(f"Clipboard error while copying key: {e!r}")
            messagebox.showerror("Clipboard error", str(e))

    def create_public_address_ui(self):
        key = self.key_entry.get().strip()
        if not key:
            messagebox.showerror("Error", "Enter a private key first.")
            return
        try:
            addr = verify_private_key(key)
            self.pub_entry.delete(0, tk.END)
            self.pub_entry.insert(0, addr)
            self.log("Public address derived from private key.")
        except Exception as e:
            self.log(f"Error deriving public address: {e!r}")
            messagebox.showerror("Invalid", str(e))

    def copy_public_address_ui(self):
        addr = self.pub_entry.get().strip()
        if not addr:
            messagebox.showerror("No address", "No public address to copy. Create it first.")
            self.log("Copy Public Address clicked but no address present.")
            return
        try:
            self.master.clipboard_clear()
            self.master.clipboard_append(addr)
            messagebox.showinfo("Copied", "Public address copied to clipboard.")
            self.log("Public address copied to clipboard.")
        except Exception as e:
            self.log(f"Clipboard error while copying public address: {e!r}")
            messagebox.showerror("Clipboard error", str(e))

    def _is_port_in_use(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('127.0.0.1', port)) == 0

    def start(self):
        self.log("Start button clicked.")
        server_cmd, app_cmd = build_cmds()
        if server_cmd is None or app_cmd is None:
            messagebox.showerror(
                "Missing dweb.exe",
                "Cannot start.\n\nPlease place dweb.exe in the same folder as this launcher."
            )
            self.log("Cannot start: dweb.exe not found next to launcher.")
            return
        self.start_button.config(state=tk.DISABLED)
        self.status_label.config(text="Starting Dweb server...")
        self.log(f"Starting Dweb server with command: {server_cmd!r}")
        threading.Thread(target=self._launch, args=(server_cmd, app_cmd), daemon=True).start()

    def _launch(self, server_cmd, app_cmd):
        try:
            if self._is_port_in_use(APP_PORT):
                msg = f"Port {APP_PORT} is already in use."
                self.status_label.config(text=msg)
                self.start_button.config(state=tk.NORMAL)
                self.log(msg)
                return

            self.process_server = None
            for attempt in range(3):
                try:
                    creationflags = 0
                    if is_windows():
                        if self.hide_console_var.get():
                            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                        elif hasattr(subprocess, "CREATE_NEW_CONSOLE"):
                            creationflags = subprocess.CREATE_NEW_CONSOLE

                    self.process_server = subprocess.Popen(server_cmd, creationflags=creationflags)
                    self.log(
                        f"Dweb server process started on attempt {attempt + 1}. "
                        f"PID={self.process_server.pid}, hide_console={self.hide_console_var.get()}"
                    )
                    break
                except Exception as e:
                    self.log(f"Failed to start Dweb server on attempt {attempt + 1}: {e!r}")
                    time.sleep(1)

            if not self.process_server:
                msg = "Failed to start Dweb server after multiple attempts."
                self.status_label.config(text=msg)
                self.start_button.config(state=tk.NORMAL)
                self.log(msg)
                return

            server_ready = False
            for _ in range(30):
                try:
                    r = requests.get(APP_URL)
                    if r.status_code == 200:
                        server_ready = True
                        break
                except requests.RequestException:
                    time.sleep(1)

            if not server_ready:
                msg = "Server did not become ready. Please check the Dweb console window."
                self.status_label.config(text=msg)
                self.start_button.config(state=tk.NORMAL)
                self.log(msg)
                return

            self.status_label.config(text="Launching Friends app...")
            self.log(f"Launching Friends app with command: {app_cmd!r}")
            try:
                self.process_app = subprocess.Popen(app_cmd)
                self.log(f"Friends app started. PID={self.process_app.pid}")
            except Exception as e:
                msg = f"Failed to start Friends app: {e}"
                self.status_label.config(text=msg)
                self.start_button.config(state=tk.NORMAL)
                self.log(msg)
                return

            time.sleep(2)
            if self.open_browser_var.get():
                open_browser(APP_URL)
                self.status_label.config(text="Opening browser...")
                self.log("Browser opened to Friends URL.")
            else:
                self.status_label.config(text="App started (browser not opened).")
                self.log("App started without opening browser.")

            self.start_button.config(state=tk.NORMAL)
        except Exception as e:
            self.log(f"Unexpected error in _launch: {e!r}")
            self.status_label.config(text="Unexpected error while starting. See log for details.")
            self.start_button.config(state=tk.NORMAL)

    def open_log_folder(self):
        """
        Open the folder where launcher log files are stored.
        """
        try:
            path = get_log_dir()
            if not os.path.isdir(path):
                messagebox.showerror("Error", "Log folder does not exist.")
                self.log("Open log folder failed: directory does not exist.")
                return

            self.log(f"Opening log folder: {path!r}")

            if is_windows():
                subprocess.Popen(["explorer", path])
            else:
                system = platform.system().lower()
                if system == "darwin":
                    subprocess.Popen(["open", path])
                else:
                    subprocess.Popen(["xdg-open", path])
        except Exception as e:
            self.log(f"Error opening log folder: {e!r}")
            messagebox.showerror("Error", f"Could not open log folder:\n{e}")

    def shutdown(self):
        self.log("Shutdown requested.")
        if self.process_app and self.process_app.poll() is None:
            try:
                self.log(f"Killing Friends app process PID={self.process_app.pid}")
                kill_process_tree(self.process_app)
            except Exception as e:
                self.log(f"Error killing Friends app process: {e!r}")
        if self.process_server and self.process_server.poll() is None:
            try:
                self.log(f"Killing Dweb server process PID={self.process_server.pid}")
                kill_process_tree(self.process_server)
            except Exception as e:
                self.log(f"Error killing Dweb server process: {e!r}")
        self.log("Launcher window closed.")
        self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = DwebLauncherWin(root)
    root.mainloop()
