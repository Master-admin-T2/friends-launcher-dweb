Friends Launcher Documentation
===============================

This document contains the main launcher documentation.

# Friends Launcher for dweb

**Friends Launcher** is a GUI tool that helps you run the dweb Friends application easily.  
It provides a simple interface for starting the dweb server, opening the Friends app, and managing the Ethereum private key required by dweb.

The launcher is optimized for **Windows 10/11**, but can also run on Linux and macOS when executed as a Python script.

Current version: **v9.33**

---

## Features

### ✔ dweb Integration
- Start the dweb server (`dweb serve`)
- Open the Friends app (`dweb open friends`)
- Automatic browser launch (optional)
- Port 5537 availability check

### ✔ Ethereum Key Management
- Read `SECRET_KEY` from:
  - Windows environment (User Environment / Registry)
  - Linux/Mac shell files (`~/.bashrc`, `.profile`, etc.)
- Save key temporarily (session only)
- Save key permanently (registry or `.bashrc`)
- Generate new private keys
- Verify keys and derive public Ethereum addresses
- Clipboard copy functionality

### ✔ Public Address Tools (Collapsible)
- Hidden by default
- Convert private key → checksum Ethereum address
- Copy generated address

### ✔ Advanced Options
- Save launcher log files
- Open log folder
- Hide dweb server console window (Windows)

### ✔ UI Enhancements
- True dark mode (default)
- Light mode option
- Best-effort dark title bar on Windows 10/11
- Scrollable UI with smooth layout
- Friends logo in title bar

### ✔ Security Features
- Optional SHA-256 hash verification of `dweb.exe`
- Private keys are never written to log files
- Clear warnings about key handling

---

## System Requirements

- **Python 3.10+** (if running `.py` directly)
- **Operating systems**
  - Windows 10/11 (primary)
  - Linux/macOS (supported but untested without PyInstaller build)
- **Python packages**

---
pip install requests psutil ecdsa pycryptodome

## Installation

1. Place the launcher script and `dweb.exe` in the same folder.
2. Run python friends-launcher-v9.33-win.py
or use a packaged executable.

---

## Usage

### Starting Friends
1. Launch Friends Launcher
2. Ensure `dweb.exe found` is displayed
3. (Optional) Enable automatic browser opening
4. Press **Start**

The launcher:
- Starts the dweb server
- Waits until the Friends endpoint responds
- Opens the app

### Ethereum Key Management

The launcher looks for a valid private key in:

1. `SECRET_KEY` environment variable  
2. Windows Registry (User Environment)
3. Linux/macOS shell files like `~/.bashrc`

You can:

- Save temporary key  
- Save permanent key  
- Generate new SECP256k1 keys  
- Verify keys  
- Derive public addresses  

**Never use large sums with this launcher.**  
Private keys are unencrypted environment variables.

---

## Public Address Tools

This section is hidden by default.  
Click **“Show public address tools”** to expand it.

---

## Advanced Settings

- **Save launcher log to file**  
- **Open log folder**  
- **Hide dweb server console window**

---

## Log Storage

Logs are stored in:

### Windows
%LOCALAPPDATA%\FriendsLauncher\logs\\


### Linux/Mac
\~/.friends-launcher/logs/


---

## Hash Verification

You may configure:

EXPECTED_DWEB_SHA256 = "<sha256-hash>"
If set, the launcher:

* Computes the SHA-256 of `dweb.exe`

* Compares it against the expected value

* Shows a warning if mismatched

## Dark Mode

* Enabled by default

* Toggle available

* Windows 10/11: tries to use dark title bar via DWM API

## Building Executables

### Windows

Example PyInstaller command:

pyinstaller ^
  --name FriendsLauncher ^
  --icon friends-launcher-logo.ico ^
  --noconsole ^
  friends-launcher-v9.33-win.py

Linux / macOS

pyinstaller --name FriendsLauncher friends-launcher-v9.33-win.py

You can also use **GitHub Actions** to build all three OS targets without owning those systems.

## License

This project is licensed under the **GNU Affero General Public License Version 3 (AGPLv3)**.

You are free to use, modify, and distribute this software, including for commercial purposes, as long as:

- You provide **proper attribution** to the original author (Master-admin-T2).
- Any modified versions you distribute are also licensed under **AGPLv3**.
- If the software is used to provide a network service, you must make the
  **full modified source code available** to the users of that service.

Full license text:  
https://www.gnu.org/licenses/agpl-3.0.html
