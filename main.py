#!/usr/bin/env python3
# coding: utf-8

import os
import json
import base64
import zlib
import getpass
import zipfile
import tempfile
import hashlib
import secrets
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox, scrolledtext
from datetime import datetime
from getpass import getpass as gp

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---------------------------
# Config / Constants
# ---------------------------
SALT_SIZE = 16
KDF_ITERS = 200_000
AES_KEY_SIZE = 32
AES_NONCE_SIZE = 12
LOG_FILE = "crypto_log.txt"
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"
PUBLIC_KEYS_DIR = "public_keys"
FRIENDS_FILE = "friends.json"
BACKUP_FILE_PREFIX = "crypto_backup_"
MAX_COMPRESS = True

# ---------------------------
# Helper functions
# ---------------------------

def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def derive_key_from_password(password: bytes, salt: bytes, length=AES_KEY_SIZE) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=KDF_ITERS,
    )
    return kdf.derive(password)

def ensure_dirs():
    if not os.path.exists(PUBLIC_KEYS_DIR):
        os.makedirs(PUBLIC_KEYS_DIR)

# ---------------------------
# App class
# ---------------------------

class AdvancedCryptoApp:
    def __init__(self):
        ensure_dirs()
        self.log_file = LOG_FILE
        self.private_key_file = PRIVATE_KEY_FILE
        self.public_key_file = PUBLIC_KEY_FILE
        self.friends_file = FRIENDS_FILE

        self.password = gp("Enter password to protect/access private key: ").encode('utf-8')

        self._init_files()
        self.private_key, self.public_key = self.load_or_generate_keys()
        self.friends = self.load_friends()

    def _init_files(self):
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w", encoding='utf-8') as f:
                f.write("=== CRYPTOGRAPHIC OPERATIONS LOG ===\n\n")
        if not os.path.exists(self.friends_file):
            with open(self.friends_file, "w", encoding='utf-8') as f:
                json.dump([], f)

    def log_operation(self, operation: str, metadata: dict):
        timestamp = now_ts()
        user = None
        try:
            user = os.getlogin()
        except Exception:
            import getpass as _gp
            user = _gp.getuser()
        entry = {
            "timestamp": timestamp,
            "operation": operation,
            "user": user,
            "meta": metadata
        }
        with open(self.log_file, "a", encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def load_or_generate_keys(self):
        try:
            with open(self.private_key_file, "rb") as f:
                priv_pem = f.read()
            private_key = serialization.load_pem_private_key(
                priv_pem,
                password=self.password
            )
            with open(self.public_key_file, "rb") as f:
                pub_pem = f.read()
            public_key = serialization.load_pem_public_key(pub_pem)
            self.log_operation("KEYS_LOADED", {"note": "Keys loaded successfully"})
            return private_key, public_key
        except FileNotFoundError:
            print("Keys not found. Generating new key pair...")
            return self.generate_new_keys()
        except ValueError:
            print("⚠️ Wrong password or corrupted key file.")
            exit(1)

    def generate_new_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(self.password)
        )
        with open(self.private_key_file, "wb") as f:
            f.write(priv_pem)
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(self.public_key_file, "wb") as f:
            f.write(pub_pem)
        self.log_operation("NEW_KEYS_GENERATED", {"note": "New key pair generated"})
        return private_key, private_key.public_key()

    def load_friends(self):
        try:
            with open(self.friends_file, "r", encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def save_friends(self):
        with open(self.friends_file, "w", encoding='utf-8') as f:
            json.dump(self.friends, f, indent=2, ensure_ascii=False)

    def add_friend(self, name: str, pub_key_data_or_path: str):
        try:
            if any(f['name'] == name for f in self.friends):
                print(f"Error: friend '{name}' already exists")
                return False

            if os.path.exists(pub_key_data_or_path):
                with open(pub_key_data_or_path, "rb") as f:
                    pub_pem = f.read()
            else:
                pub_pem = pub_key_data_or_path.encode('utf-8')

            serialization.load_pem_public_key(pub_pem)

            friend_key_file = os.path.join(PUBLIC_KEYS_DIR, f"{name}.pem")
            with open(friend_key_file, "wb") as f:
                f.write(pub_pem)

            self.friends.append({
                "name": name,
                "key_file": friend_key_file,
                "added": now_ts()
            })
            self.save_friends()
            self.log_operation("FRIEND_ADDED", {"name": name})
            return True
        except Exception as e:
            print(f"Error adding friend: {str(e)}")
            return False

    def remove_friend(self, name: str):
        friend = next((f for f in self.friends if f['name'] == name), None)
        if not friend:
            print(f"Friend '{name}' not found")
            return False
        try:
            if os.path.exists(friend['key_file']):
                os.remove(friend['key_file'])
            self.friends = [f for f in self.friends if f['name'] != name]
            self.save_friends()
            self.log_operation("FRIEND_REMOVED", {"name": name})
            return True
        except Exception as e:
            print(f"Error removing friend: {str(e)}")
            return False

    def list_friends(self):
        return self.friends

    def compress_data(self, data: bytes) -> bytes:
        return zlib.compress(data, level=9)

    def decompress_data(self, compressed_data: bytes) -> bytes:
        return zlib.decompress(compressed_data)

    def hybrid_encrypt(self, pub_key, plaintext: bytes, compress=True) -> str:
        if compress:
            plaintext = self.compress_data(plaintext)
        aes_key = secrets.token_bytes(AES_KEY_SIZE)
        nonce = secrets.token_bytes(AES_NONCE_SIZE)
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        wrapped_key = pub_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        payload = {
            "wrapped_key": base64.b64encode(wrapped_key).decode('ascii'),
            "nonce": base64.b64encode(nonce).decode('ascii'),
            "ciphertext": base64.b64encode(ciphertext).decode('ascii'),
            "compress": bool(compress)
        }
        json_payload = json.dumps(payload).encode('utf-8')
        return base64.b85encode(json_payload).decode('ascii')

    def hybrid_decrypt(self, encrypted_payload_b85: str) -> bytes or None:
        try:
            json_bytes = base64.b85decode(encrypted_payload_b85)
            payload = json.loads(json_bytes.decode('utf-8'))
            wrapped_key = base64.b64decode(payload['wrapped_key'])
            nonce = base64.b64decode(payload['nonce'])
            ciphertext = base64.b64decode(payload['ciphertext'])
            compress = payload.get('compress', False)
            aes_key = self.private_key.decrypt(
                wrapped_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            aesgcm = AESGCM(aes_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
            if compress:
                plaintext = self.decompress_data(plaintext)
            return plaintext
        except Exception as e:
            print(f"Hybrid decryption error: {e}")
            return None

    def encrypt_message_for_friend(self, friend_name: str, message: str, compress=True) -> str or None:
        friend = next((f for f in self.friends if f['name'] == friend_name), None)
        if not friend:
            print("Friend not found")
            return None
        with open(friend['key_file'], "rb") as f:
            pub_pem = f.read()
        pub_key = serialization.load_pem_public_key(pub_pem)
        plaintext = message.encode('utf-8')
        encrypted = self.hybrid_encrypt(pub_key, plaintext, compress=compress)
        self.log_operation("ENCRYPT_MESSAGE", {
            "to": friend_name,
            "sha256": sha256_hex(plaintext),
            "len": len(plaintext)
        })
        return encrypted

    def decrypt_message(self, encrypted_b85: str) -> str or None:
        plaintext = self.hybrid_decrypt(encrypted_b85)
        if plaintext is None:
            return None
        self.log_operation("DECRYPT_MESSAGE", {
            "sha256": sha256_hex(plaintext),
            "len": len(plaintext)
        })
        try:
            return plaintext.decode('utf-8', errors='replace')
        except Exception:
            return base64.b64encode(plaintext).decode('ascii')

    def encrypt_file_for_friend(self, friend_name: str, filepath: str, compress=True) -> str or None:
        if not os.path.exists(filepath):
            print("File not found")
            return None
        with open(filepath, "rb") as f:
            data = f.read()
        friend = next((f for f in self.friends if f['name'] == friend_name), None)
        if not friend:
            print("Friend not found")
            return None
        with open(friend['key_file'], "rb") as f:
            pub_pem = f.read()
        pub_key = serialization.load_pem_public_key(pub_pem)
        encrypted = self.hybrid_encrypt(pub_key, data, compress=compress)
        self.log_operation("ENCRYPT_FILE", {
            "to": friend_name,
            "filename": os.path.basename(filepath),
            "sha256": sha256_hex(data),
            "len": len(data)
        })
        return encrypted

    def decrypt_file(self, encrypted_b85: str, out_path: str) -> bool:
        plaintext = self.hybrid_decrypt(encrypted_b85)
        if plaintext is None:
            return False
        with open(out_path, "wb") as f:
            f.write(plaintext)
        self.log_operation("DECRYPT_FILE", {
            "outfile": out_path,
            "sha256": sha256_hex(plaintext),
            "len": len(plaintext)
        })
        return True

    def create_session_token_for_friend(self, friend_name: str) -> str or None:
        friend = next((f for f in self.friends if f['name'] == friend_name), None)
        if not friend:
            print("Friend not found")
            return None
        with open(friend['key_file'], "rb") as f:
            pub_pem = f.read()
        pub_key = serialization.load_pem_public_key(pub_pem)
        sess_id = secrets.token_hex(16)
        sess_key = secrets.token_bytes(AES_KEY_SIZE)
        wrapped = pub_key.encrypt(
            sess_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        payload = {
            "sess_id": sess_id,
            "wrapped_key": base64.b64encode(wrapped).decode('ascii'),
            "note": "session token AES key (wrap with RSA). Use import_session_token to unlock."
        }
        token = base64.b85encode(json.dumps(payload).encode('utf-8')).decode('ascii')
        if not hasattr(self, "_sessions"):
            self._sessions = {}
        self._sessions[sess_id] = sess_key
        self.log_operation("SESSION_CREATED", {"to": friend_name, "sess_id": sess_id})
        return token

    def import_session_token(self, token_b85: str) -> str or None:
        try:
            payload_json = base64.b85decode(token_b85)
            payload = json.loads(payload_json.decode('utf-8'))
            wrapped = base64.b64decode(payload['wrapped_key'])
            sess_id = payload['sess_id']
            sess_key = self.private_key.decrypt(
                wrapped,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            if not hasattr(self, "_sessions"):
                self._sessions = {}
            self._sessions[sess_id] = sess_key
            self.log_operation("SESSION_IMPORTED", {"sess_id": sess_id})
            return sess_id
        except Exception as e:
            print(f"Error importing session token: {e}")
            return None

    def session_encrypt(self, sess_id: str, message: bytes) -> str or None:
        if not hasattr(self, "_sessions") or sess_id not in self._sessions:
            print("Session not found/imported")
            return None
        key = self._sessions[sess_id]
        nonce = secrets.token_bytes(AES_NONCE_SIZE)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, message, associated_data=None)
        payload = {
            "sess_id": sess_id,
            "nonce": base64.b64encode(nonce).decode('ascii'),
            "ciphertext": base64.b64encode(ct).decode('ascii')
        }
        token = base64.b85encode(json.dumps(payload).encode('utf-8')).decode('ascii')
        self.log_operation("SESSION_ENCRYPT", {"sess_id": sess_id, "sha256": sha256_hex(message), "len": len(message)})
        return token

    def session_decrypt(self, token_b85: str) -> bytes or None:
        try:
            payload_json = base64.b85decode(token_b85)
            payload = json.loads(payload_json.decode('utf-8'))
            sess_id = payload['sess_id']
            nonce = base64.b64decode(payload['nonce'])
            ct = base64.b64decode(payload['ciphertext'])
            if not hasattr(self, "_sessions") or sess_id not in self._sessions:
                print("Session not available locally (import session token).")
                return None
            key = self._sessions[sess_id]
            aesgcm = AESGCM(key)
            pt = aesgcm.decrypt(nonce, ct, associated_data=None)
            self.log_operation("SESSION_DECRYPT", {"sess_id": sess_id, "sha256": sha256_hex(pt), "len": len(pt)})
            return pt
        except Exception as e:
            print(f"Session decryption error: {e}")
            return None

    def create_encrypted_backup(self, out_file: str = None) -> str:
        if out_file is None:
            out_file = f"{BACKUP_FILE_PREFIX}{datetime.now().strftime('%Y%m%d_%H%M%S')}.backup"
        tmpzip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        tmpzip.close()
        with zipfile.ZipFile(tmpzip.name, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for fname in [self.private_key_file, self.public_key_file, self.friends_file, self.log_file]:
                if fname and os.path.exists(fname):
                    zf.write(fname, arcname=os.path.basename(fname))
        with open(tmpzip.name, "rb") as f:
            zip_bytes = f.read()
        os.remove(tmpzip.name)
        salt = secrets.token_bytes(SALT_SIZE)
        key = derive_key_from_password(self.password, salt)
        nonce = secrets.token_bytes(AES_NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, zip_bytes, associated_data=None)
        payload = {
            "salt": base64.b64encode(salt).decode('ascii'),
            "nonce": base64.b64encode(nonce).decode('ascii'),
            "ciphertext": base64.b64encode(ciphertext).decode('ascii'),
            "kdf_iters": KDF_ITERS
        }
        with open(out_file, "wb") as f:
            f.write(json.dumps(payload).encode('utf-8'))
        self.log_operation("BACKUP_CREATED", {"outfile": out_file, "len": len(zip_bytes)})
        return out_file

    def restore_encrypted_backup(self, backup_file: str) -> bool:
        if not os.path.exists(backup_file):
            print("Backup not found")
            return False
        with open(backup_file, "rb") as f:
            payload = json.loads(f.read().decode('utf-8'))
        salt = base64.b64decode(payload['salt'])
        nonce = base64.b64decode(payload['nonce'])
        ciphertext = base64.b64decode(payload['ciphertext'])
        key = derive_key_from_password(self.password, salt)
        aesgcm = AESGCM(key)
        try:
            zip_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
            tmpzip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
            tmpzip.close()
            with open(tmpzip.name, "wb") as f:
                f.write(zip_bytes)
            with zipfile.ZipFile(tmpzip.name, "r") as zf:
                zf.extractall(".")
            os.remove(tmpzip.name)
            self.log_operation("BACKUP_RESTORED", {"backup_file": backup_file})
            return True
        except Exception as e:
            print(f"Backup restore error: {e}")
            return False

    def show_friends_cli(self):
        if not self.friends:
            print("No friends added.")
            return
        print("\nFRIEND LIST:")
        for i, friend in enumerate(self.friends, 1):
            print(f"{i}. {friend['name']} (added on {friend['added']})")

    def friend_menu_cli(self):
        while True:
            print("\nFRIEND MANAGEMENT:")
            print("1. Show friends")
            print("2. Add friend")
            print("3. Remove friend")
            print("4. Back to main menu")
            choice = input("Choice > ")
            if choice == "1":
                self.show_friends_cli()
            elif choice == "2":
                name = input("Friend name: ")
                print("Paste public key (PEM) or enter file path (.pem):")
                pub_key_input = input().strip()
                self.add_friend(name, pub_key_input)
            elif choice == "3":
                self.show_friends_cli()
                if self.friends:
                    name = input("Friend name to remove: ")
                    self.remove_friend(name)
            elif choice == "4":
                return
            else:
                print("Invalid choice")

    def encrypt_menu_cli(self):
        print("\nADVANCED ENCRYPTION (hybrid AES+RSA):")
        print("1. Encrypt for myself")
        print("2. Encrypt for a friend")
        print("3. Encrypt file for a friend")
        print("4. Create session token for a friend (secure session)")
        print("5. Go back")
        choice = input("Choice > ")
        if choice == "1":
            message = input("Message to encrypt: ")
            encrypted = self.hybrid_encrypt(self.public_key, message.encode('utf-8'))
            print("\nENCRYPTED MESSAGE (base85):")
            print(encrypted)
            self.log_operation("ENCRYPT_SELF", {"sha256": sha256_hex(message.encode('utf-8')), "len": len(message)})
        elif choice == "2":
            if not self.friends:
                print("No friends saved.")
                return
            self.show_friends_cli()
            friend_idx = input("Select friend (number): ")
            if friend_idx.isdigit():
                idx = int(friend_idx) - 1
                if 0 <= idx < len(self.friends):
                    friend = self.friends[idx]
                    message = input("Message to encrypt: ")
                    encrypted = self.encrypt_message_for_friend(friend['name'], message)
                    print(f"\nENCRYPTED MESSAGE FOR {friend['name']} (base85):")
                    print(encrypted)
                else:
                    print("Invalid number")
            else:
                print("Please enter a valid number")
        elif choice == "3":
            if not self.friends:
                print("No friends saved.")
                return
            self.show_friends_cli()
            friend_idx = input("Select friend (number): ")
            if friend_idx.isdigit():
                idx = int(friend_idx) - 1
                if 0 <= idx < len(self.friends):
                    friend = self.friends[idx]
                    path = input("File path to encrypt: ")
                    token = self.encrypt_file_for_friend(friend['name'], path)
                    if token:
                        print("\nENCRYPTED FILE (base85):")
                        print(token)
                else:
                    print("Invalid number")
            else:
                print("Please enter a valid number")
        elif choice == "4":
            if not self.friends:
                print("No friends saved.")
                return
            self.show_friends_cli()
            friend_idx = input("Select friend (number): ")
            if friend_idx.isdigit():
                idx = int(friend_idx) - 1
                if 0 <= idx < len(self.friends):
                    friend = self.friends[idx]
                    token = self.create_session_token_for_friend(friend['name'])
                    print("\nSESSION TOKEN (send to your friend):")
                    print(token)
                else:
                    print("Invalid number")
            else:
                print("Please enter a valid number")
        elif choice == "5":
            return
        else:
            print("Invalid choice")

    def decrypt_menu_cli(self):
        print("\nDECRYPT MESSAGE/FILE/SESSION:")
        print("Paste encrypted message (base85). Press Enter when done:")
        encrypted_b85 = input().strip()
        if not encrypted_b85:
            print("No message provided")
            return
        maybe_session = False
        try:
            json_bytes = base64.b85decode(encrypted_b85)
            p = json.loads(json_bytes.decode('utf-8'))
            if 'sess_id' in p and 'ciphertext' in p:
                maybe_session = True
        except Exception:
            maybe_session = False
        if maybe_session:
            pt = self.session_decrypt(encrypted_b85)
            if pt is not None:
                print("\nDECRYPTED SESSION MESSAGE (utf-8 if possible):")
                try:
                    print(pt.decode('utf-8'))
                except:
                    print("[binary data] -> save to file if needed")
                return
        dec = self.decrypt_message(encrypted_b85)
        if dec is None:
            print("Decryption failed")
            return
        try:
            print("\nDECRYPTED MESSAGE:")
            print(dec)
        except Exception:
            print("Decrypted message (binary). Save to file? [y/N]")
            if input().lower().startswith('y'):
                outp = input("Output filename: ")
                with open(outp, "wb") as f:
                    f.write(dec)
                print("Saved.")

    def main_menu_cli(self):
        while True:
            print("\nMAIN MENU:")
            print("1. Encrypt/Decrypt (extended CLI)")
            print("2. Manage friends")
            print("3. Encrypted backup")
            print("4. Launch GUI (tkinter)")
            print("5. Exit")
            choice = input("Choice > ")
            if choice == "1":
                print("1. Encrypt\n2. Decrypt\n3. Back")
                sub = input("Choice > ")
                if sub == "1":
                    self.encrypt_menu_cli()
                elif sub == "2":
                    self.decrypt_menu_cli()
                else:
                    continue
            elif choice == "2":
                self.friend_menu_cli()
            elif choice == "3":
                print("1. Create backup\n2. Restore backup\n3. Back")
                sub = input("Choice > ")
                if sub == "1":
                    out = self.create_encrypted_backup()
                    print(f"Backup created: {out}")
                elif sub == "2":
                    b = input("Backup file path: ")
                    ok = self.restore_encrypted_backup(b)
                    print("Restore completed" if ok else "Restore failed")
            elif choice == "4":
                self.start_gui()
            elif choice == "5":
                print("Goodbye!")
                return
            else:
                print("Invalid choice")

    def start_gui(self):
        root = tk.Tk()
        root.title("Advanced Crypto App - GUI")
        root.geometry("800x600")

        left = tk.Frame(root, padx=10, pady=10)
        left.pack(side=tk.LEFT, fill=tk.Y)
        right = tk.Frame(root, padx=10, pady=10)
        right.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH)

        tk.Label(left, text="Friends:").pack()
        friends_listbox = tk.Listbox(left, width=30)
        friends_listbox.pack(fill=tk.Y)

        def refresh_friends():
            friends_listbox.delete(0, tk.END)
            for fr in self.friends:
                friends_listbox.insert(tk.END, fr['name'])
        refresh_friends()

        def add_friend_gui():
            name = simpledialog.askstring("Add Friend", "Friend name:")
            if not name:
                return
            choice = messagebox.askyesno("Method", "Do you want to paste the public key manually?")
            if choice:
                key_data = simpledialog.askstring("Public Key", "Paste the full PEM key:")
                if key_data:
                    ok = self.add_friend(name, key_data)
                else:
                    return
            else:
                path = filedialog.askopenfilename(title="Select public key file (.pem)")
                if not path:
                    return
                ok = self.add_friend(name, path)
            if ok:
                messagebox.showinfo("Success", f"Friend {name} added")
                refresh_friends()
            else:
                messagebox.showerror("Error", "Could not add friend")

        def remove_friend_gui():
            sel = friends_listbox.curselection()
            if not sel:
                messagebox.showwarning("Select", "Please select a friend from the list")
                return
            name = friends_listbox.get(sel[0])
            if messagebox.askyesno("Confirm", f"Remove {name}?"):
                self.remove_friend(name)
                refresh_friends()

        tk.Button(left, text="Add", command=add_friend_gui).pack(fill=tk.X, pady=2)
        tk.Button(left, text="Remove", command=remove_friend_gui).pack(fill=tk.X, pady=2)

        action_frame = tk.Frame(right)
        action_frame.pack(fill=tk.BOTH, expand=True)

        txt = scrolledtext.ScrolledText(action_frame)
        txt.pack(fill=tk.BOTH, expand=True)

        def encrypt_selected_for_friend():
            sel = friends_listbox.curselection()
            if not sel:
                messagebox.showwarning("Select", "Choose a friend")
                return
            friend_name = friends_listbox.get(sel[0])
            message = txt.get("1.0", tk.END).rstrip("\n")
            if not message:
                messagebox.showwarning("Empty", "Enter a message")
                return
            token = self.encrypt_message_for_friend(friend_name, message)
            if token:
                txt.delete("1.0", tk.END)
                txt.insert("1.0", token)
                messagebox.showinfo("Done", "Message encrypted and shown in text box")

        def decrypt_from_textbox():
            data = txt.get("1.0", tk.END).strip()
            if not data:
                messagebox.showwarning("Empty", "Paste encrypted message")
                return
            maybe_session = False
            try:
                j = base64.b85decode(datan.loads(j.decode('utf-8'))
                if 'sess_id' in p and 'ciphertext' in p:
                    maybe_session = True
            except Exception:
                maybe_session = False
            if maybe_session:
                pt = self.session_decrypt(data)
                if pt:
                    try:
                        txt.delete("1.0", tk.END)
                        txt.insert("1.0", pt.decode('utf-8'))
                        messagebox.showinfo("Decrypted", "Session message decrypted")
                        return
                    except:
                        txt.delete("1.0", tk.END)
                        txt.insert("1.0", "[binary data]")
                        return
            dec = self.decrypt_message(data)
            if dec is None:
                messagebox.showerror("Error", "Decryption failed")
            else:
                txt.delete("1.0", tk.END)
                txt.insert("1.0", dec)
                messagebox.showinfo("Decrypted", "Decryption completed")

        def encrypt_file_gui():
            sel = friends_listbox.curselection()
            if not sel:
                messagebox.showwarning("Select", "Choose a friend")
                return
            friend_name = friends_listbox.get(sel[0])
            path = filedialog.askopenfilename(title="Select file to encrypt")
            if not path:
                return
            token = self.encrypt_file_for_friend(friend_name, path)
            if token:
                txt.delete("1.0", tk.END)
                txt.insert("1.0", token)
                messagebox.showinfo("Done", "File encrypted and token inserted")

        def create_backup_gui():
            out = filedialog.asksaveasfilename(defaultextension=".backup", title="Save backup as...")
            if not out:
                return
            path = self.create_encrypted_backup(out)
            messagebox.showinfo("Backup Created", f"Backup created: {path}")

        def import_session_gui():
            token = simpledialog.askstring("Import session token", "Paste received session token:")
            if not token:
                return
            sess_id = self.import_session_token(token)
            if sess_id:
                messagebox.showinfo("Session imported", f"Session imported: {sess_id}")
            else:
                messagebox.showerror("Error", "Session import failed")

        btn_frame = tk.Frame(right)
        btn_frame.pack(fill=tk.X, pady=5)
        tk.Button(btn_frame, text="Encrypt for friend", command=encrypt_selected_for_friend).pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text="Decrypt", command=decrypt_from_textbox).pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text="Encrypt file", command=encrypt_file_gui).pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text="Import session token", command=import_session_gui).pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text="Encrypted backup", command=create_backup_gui).pack(side=tk.LEFT, padx=2)

        root.mainloop()

# ---------------------------
# Main
# ---------------------------
if __name__ == "__main__":
    app = AdvancedCryptoApp()
    print("\n=== CRYPTO APP ===")
    print("Public key available:", "YES" if app.public_key else "NO")
    print("Private key available:", "YES" if app.private_key else "NO")
    print("Number of friends:", len(app.friends))
    app.main_menu_cli()
