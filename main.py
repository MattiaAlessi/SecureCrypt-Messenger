import base64
import zlib
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime

class AdvancedCryptoApp:
    MAX_CHUNK_SIZE = 190  # Maximum size for RSA-4096 chunks with OAEP
    LOG_FILE = "crypto_log.txt"
    PRIVATE_KEY_FILE = "private_key.pem"
    PUBLIC_KEY_FILE = "public_key.pem"
    PUBLIC_KEYS_DIR = "public_keys"
    FRIENDS_FILE = "friends.json"

    def __init__(self):
        self.init_files()
        self.private_key, self.public_key = self.load_or_generate_keys()
        self.friends = self.load_friends()

    def init_files(self):
        """Initialize all necessary files and directories"""
        if not os.path.exists(self.LOG_FILE):
            with open(self.LOG_FILE, "w") as f:
                f.write("=== CRYPTOGRAPHIC OPERATIONS LOG ===\n\n")
        
        if not os.path.exists(self.PUBLIC_KEYS_DIR):
            os.makedirs(self.PUBLIC_KEYS_DIR)
        
        if not os.path.exists(self.FRIENDS_FILE):
            with open(self.FRIENDS_FILE, "w") as f:
                json.dump([], f)

    def log_operation(self, operation, message):
        """Log an operation to the log file"""
        timestamp = datetime.now().strftime("%H:%M:%S on %d %B %Y")
        with open(self.LOG_FILE, "a", encoding='utf-8') as f:
            f.write(f"{timestamp} - {operation}: {message}\n")

    def load_or_generate_keys(self):
        """Load existing keys or generate new ones"""
        try:
            with open(self.PRIVATE_KEY_FILE, "r") as f:
                priv_pem = f.read()
            private_key = serialization.load_pem_private_key(
                priv_pem.encode('utf-8'),
                password=None
            )
            
            with open(self.PUBLIC_KEY_FILE, "r") as f:
                pub_pem = f.read()
            public_key = serialization.load_pem_public_key(
                pub_pem.encode('utf-8')
            )
            
            self.log_operation("KEYS LOADED", "Keys loaded successfully")
            return private_key, public_key
        
        except FileNotFoundError:
            print("Generating new keys...")
            return self.generate_new_keys()

    def generate_new_keys(self):
        """Generate a new RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        
        # Save private key
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        with open(self.PRIVATE_KEY_FILE, "w") as f:
            f.write(priv_pem)
        
        # Save public key
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        with open(self.PUBLIC_KEY_FILE, "w") as f:
            f.write(pub_pem)
        
        self.log_operation("NEW KEYS GENERATED", "New keys generated")
        return private_key, private_key.public_key()

    def load_friends(self):
        """Load friends list from JSON file"""
        try:
            with open(self.FRIENDS_FILE, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def save_friends(self):
        """Save friends list to JSON file"""
        with open(self.FRIENDS_FILE, "w") as f:
            json.dump(self.friends, f, indent=2)

    def add_friend(self, name, pub_key_path):
        """Add a new friend to the list"""
        try:
            # Check if name already exists
            if any(f['name'] == name for f in self.friends):
                print(f"Error: Friend with name '{name}' already exists")
                return False
            
            # Load and verify public key
            with open(pub_key_path, "r") as f:
                pub_pem = f.read()
            
            # Verify it's a valid key
            serialization.load_pem_public_key(pub_pem.encode('utf-8'))
            
            # Save key to directory
            friend_key_file = os.path.join(self.PUBLIC_KEYS_DIR, f"{name}.pem")
            with open(friend_key_file, "w") as f:
                f.write(pub_pem)
            
            # Add to friends list
            self.friends.append({
                "name": name,
                "key_file": friend_key_file,
                "added": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            
            self.save_friends()
            self.log_operation("FRIEND ADDED", f"Added friend: {name}")
            return True
        
        except Exception as e:
            print(f"Error adding friend: {str(e)}")
            return False

    def remove_friend(self, name):
        """Remove a friend from the list"""
        friend = next((f for f in self.friends if f['name'] == name), None)
        if not friend:
            print(f"Friend '{name}' not found")
            return False
        
        try:
            # Remove key file
            if os.path.exists(friend['key_file']):
                os.remove(friend['key_file'])
            
            # Remove from list
            self.friends = [f for f in self.friends if f['name'] != name]
            self.save_friends()
            
            self.log_operation("FRIEND REMOVED", f"Removed friend: {name}")
            return True
        
        except Exception as e:
            print(f"Error removing friend: {str(e)}")
            return False

    def compress_data(self, data):
        """Advanced compression with maximum level"""
        return zlib.compress(data, level=9)

    def decompress_data(self, compressed_data):
        """Data decompression"""
        return zlib.decompress(compressed_data)

    def encrypt_message(self, pub_key, message, compress=True):
        """Optimized encryption with chunk splitting and advanced compression"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        if compress:
            message = self.compress_data(message)
        
        # Split into chunks to avoid RSA size limits
        chunks = [message[i:i+self.MAX_CHUNK_SIZE] for i in range(0, len(message), self.MAX_CHUNK_SIZE)]
        encrypted_chunks = []
        
        for chunk in chunks:
            encrypted = pub_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_chunks.append(encrypted)
        
        # More efficient encoding with Base85 (more compact than Base64)
        combined = b''.join(encrypted_chunks)
        return base64.b85encode(combined).decode('ascii')

    def decrypt_message(self, encrypted_b85, decompress=True):
        """Decryption with chunk handling and decompression"""
        try:
            combined = base64.b85decode(encrypted_b85)
            chunk_size = 512  # RSA-4096 output size
            
            chunks = [combined[i:i+chunk_size] for i in range(0, len(combined), chunk_size)]
            decrypted_chunks = []
            
            for chunk in chunks:
                decrypted = self.private_key.decrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                decrypted_chunks.append(decrypted)
            
            message = b''.join(decrypted_chunks)
            
            if decompress:
                message = self.decompress_data(message)
            
            return message.decode('utf-8')
        
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            return None

    def show_compression_info(self, original, encrypted):
        """Show compression information"""
        orig_len = len(original)
        enc_len = len(encrypted)
        ratio = (enc_len/orig_len)*100 if orig_len > 0 else 0
        
        print("\nCOMPRESSION INFO:")
        print(f"Original: {orig_len} bytes")
        print(f"Encrypted: {enc_len} bytes")
        print(f"Ratio: {ratio:.2f}%")
        
        if orig_len > 0:
            savings = max(0, 100 - ratio)
            print(f"Savings: {savings:.2f}%")

    def show_friends(self):
        """Display friends list"""
        if not self.friends:
            print("No friends in list")
            return
        
        print("\nFRIENDS LIST:")
        for i, friend in enumerate(self.friends, 1):
            print(f"{i}. {friend['name']} (added on {friend['added']})")

    def friend_menu(self):
        """Friends management menu"""
        while True:
            print("\nFRIENDS MANAGEMENT:")
            print("1. Show friends list")
            print("2. Add new friend")
            print("3. Remove friend")
            print("4. Return to main menu")
            
            choice = input("Choice > ")
            
            if choice == "1":
                self.show_friends()
            
            elif choice == "2":
                name = input("Friend's name: ")
                pub_key_path = input("Public key file path (.pem): ")
                self.add_friend(name, pub_key_path)
            
            elif choice == "3":
                self.show_friends()
                if self.friends:
                    name = input("Friend name to remove: ")
                    self.remove_friend(name)
            
            elif choice == "4":
                return
            
            else:
                print("Invalid choice")

    def encrypt_menu(self):
        """Encryption menu with optimizations"""
        if not self.public_key:
            print("Public key not available")
            return
        
        print("\nADVANCED ENCRYPTION:")
        print("1. Encrypt for myself")
        print("2. Encrypt for a friend")
        print("3. Go back")
        
        choice = input("Choice > ")
        
        if choice == "1":
            message = input("Message to encrypt: ")
            encrypted = self.encrypt_message(self.public_key, message)
            
            print("\nENCRYPTED MESSAGE (base85):")
            print(encrypted)
            
            self.show_compression_info(message.encode('utf-8'), encrypted.encode('ascii'))
        
        elif choice == "2":
            if not self.friends:
                print("No friends in list")
                return
            
            self.show_friends()
            friend_idx = input("Select friend (number): ")
            
            if friend_idx.isdigit():
                idx = int(friend_idx) - 1
                if 0 <= idx < len(self.friends):
                    friend = self.friends[idx]
                    try:
                        with open(friend['key_file'], "r") as f:
                            pub_pem = f.read()
                        pub_key = serialization.load_pem_public_key(pub_pem.encode('utf-8'))
                        
                        message = input("Message to encrypt: ")
                        encrypted = self.encrypt_message(pub_key, message)
                        
                        print(f"\nMESSAGE ENCRYPTED FOR {friend['name']} (base85):")
                        print(encrypted)
                        
                        self.show_compression_info(message.encode('utf-8'), encrypted.encode('ascii'))
                    except Exception as e:
                        print(f"Error: {str(e)}")
                else:
                    print("Invalid number")
            else:
                print("Please enter a valid number")
        
        elif choice == "3":
            return
        
        else:
            print("Invalid choice")

    def decrypt_menu(self):
        """Decryption menu"""
        if not self.private_key:
            print("Private key not available")
            return
        
        print("\nMESSAGE DECRYPTION:")
        print("Paste the base85 encrypted message (end with CTRL+D/CTRL+Z):")
        
        lines = []
        while True:
            try:
                line = input()
                lines.append(line)
            except EOFError:
                break
        
        encrypted_b85 = ''.join(lines)
        
        if not encrypted_b85.strip():
            print("No message entered")
            return
        
        decrypted = self.decrypt_message(encrypted_b85)
        
        if decrypted:
            print("\nDECRYPTED MESSAGE:")
            print(decrypted)
        else:
            print("Decryption failed!")

    def main_menu(self):
        """Main menu"""
        while True:
            print("\nMAIN MENU:")
            print("1. Encrypt message")
            print("2. Decrypt message")
            print("3. Manage friends")
            print("4. Exit")
            
            choice = input("Choice > ")
            
            if choice == "1":
                self.encrypt_menu()
            
            elif choice == "2":
                self.decrypt_menu()
            
            elif choice == "3":
                self.friend_menu()
            
            elif choice == "4":
                print("Goodbye!")
                return
            
            else:
                print("Invalid choice")

if __name__ == "__main__":
    app = AdvancedCryptoApp()
    print("\n=== CRYPTO APP ===")
    print("Public key present:", "YES" if app.public_key else "NO")
    print("Private key present:", "YES" if app.private_key else "NO")
    print("Friends in list:", len(app.friends))
    app.main_menu()
