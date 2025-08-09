# 🔐 SecureCrypt Messenger

**End-to-end encrypted communication with hybrid cryptography, secure sessions, and encrypted backups.**

A Python-based encryption tool that combines **AES-256-GCM** and **RSA-4096-OAEP** to securely encrypt messages, files, and session keys — with compression, logging, and a simple GUI.

> ⚠️ **Not for high-risk environments.** Designed for learning and personal use.

---

## ✨ Features

- **Hybrid Encryption**:
  - **AES-256-GCM** for fast, secure data encryption
  - **RSA-4096-OAEP (SHA-256)** for secure key wrapping
- **Efficient Encoding & Compression**:
  - **Base85 encoding** – 25% smaller than Base64
  - **Zlib Level 9 compression** – up to 70% size reduction for text
- **Contact Management**:
  - Add friends via public key (paste PEM or load `.pem` file)
  - Keys stored securely in `public_keys/`
- **File Encryption**:
  - Encrypt and decrypt any file using your friend’s public key
- **Secure Session Tokens**:
  - Exchange temporary AES keys for fast, repeated communication
  - Session keys never stored on disk
- **Encrypted Backups**:
  - Create password-protected backups of keys, contacts, and logs
  - Restore securely using your password
- **Audit Logging**:
  - Full log (`crypto_log.txt`) with timestamps, user, and **SHA-256 hashes** of payloads
- **Dual Interface**:
  - CLI menu system for full control
  - Minimal **Tkinter GUI** for basic operations

> ❗ **WARNING**: Do **not** send encrypted tokens via WhatsApp, Telegram, or social media.  
> These platforms often **alter special characters** (`+`, `/`, `=`, newlines), corrupting the ciphertext and making decryption **impossible**.

---

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/AdvancedCryptoApp
cd AdvancedCryptoApp

# Install the required dependency
pip install cryptography

# Run the app
python main.py

📜 License
This project is licensed under the MIT License
