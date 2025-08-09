# 🔐 SecureCrypt Messenger


## ✨ Features

- **Encryption**: RSA-4096 with OAEP/SHA-256 padding
- **Space Optimization**:
  - Base85 encoding (25% more efficient than Base64)
  - Zlib Level 9 compression (up to 70% size reduction)
- **Contact Management**: Securely store and manage friends' public keys
- **Large File Support**: Automatic chunking for messages >190 bytes
- **Audit Trail**: Detailed timestamped operation logging
- **DANGER**: Don't send the encripted message via whatsapp because it
  eliminates some special character essentials for the decription

### Installation
```bash
# Clone the repository
git clone https://github.com/MattiaAlessi/SecureCrypt-Messenger
cd SecureCrypt-Messenger

# Install dependencies
pip install cryptography

# Run the application
python main.py


🛠️ Basic Usage
Generate your keys on first launch

Add contacts via the "Manage Friends" menu

Encrypt messages for yourself or your contacts

Decrypt received messages with your private key

📊 Compression Example
For a 10,000-character message:

Original: 10,000 bytes

Encrypted (Base85 + compression): ~3,300 bytes (67% space savings)

📜 License
This project is licensed under the MIT License
