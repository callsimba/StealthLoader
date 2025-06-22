# StealthLoader

A multi-stage, hybrid-encrypted payload delivery framework for red teams and offensive-security researchers.

---

## Overview

StealthLoader implements a robust, end-to-end pipeline that takes an arbitrary executable, encrypts it with AES-GCM wrapped by RSA-OAEP, and then delivers and executes it stealthily:

1. **Payload Encryption (`encrypt_payload.py`)**  
   - Generates a random AES-GCM key and nonce  
   - Encrypts your payload and its SHA-256 “golden” hash  
   - Wraps the AES key with RSA-OAEP (`rsa_pub.pem`)  
   - Outputs `payload.enc`

2. **Stealthy Loader (`Program.cs`)**  
   - Launches a decoy browser window to distract the user  
   - Downloads `payload.enc` and the wrapped private key (`rsa_priv.pem`) over HTTPS  
   - Unwraps the AES key in-memory using RSA-OAEP  
   - Decrypts the payload and verifies its integrity  
   - Writes the decrypted EXE to `%TEMP%` under a randomized name, executes it hidden  
   - Self-deletes via a delayed CMD trick, leaving no disk artifacts

> **For educational and research purposes only.**

---

## Features

- **Hybrid envelope encryption** (AES-GCM + RSA-OAEP)  
- **Authenticated integrity checks** (SHA-256 golden hash)  
- **Decoy UI** to mask network activity  
- **In-memory key handling** with no plaintext key on disk  
- **Randomized payload drop** to evade signature detection  
- **Silent execution** with no visible windows  
- **Self-cleanup** to remove loader artifacts  

---

## Requirements

- **Python 3.6+**  
- **`cryptography`** library for Python encryption  
- **.NET 5.0+** (or .NET Framework 4.7.2+) for the C# loader  
- Windows 10 / 11 (x64)

---

## Setup & Usage

### 1. Encrypt your payload

```bash
pip install cryptography
python3 encrypt_payload.py \
  --input path/to/your_executable.exe \
  --pubkey rsa_pub.pem \
  --output payload.enc
   --input : path to the clear-text payload

   --pubkey: RSA public key (rsa_pub.pem)
   
   --output : encrypted payload file (payload.enc)


2. Host the encrypted files
Place payload.enc and rsa_priv.pem on an HTTPS-accessible server.



Contributing
Contributions, issues, and suggestions are welcome!

Fork the repo

Create a feature branch (git checkout -b feature/YourFeature)

Commit your changes (git commit -m "Add awesome feature")

Push to GitHub (git push origin feature/YourFeature)

Open a Pull Request

License
This project is licensed under the MIT License. See LICENSE for details.

Author & Contact
Call Simba
Telegram: @lets_sudosu

Let’s make the world a better place—one clean payload at a time!
