............................................................................
. Project: A1B2                                                            .
. Build for educational purpose in authorized lab environments only.        .
. Purpose: Encrypts payloads with AES-GCM and RSA for secure delivery.      .
. Author: Ebere Michhael (Call Simba)                                      .
. Telegram: @lets_sudosu                                                   .
. Make the world a better place.                                           .
............................................................................

#!/usr/bin/env python3
import os, sys, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def encrypt_payload(input_exe, out_enc, pubkey_pem):
    with open(input_exe, "rb") as f: data = f.read()
    aes_key = os.urandom(32); nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    cipher_and_tag = aesgcm.encrypt(nonce, data, None)
    with open(pubkey_pem,"rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    wrapped_key = pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(),label=None)
    )
    with open(out_enc,"wb") as f:
        f.write(len(wrapped_key).to_bytes(2,"big"))
        f.write(wrapped_key)
        f.write(nonce)
        f.write(cipher_and_tag)
    print(f"→ Encrypted payload to {out_enc}")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    golden = digest.finalize()
    golden_ct = aesgcm.encrypt(nonce, golden, None)
    print("Base64 constants for C# integrity check:")
    print("HashKeyB64   =", base64.b64encode(aes_key).decode())
    print("HashNonceB64 =", base64.b64encode(nonce).decode())
    print("GoldenHashB64=", base64.b64encode(golden_ct).decode())

if __name__ == "__main__":
    if len(sys.argv)!=4:
        print("Usage: encrypt_payload.py <in.exe> <out.enc> <pubkey.pem>")
        sys.exit(1)
    encrypt_payload(*sys.argv[1:])