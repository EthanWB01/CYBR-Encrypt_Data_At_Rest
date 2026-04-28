import os
import sys
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
ENC_SUFFIX = ".enc"
SALT_LEN = 16
FLAG_CRYPTO = b"C"
FLAG_PASSWORD = b"P"

def generate_random_key(key_len):
    key = os.urandom(key_len)
    with open("secret.key", "wb") as f:
        f.write(key)
        print("Key written successfully")
    return key

def load_key(saved_key = "secret"):
    if Path(saved_key).exists():
        with open(saved_key, "rb") as f:
            return f.read()
    else:
        raise FileNotFoundError(f"file could not be found")




def users_crypto_key(saved_key = "myhexkey"):
    raw = bytes.fromhex(saved_key)
    with open("secret.key", "wb") as f:
        f.write(raw)
        print(f"Successfully written to file")
    return raw


def users_password_key(password_key = "password", crypto_len = 32):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC( algorithm=hashes.SHA256() ,length=crypto_len ,salt=salt ,iterations=480_000,)
    key = kdf.derive(password_key.encode("utf-8"))
    with open("secret.key", "wb") as f:
        f.write(key)
        f.write(salt)
        print("Key written successfully")
    return key, salt


def key_from_password(password: str, key_len: int, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_len,
        salt=salt,
        iterations=480_000,
    )
    return kdf.derive(password.encode("utf-8"))



def encrypt_file_dir(file_path: Path, key: bytes, key_type_flag: bytes, salt: bytes = None) -> Path:
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    plaintext = file_path.read_bytes()
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    out_path = file_path.with_suffix(file_path.suffix + ENC_SUFFIX)

    with open(out_path, "wb") as f:
        f.write(key_type_flag)
        f.write(len(key).to_bytes(1, "big"))
        if key_type_flag == FLAG_PASSWORD:
            f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

    print(f"Encrypted-> {file_path} -> {out_path}")
    return out_path

def decrypt_file_dir(file_path: Path, key: bytes = None):
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if not str(file_path).endswith(ENC_SUFFIX):
        raise ValueError(f"Not an encrypted file (missing {ENC_SUFFIX}): {file_path}")

    data = file_path.read_bytes()
    offset = 0
    key_type_flag = data[offset:offset + 1]
    offset += 1
    key_len = data[offset]
    offset += 1

    if key_type_flag == FLAG_PASSWORD:
        salt = data[offset:offset + SALT_LEN]
        offset += SALT_LEN
        if key is None:
            print("Missing password")
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        key = key_from_password(key, key_len, salt)  # ← use stored key length
    elif key_type_flag == FLAG_CRYPTO:
        if key is None:
            print("no key found")
    else:
        print("key is wrong")

    nonce = data[offset:offset + NONCE_LEN]
    offset += NONCE_LEN
    ciphertext = data[offset:]
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)


    out_path = file_path.with_suffix(".dec")
    out_path.write_bytes(plaintext)
    print(f"Decrypted: {file_path} -> {out_path}")
    return out_path




if __name__ == "__main__":
    crypto_len = 32
    crypto_strength = input("What AES strength do you want (128/192/256): ")
    if crypto_strength == "128":
        crypto_len = 16
    elif crypto_strength == "192":
        crypto_len = 24
    elif crypto_strength == "256":
        crypto_len = 32

    answer = input("Do you want a true cryptographic key or password key? (crypto/pass): ")

    if answer == "crypto":
        answer_choice = input("Do you want to add your own hex key? (yes/no): ")
        if answer_choice == "yes":
            users_key = input("What's the crypto key (hex): ")
            test_key = users_crypto_key(users_key)
        else:
            test_key = generate_random_key(crypto_len)

        while True:
            file_input = input("\nEnter file path(s) (comma-separated), or 'done' to exit: ")
            if file_input.strip().lower() == "done":
                break

            raw_paths = [Path(f.strip()) for f in file_input.split(",")]
            file_paths = []
            action = input("Encrypt or decrypt? (e/d): ").strip().lower()
            for p in raw_paths:
                if p.is_dir():
                    if action == "e":
                        file_paths.extend(f for f in p.rglob("*") if f.suffix != ".enc" and f.is_file())
                    elif action == "d":
                        file_paths.extend(f for f in p.rglob("*") if f.suffix == ".enc")
                else:
                    file_paths.append(p)

            for file_path in file_paths:
                try:
                    if action == "e":
                        encrypt_file_dir(file_path, test_key, FLAG_CRYPTO)
                    elif action == "d":
                        decrypt_file_dir(file_path, test_key)
                    else:
                        print("Invalid action, skipping.")
                except (FileNotFoundError, ValueError) as e:
                    print(f" Error with {file_path}: {e}")

    elif answer == "pass":
        answer_pass = input("What is the password: ")
        password = answer_pass
        key, salt = users_password_key(password, crypto_len)

        while True:
            file_input = input("\nEnter file path(s) (comma-separated), or 'done' to exit:  ")
            if file_input.strip().lower() == "done":
                break

            raw_paths = [Path(f.strip()) for f in file_input.split(",")]
            file_paths = []
            action = input("Encrypt or decrypt? (e/d): ").strip().lower()
            for p in raw_paths:
                if p.is_dir():
                    if action == "e":
                        file_paths.extend(f for f in p.rglob("*") if f.suffix != ".enc" and f.is_file())
                    elif action == "d":
                        file_paths.extend(f for f in p.rglob("*") if f.suffix == ".enc")
                else:
                    file_paths.append(p)

            for file_path in file_paths:
                try:
                    if action == "e":
                        encrypt_file_dir(file_path, key, FLAG_PASSWORD, salt)
                    elif action == "d":
                        decrypt_file_dir(file_path, password)
                    else:
                        print("Invalid action, skipping.")
                except (FileNotFoundError, ValueError) as e:
                    print(f"Error with {file_path}: {e}")