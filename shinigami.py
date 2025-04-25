import secrets
import string
import os
import hashlib
import requests
import base64
import json
import logging
from typing import Tuple, Optional, Dict
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from colorama import Fore, Style, init
from datetime import datetime
import art
import zxcvbn
import getpass
import shutil
import stat

HIBP_API = "https://api.pwnedpasswords.com/range/"
ROCKYOU_PATH = "rockyou.txt"
EFF_WORDLIST_PATH = "eff_large_wordlist.txt"
CONFIG_DIR = os.path.expanduser("~/.rutyshinigamii")
KEY_FILE = os.path.join(CONFIG_DIR, "master.key")
SALT_FILE = os.path.join(CONFIG_DIR, "salt.key")
VAULT_FILE = os.path.join(CONFIG_DIR, "vault.enc")
LOG_FILE = os.path.join(CONFIG_DIR, "rutyshinigamii.log")
DEFAULT_ITERATIONS = 2000000
MIN_PASSWORD_LENGTH = 25
VERSION = "3.0"

# Initialize logger without handlers inasmuch as handlers will be added later
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def setup_config_directory():
    """Create config directory and log file if they don't exist."""
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)
        os.chmod(CONFIG_DIR, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()
        os.chmod(LOG_FILE, stat.S_IRUSR | stat.S_IWUSR)

def setup_logging():
    """Set up logging with a FileHandler after config directory is ready."""
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(formatter)
    # Remove existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    logger.addHandler(file_handler)
    logging.info("Logging initialized")

# Call setup_config_directory before setting up logging
setup_config_directory()
setup_logging()

def generate_master_key(key_file=KEY_FILE):
    if not os.path.exists(key_file):
        salt = secrets.token_bytes(32)
        kdf = Scrypt(salt=salt, length=32, n=2**16, r=8, p=1)
        master_pass = getpass.getpass("Enter master password: ")
        key = kdf.derive(master_pass.encode())
        with open(key_file, "wb") as f:
            f.write(key + salt)
        os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)
        logging.info("Master key generated")
    return load_master_key()

def load_master_key(key_file=KEY_FILE):
    if not os.path.exists(key_file):
        return generate_master_key()
    with open(key_file, "rb") as f:
        data = f.read()
        return data[:32]

def get_key_salt(key_file=KEY_FILE):
    with open(key_file, "rb") as f:
        data = f.read()
        return data[32:]

def generate_salt(salt_file=SALT_FILE):
    if not os.path.exists(salt_file):
        salt = secrets.token_bytes(32)
        with open(salt_file, "wb") as f:
            f.write(salt)
        os.chmod(salt_file, stat.S_IRUSR | stat.S_IWUSR)
        logging.info("Salt generated")
    with open(salt_file, "rb") as f:
        return f.read()

def encrypt_data(data, key):
    iv = secrets.token_bytes(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted

def decrypt_data(data, key):
    iv, encrypted = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data).decode() + unpadder.finalize()

def generate_passphrase(word_count=5, wordlist_path=EFF_WORDLIST_PATH):
    if not os.path.exists(wordlist_path):
        raise ValueError(f"Wordlist not found: {wordlist_path}")
    with open(wordlist_path, "r") as f:
        words = [line.strip() for line in f if line.strip()]
    return " ".join(secrets.choice(words) for _ in range(word_count))

def generate_password(length=MIN_PASSWORD_LENGTH, passphrase=False, word_count=5):
    if passphrase:
        return generate_passphrase(word_count)
    length = max(length, MIN_PASSWORD_LENGTH)
    char_pool = string.ascii_letters + string.digits + string.punctuation
    while True:
        pwd = ''.join(secrets.choice(char_pool) for _ in range(length))
        if (any(c.isupper() for c in pwd) and any(c.islower() for c in pwd) and 
            any(c.isdigit() for c in pwd) and any(c in string.punctuation for c in pwd)):
            return pwd

def secure_hash_password(password, salt=None, iterations=DEFAULT_ITERATIONS):
    salt = salt or generate_salt()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=salt, iterations=iterations)
    hashed = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return f"{hashed.decode()}:{salt.hex()}:{iterations}"

def verify_password(password, stored_hash):
    try:
        hashed, salt, iterations = stored_hash.split(":")
        return secure_hash_password(password, bytes.fromhex(salt), int(iterations)) == stored_hash
    except ValueError:
        return False

def check_password_pwned(password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    headers = {"User-Agent": f"Rutyshinigamii/{VERSION}"}
    try:
        response = requests.get(HIBP_API + prefix, headers=headers, timeout=10)
        response.raise_for_status()
        count = sum(int(line.split(':')[1]) for line in response.text.splitlines() if suffix in line)
        if count:
            logging.warning(f"Password breach detected: {count} occurrences")
            print(f"{Fore.RED}[!] Compromised in {count} breaches!{Style.RESET_ALL}")
            return True, count
        print(f"{Fore.GREEN}[+] No breaches found{Style.RESET_ALL}")
        return False, 0
    except requests.RequestException as e:
        logging.error(f"Breach check failed: {str(e)}")
        print(f"{Fore.YELLOW}[~] Breach check failed: {e}{Style.RESET_ALL}")
        return False, -1

def dictionary_attack(target_hash, algo="sha256", wordlist_path=ROCKYOU_PATH):
    hash_funcs = {"sha256": hashlib.sha256, "sha512": hashlib.sha512, "md5": hashlib.md5}
    if algo not in hash_funcs:
        print(f"{Fore.RED}[-] Unsupported algorithm. Supported: {', '.join(hash_funcs.keys())}{Style.RESET_ALL}")
        return None
    if not os.path.exists(wordlist_path):
        print(f"{Fore.RED}[!] Wordlist not found: {wordlist_path}{Style.RESET_ALL}")
        return None
    print(f"{Fore.YELLOW}[*] Dictionary attack loading...{Style.RESET_ALL}")
    total_lines = sum(1 for _ in open(wordlist_path, 'r', errors='ignore'))
    hash_func = hash_funcs[algo]
    with open(wordlist_path, "r", errors="ignore") as file:
        for i, word in enumerate(file):
            word = word.strip()
            if i % 10000 == 0:
                print(f"{Fore.CYAN}[~] Progress: {(i/total_lines)*100:.2f}% ({i}/{total_lines}){Style.RESET_ALL}", end='\r')
            if hash_func(word.encode()).hexdigest() == target_hash:
                print(f"\n{Fore.GREEN}[+] Cracked: {word}{Style.RESET_ALL}")
                logging.info(f"Dictionary attack succeeded: {word}")
                return word
    print(f"\n{Fore.RED}[-] No match found after {total_lines} attempts{Style.RESET_ALL}")
    return None

def save_to_vault(name, password, key, metadata=None):
    vault = {}
    if os.path.exists(VAULT_FILE):
        try:
            with open(VAULT_FILE, "rb") as f:
                vault = json.loads(decrypt_data(f.read(), key))
        except (InvalidToken, ValueError):
            logging.error("Vault decryption failed")
            raise ValueError("Vault corrupted or wrong master key")
    entry = {
        "hash": secure_hash_password(password),
        "created": datetime.now().isoformat(),
        "metadata": metadata or {}
    }
    vault[name] = entry
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypt_data(json.dumps(vault, indent=2), key))
    os.chmod(VAULT_FILE, stat.S_IRUSR | stat.S_IWUSR)
    logging.info(f"Saved entry to vault: {name}")

def load_from_vault(name, key):
    if not os.path.exists(VAULT_FILE):
        return None
    try:
        with open(VAULT_FILE, "rb") as f:
            vault = json.loads(decrypt_data(f.read(), key))
            return vault.get(name)
    except (InvalidToken, ValueError):
        logging.error("Vault decryption failed during load")
        return None

def backup_vault():
    if os.path.exists(VAULT_FILE):
        backup_path = f"{VAULT_FILE}.{datetime.now().strftime('%Y%m%d_%H%M%S')}.bak"
        shutil.copy2(VAULT_FILE, backup_path)
        os.chmod(backup_path, stat.S_IRUSR | stat.S_IWUSR)
        logging.info(f"Vault backed up to {backup_path}")

def shinigami_seal(files=None):
    """Irreversibly wipe Rutyshinigamii files with 3-pass overwrite, inspired by Minato's Dead Demon consuming seal."""
    files = files or [KEY_FILE, SALT_FILE, VAULT_FILE, LOG_FILE]
    print(f"{Fore.YELLOW}[*] Targeted files: {', '.join(files)}{Style.RESET_ALL}")
    confirm = input(f"{Fore.RED}[!] WARNING: This will permanently destroy selected data. Type 'SHIKI_FUJIN' to confirm: {Style.RESET_ALL}")
    if confirm != "SHIKI_FUJIN":
        print(f"{Fore.YELLOW}[-] Shinigami seal aborted{Style.RESET_ALL}")
        logging.info("Shinigami seal aborted: Incorrect confirmation")
        return
    # Close logging handler to release rutyshinigamii.log
    for handler in logger.handlers[:]:
        if isinstance(handler, logging.FileHandler) and handler.baseFilename == os.path.abspath(LOG_FILE):
            handler.close()
            logger.removeHandler(handler)
    for file in files:
        if os.path.exists(file):
            try:
                # Ensure file is writable
                os.chmod(file, stat.S_IRUSR | stat.S_IWUSR)
                size = os.path.getsize(file)
                # Pass 1: Random data
                with open(file, 'wb') as f:
                    f.write(os.urandom(size))
                # Pass 2: Zeros
                with open(file, 'wb') as f:
                    f.write(b'\x00' * size)
                # Pass 3: Ones
                with open(file, 'wb') as f:
                    f.write(b'\xFF' * size)
                os.remove(file)
                print(f"{Fore.RED}[!] {file} destroyed{Style.RESET_ALL}")
            except PermissionError as e:
                print(f"{Fore.RED}[-] Failed to destroy {file}: Permission denied. Try running as administrator or ensure the file is not in use.{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Failed to destroy {file}: {str(e)}{Style.RESET_ALL}")
    # Reinitialize logging after wiping log file
    if LOG_FILE in files and not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()
        os.chmod(LOG_FILE, stat.S_IRUSR | stat.S_IWUSR)
        new_handler = logging.FileHandler(LOG_FILE)
        new_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(new_handler)
    print(f"{Fore.RED}[!] Shinigami seal completed: Data sealed in the void{Style.RESET_ALL}")
    logging.info("Shinigami seal executed")

def ensure_logging_handler(log_file=LOG_FILE):
    """Ensure the logger has an active FileHandler."""
    has_file_handler = any(isinstance(h, logging.FileHandler) and h.baseFilename == os.path.abspath(log_file) 
                          for h in logger.handlers)
    if not has_file_handler:
        if not os.path.exists(log_file):
            open(log_file, 'a').close()
            os.chmod(log_file, stat.S_IRUSR | stat.S_IWUSR)
        new_handler = logging.FileHandler(log_file)
        new_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(new_handler)
        logging.info("Reattached FileHandler to logger")

def main():
    init()
    key = generate_master_key()
    row_banner = """
                        .
              /^\\     .
         /\\   "V"
        /__\\   I      O  o
       //..\\\\  I     .
       \\].`[/  I
       /l\\/j\\  (]    .  O
      /. ~~ ,\\/I          .
      \\\\L__j^\\I       o
       \\/--v}  I     o   .
       |    |  I   _________
       |    |  I c(`       ')o
       |    l  I   \\.     ,/
     _/j  L l\\!  _//^---^\\\\    
    """
    banner = f"""
{Fore.RED}{row_banner}{Style.RESET_ALL}
{Fore.BLUE}╭━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╮{Style.RESET_ALL}
{Fore.BLUE}│ {Fore.CYAN}Professional Password Security Suite{Fore.BLUE}      │{Style.RESET_ALL}
{Fore.BLUE}│ {Fore.CYAN}Creator: st34lthv3ct3r{Fore.BLUE}                    │{Style.RESET_ALL}
{Fore.BLUE}│ {Fore.CYAN}Version: {VERSION} - {datetime.now().strftime('%Y-%m-%d')}{Fore.BLUE}   {Style.RESET_ALL}
{Fore.BLUE}│ {Fore.CYAN}Security Level: Great{Fore.BLUE}                     │{Style.RESET_ALL}
{Fore.BLUE}╰━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╯{Style.RESET_ALL}
"""
    print(banner)
    while True:
        print(f"{Fore.YELLOW}\nSecurity Operations:{Style.RESET_ALL}")
        print(f"1. {Fore.RED}Generate a secure password/passphrase")
        print(f"2. {Fore.YELLOW}Hash password")
        print(f"3. {Fore.CYAN}Check password breach")
        print(f"4. {Fore.RED}Perform dictionary attack")
        print(f"5. {Fore.WHITE}Save password to vault")
        print(f"6. {Fore.MAGENTA}Retrieve from vault")
        print(f"7. {Fore.CYAN}Backup vault")
        print(f"8. {Fore.RED}Activate Shinigami seal (wipe all data)")
        print("9. Exit")
        choice = input(f"{Fore.CYAN}Select operation [1-9]: {Style.RESET_ALL}").strip()
        try:
            if choice == "1":
                pwd_type = input(f"Generate (1) password or (2) passphrase? [1/2]: ").strip()
                if pwd_type == "1":
                    length = int(input(f"Length (min {MIN_PASSWORD_LENGTH}): ") or MIN_PASSWORD_LENGTH)
                    pwd = generate_password(length=length)
                elif pwd_type == "2":
                    word_count = int(input("Number of words (default 5): ") or 5)
                    pwd = generate_password(passphrase=True, word_count=word_count)
                else:
                    raise ValueError("Invalid type")
                score = zxcvbn.zxcvbn(pwd)
                print(f"{Fore.GREEN}Generated: {pwd}{Style.RESET_ALL}")
                print(f"Strength: {score['score']}/4")
                print(f"Crack Time: {score['crack_times_display']['offline_fast_hashing_1e10_per_second']}")
                logging.info(f"Generated {'passphrase' if pwd_type == '2' else 'password'}")
            elif choice == "2":
                pwd = getpass.getpass("Password (hidden input): ")
                salt = input("Custom salt (hex, optional): ").strip()
                salt = bytes.fromhex(salt) if salt else None
                iterations = int(input(f"Iterations (default {DEFAULT_ITERATIONS}): ") or DEFAULT_ITERATIONS)
                if iterations < 1000000:
                    print(f"{Fore.YELLOW}[!] Warning: Low iterations may reduce security{Style.RESET_ALL}")
                hashed = secure_hash_password(pwd, salt, iterations)
                print(f"{Fore.GREEN}Hash: {hashed}{Style.RESET_ALL}")
                logging.info("Password hashed")
            elif choice == "3":
                pwd = getpass.getpass("Password (hidden input): ")
                is_pwned, count = check_password_pwned(pwd)
            elif choice == "4":
                hash_val = input("Target hash: ").strip()
                algo = input("Algorithm (md5/sha256/sha512): ").lower()
                wordlist = input(f"Wordlist (default {ROCKYOU_PATH}): ") or ROCKYOU_PATH
                dictionary_attack(hash_val, algo, wordlist)
            elif choice == "5":
                name = input("Entry name: ").strip()
                if not name:
                    raise ValueError("Name cannot be empty")
                pwd = getpass.getpass("Password (hidden input): ")
                metadata = {"note": input("Optional note: ").strip()}
                save_to_vault(name, pwd, key, metadata)
                print(f"{Fore.GREEN}[+] Secured in vault{Style.RESET_ALL}")
            elif choice == "6":
                name = input("Entry name: ").strip()
                if entry := load_from_vault(name, key):
                    print(f"{Fore.GREEN}Hash: {entry['hash']}{Style.RESET_ALL}")
                    print(f"Created: {entry['created']}")
                    if entry['metadata'].get('note'):
                        print(f"Note: {entry['metadata']['note']}")
                else:
                    print(f"{Fore.RED}[-] Entry not found or vault corrupted{Style.RESET_ALL}")
            elif choice == "7":
                backup_vault()
                print(f"{Fore.GREEN}[+] Vault backup created{Style.RESET_ALL}")
            elif choice == "8":
                shinigami_seal()
            elif choice == "9":
                print(f"{Fore.GREEN}[+] Shutting down securely{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}[-] Invalid selection. Choose 1-9{Style.RESET_ALL}")
        except ValueError as e:
            print(f"{Fore.RED}[-] Input error: {e}{Style.RESET_ALL}")
            logging.error(f"ValueError: {str(e)}")
        except Exception as e:
            print(f"{Fore.RED}[-] Unexpected error: {e}{Style.RESET_ALL}")
            logging.error(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    try:
        # Ensure logging is set up properly at startup
        ensure_logging_handler()
        main()
    finally:
        # Log termination message before closing handlers
        ensure_logging_handler()  # Ensure a handler exists
        logging.info("Program terminated")
        # Now close all logging handlers
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
        # Secure file permissions
        for file in [KEY_FILE, SALT_FILE, VAULT_FILE, LOG_FILE]:
            if os.path.exists(file):
                os.chmod(file, stat.S_IRUSR | stat.S_IWUSR)