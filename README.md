![Screenshot 2025-04-18 132703](https://github.com/user-attachments/assets/b84d7cc3-e3db-43b8-a302-2cb5e0ac4a13)


---

# 🔐 RUTYSHINIGAMI

**RUTYSHINIGAMI** is a professional-grade password security suite written in Python. It empowers security enthusiasts and pentesters to generate strong passwords, hash and verify credentials, detect breaches, manage encrypted vaults, and perform dictionary attacks.

Created by **st34lthv3ct3r**  
Version: **3.0**

---

## Features

* 🔑 **Master Key & Vault System**  
  Secure passwords with AES encryption and store them in a locally encrypted vault.

-  **Password Generator**  
  Generate strong random passwords or passphrases using a customizable EFF-style wordlist.

-   **Hashing & Verification**  
  Hash passwords using PBKDF2 with high iteration counts. Supports custom salts and verification.

* 🌐 **Breach Detection**  
  Query the HaveIBeenPwned API to check if a password has appeared in known breaches.

* 📖 **Dictionary Attack**  
  Crack hashes with a custom or default wordlist (e.g., `rockyou.txt`).

* 🩻 **Shinigami Seal (Data Wipe)**  
  Securely erase all sensitive files using multi-pass overwrites.

---

## 📁 Installation

```bash
git clone https://github.com/calebpentest/RUTYSHINIGAMII.git
cd RUTYSHINIGAMII
pip install -r requirements.txt
```
Set Up a Virtual Environment (recommended):
bash
python3 -m venv venv
source venv/bin/activate
---

## Usage
Run the main interface:

```bash
python3 ruty.py
```

You'll be presented with an interactive CLI to:
* Generate passwords/passphrases
* Hash or verify a password
* Check for breaches
* Save/retrieve from a secure vault
* Perform dictionary attacks
* Wipe all data with the “Shinigami Seal”

---

## 🔐 Vault Storage

Sensitive data is stored in:
```
~/.rutyshinigamii/
├── master.key     # Master encryption key
├── salt.key       # Salt used in hashing
├── vault.enc      # Encrypted password vault
├── rutyshinigamii.log    # Operation logs
```

---

## ⚠️Security Notes

* **Always remember your master password** cos it is required to unlock your vault.
* Files are permission-locked to the user and stored securely.
* For full data deletion, use the **Shinigami Seal** function (invoked with `SHIKI_FUJIN` confirmation).

---

## License

This project is for **educational purpose only**.  
Unauthorized use for malicious purposes is strictly prohibited.

---
