# PyKeytool (Python Keytool Replica)

A lightweight Python replica of Java's `keytool` utility for managing cryptographic keys, X.509 certificates, and PKCS#12 (`.p12` / `.pfx`) keystores. Built with modular architecture using Python's standard library and the `cryptography` package.

---

## Authors / Collaborators

- **Nil Creus Palma** ([@nilcrepa-ops](https://github.com/nilcrepa-ops))

---

## Dependencies & Requirements

- **Python**: `3.10+` (tested up to Python `3.14`)
- **Third-party Packages**:
  - [`cryptography`](https://cryptography.io/) (>= 41.0.0): Handles RSA key generation, X.509 certificates, PKCS#12 storage serialization, and CSR creation.

### Installation

```bash
# Clone repository
git clone https://github.com/nilcrepa-ops/pykeytool.git
cd pykeytool

# (Optional) Create and activate virtual environment
python -m venv venv
# Linux / macOS:
source venv/bin/activate
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1

# Install required dependencies
pip install -r requirements.txt
```

---

## CLI Usage Guide

The tool is invoked via `python main.py <command> [options]`.

```bash
python main.py --help
```

### Supported Commands Overview

| Command | Description |
| :--- | :--- |
| `genkeypair` | Generates an RSA key pair and a self-signed X.509 certificate, storing it under an alias in a PKCS#12 keystore. |
| `list` | Lists keystore contents and outputs certificate details (subject, issuer, validity, fingerprints). |
| `exportcert` | Exports the certificate associated with an alias to a file (DER or RFC/PEM format). |
| `printcert` | Reads and inspects an external certificate file (PEM or DER format). |
| `certreq` | Generates a PKCS#10 Certificate Signing Request (CSR) in PEM format for a given key pair entry. |
| `delete` | Removes an entry / alias from the PKCS#12 keystore. |

---

### Detailed Command Examples

#### 1. Generate Key Pair & Certificate (`genkeypair`)

Generates an RSA key pair and self-signed certificate, prompting interactively for password verification (entered twice). Supports creating new keystores or appending aliases to existing ones.

```bash
# Basic generation (interactive password verification)
python main.py genkeypair -alias cert1 -keystore mykeystore.p12

# Custom keysize, validity, and distinguished name (DName)
python main.py genkeypair -alias webserver -keystore mykeystore.p12 -keysize 4096 -validity 730 -dname "CN=myserver.local, O=MyOrg, C=ES"

# Non-interactive / script mode (using storepass)
python main.py genkeypair -alias cert2 -keystore mykeystore.p12 -storepass "MyPassword123"
```

*Options for `genkeypair`:*
- `-alias` *(required)*: Unique alias name for the key/cert entry.
- `-keystore` *(required)*: Path to PKCS#12 keystore file (`.p12` / `.pfx`).
- `-storepass`: Keystore password (if omitted, prompts interactively with double confirmation).
- `-keysize`: RSA key size in bits (default: `2048`).
- `-validity`: Certificate validity in days (default: `365`).
- `-dname`: Distinguished Name string (e.g., `"CN=Name, O=Org, C=ES"`).
- `-keyalg`: Key algorithm (default: `Rsa`).

---

#### 2. List Keystore Entries (`list`)

Displays summary or detailed certificate information from the keystore.

```bash
# Summary view
python main.py list -keystore mykeystore.p12

# Verbose view (shows Owner, Issuer, Serial number, Dates, SHA1 and SHA256 fingerprints)
python main.py list -keystore mykeystore.p12 -v
```

---

#### 3. Export Certificate (`exportcert`)

Exports a certificate from the keystore into binary DER format or PEM (`-rfc`).

```bash
# Export in DER binary format
python main.py exportcert -alias cert1 -keystore mykeystore.p12 -file cert1.crt

# Export in RFC / PEM format
python main.py exportcert -alias cert1 -keystore mykeystore.p12 -file cert1.pem -rfc
```

---

#### 4. Print / Inspect Certificate File (`printcert`)

Inspects standalone certificate files directly (without opening a keystore).

```bash
# View certificate summary
python main.py printcert -file cert1.crt

# Detailed verbose inspection
python main.py printcert -file cert1.pem -v
```

---

#### 5. Generate Certificate Signing Request (`certreq`)

Creates a standard PKCS#10 CSR from an existing keystore entry to submit to a Certificate Authority (CA).

```bash
python main.py certreq -alias cert1 -keystore mykeystore.p12 -file cert1.csr
```

---

#### 6. Delete Keystore Entry (`delete`)

Deletes an alias entry from the keystore.

```bash
python main.py delete -alias cert1 -keystore mykeystore.p12
```

---

## Test Matrix / Evaluation Checklist

Below is the verification and testing matrix covering functional requirements, validation, and security edge cases:

| # | Test Scenario / Feature | Command / Procedure | Expected Result | Status |
| :-: | :--- | :--- | :--- | :---: |
| **1** | **CLI Help & Options** | `python main.py --help`<br>`python main.py <cmd> --help` | Displays usage instructions, available subcommands, and flags without throwing errors. | Passed |
| **2** | **New Keystore Creation** | `python main.py genkeypair -alias cert1 -keystore test.p12` | Prompts for password twice; creates encrypted PKCS#12 file containing key pair and self-signed certificate. | Passed |
| **3** | **Interactive Password Double Check** | Run `genkeypair` and intentionally type mismatched passwords | Aborts execution with `Passwords do not match` error message and non-zero exit code. | Passed |
| **4** | **Password Length Validation** | Run `genkeypair` and input password < 6 characters | Rejects password with `Password must be at least 6 characters long`. | Passed |
| **5** | **Duplicate Alias Prevention** | Run `genkeypair -alias cert1` on a keystore where `cert1` already exists | Aborts with `Error: Key pair not generated, alias <cert1> already exists`. | Passed |
| **6** | **Multiple Aliases in Same Keystore** | Run `genkeypair -alias cert2 -keystore test.p12` | Successfully adds `cert2` without overwriting or corrupting `cert1`. | Passed |
| **7** | **Keystore Listing & Verbose Info** | `python main.py list -keystore test.p12 -v` | Shows PKCS#12 type, Owner, Issuer, Serial, Validity dates, and SHA-1 / SHA-256 fingerprints. | Passed |
| **8** | **Certificate Export (DER & PEM)** | `python main.py exportcert -alias cert1 -keystore test.p12 -file cert1.crt`<br>`python main.py exportcert -alias cert1 -keystore test.p12 -file cert1.pem -rfc` | Successfully generates valid DER binary file and RFC-compliant base64 PEM encoded file. | Passed |
| **9** | **Certificate Inspection (`printcert`)** | `python main.py printcert -file cert1.crt -v` | Reads and decodes certificate details directly from file. | Passed |
| **10** | **CSR Generation (`certreq`)** | `python main.py certreq -alias cert1 -keystore test.p12 -file cert1.csr` | Produces valid PKCS#10 PEM certificate signing request signed with private key. | Passed |
| **11** | **Alias Deletion (`delete`)** | `python main.py delete -alias cert1 -keystore test.p12` | Removes `cert1` from keystore while retaining remaining entries (or empties store if last entry). | Passed |
| **12** | **Invalid Password / Decryption Error** | Provide wrong password when opening keystore | Raises clean error message and exits without modifying keystore file. | Passed |

---

## Project Architecture

```
pykeytool/
├── cli.py             # Argument parsing and CLI definitions
├── commands.txt       # Quick command reference and test guide
├── core/
│   ├── __init__.py
│   ├── crypto.py      # Cryptographic operations (RSA keygen, X.509 cert, CSR, fingerprints)
│   └── keystore.py    # PKCS#12 serialization, builder, entry management & deletion
├── main.py            # Execution entry point and command orchestration
├── README.md          # Project documentation, CLI guide and test matrix
└── requirements.txt   # Project dependencies
```
