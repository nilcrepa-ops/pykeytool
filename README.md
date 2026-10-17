# pykeytool

A Python reimplementation of the common functionality of Java's `keytool`, built on
`cryptography` and `asn1crypto`.

**Keystores it writes are read by the real `keytool` — and vice versa.**

---

## Why

`keytool` is the standard way to manage keys and certificates on the JVM, but it is
bound to Java. This project asks how much of it can be rebuilt in Python, and how
faithfully — down to the file format, so that a Java application and a Python script
can share the same keystore.

---

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python main.py --help
```

Run from the repository root (there is no packaging/entry point yet).

---

## What works

| Command | Meaning |
| --- | --- |
| `genkeypair` | Generate a key pair and a self-signed certificate |
| `list` | List entries, with `-v` for full certificate detail |
| `exportcert` | Export a certificate (DER, or PEM with `-rfc`) |
| `printcert` | Print a certificate file (PEM or DER) |
| `certreq` | Generate a certificate signing request |
| `importcert` | Import a certificate or a certificate chain |
| `importkeystore` | Copy entries between keystores |
| `delete` | Delete one entry |

Plus `-cacerts` (read the JDK truststore), `-version` and `--help`.

**Algorithms:** RSA, EC, DSA, Ed25519, Ed448 — with signature algorithms validated
against the key type.

**Extensions (`-ext`):** `bc`, `ku`, `eku`, `san`, `ian`, `sia`, `aia`, `crl`, plus
arbitrary OIDs as `#hexDER`, with `:critical` on any of them.

**Names:** RFC 2253 `-dname` — escaping, multi-valued RDNs, numeric OID attributes.

---

## Demo

A self-signed TLS server certificate, checked by Java and OpenSSL.

> Output below is from one run — dates and fingerprints will differ each time.

### 1. Create a TLS-ready certificate

```bash
python main.py genkeypair \
    -alias web -keystore demo.p12 -storepass secret123 \
    -dname "CN=web.example.com, O=Example, C=ES" \
    -keyalg EC \
    -ext san=dns:web.example.com,dns:www.web.example.com,ip:10.0.0.5 \
    -ext ku:critical=digitalSignature,keyEncipherment \
    -ext eku=serverAuth
```

```
Generating 384 bit EC key pair and self-signed certificate (SHA384withECDSA) with a validity of 90 days
	for: CN=web.example.com, O=Example, C=ES
```

The extensions are what make the certificate usable for TLS — a self-signed
certificate without `SAN` is rejected by every modern client.

### 2. Look at it

```bash
python main.py list -keystore demo.p12 -storepass secret123
```

```
Keystore type: PKCS12

Your keystore contains 1 entry

web, Oct 17, 2026, PrivateKeyEntry,
Certificate fingerprint (SHA-256): 2E:34:45:A2:A0:FC:50:40:0C:FF:76:5E:B1:66:60:E2:C8:49:4A:20:9E:C4:D6:CE:1E:A4:19:34:AB:3E:E5:E2
```

### 3. Verify the certificate with OpenSSL

```bash
python main.py exportcert -alias web -keystore demo.p12 -storepass secret123 -rfc \
  | openssl x509 -noout -text | sed -n '/X509v3 extensions/,/Signature Algorithm/p'
```

```
        X509v3 extensions:
            X509v3 Subject Alternative Name:
                DNS:web.example.com, DNS:www.web.example.com, IP Address:10.0.0.5
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Subject Key Identifier:
                6D:F2:D7:E2:5F:11:EB:14:D9:11:FB:01:C4:2D:32:4C:FD:18:0C:E2
    Signature Algorithm: ecdsa-with-SHA384
```

### 4. Java reads the same store

```bash
keytool -list -keystore demo.p12 -storepass secret123 -v
```

```
Your keystore contains 1 entry
Entry type: PrivateKeyEntry
Signature algorithm name: SHA384withECDSA
Subject Public Key Algorithm: 384-bit EC (secp384r1) key
  DNSName: web.example.com
  DNSName: www.web.example.com
  IPAddress: 10.0.0.5
```

### 5. More than one entry in a keystore

```bash
python main.py genkeypair \
    -alias rootca -keystore demo.p12 -storepass secret123 \
    -dname "CN=Demo Root CA, O=Example, C=ES" \
    -keyalg RSA -keysize 2048 -ext bc:c -validity 3650

python main.py list -keystore demo.p12 -storepass secret123
```

```
Keystore type: PKCS12

Your keystore contains 2 entries

web, Oct 17, 2026, PrivateKeyEntry,
Certificate fingerprint (SHA-256): 2E:34:45:A2:A0:FC:50:40:0C:FF:76:5E:B1:66:60:E2:C8:49:4A:20:9E:C4:D6:CE:1E:A4:19:34:AB:3E:E5:E2
rootca, Oct 17, 2026, PrivateKeyEntry,
Certificate fingerprint (SHA-256): 4C:D0:6E:38:43:59:34:19:0A:CA:79:3C:41:19:49:63:B6:10:A6:18:62:22:5C:B4:6C:11:C2:CA:B4:24:91:3D
```

`-ext bc:c` makes it a CA certificate — the same store can hold keys and a CA.

### 6. Read the JDK truststore

```bash
python main.py list -cacerts -storepass changeit
```

```
Keystore type: JKS

Your keystore contains 121 entries
```

The JDK `cacerts` file is a JKS keystore; pykeytool reads it — same 121 entries and
identical fingerprints as `keytool -list -cacerts`.

### 7. Remove just one entry

```bash
python main.py delete -alias rootca -keystore demo.p12 -storepass secret123 -v
```

```
Deleted entry <rootca> from demo.p12
```

`web` is untouched: every operation is a read-modify-write of the whole store.

---

## A CA-issued chain (the other half of the story)

pykeytool can import a real certificate chain, so it works with a CA that lives in Java:

```bash
# 1. the CA (made with keytool)
keytool -genkeypair -alias ca -keystore ca.p12 -storetype PKCS12 \
        -storepass secret123 -keypass secret123 \
        -dname "CN=Root CA" -keyalg RSA -keysize 2048 -ext bc:c

# 2. a request from pykeytool
python main.py genkeypair -alias srv -keystore srv.p12 -storepass secret123 \
        -dname "CN=srv.example.com" -keyalg RSA -keysize 2048
python main.py certreq -alias srv -keystore srv.p12 -storepass secret123 -file srv.csr

# 3. the CA signs it
keytool -gencert -alias ca -keystore ca.p12 -storepass secret123 \
        -infile srv.csr -outfile srv.pem -rfc
keytool -exportcert -alias ca -keystore ca.p12 -storepass secret123 -rfc -file ca.pem

# 4. pykeytool installs the reply with its chain
cat srv.pem ca.pem > chain.pem
python main.py importcert -alias srv -keystore srv.p12 -storepass secret123 \
        -file chain.pem -noprompt -v

keytool -list -keystore srv.p12 -storepass secret123 -v | grep 'chain length'
```

```
Certificate reply was installed in keystore for <srv>
Certificate chain length: 2
```

---

## How it is built

| File | Responsibility |
| --- | --- |
| `main.py` | Command dispatch, output formatting, `keytool error:` handling |
| `cli.py` | `argparse` definitions for every command and option |
| `core/crypto.py` | Key generation, DNs, certificates, CSRs, start dates |
| `core/extensions.py` | The `-ext` grammar (`bc`, `ku`, `eku`, `san`, …) |
| `core/pkcs12.py` | Multi-entry PKCS#12 reader/writer, KDF, PBES1/PBES2, MAC |
| `core/keystore.py` | Entry-level operations: load, add, delete, import |
| `core/jks.py` | Read-only JKS truststore reader (`-cacerts`) |
| `core/cacerts.py` | Locating the JDK truststore |
| `core/errors.py` | `KeytoolError` — the only exception the CLI shows the user |

Roughly 3,300 lines. The interesting part is `core/pkcs12.py`: Python's `cryptography`
library can only read **one** private key per PKCS#12 file, so multi-entry support meant
speaking the format directly — ASN.1 structures with `asn1crypto`, the RFC 7292 key
derivation function, PBES2 (PBKDF2 + AES-CBC), PBES1 (3DES), and the file MAC.

---

## How it was verified

Not by unit tests — by cross-checking against the real tools:

- **16 `-ext` forms** were encoded with both keytool and pykeytool; the resulting
  extensions matched **byte-for-byte** (OID, criticality, value DER).
- Java **signs a CSR with a key pykeytool wrote**, proving the encrypted private key
  really decrypts — not just that the file parses.
- `keytool -importkeystore` re-imports every pykeytool entry; exported certificates have
  identical SHA-256 fingerprints.
- The JDK truststore reads as 121 certificates, matching `keytool -list -cacerts`.
- Deleting the last entry leaves a valid empty store that Java reads as "0 entries".

Bugs found and fixed along the way: X.500 names were encoded in the wrong order,
trusted-certificate entries were invisible to Java, multi-entry stores were silently
truncated, and several options were accepted but ignored.

---

## Limitations

- **No `-gencert`** — the tool can create a CA but not sign with it (it can import the
  result from `keytool`).
- Also missing: `-genseckey`, `-importpass`, `-keypasswd`, `-storepasswd`,
  `-changealias`, `-printcertreq`, `-printcrl`, `-showinfo`.
- **JKS is read-only** — writing one refuses rather than silently converting it.
- `-keypass` must equal `-storepass`.
- Multi-valued RDNs (`CN=A+OU=B`) are flattened into separate RDNs — a limitation of
  `cryptography`, values preserved.
- Attribute values are encoded as UTF8String where keytool uses PrintableString;
  semantically equivalent, and both render the same.

---

## Further reading

[GAPS.md](GAPS.md) is the full engineering record: a command-by-command comparison with
keytool, every defect found with the evidence, and the design of the multi-entry PKCS#12
engine.
