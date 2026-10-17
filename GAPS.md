# pykeytool — Gap Analysis vs. Java `keytool`

**Goal of the project:** reimplement the common functionality of the JDK's `keytool`
(key and certificate management) in Python.

**Assessed:** 2026-10-15

| Item | Value |
| --- | --- |
| Reference implementation | OpenJDK **27** `keytool` (`/usr/bin/keytool`, 18 commands) |
| Working tree | branch `main` @ `ba05cee` (2026-10-08) |
| Other branch with work | `origin/dev` @ `947ee10` (2026-10-15) — 6 commands partially implemented |
| Runtime present | Python 3.14.8, `cryptography` 50.0.2 |

This document lists **what is missing or broken**. It is based on reading every source
file plus executing both branches and cross-checking their output against the real
`keytool` (see [Appendix A](#appendix-a--how-to-reproduce)).

> **Status update (P0 complete, 2026-10-15).** All eight P0 items are implemented on the
> working tree, including true multi-entry stores (§12). The CLI is wired to the crypto
> layer in a single codebase; `-keysize`/`-validity` no longer crash; `-keyalg` and
> `-sigalg` are honoured; aliases are verified on every alias-taking command; errors are
> reported as `keytool error: …` on stderr with exit code 1 instead of tracebacks; and
> dependencies are declared. Sections below still describe the pre-fix state for context.
>
> **§11** tracks the P0 items and their state; **§12** documents the multi-entry engine.

---

## 0. Executive summary

The project currently implements **6 of 18** `keytool` commands, and only as *partial*
versions, and only on the unmerged `dev` branch. The `main` branch is a **stub**: it
parses arguments for a single command and prints them without doing any cryptography.

The three largest structural gaps are:

1. **One entry per keystore file.** `save_keystore_pkcs12()` always serializes a single
   key+cert and truncates the file, so adding a second alias *silently destroys the
   first* (verified). Real `keytool` stores are a collection of independently named
   entries.
2. **Only PKCS#12, no `-storetype`, no JKS/JCEKS.** Existing Java keystores (JKS/JCEKS),
   `cacerts` truststores, and `-importkeystore` migration are all unsupported.
3. **Certificates carry almost no extensions** (only `BasicConstraints`). A generated
   certificate has no `SubjectAlternativeName`, `KeyUsage`, or `ExtendedKeyUsage`, so it
   cannot be used as a TLS server certificate by modern clients — which is the main
   reason people run `keytool -genkeypair` in the first place.

Note: items marked **[dev]** exist only on `origin/dev`, not on the checked-out `main`.

---

## 1. Command coverage matrix

| # | `keytool` command | Purpose | `main` | `dev` | Gap |
| --- | --- | --- | --- | --- | --- |
| 1 | `-genkeypair` | Generate key pair + self-signed cert | stub | partial | No `-ext`, `-sigalg`, `-keypass`, `-storetype`, `-startdate`, `-signer`; no EC/DSA/EdDSA |
| 2 | `-list` | List keystore entries | ✗ | partial | No `-alias` filter, no `-rfc`, no `-cacerts`; non-verbose mode prints **no entries at all** |
| 3 | `-exportcert` | Export certificate | ✗ | partial | No stdout output, no truststore/cert-entry export, no `-v` |
| 4 | `-printcert` | Print certificate content | ✗ | partial | No `-sslserver`, `-jarfile`, `-keystore`, `-rfc`, `-trustcacerts`; thin `-v` output |
| 5 | `-certreq` | Generate a CSR | ✗ | partial | No `-dname`, `-ext`, `-sigalg` (ignored), `-keypass`, `-v`; no extensions in the CSR |
| 6 | `-delete` | Delete an entry | ✗ | partial | **Deletes the whole store**; alias argument is ignored (verified) |
| 7 | `-changealias` | Rename an entry | ✗ | ✗ | Missing entirely |
| 8 | `-genseckey` | Generate a secret key (AES/DES) | ✗ | ✗ | Missing entirely |
| 9 | `-gencert` | Sign a CSR (act as a CA) | ✗ | ✗ | Missing entirely — no CA/chain capability |
| 10 | `-importcert` | Import a certificate / chain | ✗ | ✗ | Missing entirely — the keystore is write-only from inside the tool |
| 11 | `-importpass` | Import a password entry | ✗ | ✗ | Missing entirely |
| 12 | `-importkeystore` | Import entries from another keystore | ✗ | ✗ | Missing entirely — blocks JKS→PKCS12 migration |
| 13 | `-keypasswd` | Change an entry's key password | ✗ | ✗ | Missing entirely — key passwords not modelled |
| 14 | `-printcertreq` | Print a CSR's content | ✗ | ✗ | Missing entirely |
| 15 | `-printcrl` | Print a CRL file | ✗ | ✗ | Missing entirely |
| 16 | `-storepasswd` | Change the store password | ✗ | ✗ | Missing entirely |
| 17 | `-showinfo` | Security/`-tls` info | ✗ | ✗ | Missing entirely |
| 18 | `-version` | Print program version | ✗ | ✗ | Missing entirely |

**Coverage: 6/18 commands (33%), 0/18 complete.**

---

## 2. Option-level gaps for the commands that do exist

Real option lists below come from `keytool <cmd> --help` (JDK 27).

### `-genkeypair`
Implemented: `-alias`, `-keystore`, `-storepass`, `-keypass`, `-dname`, `-keyalg`, `-keysize`, `-validity`.

Missing:

| Option | Impact |
| --- | --- |
| `-ext` | No SAN/KeyUsage/EKU/AKI/AIA/CRLDP — blocks real TLS usage |
| `-sigalg` | Signature algorithm is hardcoded to `SHA256` |
| `-keypass` | Accepted by the parser but **never used**; store and key share one password |
| `-storetype` | Cannot choose/fix a keystore format |
| `-startdate` | Certificate always starts "now" |
| `-signer`, `-signerkeypass` | Cannot issue a cert signed by an existing CA entry |
| `-groupname` | No EC named-curve selection |
| `-cacerts`, `-protected`, `-addprovider`, `-providerclass`, `-providername`, `-providerpath`, `-v` | No truststore targeting, no protected passwords, no backend pluggability, no verbose report |

### `-list`
Implemented [dev]: `-keystore`, `-storepass`, `-v`. Missing: `-alias` (single-entry
inspection), `-rfc` (PEM dump), `-cacerts`, `-storetype`, `-protected`, provider flags.
Behavioral gap: non-verbose `-list` prints only `Keystore type: PKCS12` and **no entries**
where `keytool` prints alias, creation date, entry type and a SHA-256 fingerprint.

### `-exportcert`
Implemented [dev]: `-alias`, `-keystore`, `-storepass`, `-keypass`, `-file`, `-rfc`.
Missing: writing to stdout when `-file` is absent (a documented `keytool` workflow for
piping into `openssl`), `-cacerts`, `-storetype`, `-v`, exporting **trusted-certificate**
entries (the code requires a private key).

### `-printcert`
Implemented [dev]: `-file`, `-v`. Missing: `-sslserver` (fetch from a TLS endpoint),
`-jarfile` (read a signed JAR's certificates), `-keystore` + `-alias` (print from a
store), `-rfc`, `-trustcacerts`, `-storetype`, provider flags. Its `-v` output is much
thinner than `keytool`'s (no extensions, no public key details).

### `-certreq`
Implemented [dev]: `-alias`, `-keystore`, `-storepass`, `-file`, `-sigalg` (ignored).
Missing: `-dname` (argparse **rejects** it outright, so a CSR cannot be re-issued with a
different subject), `-ext` (SAN etc. in the CSR), `-keypass`, `-v`, `-storetype`, `-protected`.
Confirmed defect: `-sigalg SHA384withRSA` is accepted but the CSR is still signed with
`sha256WithRSAEncryption`.

### `-delete`
Implemented [dev]: `-alias`, `-keystore`, `-storepass`. Missing: `-cacerts`,
`-storetype`, `-v`, `-protected`. Confirmed defect: the alias is ignored and the entry
(or everything) is deleted regardless of the name given.

---

## 3. Keystore model and format gaps

| Gap | Detail | Status |
| --- | --- | --- |
| **Multi-entry stores** | `core/keystore.py:5` `save_keystore_pkcs12()` serializes exactly one `key`+`cert` and opens the file with `"wb"` (truncate). Adding a second alias **overwrites the whole store** — verified: generating `alice` then `carol` leaves only `carol`. | ☠️ data loss |
| **Per-entry alias semantics** | `load_keystore_pkcs12()` on `main` accepts `alias` (`core/keystore.py:24`) and even builds `alias_bytes` (line 28) but never uses it. On `dev` the parameter was removed. There is no way to address a specific entry. | ☠️ |
| **`-storetype`** | Only PKCS#12 is read/written. `JKS`, `JCEKS`, `PKCS11`, `DKS` unsupported. | ✗ |
| **JKS/JCEKS interop** | Cannot read the pre-Java-9 default keystore format, nor Java-written stores in general without going through `cryptography`'s PKCS12 reader. | ✗ |
| **`cacerts` / truststore** | No `-cacerts`, no trusted-certificate entries (cert-only, no private key). | ✗ |
| **Multiple key/cert chains** | `cas=None` always (`core/keystore.py:12`); imported or issued chains cannot be represented or re-exported. | ✗ |
| **Secret-key entries** | No `SecretKeyEntry` / `-genseckey` / `-importpass`. | ✗ |
| **`-keystore` default** | `-keystore` is `required=True` on every command; `keytool` defaults to `$HOME/.keystore` (and `cacerts` with `-cacerts`). | ✗ |
| **Store discovery / creation** | No behaviour distinction between "create if absent" (`-genkeypair`) and "error if absent" (read commands), beyond a manual `os.path.exists` check. | ✗ |
| **Empty-store handling** | `dev` treats a 0-byte file as "empty" and `-delete` writes a 0-byte file, which is **not** a valid empty PKCS#12 store; `keytool` would refuse or create a well-formed store. | ⚠️ |
| **Format detection** | No magic-byte/storetype sniffing; behaviour depends entirely on the reader used. | ✗ |

**Root cause:** the data model is "one file = one key/cert pair" instead of "a keystore =
an ordered collection of named entries (private key / secret key / trusted cert)".
This single architectural decision blocks commands 7–16 in the matrix above. Fixing it
first is the highest-leverage change; a JKS/JCEKS reader (`pyjks`) plus the existing
`cryptography` PKCS12 API would cover most of it.

---

## 4. Certificate content gaps

`core/crypto.py:55-71` builds the certificate. Present extensions: **`BasicConstraints`
only** (verified with `openssl x509 -text` and `keytool -list -v`).

| Missing | Consequence |
| --- | --- |
| `SubjectAlternativeName` / `-ext san=…` | Chromium, Safari and modern `curl` reject the cert for TLS; hostname verification fails |
| `KeyUsage`, `ExtendedKeyUsage` | No key-purpose control (serverAuth/clientAuth/codeSigning/…) |
| `SubjectKeyIdentifier` / `AuthorityKeyIdentifier` | Chain building and path validation degrade |
| `CRLDistributionPoints`, `AuthorityInfoAccess` (OCSP) | No revocation checking |
| `-ext` in general (name constraints, policy, custom OID) | Arbitrary extensions impossible |
| `-sigalg` | `SHA256` hardcoded (`core/crypto.py:69`) |
| `-startdate` | `not_valid_before` is always "now" (`core/crypto.py:53`) |
| Backdating/skew tolerance | No allowance for clock skew between issuer and consumer |
| `-signer` / `gencert` | No CA-issued certificates, only self-signed |
| CA certificates | `BasicConstraints(ca=False)` is hardcoded, so the tool cannot mint a CA |
| Chain output | No `Certificate chain length` / chain handling |
| Validity limits | No check on absurd values, and `-validity` given on the CLI **crashes** (see §8) |

---

## 5. Key algorithm gaps

`generate_rsa_key()` (`core/crypto.py:7`) is the only key generator and is hardcoded to
RSA/`65537`. `-keyalg` is parsed and printed but **ignored** — verified: `-keyalg EC`
still produced a 2048-bit RSA key while the program printed `Generating key pair EC…`.

| Missing | Notes |
| --- | --- |
| `EC` + `-groupname` | Needs `cryptography`'s `ec.generate_private_key` and named curves |
| `DSA` | Legacy but still in `keytool`'s option surface |
| `Ed25519` / `Ed448` / `RSASSA-PSS` | Modern defaults on JDK 15+ for some paths |
| `-sigalg` ↔ key algorithm validation | No matrix of legal (keyalg, sigalg) pairs; no graceful error for invalid combinations |
| `-keysize` validation | No minimum/maximum check before handing it to the backend |
| Secret keys (AES/DES) | Not implemented at all (`-genseckey`) |

---

## 6. Password, security and secret-handling gaps

| Gap | Detail |
| --- | --- |
| **One password for everything** | `-keypass` is parsed but unused; store password and key password are always identical, unlike `keytool`'s two-password model (`-keypasswd`, `-importpass` exist precisely for this) |
| **No protected-password forms** | No equivalent of keytool's `-storepass:env`, `-storepass:file`, or `-protected` (password read from the console rather than the process table) |
| **Password on the command line** | No warning; `keytool` at least documents the risk and offers `-protected` |
| **Minimum length applied to reads** | `ask_password()` rejects any password shorter than 6 characters on **every** command, including read-only ones, so a legacy store with a shorter/empty password can never be opened (keytool enforces the minimum only when *setting* a new password) |
| **No retry loop** | keytool prompts up to 3 times; here a failure aborts immediately |
| **No interactive confirmation** | No `-noprompt` (`-importcert` asks `Trust this certificate? [no]:`), no `yes/no` flow at all |
| **Weak-default risk** | When `-storepass` is omitted the code prompts via `getpass` (good), but there is no policy guidance, no key-protection option (e.g. OpenSSL-style separate key encryption) |
| **No PKCS#12 iteration/algorithm control** | `BestAvailableEncryption` is fine, but `keytool` lets you pick via `-J` / provider settings, and interop with legacy stores may require weaker PBE |

---

## 7. CLI / UX / output-parity gaps

| Gap | Detail |
| --- | --- |
| **Per-command help** | `keytool -command --help` documents every option. `dev` only adds a top-level `--help`/`-h`/`-help` (argparse already gives bare `-h` only); `main` has no custom help handling at all |
| **`create_parser` vs `crear_parser`** | The function name differs between `main` (`cli.py:3`) and `dev` (`cli.py:3`), so `main.py` cannot be swapped between branches; mixed Spanish/English naming throughout (`crear_parser`, `generate_autosigned_certificate`, `emmisor`) |
| **`-v` verbosity** | Only `list` and `printcert` accept it; `genkeypair`, `exportcert`, `delete`, `certreq` do not |
| **Output format parity** | No `keytool`-style labels (`Your keystore contains N entries`, `Entry type`, `Certificate chain length`, `Valid from … until …`, `Signature algorithm name`), no localization, no columnar alignment |
| **Machine-readable output** | Everything is `print()`; no `-rfc`-to-stdout, no structured output, nothing pipeable |
| **Exit codes** | Success paths exit 0 and errors exit 1, but fatal type errors exit 1 with a **raw Python traceback** (verified for `-keysize` and `-validity`). `keytool` prints `keytool error: …` and exits 1 |
| **Errors go to stdout** | Messages are printed with `print()`, including errors, so `2>` redirection does not capture failures |
| **Duplicate messages** | Successful `-delete` prints the same "Deleted alias …" line twice (`core/keystore.py:64` on `dev` and `main.py`'s `execute_delete`), and `save_keystore_pkcs12()` prints from the storage layer |
| **`-J`, `-conf`, `-provider*`, `-addprovider`** | Unsupported. `-J`/provider flags are JVM-specific and arguably out of scope, but `-conf <url>` (preconfigured option files) and provider pluggability have Python analogues |
| **`-rfc` semantics** | Only on `exportcert`; missing from `list`, `printcert`, `gencert` |
| **No `-version` / `-showinfo`** | No way to report tool/dependency/runtime versions or JDK-style security info |
| **No stdin support** | Certificates/CSRs cannot be read from a pipe |

---

## 8. Confirmed defects (reproduced, not theoretical)

All of these were reproduced on `origin/dev` (the more complete branch) unless noted.

| # | Defect | Evidence |
| --- | --- | --- |
| 1 | **`main` is not wired to the crypto layer.** `genkeypair` prints the parsed values and exits; nothing is generated. | `main.py:9-18`; `core/` is never imported. Running it writes no keystore file. |
| 2 | **Adding a second alias destroys the store.** | `-genkeypair alice` then `-genkeypair carol` on the same file → `keytool -list` reports `contains 1 entry` / `carol`. `alice` is gone. |
| 3 | **`-delete` ignores the alias and wipes the store.** | `-delete -alias nonExistentAlias` → `Deleted alias 'nonExistentAlias'` (printed twice) and the keystore left with **0 entries**. |
| 4 | **Any explicit `-keysize` crashes.** | `-keysize 2048` → `TypeError: '<' not supported between instances of 'str' and 'int'` in `rsa._verify_rsa_parameters`. `cli.py` never sets `type=int`. |
| 5 | **Any explicit `-validity` crashes.** | `-validity 730` → `TypeError: unsupported type for timedelta days component: str`. |
| 6 | **`-keyalg` is silently ignored.** | `-keyalg EC` prints `Generating key pair EC of 2048 bits…` but produces a **2048-bit RSA** key (`generate_rsa_key` is hardcoded). The message lies. |
| 7 | **`-keypass` is silently ignored.** | Parsed in `cli.py`, never read in `main.py`/`keystore.py`. |
| 8 | **`-sigalg` is silently ignored for `certreq`.** | `-sigalg SHA384withRSA` → CSR signature is `sha256WithRSAEncryption`. |
| 9 | **Non-verbose `-list` lists nothing.** | Prints only `Keystore type: PKCS12`; no alias, no entry, no fingerprint. |
| 10 | **`alias` parameter is dead code on `main`.** | `core/keystore.py:28` builds `alias_bytes` and never passes it to `load_key_and_certificates`. |
| 11 | **`-dname` loses data on commas inside values.** | `-dname "CN=Doe, John, O=ACME"` → subject becomes `O=ACME, CN=Doe`; `" John"` is silently dropped (`core/crypto.py:34` splits on every comma; no RFC 2253 escaping). |
| 12 | **Empty/invalid `-dname` produces an unusable subject.** | Unknown attribute types are only warned about and skipped; an all-unknown input yields `x509.Name([])` with no error until signing fails. |
| 13 | **Fatal errors surface as tracebacks, not messages.** | `exit=1` with a full Python stack trace for defects 4 and 5. |
| 14 | **`dev` requires Python ≥ 3.12 without documenting it.** | `main.py` uses PEP 701 nested same-quote f-strings, e.g. `print(f'Owner: {info['owner']}')`, which is a `SyntaxError` on 3.11 and older. |
| 15 | **`-delete` on an "empty" store writes a 0-byte file.** | `core/keystore.py` (dev) `else: f.write(b'')` — not a valid empty PKCS#12 store; the reader then special-cases 0-byte files. |

---

## 9. Project / engineering gaps

| Gap | Detail |
| --- | --- |
| **No tests** | Zero test files, no fixtures, no cross-checks against `keytool` or `openssl`. Every defect in §8 is caught instantly by one interop test. |
| **`requirements.txt` is empty (0 bytes)** | `cryptography` is imported but undeclared; no pinned versions, no `dev` extras. |
| **`venv/` is committed** | `origin/dev` and `origin/nil` carry ~665 files of vendored virtualenv, including Windows-only `.exe` binaries — huge, unportable, and it masks the missing dependency declaration. |
| **No `.gitignore`** | `__pycache__/*.pyc` is tracked in the repository. |
| **No README / docs** | Only `commands.txt` (dev), which assumes **PowerShell** and a local `venv\Scripts` layout; no Linux/macOS instructions, no usage examples, no option reference. |
| **No packaging** | No `pyproject.toml`/`setup.py`, no console-script entry point; users must invoke `python main.py` from the repo root. `from cli import crear_parser` fails if run from elsewhere. |
| **No CI / hooks** | Nothing runs the tool or the tests on push. |
| **No lint/format/type config** | No `ruff`/`black`/`mypy` settings; type hints are partial (`bit_size: int`, `dname_str: str`) and inconsistent with runtime types (see `-keysize`). |
| **Monolithic dispatch** | `main.py` is an `if/elif` chain of `execute_*` functions; adding commands 7–18 this way does not scale — a command registry (`{name: handler}` + one argparse spec per command) is needed. |
| **Layer leakage** | `core/keystore.py` prints user-facing messages (`save_keystore_pkcs12`, `delete_pkcs12_entry`), so the core library cannot be reused programmatically. |
| **No logging / no `-v` plumbing** | All output is unconditional `print()`. |
| **Long-lived branch divergence** | `main` (stub) and `dev` (6 commands) have incompatible `cli.py`/`main.py` APIs; the working tree is `main`, so the visible project is the least capable version. |
| **Naming inconsistency** | Spanish identifiers (`crear_parser`, `emmisor`) with English output/options; `generate_autosigned_certificate` is a typo for *self-signed*. |
| **No license / CONTRIBUTING** | Not required, but notable for a tool emulating a JDK component. |
| **No security review** | Password handling, temp files, and permissions (keystore file mode) are unaddressed. |

---

## 10. Suggested priority order

**P0 — make what exists correct and safe (small, high value)** — *see §11 for status*
1. Fix the `-keysize` / `-validity` argument types (`type=int`) and wrap fatal errors into `keytool`-style messages with exit code 1 (no tracebacks). — **done**
2. Implement multi-entry stores: load → mutate → re-serialize all entries (never truncate an existing store). — **done** (see §12)
3. Honor `alias` on lookup/delete/export; error clearly when the alias is unknown. — **done**
4. Honor `-keyalg` (RSA/EC/DSA/Ed25519) or reject unsupported values explicitly instead of silently producing RSA. — **done**
5. Honor `-sigalg`, `-keypass` (or remove them from the CLI until supported). — **done** (`-sigalg` honoured; a differing `-keypass` is rejected explicitly)
6. Fix non-verbose `-list` to print alias, creation date, entry type and fingerprint. — **done**
7. Make `main` actually call the crypto layer (or merge/delete `main` in favour of `dev`). — **done**
8. Declare `cryptography` in `requirements.txt`; stop tracking `venv/` and `__pycache__`. — **done** (`.gitignore` added; `git rm --cached` still to be run by the owner)

**P1 — close the certification gap that makes the tool usable for TLS**
9. `-ext` support: `san`, `ku`, `eku`, `bc`, `ski`/`aki`, `crl`, `aia`.
10. `-dname` parsing per RFC 2253 (escaping, multi-valued RDNs, `EmailAddress`, `UID`, `DC`, `SERIALNUMBER`) with validation.
11. `-startdate`, and CA mode (`BasicConstraints(ca=True)`) for `genkeypair`/`gencert`.
12. `-importcert` (with `-noprompt`, `-trustcacerts`, alias assignment) and `-importkeystore`.
13. Truststore / certificate-only entries + `-cacerts`.
14. Full `-list -v` / `printcert -v` output parity (extensions, public key, chain length). *Partially done in the P0 pass.*

**P2 — reach real feature parity**
15. `-changealias`, `-keypasswd`, `-storepasswd`, `-genseckey`, `-importpass`.
16. `-storetype` with JKS/JCEKS read/write (e.g. via `pyjks`) and PKCS#12 as the default.
17. `-certreq -dname -ext -sigalg`, `-gencert`, `-printcertreq`, `-printcrl`.
18. `-printcert -sslserver`, `-jarfile`; `-exportcert`/`-list -rfc` to stdout; stdin piping.
19. `-version`, `-showinfo`, `-conf`, protected passwords (`-protected`, `*:env`, `*:file`).

**P3 — engineering hardening**
20. Test suite: unit tests for DN/cert/keystore plus an interop matrix against `keytool` and `openssl`.
21. `pyproject.toml` + `pykeytool` console entry point; `README.md`; `.gitignore`; CI (lint + tests on Linux/macOS/Windows; document Python ≥ 3.12 or remove PEP 701 syntax to support 3.11).
22. Refactor to a command registry; move all user-facing printing out of `core/`; add logging behind `-v`.

---

## Appendix A — how to reproduce

```bash
# reference surface (JDK 27)
keytool -help
keytool -genkeypair --help

# the stub on main
python3 main.py genkeypair -alias test -keystore /tmp/s.p12 -storepass secret123
ls -l /tmp/s.p12            # -> no such file: nothing was generated

# the partial implementation on dev, in a scratch copy
mkdir -p /tmp/dev && git archive origin/dev | tar -x -C /tmp/dev && cd /tmp/dev

python3 main.py genkeypair -alias alice  -keystore store.p12 -storepass secret123 -dname "CN=Alice"
python3 main.py genkeypair -alias carol  -keystore store.p12 -storepass secret123 -dname "CN=Carol"
keytool -list -keystore store.p12 -storepass secret123      # -> 1 entry: carol (alice lost)

python3 main.py list -keystore store.p12 -storepass secret123          # -> prints no entries
python3 main.py delete -alias noSuchAlias -keystore store.p12 -storepass secret123
keytool -list -keystore store.p12 -storepass secret123      # -> 0 entries

python3 main.py genkeypair -alias d -keystore s.p12 -storepass secret123 -keysize 2048   # TypeError
python3 main.py genkeypair -alias d -keystore s.p12 -storepass secret123 -validity 730   # TypeError
python3 main.py genkeypair -alias e -keystore ec.p12 -storepass secret123 -keyalg EC     # still RSA

python3 main.py exportcert -alias carol -keystore store.p12 -storepass secret123 -file c.pem -rfc
openssl x509 -in c.pem -noout -text | sed -n '/X509v3 extensions/,/Signature Algorithm/p'
#   -> only "X509v3 Basic Constraints: critical / CA:FALSE"
```

Cross-checks worth keeping as permanent interop tests: `keytool -list` on a
pykeytool-written store (works today — the PKCS#12 output is readable by Java), and
`openssl x509 -text` on an exported certificate.

---

## 11. P0 implementation status

Everything below was verified by running the tool and cross-checking the result with the
real `keytool` and with `openssl`.

### Fixed

| Defect (from §8) | Before | After |
| --- | --- | --- |
| 1 — `main` not wired to crypto | printed the arguments | `main.py` dispatches to real handlers; keys and certificates are produced |
| 3 — `-delete` ignored the alias | wiped the whole store | unknown alias → `Alias <x> does not exist in <store> (available: alice)`, exit 1, store untouched |
| 2 — second alias destroyed the store | truncated the file | refuses up front: *"Refusing to generate a key pair: a.p12 already contains 1 entry …"*; the existing entry survives |
| 4 — explicit `-keysize` crashed | `TypeError` traceback | works; out-of-range values give `Invalid -keysize 100 for RSA (must be between 1024 and 16384)` |
| 5 — explicit `-validity` crashed | `TypeError` traceback | works; `-validity 0` gives a clean error |
| 6 — `-keyalg` ignored | always RSA, message claimed otherwise | RSA, EC, DSA, Ed25519 and Ed448 all work; unsupported values are rejected |
| 8 — `-sigalg` ignored | always SHA-256 | honoured (`SHA384withRSA` → `SHA384withRSA` in the certificate and CSR); incompatible pairs are rejected |
| 7 — `-keypass` ignored | silently unused | a value differing from `-storepass` is rejected with an explanation |
| 9 — non-verbose `-list` printed nothing | `Keystore type: PKCS12` only | prints entry count, `alias, date, PrivateKeyEntry,` and the SHA-256 fingerprint |
| 10 — dead `alias` parameter | built and discarded | aliases are read from the PKCS#12 `friendlyName` and matched case-insensitively |
| 11 — DN commas lost data | `CN=Doe, John` truncated to `CN=Doe` | `-dname 'CN=Doe\, John, O=ACME'` → `O=ACME,CN=Doe\, John` |
| 12 — invalid DN produced a broken subject | warning + silent skip | unknown attribute, empty value and non-2-character country codes are all errors |
| 13 — fatal errors were tracebacks | Python stack trace | `keytool error: <message>` on stderr, exit code 1 (set `PYKEYTOOL_DEBUG=1` to see the traceback) |
| 15 — 0-byte store written on delete | invalid empty file | deleting the last entry removes the file and says so |
| P0-8 — `requirements.txt` empty | 0 bytes | declares `cryptography>=42.0`; `.gitignore` added for `venv/`, `__pycache__`, key material |

Compatibility is unchanged in the good direction: stores written by pykeytool are read
by `keytool -list -v`, and multi-entry stores written by `keytool` are read (first entry)
by pykeytool.

### Not fixed — approach decided, implementation not started

**P0-2, true multi-entry stores.** `cryptography` cannot do it. Verified against a real
2-entry store produced by `keytool`:

```python
obj = pkcs12.load_pkcs12(data, b"secret123")
obj.key              # -> only ONE private key (alice)
obj.cert             # -> alice's certificate
obj.additional_certs # -> bob's certificate, classified as a "CA certificate"
```

So a second *entry* is indistinguishable from a chain certificate except that it carries
its own `friendlyName` — which is what this pass uses to detect the situation and refuse
to write, instead of destroying data. Two further concrete limits:

* `pkcs12.serialize_key_and_certificates(name, key, cert, cas, ...)` writes exactly one
  entry, and raises `ValueError: You must supply at least one of key, cert, or cas` for an
  empty store — hence the file removal on delete.
* The PKCS#12 `creationTime` attribute is not exposed either, so `-list` shows the
  certificate's `not_valid_before` as the creation date (identical for self-signed
  entries, approximate for imported ones).

**Decision (2026-10-15): option 1 — own the PKCS#12 format.** Implemented — see §12.
Multi-entry PKCS#12 is now built on `asn1crypto` plus `cryptography` primitives rather
than adopting `pyjks` or keeping the guarded behaviour.

Options that were considered:

1. **Own the PKCS#12 format** (`asn1crypto` + `cryptography` primitives): parse and emit
   `AuthenticatedSafe`/`SafeBag` structures, PBES2 (PBKDF2 + AES-CBC) and legacy PBES1
   (3DES), plus the RFC 7292 Appendix B KDF for the MAC. Java-compatible and unblocks
   *all* of P0-2, `-importcert`, `-importkeystore` and chain support. **← chosen, done**
2. **Add JKS/JCEKS via `pyjks`** (pure Python, multi-entry native) and keep PKCS#12
   single-entry for now. Solves multi-entry for the `-storetype JKS` path only.
3. **Stay guarded**: keep the current refuse-to-destroy behaviour and revisit later.

### Next up (P1)

`-ext` (`san`, `ku`, `eku`, `ski`/`aki`), the full RFC 2253 `-dname` parser
(multi-valued RDNs, hex escapes, arbitrary OIDs), `-startdate`, CA mode, and
`-importcert` / `-importkeystore`. Chain *reading* already works (see §12), so
`-importcert` is now mostly a matter of merging an incoming chain into an entry.

---

## 12. P0-2 implementation — true multi-entry stores (done)

`core/pkcs12.py` now reads and writes PKCS#12 directly instead of going through
`cryptography`'s single-key helper, so a store can hold any number of entries.

### What was built

| Piece | Detail |
| --- | --- |
| RFC 7292 KDF | Appendix B.2 (`pkcs12_kdf`), validated **byte-for-byte** against the MAC of a keytool-written store |
| MAC | HMAC-SHA256 over the `authSafe` content, 10000 iterations, verified on load and written on save |
| PBES2 | PBKDF2-HMAC-SHA256 + AES-128/192/256-CBC, used for the shrouded keys and the certificate section |
| PBES1 | `PBEWithSHAAnd3KeyTripleDESCBC` (Java 8's default) decrypted with the PKCS#12 KDF |
| Entry grouping | leaf certificate matched to its key by `localKeyId`, chains rebuilt by issuer/subject DN, leftovers become `trustedCertEntry` |
| Unknown bags | secret bags, CRLs and anything unmodelled are kept as raw DER and re-emitted on save, so saving never discards content |
| Writes | atomic (temp file + `os.replace`) with `0600` permissions, since a keystore holds private keys |

### Layout written (determined by inspecting a JDK 27 store)

```
PFX
├── authSafe: ContentInfo(data) ── OCTET STRING ── AuthenticatedSafe
│   ├── ContentInfo(data)            → SafeContents [pkcs8ShroudedKeyBag × N]
│   └── ContentInfo(encrypted_data)  → PBES2(AES-256-CBC) → SafeContents [certBag × M]
└── macData: HMAC-SHA256, 20-byte salt, 10000 iterations
```

Key bags are individually encrypted, so Java keeps that section in plaintext; the
certificate section is encrypted as a whole. Chain certificates are written **without** a
`localKeyId` and named after their subject, exactly as keytool does — which is why
chains have to be recovered from the issuer/subject relationship rather than from the id.

### Verified against Java (keytool) and OpenSSL

* `keytool -list -v` reads a 3-entry store written by pykeytool, with correct key types
  (RSA/EC/Ed25519) and chain lengths.
* `keytool -certreq` **signs with a key pykeytool wrote**, proving the shrouded key
  decrypts (not just that the file parses).
* `keytool -importkeystore` re-imports every entry successfully.
* Exported certificates are byte-identical to the originals (SHA-256 fingerprints match).
* A real CA chain written by keytool is read (2 entries, `server` with chain length 2,
  `ca` as a trusted entry), survives a pykeytool rewrite, and is still reported by Java as
  chain length 2.
* Deleting the last entry leaves a **valid 122-byte empty store** that Java reads as
  "0 entries" — no more file removal and no 0-byte corruption.
* `openssl pkcs12` parses the output, verifies the MAC, and separates `-clcerts` from
  `-cacerts` correctly.

### Behavioural changes

| Before | After |
| --- | --- |
| Second `genkeypair` refused (to avoid destroying the first) | Adds a second entry |
| `delete` removed the whole store / the file | Removes exactly one entry; the store survives, even when emptied |
| Non-representable entries reported as unreadable | All entries readable; chains reconstructed |
| `-createTime` unavailable | Still approximated by the certificate's `not_valid_before` (the PKCS#12 time attribute is not exposed by `asn1crypto` either) |

### Dependency note

`asn1crypto>=1.5.1` is now required and declared in `requirements.txt`. If it is missing,
the tool reports `keytool error: PKCS#12 keystore support requires the 'asn1crypto'
package…` and exits 1 rather than raising an import traceback. A virtualenv was created
at `.venv/` for development; `.venv/` is git-ignored.

### Still open

* `-keypass` remains rejected when it differs from `-storepass`. Now that the format is
  under our control this is easy to support (encrypt the key bag with the key password,
  the certificate section and MAC with the store password), but it belongs with
  `-keypasswd` in P2.
* `-storetype` is still PKCS#12-only; JKS/JCEKS remains P2.


