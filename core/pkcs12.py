#!/usr/bin/env python3
"""Multi-entry PKCS#12 (RFC 7292) keystore engine.

Python's `cryptography` library exposes only **one** private key per PKCS#12 file:
``pkcs12.load_key_and_certificates()`` returns the first key and silently reports
every other entry as an "additional certificate". That made real multi-entry
stores impossible to handle safely (and caused the original `delete` command to
destroy them).

This module speaks the format directly with `asn1crypto` for the ASN.1
structures and `cryptography` for the primitives, so any number of entries can be
read and written.

Layout written here mirrors what modern Java's `keytool` produces, which was
determined by inspecting a store written by JDK 27:

* ``AuthenticatedSafe`` holds two ``ContentInfo`` values:
  1. ``data`` -- plaintext ``SafeContents`` with one ``pkcs8ShroudedKeyBag``
     per entry (each key individually encrypted);
  2. ``encrypted_data`` -- PBES2-encrypted ``SafeContents`` holding the
     certificate bags.
* Keys and certificates are linked by a shared ``localKeyId`` attribute and
  named by a ``friendlyName`` attribute.
* Both PBES2 blobs use PBKDF2-HMAC-SHA256 (10000 iterations, 20-byte salt) with
  AES-256-CBC.
* The file carries a ``MacData`` HMAC-SHA256 computed with the RFC 7292
  Appendix B key derivation function.

Legacy stores are read too: PBES1 ``PBEWithSHAAnd3KeyTripleDESCBC`` (the
pre-Java-9 default) and PBES2 with AES-128/192 or DES-EDE3-CBC.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .errors import KeytoolError

try:
    from asn1crypto import algos as asn1algos
    from asn1crypto import cms as asn1cms
    from asn1crypto import keys as asn1keys
    from asn1crypto import pkcs12 as asn1pkcs12
    from asn1crypto import x509 as asn1x509
except ImportError as error:  # pragma: no cover - depends on the environment
    raise KeytoolError(
        "PKCS#12 keystore support requires the 'asn1crypto' package. "
        "Install the dependencies with: pip install -r requirements.txt"
    ) from error

from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:  # 3DES moved out of the main namespace in cryptography 43+
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # pragma: no cover - older cryptography
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES  # type: ignore

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

WRONG_PASSWORD_MESSAGE = "Keystore was tampered with, or password was incorrect"

#: `localKeyId` values link a key bag to its leaf certificate bag. Java derives
#: them from a timestamp, but that collides when several entries are written in
#: the same millisecond, so random octets are used (which is also what RFC 7292
#: suggests). Java's reader treats the value as opaque.
def _new_key_id() -> bytes:
    return secrets.token_bytes(20)

DEFAULT_ITERATIONS = 10000
SALT_BYTES = 20
MAC_DIGEST = "sha256"

BAG_KEY = "key_bag"
BAG_SHROUDED_KEY = "pkcs8_shrouded_key_bag"
BAG_CERT = "cert_bag"

#: cipher name -> (key bytes, iv bytes, algorithm factory)
_CBC_CIPHERS: dict[str, tuple[int, int, Callable[[bytes], Any]]] = {
    "aes128_cbc": (16, 16, algorithms.AES),
    "aes192_cbc": (24, 16, algorithms.AES),
    "aes256_cbc": (32, 16, algorithms.AES),
    "tripledes_3key": (24, 8, TripleDES),
}

#: asn1crypto HMAC/digest name -> cryptography hash
_HASHES: dict[str, Callable[[], Any]] = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


# --------------------------------------------------------------------------- #
# Key derivation
# --------------------------------------------------------------------------- #


def _bmp_password(password: str) -> bytes:
    """PKCS#12 password encoding: BMPString (UTF-16BE) with a NUL terminator."""
    return password.encode("utf-16-be") + b"\x00\x00"


def pkcs12_kdf(
    hash_name: str,
    password: str,
    salt: bytes,
    iterations: int,
    key_size: int,
    purpose: int,
) -> bytes:
    """RFC 7292 Appendix B.2 key derivation.

    ``purpose`` is 1 for an encryption key, 2 for an IV and 3 for a MAC key.
    Validated byte-for-byte against a store written by keytool.
    """
    digest_size = hashlib.new(hash_name).digest_size
    block_size = hashlib.new(hash_name).block_size

    diversifier = bytes([purpose]) * block_size

    def expand(data: bytes) -> bytes:
        if not data:
            return b""
        needed = block_size * ((len(data) + block_size - 1) // block_size)
        return (data * ((needed // len(data)) + 1))[:needed]

    buffer = expand(salt) + expand(_bmp_password(password))

    blocks = (key_size + digest_size - 1) // digest_size
    output = b""
    for _ in range(blocks):
        block = hashlib.new(hash_name, diversifier + buffer).digest()
        for _ in range(iterations - 1):
            block = hashlib.new(hash_name, block).digest()
        output += block

        # I_j = (I_j + B + 1) mod 2^(v*8)
        b = (block * ((block_size // len(block)) + 1))[:block_size]
        b_int = int.from_bytes(b, "big")
        mutated = bytearray()
        for offset in range(0, len(buffer), block_size):
            value = (int.from_bytes(buffer[offset : offset + block_size], "big") + b_int + 1) & (
                (1 << (block_size * 8)) - 1
            )
            mutated += value.to_bytes(block_size, "big")
        buffer = bytes(mutated)

    return output[:key_size]


# --------------------------------------------------------------------------- #
# Symmetric helpers
# --------------------------------------------------------------------------- #


def _cbc_decrypt(cipher_name: str, key: bytes, iv: bytes, data: bytes) -> bytes:
    key_size, iv_size, factory = _CBC_CIPHERS[cipher_name]
    if len(key) != key_size:
        raise KeytoolError(f"Bad key size for {cipher_name}: {len(key)} bytes")
    if len(iv) != iv_size:
        raise KeytoolError(f"Bad IV size for {cipher_name}: {len(iv)} bytes")

    decryptor = Cipher(factory(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    # For CBC the IV length equals the cipher block size.
    unpad = padding.PKCS7(len(iv) * 8).unpadder()
    return unpad.update(padded) + unpad.finalize()


def _cbc_encrypt(cipher_name: str, key: bytes, iv: bytes, data: bytes) -> bytes:
    _, iv_size, factory = _CBC_CIPHERS[cipher_name]
    padder = padding.PKCS7(iv_size * 8).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(factory(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _pbes2_decrypt(parameters: Any, password: str, data: bytes) -> bytes:
    """Decrypt a PBES2 (PBKDF2 + CBC) blob."""
    kdf = parameters["key_derivation_func"]
    if kdf["algorithm"].native != "pbkdf2":
        raise KeytoolError(f"Unsupported PBES2 key derivation: {kdf['algorithm'].native}")

    kdf_params = kdf["parameters"]
    salt = kdf_params["salt"].native
    iterations = kdf_params["iteration_count"].native
    prf = kdf_params["prf"]["algorithm"].native

    scheme = parameters["encryption_scheme"]
    cipher_name = scheme["algorithm"].native
    if cipher_name not in _CBC_CIPHERS:
        raise KeytoolError(f"Unsupported PKCS#12 cipher: {cipher_name}")

    key_size = _CBC_CIPHERS[cipher_name][0]
    if kdf_params["key_length"].native:
        key_size = kdf_params["key_length"].native

    iv = scheme["parameters"].native
    # PBES2 uses the PKCS#5 password encoding (UTF-8), not the PKCS#12 BMPString.
    key = PBKDF2HMAC(
        algorithm=_HASHES[prf](),
        length=key_size,
        salt=salt,
        iterations=iterations,
    ).derive(password.encode("utf-8"))

    return _cbc_decrypt(cipher_name, key, iv, data)


def _pbes2_encrypt(cipher_name: str, password: str, data: bytes, iterations: int) -> Any:
    """Return a PBES2 `AlgorithmIdentifier` and the encrypted bytes."""
    key_size, iv_size, _ = _CBC_CIPHERS[cipher_name]
    salt = secrets.token_bytes(SALT_BYTES)
    iv = secrets.token_bytes(iv_size)

    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=iterations,
    ).derive(password.encode("utf-8"))

    encrypted = _cbc_encrypt(cipher_name, key, iv, data)

    algorithm = asn1algos.EncryptionAlgorithm(
        {
            "algorithm": "pbes2",
            "parameters": asn1algos.Pbes2Params(
                {
                    "key_derivation_func": asn1algos.KdfAlgorithm(
                        {
                            "algorithm": "pbkdf2",
                            "parameters": asn1algos.Pbkdf2Params(
                                {
                                    # `salt` is a CHOICE: `specified` (an explicit
                                    # salt) or `other_source`.
                                    "salt": {"specified": salt},
                                    "iteration_count": iterations,
                                    "key_length": key_size,
                                    "prf": {"algorithm": "sha256"},
                                }
                            ),
                        }
                    ),
                    "encryption_scheme": asn1algos.EncryptionAlgorithm(
                        {"algorithm": cipher_name, "parameters": iv}
                    ),
                }
            ),
        }
    )
    return algorithm, encrypted


def _pbes1_decrypt(algorithm: str, parameters: Any, password: str, data: bytes) -> bytes:
    """Decrypt a legacy PBES1 blob (`PBEWithSHAAnd3KeyTripleDESCBC`)."""
    if algorithm == "pkcs12_sha1_tripledes_3key":
        cipher_name, hash_name = "tripledes_3key", "sha1"
    else:
        raise KeytoolError(
            f"Unsupported PKCS#12 encryption algorithm: {algorithm} "
            f"(only PBEWithSHAAnd3KeyTripleDESCBC and PBES2 are supported)"
        )

    salt = parameters["salt"].native
    iterations = parameters["iterations"].native
    key_size, iv_size, _ = _CBC_CIPHERS[cipher_name]

    key = pkcs12_kdf(hash_name, password, salt, iterations, key_size, 1)
    iv = pkcs12_kdf(hash_name, password, salt, iterations, iv_size, 2)
    return _cbc_decrypt(cipher_name, key, iv, data)


def _decrypt_algorithm(algorithm_identifier: Any, password: str, data: bytes) -> bytes:
    """Decrypt `data` using whatever scheme `algorithm_identifier` describes."""
    name = algorithm_identifier["algorithm"].native
    parameters = algorithm_identifier["parameters"]

    if name == "pbes2":
        return _pbes2_decrypt(parameters, password, data)
    if name.startswith("pkcs12_") or name.startswith("pbes1_"):
        return _pbes1_decrypt(name, parameters, password, data)

    raise KeytoolError(f"Unsupported PKCS#12 encryption algorithm: {name}")


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class Pkcs12Entry:
    """One named keystore entry."""

    alias: Optional[str] = None
    private_key: Any = None
    certificate: Optional[x509.Certificate] = None
    chain: list[x509.Certificate] = field(default_factory=list)
    #: PKCS#12 `localKeyId`; links a key bag to its certificate bags.
    key_id: Optional[bytes] = None

    @property
    def entry_type(self) -> str:
        return "PrivateKeyEntry" if self.private_key is not None else "trustedCertEntry"


@dataclass
class Pkcs12File:
    """The readable contents of a PKCS#12 file."""

    entries: list[Pkcs12Entry] = field(default_factory=list)
    #: DER of SafeBags we do not model (secret bags, CRLs, ...), re-emitted
    #: unchanged so that saving a store never discards unknown content.
    preserved_bags: list[bytes] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #


def verify_mac(pfx: Any, password: str) -> None:
    """Check the file's `macData`, if it has one."""
    mac_data = pfx["mac_data"]
    if mac_data.native is None:
        return

    algorithm = mac_data["mac"]["digest_algorithm"]["algorithm"].native
    if algorithm not in hashlib.algorithms_available:
        raise KeytoolError(f"Unsupported PKCS#12 MAC digest: {algorithm}")

    key = pkcs12_kdf(
        algorithm,
        password,
        mac_data["mac_salt"].native,
        mac_data["iterations"].native,
        hashlib.new(algorithm).digest_size,
        3,
    )
    expected = mac_data["mac"]["digest"].native
    actual = hmac.new(key, pfx["auth_safe"]["content"].native, hashlib.new(algorithm).name).digest()

    if not hmac.compare_digest(expected, actual):
        raise KeytoolError(WRONG_PASSWORD_MESSAGE)


def _bag_alias(bag: Any) -> Optional[str]:
    attributes = bag["bag_attributes"]
    if attributes is None:
        return None
    for attribute in attributes:
        if attribute["type"].native == "friendly_name":
            values = attribute["values"].native
            if values:
                return values[0]
    return None


def _bag_key_id(bag: Any) -> Optional[bytes]:
    attributes = bag["bag_attributes"]
    if attributes is None:
        return None
    for attribute in attributes:
        if attribute["type"].native == "local_key_id":
            values = attribute["values"].native
            if values:
                return values[0]
    return None


def _load_certificate_bag(bag: Any) -> Optional[x509.Certificate]:
    value = bag["bag_value"]
    if not isinstance(value, asn1pkcs12.CertBag):
        return None
    if value["cert_id"].native != "x509":
        return None
    try:
        # `cert_value` is a ParsableOctetString: `.native` would hand back the
        # *parsed* certificate, so take the raw octets instead.
        return x509.load_der_x509_certificate(value["cert_value"].contents)
    except ValueError as error:
        raise KeytoolError(f"Malformed certificate in keystore: {error}") from error


def _load_key_bag(bag: Any, password: str) -> Any:
    bag_id = bag["bag_id"].native
    value = bag["bag_value"]

    if bag_id == BAG_KEY:
        der = value.dump()
    elif bag_id == BAG_SHROUDED_KEY:
        try:
            plain = _decrypt_algorithm(value["encryption_algorithm"], password, value["encrypted_data"].native)
        except KeytoolError:
            raise
        except Exception as error:
            raise KeytoolError(WRONG_PASSWORD_MESSAGE) from error
        der = asn1keys.PrivateKeyInfo.load(plain).dump()
    else:  # pragma: no cover - guarded by the caller
        raise KeytoolError(f"Unsupported key bag: {bag_id}")

    try:
        return serialization.load_der_private_key(der, password=None)
    except Exception as error:
        raise KeytoolError(f"Unsupported private key in keystore: {error}") from error


def _safe_contents(ci: Any, password: str) -> Any:
    """Return the `SafeContents` inside a `ContentInfo`, decrypting if needed."""
    content_type = ci["content_type"].native

    if content_type == "data":
        return asn1pkcs12.SafeContents.load(ci["content"].native)

    if content_type == "encrypted_data":
        encrypted_data = ci["content"]
        info = encrypted_data["encrypted_content_info"]
        try:
            plaintext = _decrypt_algorithm(
                info["content_encryption_algorithm"],
                password,
                info["encrypted_content"].native,
            )
        except KeytoolError:
            raise
        except Exception as error:
            # Wrong password normally surfaces here as a padding failure, for
            # files that carry no MAC to check.
            raise KeytoolError(WRONG_PASSWORD_MESSAGE) from error
        return asn1pkcs12.SafeContents.load(plaintext)

    raise KeytoolError(f"Unsupported PKCS#12 content type: {content_type}")


def _build_chain(
    leaf: x509.Certificate,
    pool: list[tuple[Optional[str], Optional[bytes], x509.Certificate]],
) -> tuple[list[x509.Certificate], list[tuple[Optional[str], Optional[bytes], x509.Certificate]]]:
    """Extend `leaf` into a chain by matching issuer to subject.

    Needed because Java stores chain certificates **without** a `localKeyId`
    (only the leaf shares the key's id), so the chain can only be recovered from
    the issuer/subject relationship.
    """
    chain: list[x509.Certificate] = []
    remaining = list(pool)
    current = leaf

    while True:
        if current.subject == current.issuer:
            break  # reached a self-signed root

        match = next(
            (item for item in remaining if item[2].subject == current.issuer),
            None,
        )
        if match is None:
            break

        remaining.remove(match)
        chain.append(match[2])
        current = match[2]

        if len(chain) > 16:  # defensive: a malformed store could loop
            break

    return chain, remaining


def _attach_certificates(
    result: Pkcs12File,
    pending: list[tuple[Optional[str], Optional[bytes], x509.Certificate]],
) -> None:
    """Work out which certificate belongs to which entry.

    Order matters: leaves are matched first (by `localKeyId`, then by alias),
    then the pool is consumed into chains, and only the leftovers become
    trusted-certificate entries. That mirrors keytool's own output, where a CA
    certificate can appear both inside a chain and as a separate entry.
    """
    # 1. Leaf certificates, matched to a key by localKeyId.
    for item in list(pending):
        alias, key_id, certificate = item
        if key_id is None:
            continue
        owner = next(
            (e for e in result.entries if e.key_id == key_id and e.certificate is None),
            None,
        )
        if owner is not None:
            owner.certificate = certificate
            pending.remove(item)

    # 2. Leaf certificates for entries still without one, matched by alias.
    for item in list(pending):
        alias, _, certificate = item
        if alias is None:
            continue
        owner = next(
            (
                e
                for e in result.entries
                if e.certificate is None
                and e.alias is not None
                and e.alias.casefold() == alias.casefold()
            ),
            None,
        )
        if owner is not None:
            owner.certificate = certificate
            pending.remove(item)

    # 3. Chains, built from whatever is left.
    pool = list(pending)
    for entry in result.entries:
        if entry.certificate is None:
            continue
        entry.chain, pool = _build_chain(entry.certificate, pool)

    # 4. Anything still unused is a trusted-certificate entry of its own.
    for alias, key_id, certificate in pool:
        result.entries.append(
            Pkcs12Entry(alias=alias, certificate=certificate, key_id=key_id)
        )


def load(data: bytes, password: str) -> Pkcs12File:
    """Parse a PKCS#12 file into entries, preserving unknown bags."""
    try:
        pfx = asn1pkcs12.Pfx.load(data)
    except Exception as error:
        raise KeytoolError(f"Not a valid PKCS#12 keystore: {error}") from error

    verify_mac(pfx, password)

    try:
        authenticated_safe = asn1pkcs12.AuthenticatedSafe.load(pfx["auth_safe"]["content"].native)
    except Exception as error:
        raise KeytoolError(f"Malformed PKCS#12 keystore: {error}") from error

    result = Pkcs12File()
    # Key bags are collected first so certificate bags can be attached to them
    # by localKeyId, then by friendlyName as a fallback.
    pending_certificates: list[tuple[Optional[str], Optional[bytes], x509.Certificate]] = []

    try:
        for content_info in authenticated_safe:
            for bag in _safe_contents(content_info, password):
                bag_id = bag["bag_id"].native
                alias = _bag_alias(bag)
                key_id = _bag_key_id(bag)

                if bag_id in (BAG_KEY, BAG_SHROUDED_KEY):
                    result.entries.append(
                        Pkcs12Entry(
                            alias=alias,
                            private_key=_load_key_bag(bag, password),
                            key_id=key_id,
                        )
                    )
                elif bag_id == BAG_CERT:
                    certificate = _load_certificate_bag(bag)
                    if certificate is not None:
                        pending_certificates.append((alias, key_id, certificate))
                    else:
                        result.preserved_bags.append(bag.dump())
                else:
                    # Unknown bag (secret bag, CRL, nested safe contents...).
                    result.preserved_bags.append(bag.dump())
    except KeytoolError:
        raise
    except Exception as error:
        raise KeytoolError(f"Malformed PKCS#12 keystore: {error}") from error

    _attach_certificates(result, pending_certificates)
    return result


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #


def _attributes(alias: Optional[str], key_id: Optional[bytes]) -> list[Any]:
    attributes = []
    if alias is not None:
        attributes.append(
            asn1pkcs12.Attribute({"type": "friendly_name", "values": [alias]})
        )
    if key_id is not None:
        attributes.append(
            asn1pkcs12.Attribute({"type": "local_key_id", "values": [key_id]})
        )
    return attributes


def _key_bag(entry: Pkcs12Entry, password: str, iterations: int) -> Any:
    der = entry.private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    algorithm, encrypted = _pbes2_encrypt("aes256_cbc", password, der, iterations)

    shrouded = asn1keys.EncryptedPrivateKeyInfo(
        {"encryption_algorithm": algorithm, "encrypted_data": encrypted}
    )
    return asn1pkcs12.SafeBag(
        {
            "bag_id": BAG_SHROUDED_KEY,
            # `bag_value` is an Any narrowed by bag_id, so it takes the object.
            "bag_value": shrouded,
            "bag_attributes": _attributes(entry.alias, entry.key_id),
        }
    )


def _certificate_bag(
    certificate: x509.Certificate,
    alias: Optional[str],
    key_id: Optional[bytes],
) -> Any:
    der = certificate.public_bytes(serialization.Encoding.DER)
    return asn1pkcs12.SafeBag(
        {
            "bag_id": BAG_CERT,
            "bag_value": asn1pkcs12.CertBag(
                {
                    "cert_id": "x509",
                    # `cert_value` is a ParsableOctetString, which parses its
                    # contents, so hand it the parsed certificate.
                    "cert_value": asn1x509.Certificate.load(der),
                }
            ),
            "bag_attributes": _attributes(alias, key_id),
        }
    )


def dump(entries: list[Pkcs12Entry], password: str, preserved_bags: Optional[list[bytes]] = None) -> bytes:
    """Serialise entries into a PKCS#12 file, mirroring keytool's layout."""
    iterations = DEFAULT_ITERATIONS
    preserved_bags = preserved_bags or []

    key_bags: list[Any] = []
    certificate_bags: list[Any] = []

    for entry in entries:
        key_id = entry.key_id or _new_key_id()
        entry.key_id = key_id

        if entry.private_key is not None:
            key_bags.append(_key_bag(entry, password, iterations))
            if entry.certificate is not None:
                certificate_bags.append(
                    _certificate_bag(entry.certificate, entry.alias, key_id)
                )
        elif entry.certificate is not None:
            # Trusted-certificate entry: named by its alias, no key to link to.
            certificate_bags.append(_certificate_bag(entry.certificate, entry.alias, None))

        # Chain certificates are stored without a localKeyId and named after
        # their subject, exactly as keytool writes them; the chain is recovered
        # on load from the issuer/subject relationship.
        for extra in entry.chain:
            certificate_bags.append(
                _certificate_bag(extra, extra.subject.rfc4514_string(), None)
            )

    for raw in preserved_bags:
        certificate_bags.append(asn1pkcs12.SafeBag.load(raw))

    content_infos: list[Any] = []

    # Section 1: key bags. Each key is already shrouded, so Java keeps this
    # section in plaintext -- mirrored here for compatibility.
    if key_bags:
        content_infos.append(
            asn1cms.ContentInfo(
                {
                    "content_type": "data",
                    "content": asn1pkcs12.SafeContents(key_bags).dump(),
                }
            )
        )

    # Section 2: certificate bags (and anything we preserved), encrypted as a
    # whole.
    if certificate_bags:
        plaintext = asn1pkcs12.SafeContents(certificate_bags).dump()
        algorithm, encrypted = _pbes2_encrypt("aes256_cbc", password, plaintext, iterations)
        encrypted_data = asn1cms.EncryptedData(
            {
                "version": "v0",
                "encrypted_content_info": asn1cms.EncryptedContentInfo(
                    {
                        "content_type": "data",
                        "content_encryption_algorithm": algorithm,
                        "encrypted_content": encrypted,
                    }
                ),
            }
        )
        content_infos.append(
            asn1cms.ContentInfo({"content_type": "encrypted_data", "content": encrypted_data})
        )

    # An empty store still needs one (empty) safe contents section.
    if not content_infos:
        content_infos.append(
            asn1cms.ContentInfo(
                {"content_type": "data", "content": asn1pkcs12.SafeContents([]).dump()}
            )
        )

    authenticated_safe = asn1pkcs12.AuthenticatedSafe(content_infos).dump()

    mac_salt = secrets.token_bytes(SALT_BYTES)
    mac_key = pkcs12_kdf(
        MAC_DIGEST,
        password,
        mac_salt,
        iterations,
        hashlib.new(MAC_DIGEST).digest_size,
        3,
    )
    mac = hmac.new(mac_key, authenticated_safe, hashlib.sha256).digest()

    pfx = asn1pkcs12.Pfx(
        {
            "version": "v3",
            "auth_safe": asn1cms.ContentInfo(
                {"content_type": "data", "content": authenticated_safe}
            ),
            "mac_data": asn1pkcs12.MacData(
                {
                    "mac": asn1pkcs12.DigestInfo(
                        {"digest_algorithm": {"algorithm": MAC_DIGEST}, "digest": mac}
                    ),
                    "mac_salt": mac_salt,
                    "iterations": iterations,
                }
            ),
        }
    )
    return pfx.dump()


def write(path: str, entries: list[Pkcs12Entry], password: str, preserved_bags: Optional[list[bytes]] = None) -> None:
    """Serialise and write atomically, with owner-only permissions."""
    data = dump(entries, password, preserved_bags)

    directory = os.path.dirname(os.path.abspath(path))
    temporary = os.path.join(directory, f".{os.path.basename(path)}.tmp")

    try:
        # A keystore holds private keys: keep it readable only by its owner.
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.replace(temporary, path)
    except OSError as error:
        try:
            if os.path.exists(temporary):
                os.remove(temporary)
        except OSError:  # pragma: no cover
            pass
        raise KeytoolError(f"Can't write keystore {path}: {error.strerror}") from error
