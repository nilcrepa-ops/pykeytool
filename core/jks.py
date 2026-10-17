"""Minimal, read-only JKS (Java KeyStore) support.

Only what `-cacerts` and `-trustcacerts` need: the **trusted certificate**
entries of a JKS file, which is the format Java distributions ship their
`cacerts` truststore in.

Private-key entries (tag 1) are skipped rather than decrypted: JKS' key
protection algorithm is Sun-proprietary and is not implemented. Writing JKS is
also not implemented, so callers must refuse to modify a JKS store.

Format (big-endian)::

    u4 magic 0xFEEDFEED
    u4 version (1 or 2)
    u4 entry count
    entries:
        u4 tag (1 = private key, 2 = trusted certificate)
        UTF alias          (u2 length + modified UTF-8 bytes)
        u8 timestamp (ms)
        tag 2: UTF certType, u4 length, cert bytes
        tag 1: u4 key length, key bytes, u4 chain length, chain certs
    u2 length + UTF (the trailing SHA-1 integrity digest, 20 bytes)
"""

from __future__ import annotations

import datetime
import hashlib
import struct
import warnings
from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.utils import CryptographyDeprecationWarning

from .errors import KeytoolError

JKS_MAGIC = b"\xfe\xed\xfe\xed"

#: Phrase mixed into the trailing integrity digest (JKS-specific).
_DIGEST_PHRASE = b"Mighty Aphrodite"

TAG_PRIVATE_KEY = 1
TAG_TRUSTED_CERT = 2


@dataclass
class JksCertificate:
    alias: str
    certificate: x509.Certificate
    created: Optional[datetime.datetime] = None


def is_jks(data: bytes) -> bool:
    """True when `data` starts with the JKS magic number."""
    return data[:4] == JKS_MAGIC


def verify_digest(data: bytes, password: str) -> None:
    """Check the trailing SHA-1 integrity digest, which also validates the password."""
    if len(data) < 20:
        raise KeytoolError("Truncated JKS keystore")

    expected = data[-20:]
    body = data[:-20]
    digest = hashlib.sha1(
        password.encode("utf-16-be") + _DIGEST_PHRASE + body
    ).digest()

    if digest != expected:
        raise KeytoolError("Keystore was tampered with, or password was incorrect")


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def _take(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.data):
            raise KeytoolError("Truncated JKS keystore")
        chunk = self.data[self.offset : end]
        self.offset = end
        return chunk

    def u2(self) -> int:
        return struct.unpack(">H", self._take(2))[0]

    def u4(self) -> int:
        return struct.unpack(">I", self._take(4))[0]

    def u8(self) -> int:
        return struct.unpack(">Q", self._take(8))[0]

    def utf(self) -> str:
        length = self.u2()
        raw = self._take(length)
        # Java's modified UTF-8; plain UTF-8 matches for normal aliases.
        return raw.decode("utf-8", errors="replace")

    def certificate(self) -> x509.Certificate:
        self.utf()  # certificate type, normally "X.509"
        length = self.u4()
        der = self._take(length)
        with warnings.catch_warnings():
            # Some long-lived CA certificates in real truststores have quirks
            # (for example a negative serial number) that cryptography warns
            # about but can still parse.
            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
            return x509.load_der_x509_certificate(der)


def read_trusted_certificates(data: bytes) -> list[JksCertificate]:
    """Return the trusted-certificate entries of a JKS file."""
    if not is_jks(data):
        raise KeytoolError("Not a JKS keystore")

    reader = _Reader(data)
    reader._take(4)  # magic
    version = reader.u4()
    if version not in (1, 2):
        raise KeytoolError(f"Unsupported JKS keystore version: {version}")

    count = reader.u4()
    certificates: list[JksCertificate] = []

    for _ in range(count):
        tag = reader.u4()
        alias = reader.utf()
        # Milliseconds since the epoch.
        created = datetime.datetime.fromtimestamp(
            reader.u8() / 1000.0, datetime.timezone.utc
        )

        if tag == TAG_TRUSTED_CERT:
            try:
                certificates.append(JksCertificate(alias, reader.certificate(), created))
            except ValueError as error:
                raise KeytoolError(
                    f"Malformed certificate for <{alias}> in JKS keystore: {error}"
                ) from error
        elif tag == TAG_PRIVATE_KEY:
            # Skip the entry: JKS private keys use a proprietary encryption.
            key_length = reader.u4()
            reader._take(key_length)
            chain_length = reader.u4()
            for _ in range(chain_length):
                reader.certificate()
        else:
            raise KeytoolError(f"Unknown JKS entry tag {tag} for alias <{alias}>")

    return certificates
